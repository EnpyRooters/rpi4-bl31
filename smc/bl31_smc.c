/*
 * bl31_services_crypto_demo.c -- Extended BL31 SMC handler with demo crypto
 *
 * Features:
 *  - All previous features from your original handler (ping/version/securestore/key store/psci stubs)
 *  - Replaces XOR demo crypto with a two-stage reversible demo cipher:
 *      Stage A: XTEA (32 rounds) on 64-bit blocks (requires 128-bit key)
 *      Stage B: Reversible 64-bit mixing (rotate/add/xor sequence)
 *
 *  - Buffer lengths must be a multiple of 8 bytes for encrypt/decrypt (demo simplification).
 *
 * Security / Production notes:
 *  - This is demo code only. Replace with AES-GCM or hardware crypto for production.
 *  - Replace PRNG with hardware RNG / NIST DRBG before production.
 */

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------------
 * Basic typedefs & return codes
 * ------------------------------------------------------------------------ */
#define SMC_OK                    0ULL
#define SMC_ERROR                 ((uint64_t)-1)
#define SMC_INVALID_PARAM         ((uint64_t)-2)
#define SMC_NOT_SUPPORTED         ((uint64_t)-3)
#define SMC_ACCESS_DENIED         ((uint64_t)-4)
#define SMC_INSUFFICIENT_SPACE    ((uint64_t)-5)

#define BL31_SVC_VER_MAJOR 1
#define BL31_SVC_VER_MINOR 2

/* ------------------------------------------------------------------------
 * Non-secure RAM range (adjust to your platform)
 * ------------------------------------------------------------------------ */
#define NS_RAM_START 0x40000000ULL   // ~1 GB offset, avoids MMIO and low firmware areas
#define NS_RAM_END   0x1FFFFFFFFULL  // 8 GB RAM top

static inline int is_nonsecure_ptr(uint64_t addr, uint64_t len)
{
    if (len == 0) return 0;
    if (addr < NS_RAM_START) return 0;
    if (addr + len - 1 < addr) return 0;
    if ((addr + len - 1) > NS_RAM_END) return 0;
    return 1;
}

/* ------------------------------------------------------------------------
 * Firmware-safe memory helpers
 * ------------------------------------------------------------------------ */
static void *fw_memcpy(void *dst, const void *src, unsigned long n)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    for (unsigned long i = 0; i < n; i++)
        d[i] = s[i];
    return dst;
}

static void *fw_memset(void *dst, int value, unsigned long n)
{
    uint8_t *d = (uint8_t *)dst;
    for (unsigned long i = 0; i < n; i++)
        d[i] = (uint8_t)value;
    return dst;
}

/* secure zeroization */
static void secure_zero(void *v, unsigned long n)
{
    volatile uint8_t *p = (volatile uint8_t *)v;
    while (n--) *p++ = 0;
}

static char *fw_strcpy(char *dst, const char *src)
{
    char *d = dst;
    while ((*d++ = *src++) != 0)
        ;
    return dst;
}

/* ------------------------------------------------------------------------
 * SMC FIDs (vendor range)
 * ------------------------------------------------------------------------ */
#define SMC_FID_PING              0x82000000ULL
#define SMC_FID_GET_VERSION       0x82000001ULL

#define SMC_FID_SECSTORE_WRITE    0x82001000ULL
#define SMC_FID_SECSTORE_READ     0x82001001ULL

#define SMC_FID_KEY_IMPORT        0x82002000ULL
#define SMC_FID_KEY_GENERATE      0x82002002ULL
#define SMC_FID_KEY_CLEAR         0x82002003ULL
#define SMC_FID_KEY_EXPORT        0x82002004ULL

#define SMC_FID_CRYPTO_ENCRYPT    0x82002010ULL
#define SMC_FID_CRYPTO_DECRYPT    0x82002011ULL

#define SMC_FID_GET_CPU_FREQ      0x82004000ULL
#define SMC_FID_GET_RANDOM        0x82004001ULL

#define SMC_FID_CPU_ON            0x82003000ULL
#define SMC_FID_CPU_OFF           0x82003001ULL
#define SMC_FID_SYSTEM_RESET      0x82003002ULL

/* ------------------------------------------------------------------------
 * Secure store (demo)
 * ------------------------------------------------------------------------ */
#define SECSTORE_SIZE 4096
static uint8_t secure_store[SECSTORE_SIZE];

static uint64_t secure_store_write(uint64_t ns_ptr, uint64_t len)
{
    if (len > SECSTORE_SIZE) return SMC_INSUFFICIENT_SPACE;
    if (!is_nonsecure_ptr(ns_ptr, len)) return SMC_ACCESS_DENIED;

    fw_memcpy(secure_store, (void *)(uintptr_t)ns_ptr, (unsigned long)len);
    return SMC_OK;
}

static uint64_t secure_store_read(uint64_t ns_ptr, uint64_t len)
{
    if (len > SECSTORE_SIZE) return SMC_INSUFFICIENT_SPACE;
    if (!is_nonsecure_ptr(ns_ptr, len)) return SMC_ACCESS_DENIED;

    fw_memcpy((void *)(uintptr_t)ns_ptr, secure_store, (unsigned long)len);
    return SMC_OK;
}

/* ------------------------------------------------------------------------
 * Key store (demo)
 * ------------------------------------------------------------------------ */
#define MAX_KEYS 8
#define KEY_SIZE 32

static uint8_t key_store[MAX_KEYS][KEY_SIZE];
static uint8_t key_len[MAX_KEYS];
static uint8_t key_attr[MAX_KEYS]; /* bit0 = exportable */

/* import key: x1=key_id, x2=src_ptr, x3=len, x4=attr_flags */
static uint64_t import_key(uint64_t key_id, uint64_t src_ptr, uint64_t len, uint64_t attr_flags)
{
    if (key_id >= MAX_KEYS) return SMC_INVALID_PARAM;
    if (len == 0 || len > KEY_SIZE) return SMC_INVALID_PARAM;
    if (!is_nonsecure_ptr(src_ptr, len)) return SMC_ACCESS_DENIED;

    fw_memcpy(key_store[key_id], (void *)(uintptr_t)src_ptr, (unsigned long)len);
    key_len[key_id] = (uint8_t)len;
    key_attr[key_id] = (uint8_t)(attr_flags & 0xFF);
    return SMC_OK;
}

static uint64_t generate_key(uint64_t key_id, uint64_t len, uint64_t attr_flags);
static uint64_t clear_key(uint64_t key_id)
{
    if (key_id >= MAX_KEYS) return SMC_INVALID_PARAM;
    secure_zero(key_store[key_id], KEY_SIZE);
    key_len[key_id] = 0;
    key_attr[key_id] = 0;
    return SMC_OK;
}

static uint64_t export_key(uint64_t key_id, uint64_t dst_ptr, uint64_t dst_len)
{
    if (key_id >= MAX_KEYS) return SMC_INVALID_PARAM;
    if (key_len[key_id] == 0) return SMC_INVALID_PARAM;
    if (!(key_attr[key_id] & 0x1)) return SMC_ACCESS_DENIED;
    if (dst_len < key_len[key_id]) return SMC_INSUFFICIENT_SPACE;
    if (!is_nonsecure_ptr(dst_ptr, (uint64_t)key_len[key_id])) return SMC_ACCESS_DENIED;

    fw_memcpy((void *)(uintptr_t)dst_ptr, key_store[key_id], (unsigned long)key_len[key_id]);
    return SMC_OK;
}

/* ------------------------------------------------------------------------
 * Simple PRNG (demo only) - replace in production
 * ------------------------------------------------------------------------ */
static uint64_t prng_state[2] = {0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL};

static uint64_t prng_next(void)
{
    uint64_t s1 = prng_state[0];
    uint64_t s0 = prng_state[1];
    uint64_t result = s0 + s1;
    s1 ^= s0;
    prng_state[0] = (s0 << 55) ^ s1 ^ (s1 << 14);
    prng_state[1] = (s1 << 36);
    return result;
}

static uint64_t fill_random(uint64_t dst_ptr, uint64_t len)
{
    if (len == 0) return SMC_INVALID_PARAM;
    if (!is_nonsecure_ptr(dst_ptr, len)) return SMC_ACCESS_DENIED;

    uint8_t *dst = (uint8_t *)(uintptr_t)dst_ptr;
    uint64_t rem = len;
    while (rem) {
        uint64_t r = prng_next();
        for (unsigned i = 0; i < 8 && rem; i++, rem--) {
            *dst++ = (uint8_t)(r & 0xFF);
            r >>= 8;
        }
    }
    return SMC_OK;
}

/* generate key: demo from PRNG */
static uint64_t generate_key(uint64_t key_id, uint64_t len, uint64_t attr_flags)
{
    if (key_id >= MAX_KEYS) return SMC_INVALID_PARAM;
    if (len == 0 || len > KEY_SIZE) return SMC_INVALID_PARAM;

    uint8_t *k = key_store[key_id];
    uint64_t rem = len;
    uint32_t idx = 0;
    while (rem) {
        uint64_t r = prng_next();
        for (unsigned i = 0; i < 8 && rem; i++, rem--, idx++) {
            k[idx] = (uint8_t)(r & 0xFF);
            r >>= 8;
        }
    }
    key_len[key_id] = (uint8_t)len;
    key_attr[key_id] = (uint8_t)(attr_flags & 0xFF);
    return SMC_OK;
}

/* ------------------------------------------------------------------------
 * Demo cipher:
 *  - XTEA (32 rounds) on 64-bit blocks
 *  - Reversible mixing stage (C implementation)
 *
 * Requirements:
 *  - key_id must refer to a key with len >= 16 (128-bit)
 *  - buffer length must be multiple of 8 bytes
 *
 * Not intended for production!
 * ------------------------------------------------------------------------ */

/* utility rotates */
static inline uint64_t rol64(uint64_t x, unsigned r)
{
    return (x << r) | (x >> (64 - r));
}
static inline uint64_t ror64(uint64_t x, unsigned r)
{
    return (x >> r) | (x << (64 - r));
}

/* XTEA block encrypt (32 rounds)
 * v[0],v[1] are uint32_t words (64-bit block)
 * k[4] is 128-bit key
 */
static void xtea_encrypt_block(uint32_t v[2], const uint32_t k[4])
{
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t sum = 0;
    const uint32_t delta = 0x9E3779B9U;
    for (unsigned i = 0; i < 32; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);
    }
    v[0] = v0;
    v[1] = v1;
}

static void xtea_decrypt_block(uint32_t v[2], const uint32_t k[4])
{
    uint32_t v0 = v[0], v1 = v[1];
    const uint32_t delta = 0x9E3779B9U;
    uint32_t sum = delta * 32;
    for (unsigned i = 0; i < 32; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
    }
    v[0] = v0;
    v[1] = v1;
}

/* mixing stage (reversible). We keep it simple and fully invertible.
 *
 * encrypt mixing (applied AFTER XTEA):
 *   x += k0;
 *   x = rol64(x, 31);
 *   x ^= k1;
 *   x = rol64(x, 17);
 *   x += (k0 ^ k1);
 *
 * decrypt mixing (inverse; applied BEFORE XTEA when decrypting):
 *   x -= (k0 ^ k1);
 *   x = ror64(x, 17);
 *   x ^= k1;
 *   x = ror64(x, 31);
 *   x -= k0;
 */
static inline void mix_block(uint64_t *x, uint64_t k0, uint64_t k1)
{
#ifdef __aarch64__
    /* Optional optimized inline asm could live here.
       For portability and clarity we use the C version. */
#endif
    uint64_t v = *x;
    v += k0;
    v = rol64(v, 31);
    v ^= k1;
    v = rol64(v, 17);
    v += (k0 ^ k1);
    *x = v;
}

static inline void unmix_block(uint64_t *x, uint64_t k0, uint64_t k1)
{
    uint64_t v = *x;
    v -= (k0 ^ k1);
    v = ror64(v, 17);
    v ^= k1;
    v = ror64(v, 31);
    v -= k0;
    *x = v;
}

/* derive XTEA key (k[4]) and mixing keys (k0,k1) from the stored key bytes */
static int derive_cipher_keys_from_keystore(uint8_t keybuf[KEY_SIZE], uint8_t keylen,
                                            uint32_t out_k[4], uint64_t *out_k0, uint64_t *out_k1)
{
    if (keylen < 16) return 0; /* need >=128-bit key */
    /* XTEA key: first 16 bytes -> 4 x uint32_t (big-endian) or little-endian? We pick little-endian */
    for (int i = 0; i < 4; i++) {
        uint32_t w = 0;
        w  = (uint32_t)keybuf[(i*4) + 0];
        w |= (uint32_t)keybuf[(i*4) + 1] << 8;
        w |= (uint32_t)keybuf[(i*4) + 2] << 16;
        w |= (uint32_t)keybuf[(i*4) + 3] << 24;
        out_k[i] = w;
    }
    /* mixing keys: derive two 64-bit values from next bytes (or reuse repeated bytes) */
    uint8_t mixsrc[16];
    /* If stored key has >= 32 bytes, use bytes 16..31; otherwise fold bytes 0..15 */
    if (keylen >= 32) {
        for (int i = 0; i < 16; i++) mixsrc[i] = keybuf[16 + i];
    } else {
        for (int i = 0; i < 16; i++) mixsrc[i] = keybuf[i % keylen];
    }
    uint64_t k0 = 0, k1 = 0;
    for (int i = 0; i < 8; i++) k0 |= ((uint64_t)mixsrc[i]) << (8*i);
    for (int i = 0; i < 8; i++) k1 |= ((uint64_t)mixsrc[8+i]) << (8*i);
    *out_k0 = k0;
    *out_k1 = k1;
    return 1;
}

/* high-level encrypt/decrypt of a buffer (in-place)
 * args:
 *   ptr - NS pointer to buffer
 *   len - length in bytes (must be multiple of 8)
 *   key_id - key id in key_store (must have len >= 16)
 *
 * returns SMC_OK or error code
 */
static uint64_t demo_crypto_encrypt(uint64_t ptr, uint64_t len, uint64_t key_id)
{
    if (key_id >= MAX_KEYS) return SMC_INVALID_PARAM;
    if (key_len[key_id] < 16) return SMC_INVALID_PARAM;
    if (!is_nonsecure_ptr(ptr, len)) return SMC_ACCESS_DENIED;
    if (len == 0) return SMC_INVALID_PARAM;
    if (len % 8 != 0) return SMC_INVALID_PARAM; /* demo constraint */

    uint8_t *buf = (uint8_t *)(uintptr_t)ptr;
    uint32_t kx[4];
    uint64_t k0, k1;
    if (!derive_cipher_keys_from_keystore(key_store[key_id], key_len[key_id], kx, &k0, &k1))
        return SMC_INVALID_PARAM;

    /* process block-by-block (8 bytes) */
    uint64_t blocks = len / 8;
    for (uint64_t i = 0; i < blocks; i++) {
        uint8_t *b = &buf[i * 8];
        /* pack into two 32-bit words little-endian */
        uint32_t v[2];
        v[0] = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
        v[1] = (uint32_t)b[4] | ((uint32_t)b[5] << 8) | ((uint32_t)b[6] << 16) | ((uint32_t)b[7] << 24);

        /* XTEA encrypt */
        xtea_encrypt_block(v, kx);

        /* repack to uint64_t for mixing */
        uint64_t block64 = (uint64_t)v[0] | ((uint64_t)v[1] << 32);

        /* mixing */
        mix_block(&block64, k0, k1);

        /* store back little-endian */
        for (int j = 0; j < 4; j++) b[j] = (uint8_t)((block64 >> (8*j)) & 0xFF);
        for (int j = 0; j < 4; j++) b[4 + j] = (uint8_t)((block64 >> (8*(4 + j))) & 0xFF);
    }
    return SMC_OK;
}

static uint64_t demo_crypto_decrypt(uint64_t ptr, uint64_t len, uint64_t key_id)
{
    if (key_id >= MAX_KEYS) return SMC_INVALID_PARAM;
    if (key_len[key_id] < 16) return SMC_INVALID_PARAM;
    if (!is_nonsecure_ptr(ptr, len)) return SMC_ACCESS_DENIED;
    if (len == 0) return SMC_INVALID_PARAM;
    if (len % 8 != 0) return SMC_INVALID_PARAM; /* demo constraint */

    uint8_t *buf = (uint8_t *)(uintptr_t)ptr;
    uint32_t kx[4];
    uint64_t k0, k1;
    if (!derive_cipher_keys_from_keystore(key_store[key_id], key_len[key_id], kx, &k0, &k1))
        return SMC_INVALID_PARAM;

    uint64_t blocks = len / 8;
    for (uint64_t i = 0; i < blocks; i++) {
        uint8_t *b = &buf[i * 8];
        /* read 64-bit block (little-endian) */
        uint64_t block64 = 0;
        for (int j = 0; j < 8; j++) block64 |= ((uint64_t)b[j]) << (8*j);

        /* unmix */
        unmix_block(&block64, k0, k1);

        /* split into uint32_t words */
        uint32_t v[2];
        v[0] = (uint32_t)(block64 & 0xFFFFFFFFULL);
        v[1] = (uint32_t)((block64 >> 32) & 0xFFFFFFFFULL);

        /* XTEA decrypt */
        xtea_decrypt_block(v, kx);

        /* store back little-endian */
        b[0] = (uint8_t)(v[0] & 0xFF);
        b[1] = (uint8_t)((v[0] >> 8) & 0xFF);
        b[2] = (uint8_t)((v[0] >> 16) & 0xFF);
        b[3] = (uint8_t)((v[0] >> 24) & 0xFF);
        b[4] = (uint8_t)(v[1] & 0xFF);
        b[5] = (uint8_t)((v[1] >> 8) & 0xFF);
        b[6] = (uint8_t)((v[1] >> 16) & 0xFF);
        b[7] = (uint8_t)((v[1] >> 24) & 0xFF);
    }
    return SMC_OK;
}

/* ------------------------------------------------------------------------
 * PSCI-like stubs (weak platform hooks)
 * ------------------------------------------------------------------------ */
__attribute__((weak)) uint64_t platform_cpu_on(uint64_t cpu, uint64_t entry_phys) { (void)cpu; (void)entry_phys; return SMC_NOT_SUPPORTED; }
__attribute__((weak)) uint64_t platform_cpu_off(void) { return SMC_NOT_SUPPORTED; }
__attribute__((weak)) uint64_t platform_system_reset(void) { return SMC_NOT_SUPPORTED; }

static uint64_t handle_cpu_on(uint64_t cpu, uint64_t entry_phys) { return platform_cpu_on(cpu, entry_phys); }
static uint64_t handle_cpu_off(void) { return platform_cpu_off(); }
static uint64_t handle_system_reset(void) { return platform_system_reset(); }

/* ------------------------------------------------------------------------
 * Misc stubs
 * ------------------------------------------------------------------------ */
static uint64_t get_cpu_frequency(uint64_t cpu_id) { (void)cpu_id; return 1000000000ULL; }
static uint64_t get_random(uint64_t dst_ptr, uint64_t len) { return fill_random(dst_ptr, len); }

/* ------------------------------------------------------------------------
 * Main SMC dispatcher
 * ------------------------------------------------------------------------ */
uint64_t smc_dispatch_c(uint64_t *saved_regs)
{
    uint64_t fid = saved_regs[0];
    uint64_t a1  = saved_regs[1];
    uint64_t a2  = saved_regs[2];
    uint64_t a3  = saved_regs[3];
    uint64_t a4  = saved_regs[4];
    uint64_t ret = SMC_OK;

    switch (fid) {
        case SMC_FID_PING:
            saved_regs[0] = 0xBADC0FFEE0DDF00DULL;
            saved_regs[1] = 0;
            saved_regs[2] = 0;
            saved_regs[3] = 0;
            return 0;

        case SMC_FID_GET_VERSION:
            saved_regs[0] = ((uint64_t)BL31_SVC_VER_MAJOR << 16) | (uint64_t)BL31_SVC_VER_MINOR;
            return 0;

        case SMC_FID_SECSTORE_WRITE:
            ret = secure_store_write(a1, a2);
            saved_regs[0] = ret;
            return 0;

        case SMC_FID_SECSTORE_READ:
            ret = secure_store_read(a1, a2);
            saved_regs[0] = ret;
            return 0;

        case SMC_FID_KEY_IMPORT:
            /* x1=key_id x2=src_ptr x3=len x4=attr_flags */
            ret = import_key(a1, a2, a3, a4);
            saved_regs[0] = ret;
            return 0;

        case SMC_FID_KEY_GENERATE:
            /* x1=key_id x2=len x3=attr_flags */
            ret = generate_key(a1, a2, a3);
            saved_regs[0] = ret;
            return 0;

        case SMC_FID_KEY_CLEAR:
            /* x1=key_id */
            ret = clear_key(a1);
            saved_regs[0] = ret;
            return 0;

        case SMC_FID_KEY_EXPORT:
            /* x1=key_id x2=dst_ptr x3=dst_len */
            ret = export_key(a1, a2, a3);
            saved_regs[0] = ret;
            return 0;

        case SMC_FID_CRYPTO_ENCRYPT:
            /* x1=buf_ptr x2=len x3=key_id */
            ret = demo_crypto_encrypt(a1, a2, a3);
            saved_regs[0] = ret;
            return 0;

        case SMC_FID_CRYPTO_DECRYPT:
            /* x1=buf_ptr x2=len x3=key_id */
            ret = demo_crypto_decrypt(a1, a2, a3);
            saved_regs[0] = ret;
            return 0;

        case SMC_FID_GET_CPU_FREQ:
            saved_regs[0] = get_cpu_frequency(a1);
            return 0;

        case SMC_FID_GET_RANDOM:
            ret = get_random(a1, a2);
            saved_regs[0] = ret;
            return 0;

        case SMC_FID_CPU_ON:
            ret = handle_cpu_on(a1, a2);
            saved_regs[0] = ret;
            return 0;

        case SMC_FID_CPU_OFF:
            ret = handle_cpu_off();
            saved_regs[0] = ret;
            return 0;

        case SMC_FID_SYSTEM_RESET:
            ret = handle_system_reset();
            saved_regs[0] = ret;
            return 0;

        default:
            saved_regs[0] = SMC_NOT_SUPPORTED;
            saved_regs[1] = 0;
            saved_regs[2] = 0;
            saved_regs[3] = 0;
            return 0;
    }
}