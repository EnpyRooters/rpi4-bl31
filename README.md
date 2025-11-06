# Raspberry Pi 4 bl31
A compilable project that is meant to be used for EL3 init and rpi4 compatable bl31.
This is Raspberry Pi 4 only. I made this because real bl31 has limited RPI4 support and this is a simple replacement for it.

## Compilation
These commands are for compiling rpi4-bl31. It has support for the Raspberry Pi 4, though it doesn't have much functionality.

```
git clone https://github.com/EnpyRooters/rpi4-bl31.git
cd rpi4-bl31
make
```

## Installation
These commands are for moving it and using it after reboot and telling the GPU firmware to load our firmware.

```
sudo mv ./build/bl31.bin /boot    # This may be in /boot/firmware depending on the mount point of the boot partition
sudo nano /boot/config.txt
```

Than add

```
kernel=kernel8.img   # Or where ever your kernel is
armstub=bl31.bin
```

## Usage
ONLY REBOOT IF YOU HAVE A DEVICE THAT CAN READ THE BOOT PARTITION. If you don't, you can comment out the armstub config or continue and reboot with this in mind.

```
reboot    # DANGER! YOUR PI MAY NOT BOOT DUE TO BUGS
```

#
If you want to use the SMCs, use must make sure you are using it right. this code snippet should help. This is for custom TEE or a kernel object that will use out SMCs.

```
/* ------------------------------------------------------------------------
 * SMC FIDs (vendor range: 0x8200_0000)
 * ------------------------------------------------------------------------ */
#define SMC_FID_PING              0x82000000ULL
#define SMC_FID_GET_VERSION       0x82000001ULL
#define SMC_FID_SECSTORE_WRITE    0x82001000ULL
#define SMC_FID_SECSTORE_READ     0x82001001ULL
#define SMC_FID_KEY_IMPORT        0x82002000ULL
#define SMC_FID_CRYPTO_ENCRYPT    0x82002010ULL
#define SMC_FID_CRYPTO_DECRYPT    0x82002011ULL
#define SMC_FID_CPU_ON            0x82003000ULL
#define SMC_FID_CPU_OFF           0x82003001ULL
#define SMC_FID_SYSTEM_RESET      0x82003002ULL

/* Return codes */
#define SMC_OK                    0ULL
#define SMC_ERROR                 ((uint64_t)-1)
#define SMC_INVALID_PARAM         ((uint64_t)-2)
#define SMC_NOT_SUPPORTED         ((uint64_t)-3)
#define SMC_ACCESS_DENIED         ((uint64_t)-4)
#define SMC_INSUFFICIENT_SPACE    ((uint64_t)-5)

/* Version */
#define BL31_SVC_VER_MAJOR 1
#define BL31_SVC_VER_MINOR 0

/* ------------------------------------------------------------------------
 * Non-secure RAM range for pointer validation
 * ------------------------------------------------------------------------ */
#define NS_RAM_START 0x40000000ULL
#define NS_RAM_END   0x47FFFFFFULL
```
