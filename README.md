markdown
# Raspberry Pi 4 bl31
A compilable project that is meant to be used for EL3 init and rpi4 compatable bl31

## Compilation

git clone https://github.com/EnpyRooters/rpi4-bl31.git

cd rpi4-bl31

make

## Installation

sudo mv ./build/bl31.bin /boot    # This may be in /boot/firmware depending on the mount point

sudo nano /boot/config.txt

#
Than add

kernel=kernel8.img   # Or where ever your kernel is \n
armstub=bl31.bin

## Usage

reboot    # DANGER! YOUR PI MAY NOT BOOT DUE TO BUGS
