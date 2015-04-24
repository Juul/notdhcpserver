#!/bin/sh


export PATH=/home/juul/data/build/sudowrt-firmware/built_firmware/builder.ar71xx/staging_dir/toolchain-mips_r2_gcc-4.6-linaro_uClibc-0.9.33.2/bin:$PATH
export TARGETMACH=mips-openwrt-linux-uclibc
export BUILDMACH=x86_64-pc-linux-gnu
export CROSS=mips-openwrt-linux
export CC=${CROSS}-gcc
export LD=${CROSS}-ld
export AS=${CROSS}-as
export CXX=${CROSS}-g++
