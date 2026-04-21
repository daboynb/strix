#!/bin/bash
# Common cross-compilation environment for Android ARM64
# Source this file from all build scripts: source "$(dirname "$0")/../env.sh"

TOOLCHAIN="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64"
TARGET="aarch64-linux-android"
API="${API_LEVEL}"
PREFIX="/opt/output"
SYSROOT="/opt/sysroot"

export CC="${TOOLCHAIN}/bin/clang --target=${TARGET}${API}"
export CXX="${TOOLCHAIN}/bin/clang++ --target=${TARGET}${API}"
export AR="${TOOLCHAIN}/bin/llvm-ar"
export RANLIB="${TOOLCHAIN}/bin/llvm-ranlib"
export STRIP="${TOOLCHAIN}/bin/llvm-strip"
export LD="${TOOLCHAIN}/bin/ld"

export CFLAGS="-fPIC -O2"
export CXXFLAGS="-fPIC -O2"
export LDFLAGS="-fPIE -pie -static-libstdc++"

mkdir -p ${PREFIX}/bin ${PREFIX}/share/nmap ${SYSROOT}/lib ${SYSROOT}/include
