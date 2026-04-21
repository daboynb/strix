#!/bin/bash
source "$(dirname "$0")/../env.sh"

echo ""
echo "=== Building libssh ${LIBSSH_VERSION} ==="
cd /opt/src/libssh-${LIBSSH_VERSION}

rm -rf build && mkdir -p build && cd build

# Android bionic lacks GLOB_TILDE and S_IWRITE
sed -i 's/GLOB_TILDE/0/g' /opt/src/libssh-${LIBSSH_VERSION}/src/config.c 2>/dev/null || true
sed -i 's/S_IWRITE/S_IWUSR/g' /opt/src/libssh-${LIBSSH_VERSION}/src/misc.c 2>/dev/null || true

cmake .. \
  -DCMAKE_SYSTEM_NAME=Linux \
  -DCMAKE_SYSTEM_PROCESSOR=aarch64 \
  -DCMAKE_C_COMPILER="${TOOLCHAIN}/bin/clang" \
  -DCMAKE_C_FLAGS="--target=${TARGET}${API} -fPIC -O2 -std=gnu99 -I${SYSROOT}/include" \
  -DCMAKE_EXE_LINKER_FLAGS="--target=${TARGET}${API} -fPIE -pie -static-libstdc++ -L${SYSROOT}/lib" \
  -DCMAKE_AR="${TOOLCHAIN}/bin/llvm-ar" \
  -DCMAKE_RANLIB="${TOOLCHAIN}/bin/llvm-ranlib" \
  -DCMAKE_INSTALL_PREFIX=${SYSROOT} \
  -DCMAKE_FIND_ROOT_PATH="${SYSROOT}" \
  -DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY \
  -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY \
  -DOPENSSL_ROOT_DIR="${SYSROOT}" \
  -DOPENSSL_INCLUDE_DIR="${SYSROOT}/include" \
  -DOPENSSL_CRYPTO_LIBRARY="${SYSROOT}/lib/libcrypto.a" \
  -DOPENSSL_SSL_LIBRARY="${SYSROOT}/lib/libssl.a" \
  -DWITH_SERVER=OFF \
  -DWITH_EXAMPLES=OFF \
  -DBUILD_SHARED_LIBS=OFF \
  -DWITH_GSSAPI=OFF \
  -DWITH_ZLIB=OFF \
  -DWITH_PCAP=OFF \
  -DHAVE_COMPILER__FUNC__=1 \
  -DHAVE_COMPILER__FUNCTION__=1 \
  2>&1

make -j$(nproc) 2>&1
make install 2>&1

echo "=== libssh installed to ${SYSROOT} ==="
ls -lh ${SYSROOT}/lib/libssh.a 2>/dev/null
