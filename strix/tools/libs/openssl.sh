#!/bin/bash
source "$(dirname "$0")/../env.sh"

echo ""
echo "=== Building OpenSSL 3.2.1 ==="
cd /opt/src/openssl-3.2.1

make distclean 2>/dev/null || true

# Set NDK toolchain paths BEFORE Configure
export ANDROID_NDK_ROOT=${ANDROID_NDK_HOME}
export PATH="${TOOLCHAIN}/bin:$PATH"

./Configure android-arm64 \
  --prefix=${SYSROOT} \
  --openssldir=${SYSROOT}/ssl \
  no-shared \
  no-tests \
  no-ui-console \
  -D__ANDROID_API__=${API} \
  2>&1

make -j$(nproc) 2>&1
make install_sw 2>&1

echo "=== OpenSSL installed to ${SYSROOT} ==="
ls -lh ${SYSROOT}/lib/libssl.a ${SYSROOT}/lib/libcrypto.a 2>/dev/null || \
ls -lh ${SYSROOT}/lib64/libssl.a ${SYSROOT}/lib64/libcrypto.a 2>/dev/null || \
echo "WARNING: OpenSSL libs not found"
