#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/../env.sh"

echo ""
echo "=== Building OpenSSL ${OPENSSL_VERSION} ==="
cd /opt/src/openssl-${OPENSSL_VERSION}


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
if [ -f ${SYSROOT}/lib/libssl.a ]; then
  ls -lh ${SYSROOT}/lib/libssl.a ${SYSROOT}/lib/libcrypto.a
else
  ls -lh ${SYSROOT}/lib64/libssl.a ${SYSROOT}/lib64/libcrypto.a
fi
