#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/../env.sh"

echo ""
echo "=== Building libgpg-error ${GPG_ERROR_VERSION} ==="
cd /opt/src/libgpg-error-${GPG_ERROR_VERSION}


# Cross-compilation needs lock-obj for target platform
# Use the generic POSIX fallback
if [ -f src/syscfg/lock-obj-pub.aarch64-unknown-linux-gnu.h ]; then
  cp src/syscfg/lock-obj-pub.aarch64-unknown-linux-gnu.h \
     src/syscfg/lock-obj-pub.linux-android.h
fi

./configure \
  --host=${TARGET} \
  --prefix=${SYSROOT} \
  --disable-shared \
  --enable-static \
  --disable-doc \
  --disable-tests \
  --disable-nls \
  2>&1

make -j$(nproc) 2>&1
make install 2>&1

echo "=== libgpg-error installed to ${SYSROOT} ==="
ls -lh ${SYSROOT}/lib/libgpg-error.a
