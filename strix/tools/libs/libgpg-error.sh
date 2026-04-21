#!/bin/bash
source "$(dirname "$0")/../env.sh"

echo ""
echo "=== Building libgpg-error ${GPG_ERROR_VERSION} ==="
cd /opt/src/libgpg-error-${GPG_ERROR_VERSION}

[ -f Makefile ] && make distclean 2>/dev/null || true

# Cross-compilation needs lock-obj for target platform
# Use the generic POSIX fallback
if [ -d src/syscfg ]; then
  cp src/syscfg/lock-obj-pub.aarch64-unknown-linux-gnu.h \
     src/syscfg/lock-obj-pub.linux-android.h 2>/dev/null || \
  cp src/syscfg/lock-obj-pub.aarch64-unknown-linux-gnu.h \
     src/syscfg/lock-obj-pub.${TARGET}.h 2>/dev/null || true
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
ls -lh ${SYSROOT}/lib/libgpg-error.a 2>/dev/null
