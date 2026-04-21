#!/bin/bash
source "$(dirname "$0")/../env.sh"

echo ""
echo "=== Building librtmp ==="
cd /opt/src/rtmpdump/librtmp

make clean 2>/dev/null || true

make \
  SYS=posix \
  CROSS_COMPILE="${TARGET}${API}-" \
  CC="${CC}" \
  LD="${CC}" \
  AR="${AR}" \
  RANLIB="${RANLIB}" \
  CRYPTO=OPENSSL \
  XCFLAGS="-fPIC -O2 -I${SYSROOT}/include" \
  XLDFLAGS="-L${SYSROOT}/lib" \
  prefix=${SYSROOT} \
  SHARED= \
  -j$(nproc) install 2>&1

echo "=== librtmp installed to ${SYSROOT} ==="
