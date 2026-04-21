#!/bin/bash
source "$(dirname "$0")/../env.sh"

echo ""
echo "=== Building libnet ${LIBNET_VERSION} ==="
cd /opt/src/libnet-${LIBNET_VERSION}

[ -f Makefile ] && make distclean 2>/dev/null || true

./configure \
  --host=${TARGET} \
  --prefix=${SYSROOT} \
  --disable-shared \
  --enable-static \
  2>&1

make -j$(nproc) 2>&1
make install 2>&1

echo "=== libnet installed to ${SYSROOT} ==="
