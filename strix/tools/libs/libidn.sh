#!/bin/bash
source "$(dirname "$0")/../env.sh"

echo ""
echo "=== Building libidn 1.42 ==="
cd /opt/src/libidn-1.42

[ -f Makefile ] && make distclean 2>/dev/null || true

./configure \
  --host=${TARGET} \
  --prefix=${SYSROOT} \
  --disable-shared \
  --enable-static \
  --disable-doc \
  --disable-nls \
  2>&1

make -j$(nproc) 2>&1
make install 2>&1

echo "=== libidn installed to ${SYSROOT} ==="
