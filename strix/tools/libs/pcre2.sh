#!/bin/bash
source "$(dirname "$0")/../env.sh"

echo ""
echo "=== Building pcre2 ${PCRE2_VERSION} ==="
cd /opt/src/pcre2-${PCRE2_VERSION}

[ -f Makefile ] && make distclean 2>/dev/null || true

./configure \
  --host=${TARGET} \
  --prefix=${SYSROOT} \
  --disable-shared \
  --enable-static \
  --disable-cpp \
  2>&1

make -j$(nproc) 2>&1
make install 2>&1

echo "=== pcre2 installed to ${SYSROOT} ==="
ls -lh ${SYSROOT}/lib/libpcre2-8.a 2>/dev/null
