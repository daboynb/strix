#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/../env.sh"

echo ""
echo "=== Building libidn ${LIBIDN_VERSION} ==="
cd /opt/src/libidn-${LIBIDN_VERSION}


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
