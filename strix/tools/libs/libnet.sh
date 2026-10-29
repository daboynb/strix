#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/../env.sh"

echo ""
echo "=== Building libnet ${LIBNET_VERSION} ==="
cd /opt/src/libnet-${LIBNET_VERSION}


./configure \
  --host=${TARGET} \
  --prefix=${SYSROOT} \
  --disable-shared \
  --enable-static \
  2>&1

make -j$(nproc) 2>&1
make install 2>&1

echo "=== libnet installed to ${SYSROOT} ==="
