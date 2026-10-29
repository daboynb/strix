#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/../env.sh"

echo ""
echo "=== Building libpcap ${LIBPCAP_VERSION} ==="
cd /opt/src/libpcap-${LIBPCAP_VERSION}

# Clean any previous build

./configure \
  --host=${TARGET} \
  --prefix=${SYSROOT} \
  --with-pcap=linux \
  --disable-shared \
  --disable-dbus \
  --disable-rdma \
  --disable-bluetooth \
  --disable-usb \
  ac_cv_linux_vers=4 \
  2>&1

make -j$(nproc) 2>&1
make install 2>&1

echo "=== libpcap installed to ${SYSROOT} ==="
