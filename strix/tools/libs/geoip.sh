#!/bin/bash
source "$(dirname "$0")/../env.sh"

echo ""
echo "=== Building GeoIP ${GEOIP_VERSION} ==="
cd /opt/src/GeoIP-${GEOIP_VERSION}

[ -f Makefile ] && make distclean 2>/dev/null || true

# GeoIP uses autotools
if [ -f configure.ac ] && [ ! -f configure ]; then
  autoreconf -fi 2>&1
fi

export CFLAGS="-fPIC -O2"
export LDFLAGS="-fPIE -pie -static-libstdc++"

./configure \
  --host=${TARGET} \
  --prefix=${SYSROOT} \
  --disable-shared \
  --enable-static \
  2>&1

make -j$(nproc) 2>&1
make install 2>&1

echo "=== GeoIP installed to ${SYSROOT} ==="
ls -lh ${SYSROOT}/lib/libGeoIP.a 2>/dev/null
