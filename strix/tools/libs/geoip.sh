#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/../env.sh"

echo ""
echo "=== Building GeoIP ${GEOIP_VERSION} ==="
cd /opt/src/GeoIP-${GEOIP_VERSION}


# GeoIP uses autotools
if [ -f configure.ac ] && [ ! -f configure ]; then
  autoreconf -fi 2>&1
fi

export CFLAGS="-fPIC -O2"
export LDFLAGS="-fPIE -pie -static-libstdc++"
# Cross-compiling, configure can't run its malloc(0)/realloc(0) probes and
# falls back to rpl_malloc/rpl_realloc, which GeoIP never defines (link
# fails). Bionic returns a valid pointer for size 0, so state the answer.
export ac_cv_func_malloc_0_nonnull=yes
export ac_cv_func_realloc_0_nonnull=yes

./configure \
  --host=${TARGET} \
  --prefix=${SYSROOT} \
  --disable-shared \
  --enable-static \
  2>&1

make -j$(nproc) 2>&1
make install 2>&1

echo "=== GeoIP installed to ${SYSROOT} ==="
ls -lh ${SYSROOT}/lib/libGeoIP.a
