#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/../env.sh"

echo ""
echo "=== Building tcpdump ${TCPDUMP_VERSION} ==="
cd /opt/src/tcpdump-${TCPDUMP_VERSION}


# Point to our cross-compiled libpcap
export CFLAGS="-fPIC -O2 -I${SYSROOT}/include"
export LDFLAGS="-fPIE -pie -static-libstdc++ -L${SYSROOT}/lib"

./configure \
  --host=${TARGET} \
  --prefix=${PREFIX} \
  2>&1

make -j$(nproc) 2>&1

cp tcpdump ${PREFIX}/bin/
${STRIP} ${PREFIX}/bin/tcpdump

# Reset flags
export CFLAGS="-fPIC -O2"
export LDFLAGS="-fPIE -pie -static-libstdc++"

echo "=== tcpdump installed ==="
ls -lh ${PREFIX}/bin/tcpdump
