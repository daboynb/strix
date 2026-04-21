#!/bin/bash
source "$(dirname "$0")/../env.sh"

echo ""
echo "=== Building nmap ${NMAP_VERSION} ==="
cd /opt/src/nmap-${NMAP_VERSION}

[ -f Makefile ] && make distclean 2>/dev/null || true

# Patch libdnet for Android NDK: IN6_IS_ADDR_UNSPECIFIED macro expects
# struct in6_addr* but libdnet uses its own struct ip6_addr
if [ -f libdnet-stripped/src/route-linux.c ]; then
  sed -i 's/IN6_IS_ADDR_UNSPECIFIED(&entry->route_gw\.addr_ip6)/IN6_IS_ADDR_UNSPECIFIED((struct in6_addr*)\&entry->route_gw.addr_ip6)/g' \
    libdnet-stripped/src/route-linux.c
  echo "  Patched libdnet route-linux.c for Android NDK"
fi

# Point to our cross-compiled OpenSSL
export CFLAGS="-fPIC -O2 -I${SYSROOT}/include"
export CXXFLAGS="-fPIC -O2 -I${SYSROOT}/include"
export LDFLAGS="-fPIE -pie -static-libstdc++ -L${SYSROOT}/lib"

./configure \
  --host=${TARGET} \
  --with-openssl=${SYSROOT} \
  --with-libssh2=${SYSROOT} \
  --with-libpcap=included \
  --with-libdnet=included \
  --with-libpcre=included \
  --with-liblua=included \
  --without-zenmap \
  --without-ndiff \
  --without-nping \
  --without-ncat \
  --disable-nmap-update \
  ac_cv_linux_vers=4 \
  2>&1

# Disable shared lib for bundled libpcap (TLS relocation errors with NDK)
if [ -f libpcap/Makefile ]; then
  sed -i 's/^build-shared:.*$/build-shared:/' libpcap/Makefile
  echo "  Disabled libpcap shared lib build"
fi

make -j$(nproc) 2>&1

# Install
cp nmap ${PREFIX}/bin/
${STRIP} ${PREFIX}/bin/nmap

# Data files
cp nmap-os-db nmap-service-probes nmap-services nmap-protocols \
   nmap-mac-prefixes nmap-payloads nmap-rpc ${PREFIX}/share/nmap/ 2>/dev/null || true

# NSE engine + scripts + libraries
cp nse_main.lua ${PREFIX}/share/nmap/ 2>/dev/null || true
[ -d scripts ] && cp -r scripts ${PREFIX}/share/nmap/
[ -d nselib ] && cp -r nselib ${PREFIX}/share/nmap/

# Reset flags
export CFLAGS="-fPIC -O2"
export CXXFLAGS="-fPIC -O2"
export LDFLAGS="-fPIE -pie -static-libstdc++"

echo "=== nmap installed ==="
ls -lh ${PREFIX}/bin/nmap
