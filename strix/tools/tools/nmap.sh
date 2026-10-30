#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/../env.sh"

echo ""
echo "=== Building nmap ${NMAP_VERSION} ==="
cd /opt/src/nmap-${NMAP_VERSION}


# Patch libdnet for Android NDK: IN6_IS_ADDR_UNSPECIFIED macro expects
# struct in6_addr* but libdnet uses its own struct ip6_addr
if [ -f libdnet-stripped/src/route-linux.c ]; then
  sed -i 's/IN6_IS_ADDR_UNSPECIFIED(&entry->route_gw\.addr_ip6)/IN6_IS_ADDR_UNSPECIFIED((struct in6_addr*)\&entry->route_gw.addr_ip6)/g' \
    libdnet-stripped/src/route-linux.c
  echo "  Patched libdnet route-linux.c for Android NDK"
fi

# Point to our cross-compiled OpenSSL. libpcap and pcre2 also come from the
# sysroot (libs/libpcap.sh, libs/pcre2.sh: signature-verified, static):
# - nmap's included libpcap compiled against the sysroot pcap headers found
#   first on the include path (DLT_DEBUG_ONLY missing with 7.993's 1.10.7);
# - nmap's included pcre2 (JIT sources stripped by nmap) fails to link its
#   shared library with ld.lld: the 10.47 version script lists pcre2_jit_*.
export CFLAGS="-fPIC -O2 -I${SYSROOT}/include"
export CXXFLAGS="-fPIC -O2 -I${SYSROOT}/include"
export LDFLAGS="-fPIE -pie -static-libstdc++ -L${SYSROOT}/lib"

./configure \
  --host=${TARGET} \
  --with-openssl=${SYSROOT} \
  --with-libssh2=${SYSROOT} \
  --with-libpcap=${SYSROOT} \
  --with-libdnet=included \
  --with-libpcre=${SYSROOT} \
  --with-liblua=included \
  --without-zenmap \
  --without-ndiff \
  --without-nping \
  --without-ncat \
  --disable-nmap-update \
  ac_cv_linux_vers=4 \
  2>&1

# libdnet must use PF_PACKET sockets (eth-linux.c): with the eth-none fallback
# nmap cannot send Ethernet frames, so it never does ARP host discovery and
# reports bogus MAC addresses (bytes of the IP header) for every host.
grep -q '^#define HAVE_LINUX_PF_PACKET 1' libdnet-stripped/include/config.h \
  || { echo "ERROR: libdnet configured without Linux PF_PACKET support (eth-linux)"; exit 1; }
echo "  libdnet uses eth-linux (PF_PACKET)"

# Must link our libpcap/pcre2: the included copies are configured only as a fallback
for lib in libpcap libpcre; do
  [ ! -f "$lib/Makefile" ] \
    || { echo "ERROR: nmap fell back to its included $lib (sysroot copy not usable)"; exit 1; }
done

make -j$(nproc) 2>&1

# Install
cp nmap ${PREFIX}/bin/
${STRIP} ${PREFIX}/bin/nmap

# Data files
cp nmap-os-db nmap-service-probes nmap-services nmap-protocols \
   nmap-mac-prefixes nmap-rpc ${PREFIX}/share/nmap/
# nmap-payloads was dropped upstream in recent releases; copy it only if present
[ ! -f nmap-payloads ] || cp nmap-payloads ${PREFIX}/share/nmap/

# NSE engine + scripts + libraries
cp nse_main.lua ${PREFIX}/share/nmap/
cp -r scripts nselib ${PREFIX}/share/nmap/

# Reset flags
export CFLAGS="-fPIC -O2"
export CXXFLAGS="-fPIC -O2"
export LDFLAGS="-fPIE -pie -static-libstdc++"

echo "=== nmap installed ==="
ls -lh ${PREFIX}/bin/nmap
