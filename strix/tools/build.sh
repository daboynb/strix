#!/bin/bash
# Orchestrator: builds all libraries and tools in dependency order.
# Each script is self-contained — sources env.sh for cross-compilation vars.
set +e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

run() {
  echo ""
  echo "========================================================"
  echo "  $1"
  echo "========================================================"
  bash "$SCRIPT_DIR/$2"
  local rc=$?
  if [ $rc -ne 0 ]; then
    echo "WARNING: $1 exited with code $rc"
  fi
}

echo "========================================================"
echo "  Building Fang tools for aarch64-linux-android"
echo "========================================================"

# Stage 1: Core libraries (no external deps)
run "libpcap"       libs/libpcap.sh
run "libnet"        libs/libnet.sh

# Stage 2: OpenSSL + dependents
run "OpenSSL"       libs/openssl.sh
run "librtmp"       libs/librtmp.sh
run "libidn"        libs/libidn.sh
run "curl"          libs/curl.sh
run "GeoIP"         libs/geoip.sh
run "Lua"           libs/lua.sh
run "libssh2"       libs/libssh2.sh

# Stage 3: Hydra dependency libraries
run "pcre2"         libs/pcre2.sh
run "libgpg-error"  libs/libgpg-error.sh
run "libgcrypt"     libs/libgcrypt.sh
run "libssh"        libs/libssh.sh
run "libpq"         libs/libpq.sh
run "mariadb"       libs/mariadb.sh
run "libmemcached"  libs/libmemcached.sh

# Stage 4: Tools
run "nmap"          tools/nmap.sh
run "tcpdump"       tools/tcpdump.sh
run "hydra"         tools/hydra.sh
run "ettercap"      tools/ettercap.sh
run "arpspoof"      tools/arpspoof.sh

# Summary
echo ""
echo "========================================================"
echo "  Build Summary"
echo "========================================================"
PREFIX="/opt/output"
echo ""
echo "Binaries:"
ls -lh ${PREFIX}/bin/ 2>/dev/null
echo ""
echo "Architecture verification:"
for bin in ${PREFIX}/bin/*; do
  [ -f "$bin" ] || continue
  echo "  $(basename $bin): $(file $bin | grep -o 'ARM aarch64' || echo 'NOT ARM64!')"
done
