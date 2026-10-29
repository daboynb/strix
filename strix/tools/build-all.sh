#!/bin/bash
# In-container orchestrator (runs during `docker buildx build`, see Dockerfile):
# builds all libraries and tools in dependency order. Any failing step aborts.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PREFIX="/opt/output"

run() {
  echo ""
  echo "========================================================"
  echo "  $1"
  echo "========================================================"
  if ! bash "$SCRIPT_DIR/$2"; then
    echo "FAIL: $1 ($2)" >&2
    exit 1
  fi
}

echo "========================================================"
echo "  Building Strix tools for aarch64-linux-android${API_LEVEL}"
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

# Summary + hard verification
echo ""
echo "========================================================"
echo "  Build Summary"
echo "========================================================"
ls -lh "${PREFIX}/bin/"
echo ""
echo "Architecture verification:"
for name in nmap hydra ettercap tcpdump arpspoof; do
  bin="${PREFIX}/bin/${name}"
  [ -f "$bin" ] || { echo "FAIL: ${name} missing from ${PREFIX}/bin" >&2; exit 1; }
  info=$(file "$bin")
  if [[ "$info" != *"ARM aarch64"* ]]; then
    echo "FAIL: ${name} is not ARM64: ${info}" >&2
    exit 1
  fi
  echo "  ${name}: ARM aarch64"
done
