#!/bin/bash
# In-container orchestrator (runs during `docker buildx build`, see Dockerfile):
# builds all libraries and tools in dependency order. Any failing step aborts.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PREFIX="/opt/output"

# Each step logs to its own file instead of stdout: BuildKit truncates a
# step's output at 2 MiB, which would hide the actual error. On failure the
# tail of the step's log is printed last, so it is always visible.
LOG_DIR=/opt/build-logs
mkdir -p "$LOG_DIR"
run() {
  local log
  log="$LOG_DIR/$(basename "$2" .sh).log"
  echo "=== $1 (log: $log)"
  if ! bash "$SCRIPT_DIR/$2" > "$log" 2>&1; then
    echo "" >&2
    echo "FAIL: $1 ($2) - last 200 lines of $log:" >&2
    tail -n 200 "$log" >&2
    exit 1
  fi
  tail -n 2 "$log"
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
run "cyrus-sasl"    libs/cyrus-sasl.sh
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
