#!/bin/bash
# Sourced by ettercap.sh (same shell: inherits set -euo pipefail, env.sh vars, cwd).
set -euo pipefail
# Installs the built ettercap (run from the cmake build dir): binary, shared
# libs + SONAME links, plugins, data files.

# Install binary — check multiple possible locations
ETTERCAP_BIN=""
for candidate in ettercap src/ettercap; do
  if [ -f "$candidate" ]; then
    ETTERCAP_BIN="$candidate"
    break
  fi
done

if [ -n "${ETTERCAP_BIN}" ]; then
  cp "${ETTERCAP_BIN}" ${PREFIX}/bin/
  ${STRIP} ${PREFIX}/bin/ettercap
  echo "=== ettercap installed ==="
  ls -lh ${PREFIX}/bin/ettercap
  # Verify it's statically linked (no libettercap.so dependency)
  readelf -d ${PREFIX}/bin/ettercap 2>/dev/null | grep NEEDED || true
else
  echo "FAIL: ettercap build failed — binary not found" >&2
  exit 1
fi

# Copy shared libs (ettercap always builds as dynamic despite BUILD_SHARED_LIBS=OFF)
mkdir -p ${PREFIX}/lib
find . -name "libettercap*.so*" -type f | while read lib; do
  cp "$lib" ${PREFIX}/lib/
  echo "  Copied $(basename $lib) to ${PREFIX}/lib/"
done

# Create SONAME symlinks (ettercap binary links against libettercap.so.0, not .0.8.3.1)
cd ${PREFIX}/lib
for reallib in libettercap*.so.*.*.*; do
  [ -f "$reallib" ] || continue
  # Extract SONAME: libettercap.so.0.8.3.1 -> libettercap.so.0
  soname=$(echo "$reallib" | sed 's/\(\.so\.[0-9]*\)\..*/\1/')
  if [ "$soname" != "$reallib" ] && [ ! -e "$soname" ]; then
    ln -s "$reallib" "$soname"
    echo "  Created SONAME symlink: $soname -> $reallib"
  fi
done
cd -

# Copy ettercap plugins (ec_*.so — dns_spoof, find_ettercap, etc.)
mkdir -p ${PREFIX}/lib/ettercap
find . -name "ec_*.so" -type f | while read plugin; do
  cp "$plugin" ${PREFIX}/lib/ettercap/
  echo "  Copied plugin $(basename $plugin) to ${PREFIX}/lib/ettercap/"
done

# Copy data files — ettercap uses open_data("etc",...) for config/spoof files
# and open_data("share",...) for fingerprint/service data files.
# Path construction: INSTALL_SYSCONFDIR/ettercap/<file> and INSTALL_DATADIR/ettercap/<file>
mkdir -p ${PREFIX}/etc/ettercap ${PREFIX}/share/ettercap
cd /opt/src/ettercap-${ETTERCAP_VERSION}/share
# etter.conf doesn't exist as-is; CMake generates it from etter.conf.v4/v6
cp etter.conf.v4 ${PREFIX}/etc/ettercap/etter.conf
echo "  Created etter.conf from etter.conf.v4"
# Files loaded via open_data("etc",...) — go in etc/ettercap/
for f in etter.dns etter.mdns etter.nbns; do
  [ -f "$f" ] && cp "$f" ${PREFIX}/etc/ettercap/
done
# Files loaded via open_data("share",...) — go in share/ettercap/
for f in etter.fields etter.finger.os etter.finger.mac \
         etter.services etter.filter etter.filter.examples etter.filter.kill \
         etter.filter.ssh etter.mime etterfilter.cnt etterfilter.tbl; do
  [ -f "$f" ] && cp "$f" ${PREFIX}/share/ettercap/
done
echo "  Copied ettercap data files to ${PREFIX}/share/ettercap/"
# Files the app depends on (ToolsExtractor patches etter.conf; dns_spoof reads etter.dns)
ls -l ${PREFIX}/etc/ettercap/etter.conf ${PREFIX}/etc/ettercap/etter.dns \
      ${PREFIX}/lib/libettercap.so* ${PREFIX}/lib/ettercap/ec_dns_spoof.so
