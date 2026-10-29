#!/bin/bash
# Create tools-bundle.tar.gz (+ signed manifest tools-bundle.json/.json.sig) and
# copy it to the APK assets as tools-bundle.tar.gz.bin.
# Uses output/ from ./build.sh. Signing: see strix/scripts/sign-bundle.sh
# (BUNDLE_SIGNING_KEY, or ALLOW_UNSIGNED=1 for local test builds).
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=../scripts/lib.sh
source ../scripts/lib.sh
load_versions

OUTPUT_DIR="$(pwd)/output"
[ -d "$OUTPUT_DIR/bin" ] || die "output/bin/ not found. Run ./build.sh first."

BUNDLE_DIR="$(pwd)/bundle-staging"
rm -rf "$BUNDLE_DIR"
mkdir -p "$BUNDLE_DIR/bin" "$BUNDLE_DIR/lib" "$BUNDLE_DIR/share/nmap" "$BUNDLE_DIR/share/ettercap" "$BUNDLE_DIR/etc/ettercap"

# Only include binaries that Fang actually uses
REQUIRED_BINS=(nmap hydra ettercap tcpdump arpspoof)
echo "Binaries:"
for bin in "${REQUIRED_BINS[@]}"; do
  if [ -f "$OUTPUT_DIR/bin/$bin" ]; then
    cp "$OUTPUT_DIR/bin/$bin" "$BUNDLE_DIR/bin/"
    echo "  $(ls -lh "$BUNDLE_DIR/bin/$bin" | awk '{print $5, $NF}')"
  else
    die "$bin not found in output/bin/"
  fi
done

# Skipped binaries (no longer used by Fang)
SKIPPED=()
for bin in "$OUTPUT_DIR/bin/"*; do
  name=$(basename "$bin")
  if [[ ! " ${REQUIRED_BINS[*]} " =~ " $name " ]]; then
    SKIPPED+=("$name")
  fi
done
if [ ${#SKIPPED[@]} -gt 0 ]; then
  echo ""
  echo "Skipped (unused): ${SKIPPED[*]}"
fi

# Copy shared libraries (ettercap .so) — resolve symlinks to real files
if [ -d "$OUTPUT_DIR/lib" ]; then
  for lib in "$OUTPUT_DIR/lib/"*.so*; do
    [ -f "$lib" ] || continue
    cp -L "$lib" "$BUNDLE_DIR/lib/"
  done
  if [ -d "$OUTPUT_DIR/lib/ettercap" ]; then
    mkdir -p "$BUNDLE_DIR/lib/ettercap"
    cp -L "$OUTPUT_DIR/lib/ettercap/"*.so "$BUNDLE_DIR/lib/ettercap/"
  fi
fi
compgen -G "$BUNDLE_DIR/lib/libettercap.so*" > /dev/null || die "libettercap.so* missing from output/lib"
compgen -G "$BUNDLE_DIR/lib/ettercap/ec_*.so" > /dev/null || die "ettercap plugins missing from output/lib/ettercap"
echo ""
echo "Libraries: $(find "$BUNDLE_DIR/lib" -maxdepth 1 -name '*.so*' | wc -l) files"
echo "Ettercap plugins: $(find "$BUNDLE_DIR/lib/ettercap" -name '*.so' | wc -l) plugins"

# Copy nmap data files
[ -f "$OUTPUT_DIR/share/nmap/nmap-services" ] || die "nmap data files missing from output/share/nmap"
cp -r "$OUTPUT_DIR/share/nmap/"* "$BUNDLE_DIR/share/nmap/"
echo "Nmap data: $(find "$BUNDLE_DIR/share/nmap" -maxdepth 1 | wc -l) entries"

# Copy ettercap data files
[ -f "$OUTPUT_DIR/etc/ettercap/etter.conf" ] || die "etter.conf missing from output/etc/ettercap"
cp "$OUTPUT_DIR/share/ettercap/"* "$BUNDLE_DIR/share/ettercap/"
cp "$OUTPUT_DIR/etc/ettercap/"* "$BUNDLE_DIR/etc/ettercap/"
echo "Ettercap share data: $(find "$BUNDLE_DIR/share/ettercap" -type f | wc -l) files"
echo "Ettercap etc data: $(find "$BUNDLE_DIR/etc/ettercap" -type f | wc -l) files"

# Create the tar.gz bundle
echo ""
echo "Creating tools-bundle.tar.gz..."
cd "$BUNDLE_DIR"
tar czf ../tools-bundle.tar.gz bin/ lib/ share/ etc/
cd ..

echo ""
echo "=== Bundle created ==="
ls -lh tools-bundle.tar.gz
echo ""
echo "Contents: $(tar tzf tools-bundle.tar.gz | wc -l) entries"
echo ""

# Manifest + signature (release assets: tools-bundle.tar.gz.bin, tools-bundle.json, tools-bundle.json.sig)
TOOLS_VERSION="nmap ${NMAP_VERSION}, hydra ${HYDRA_VERSION}, ettercap ${ETTERCAP_VERSION}, tcpdump ${TCPDUMP_VERSION}"
../scripts/sign-bundle.sh tools "$TOOLS_VERSION" "$TOOLS_BUNDLE_MIN_APP" \
  tools-bundle.tar.gz tools-bundle.tar.gz.bin tools-bundle.json

# Copy to APK assets
ASSETS_DIR="../app/src/main/assets"
mkdir -p "$ASSETS_DIR"
cp tools-bundle.tar.gz "$ASSETS_DIR/tools-bundle.tar.gz.bin"
# The app installs the asset only if it matches this manifest's sha256
cp tools-bundle.json "$ASSETS_DIR/tools-bundle.json"
echo "Copied to $ASSETS_DIR/tools-bundle.tar.gz.bin (+ tools-bundle.json)"

# Cleanup
rm -rf "$BUNDLE_DIR"
