#!/bin/bash
# Create tools-bundle.tar.gz.bin for Fang APK assets
# Uses output/ from Docker build
cd "$(dirname "$0")"

OUTPUT_DIR="$(pwd)/output"
if [ ! -d "$OUTPUT_DIR/bin" ]; then
  echo "ERROR: output/bin/ not found. Run the Docker build first:"
  echo "  docker build -t fang-tools . && docker run --rm -v \$(pwd)/output:/opt/output fang-tools"
  exit 1
fi

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
    echo "  WARNING: $bin not found in output/bin/"
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
    cp -L "$OUTPUT_DIR/lib/ettercap/"*.so "$BUNDLE_DIR/lib/ettercap/" 2>/dev/null
  fi
  echo ""
  echo "Libraries: $(ls "$BUNDLE_DIR/lib/"*.so* 2>/dev/null | wc -l) files"
  echo "Ettercap plugins: $(ls "$BUNDLE_DIR/lib/ettercap/"*.so 2>/dev/null | wc -l) plugins"
fi

# Copy nmap data files
if [ -d "$OUTPUT_DIR/share/nmap" ]; then
  cp -r "$OUTPUT_DIR/share/nmap/"* "$BUNDLE_DIR/share/nmap/"
  echo "Nmap data: $(ls "$BUNDLE_DIR/share/nmap/" | wc -l) files"
fi

# Copy ettercap data files
if [ -d "$OUTPUT_DIR/share/ettercap" ]; then
  cp "$OUTPUT_DIR/share/ettercap/"* "$BUNDLE_DIR/share/ettercap/"
  echo "Ettercap share data: $(ls "$BUNDLE_DIR/share/ettercap/" | wc -l) files"
fi
if [ -d "$OUTPUT_DIR/etc/ettercap" ]; then
  cp "$OUTPUT_DIR/etc/ettercap/"* "$BUNDLE_DIR/etc/ettercap/"
  echo "Ettercap etc data: $(ls "$BUNDLE_DIR/etc/ettercap/" | wc -l) files"
fi

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
echo "Contents:"
tar tzf tools-bundle.tar.gz
echo ""

# Copy to Fang APK assets
ASSETS_DIR="../app/src/main/assets"
mkdir -p "$ASSETS_DIR"
cp tools-bundle.tar.gz "$ASSETS_DIR/tools-bundle.tar.gz.bin"
echo "Copied to $ASSETS_DIR/tools-bundle.tar.gz.bin"

# Cleanup
rm -rf "$BUNDLE_DIR"
