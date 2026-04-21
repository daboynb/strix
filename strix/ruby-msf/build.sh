#!/bin/bash
# ============================================================
# Build completo: Ruby + MSF per Android ARM64
#
# Produce in /tmp/ruby-android-output/:
#   ruby-android/             — Ruby 3.3.6 cross-compilato
#   metasploit-framework/     — MSF con gem native aarch64
#   libpq.so.5                — PostgreSQL client lib
#
# Requisiti: Docker
# Tempo stimato: ~30-45 min (prima build, poi cache Docker)
# ============================================================

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
OUTPUT=/tmp/ruby-android-output

echo "============================================"
echo "  RUBY + MSF ANDROID BUILD"
echo "  $(date)"
echo "============================================"
echo ""

# ============================================================
# Stage 1: Ruby + dipendenze
# ============================================================
echo "=== STAGE 1: Ruby cross-compilation ==="

cd "${SCRIPT_DIR}/01-ruby"
docker build -t ruby-android-build . 2>&1 | tail -5

echo "Running build (this takes a while)..."
mkdir -p ${OUTPUT}
docker run --rm \
    -v ${OUTPUT}:/output \
    ruby-android-build \
    2>&1 | tee ${OUTPUT}/01-ruby-build.log | grep -E "^(PASS|FAIL|===|Ext:|ruby-)"

echo ""

# ============================================================
# Stage 2: MSF bundle + cross-compile native gems
# ============================================================
echo "=== STAGE 2: MSF bundle ==="

cd "${SCRIPT_DIR}/02-msf"
docker build -t msf-android-build . 2>&1 | tail -5

echo "Running MSF build (this takes a while)..."
docker run --rm \
    -v ${OUTPUT}:/output \
    msf-android-build \
    2>&1 | tee ${OUTPUT}/02-msf-build.log | grep -E "^(PASS|FAIL|===|DONE|Gemme|MSF:)"

echo ""

# ============================================================
# Riepilogo
# ============================================================
echo "============================================"
echo "  BUILD COMPLETATO"
echo "============================================"
echo ""
echo "Output in: ${OUTPUT}/"
ls -lh ${OUTPUT}/ 2>/dev/null
echo ""
echo "Prossimo passo:"
echo "  ./create-bundle.sh"
echo ""
echo "============================================"
