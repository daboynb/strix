#!/bin/bash
# Host-side build of the tools bundle inputs (x86_64 host, Docker with buildx).
# Builds the Docker image with versions from strix/versions.env and exports the
# cross-compiled tree (bin/ lib/ share/ etc/) to ./output (wiped first).
# Next step: ./create-bundle.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../scripts/lib.sh
source "${SCRIPT_DIR}/../scripts/lib.sh"

OUTPUT_DIR="${SCRIPT_DIR}/output"
fresh_dir "$OUTPUT_DIR"

echo "=== Building tools (log: ${SCRIPT_DIR}/build.log) ==="
bundle_docker_build "$SCRIPT_DIR" "$OUTPUT_DIR" "${SCRIPT_DIR}/build.log"

[ -d "${OUTPUT_DIR}/bin" ] || die "build finished but ${OUTPUT_DIR}/bin is missing"
echo ""
echo "Output: ${OUTPUT_DIR}"
ls -lh "${OUTPUT_DIR}/bin"
echo "Next: ./create-bundle.sh"
