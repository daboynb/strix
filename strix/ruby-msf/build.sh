#!/bin/bash
# ============================================================
# Build completo: Ruby + MSF per Android ARM64 (host x86_64, Docker + buildx)
#
# Una sola `docker buildx build` multi-stage (Dockerfile: ruby -> msf -> export),
# versioni/checksum da strix/versions.env. Produce in ${BUILD_OUTPUT}
# (default ruby-msf/output/, svuotata a ogni build):
#   ruby-android/             — Ruby cross-compilato
#   metasploit-framework/     — MSF con gem native aarch64
#   libpq.so.5                — PostgreSQL client lib
#   android-deps/lib/ossl-modules/ (solo se OpenSSL produce il legacy provider)
#
# Tempo stimato: ~1-3 h (prima build, poi cache BuildKit)
# Prossimo passo: ./create-bundle.sh
# ============================================================
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=../scripts/lib.sh
source "${SCRIPT_DIR}/../scripts/lib.sh"

OUTPUT=${BUILD_OUTPUT:-${SCRIPT_DIR}/output}
LOG="${SCRIPT_DIR}/build.log"

echo "============================================"
echo "  RUBY + MSF ANDROID BUILD"
echo "  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "  Output: ${OUTPUT}"
echo "  Log:    ${LOG}"
echo "============================================"

fresh_dir "${OUTPUT}"
bundle_docker_build "${SCRIPT_DIR}" "${OUTPUT}" "${LOG}"

for p in ruby-android/bin/ruby metasploit-framework/msfconsole libpq.so.5; do
  [ -e "${OUTPUT}/${p}" ] || die "build finished but ${OUTPUT}/${p} is missing"
done

echo ""
echo "============================================"
echo "  BUILD COMPLETATO"
echo "============================================"
ls -lh "${OUTPUT}/"
echo ""
echo "Prossimo passo: ./create-bundle.sh"
