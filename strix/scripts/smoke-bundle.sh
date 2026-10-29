#!/bin/bash
# CI smoke checks for a built bundle (no emulator needed).
#
#   smoke-bundle.sh <tools|msf> <bundle.tar.gz[.bin]> <manifest.json>
#
# Checks: manifest signature (unless ALLOW_UNSIGNED=1 and no .sig) + id/sha256/size,
# safe extraction (no traversal/escaping links), expected files, every relevant ELF is
# aarch64; msf also: VERSION files, key native gems + build markers, no gem installed
# in two versions across Ruby's own gem dir and vendor/bundle.
# Versions to compare against come from strix/versions.env.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"
load_versions

[ $# -eq 3 ] || die "usage: $0 <tools|msf> <bundle> <manifest.json>"
id=$1 bundle=$2 manifest=$3
pub="${BUNDLE_SIGNING_PUB:-${SCRIPT_DIR}/bundle-signing.pub}"
FAILS=0
fail() { echo "FAIL: $*" >&2; FAILS=$((FAILS+1)); }
pass() { echo "PASS: $*"; }

# --- manifest ---------------------------------------------------------------
if [ -f "${manifest}.sig" ]; then
  openssl dgst -sha256 -verify "$pub" -signature "${manifest}.sig" "$manifest" > /dev/null \
    && pass "manifest signature" || fail "manifest signature does not verify with $pub"
elif [ "${ALLOW_UNSIGNED:-0}" = 1 ]; then
  echo "WARN: ${manifest}.sig missing (ALLOW_UNSIGNED=1)"
else
  fail "${manifest}.sig missing"
fi
[ "$(jq -er .id "$manifest")" = "$id" ] || fail "manifest id is not '$id'"
[ "$(jq -er .sha256 "$manifest")" = "$(sha256sum "$bundle" | cut -d' ' -f1)" ] || fail "manifest sha256 != bundle"
[ "$(jq -er .size "$manifest")" = "$(stat -c %s "$bundle")" ] || fail "manifest size != bundle"
jq -e '.built > 0 and .minApp >= 0 and .unpacked > 0' "$manifest" > /dev/null || fail "manifest built/minApp/unpacked invalid"

# --- safe extraction ---------------------------------------------------------
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
case "$id" in
  tools) tops=(bin lib share etc) ;;
  msf)   tops=(ruby-android metasploit-framework) ;;
  *)     die "unknown bundle id '$id'" ;;
esac
python3 -I "${SCRIPT_DIR}/tar_safe_extract.py" "$bundle" "$root" "${tops[@]}" || die "unsafe or unreadable archive"

require() { local p; for p in "$@"; do [ -e "$root/$p" ] || fail "missing $p"; done; }

# elf_check <dir>... : every ELF under the given dirs must be ARM aarch64
elf_check() {
  local bad n=0 line
  while IFS= read -r line; do
    n=$((n+1))
    [[ "$line" == *"ARM aarch64"* ]] || { bad=1; fail "non-aarch64 ELF: ${line#"$root"/}"; }
  done < <(find "$@" -type f -print0 | xargs -0 -r file -N -F '|' | grep '| ELF ' || true)
  [ "${bad:-0}" = 1 ] || pass "$n ELF files under ${*#"$root"/} are aarch64"
}

if [ "$id" = tools ]; then
  require bin/nmap bin/hydra bin/ettercap bin/tcpdump bin/arpspoof \
          lib/libettercap.so.0 lib/ettercap/ec_dns_spoof.so \
          etc/ettercap/etter.conf etc/ettercap/etter.dns share/nmap/nmap-services share/nmap/nse_main.lua
  elf_check "$root"
else
  # shellcheck source=smoke-msf.sh
  source "${SCRIPT_DIR}/smoke-msf.sh"
  smoke_msf
fi

[ "$FAILS" -eq 0 ] || die "$FAILS smoke check(s) failed for $id bundle"
echo "All smoke checks passed for $id bundle"
