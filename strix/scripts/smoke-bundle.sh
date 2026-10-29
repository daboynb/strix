#!/bin/bash
# CI smoke checks for a built bundle (no emulator needed).
#
#   smoke-bundle.sh <tools|msf> <bundle.tar.gz[.bin]> <manifest.json>
#
# Checks: manifest signature (unless ALLOW_UNSIGNED=1 and no .sig) + id/sha256/size,
# safe extraction (no traversal/escaping links), expected files, every relevant ELF is
# aarch64; msf also: VERSION files, key native gems + build markers, no gem installed
# in two versions across Ruby's own gem dir and vendor/bundle; DT_NEEDED of our own ELFs
# satisfied by the bundle or Android system libs (tools: everything).
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

# deps_check <dir> : every DT_NEEDED of every ELF must be an Android NDK public
# system library or be shipped in the bundle itself (otherwise the binary fails
# to start on the device with "library ... not found").
ANDROID_SYSTEM_LIBS="libc.so libm.so libdl.so liblog.so libz.so libandroid.so libstdc++.so
  libjnigraphics.so libEGL.so libGLESv1_CM.so libGLESv2.so libGLESv3.so libOpenSLES.so
  libOpenMAXAL.so libvulkan.so libmediandk.so libneuralnetworks.so libsync.so
  libbinder_ndk.so libnativewindow.so libcamera2ndk.so libaaudio.so libamidi.so"
# deps_check [--prune <glob>]... <dir>... : ELFs and shipped libs are searched under
# all the given dirs, skipping paths that match a --prune glob (e.g. gem-shipped
# target payloads, which our Ruby never loads).
deps_check() {
  local shipped elf need bad=0 n=0
  local -a prune=()
  while [ "${1:-}" = --prune ]; do prune+=(-not -path "$2"); shift 2; done
  shipped=" $(find "$@" \( -type f -o -type l \) -name '*.so*' "${prune[@]}" -printf '%f ') "
  while IFS= read -r -d '' elf; do
    file -b "$elf" | grep -q '^ELF ' || continue
    n=$((n+1))
    while read -r need; do
      [ -n "$need" ] || continue
      case " $ANDROID_SYSTEM_LIBS $shipped " in
        *" $need "*) ;;
        *) bad=1; fail "${elf#"$root"/} needs $need, which is neither an Android system library nor in the bundle" ;;
      esac
    done < <(readelf -d "$elf" 2>/dev/null | sed -nE 's/.*\(NEEDED\).*\[(.*)\]/\1/p')
  done < <(find "$@" -type f "${prune[@]}" -print0)
  [ "$bad" = 1 ] || pass "shared library deps of $n ELF files are satisfied"
}

if [ "$id" = tools ]; then
  require bin/nmap bin/hydra bin/ettercap bin/tcpdump bin/arpspoof \
          lib/libettercap.so.0 lib/ettercap/ec_dns_spoof.so \
          etc/ettercap/etter.conf etc/ettercap/etter.dns share/nmap/nmap-services share/nmap/nse_main.lua
  elf_check "$root"
  deps_check "$root"
  # hydra memcached module: compiled in, and libmemcached's SASL path actually linked
  # (static libsasl2 objects are only pulled in when memcached_*_sasl_* references them)
  if grep -aqF 'Compiled without LIBMCACHED support' "$root/bin/hydra"; then
    fail "hydra built without the memcached module (LIBMCACHED)"
  elif ! grep -aqF 'No sasl_conn_t passed to sasl_seterror' "$root/bin/hydra"; then
    fail "hydra memcached module has no SASL (libsasl2 not linked)"
  else
    pass "hydra memcached module with SASL (libsasl2 linked)"
  fi
else
  # shellcheck source=smoke-msf.sh
  source "${SCRIPT_DIR}/smoke-msf.sh"
  smoke_msf
fi

[ "$FAILS" -eq 0 ] || die "$FAILS smoke check(s) failed for $id bundle"
echo "All smoke checks passed for $id bundle"
