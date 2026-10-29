#!/bin/bash
# Write a bundle manifest (<manifest>.json) and its detached ECDSA P-256 / SHA256
# DER signature (<manifest>.json.sig), then verify the signature with the public key.
#
#   sign-bundle.sh <id> <version> <min-app> <bundle-file> <asset-name> <manifest-out>
#
# Env:
#   BUNDLE_SIGNING_KEY  path to the PEM EC private key (required unless ALLOW_UNSIGNED=1)
#   BUNDLE_SIGNING_PUB  public key used to verify (default: scripts/bundle-signing.pub)
#   BUNDLE_BUILT        "built" field (UTC epoch seconds); default: now. The app orders
#                       bundles by it (newer wins: APK copy vs downloaded vs release),
#                       so it must grow with every release of the same bundle id.
#   ALLOW_UNSIGNED=1    only honoured when BUNDLE_SIGNING_KEY is unset: write the
#                       manifest without a signature and warn
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
die() { echo "ERROR: $*" >&2; exit 1; }

[ $# -eq 6 ] || die "usage: $0 <id> <version> <min-app> <bundle-file> <asset-name> <manifest-out>"
id=$1 version=$2 min_app=$3 bundle=$4 asset=$5 manifest=$6
sig="${manifest}.sig"
pub="${BUNDLE_SIGNING_PUB:-${SCRIPT_DIR}/bundle-signing.pub}"

[[ "$id" =~ ^[a-z0-9-]+$ ]] || die "invalid id '$id'"
[[ "$min_app" =~ ^[0-9]+$ ]] || die "invalid min-app '$min_app'"
[[ "$asset" =~ ^[A-Za-z0-9._-]+$ ]] || die "invalid asset name '$asset'"
[[ "$version" =~ ^[A-Za-z0-9._+\ ,/:-]+$ ]] || die "invalid version string '$version'"
[ -s "$bundle" ] || die "bundle '$bundle' missing or empty"
built="${BUNDLE_BUILT:-$(date -u +%s)}"
[[ "$built" =~ ^[0-9]+$ ]] && [ "$built" -gt 0 ] || die "invalid BUNDLE_BUILT '$built'"

# Decide on signing before doing any work
if [ -z "${BUNDLE_SIGNING_KEY:-}" ]; then
  [ "${ALLOW_UNSIGNED:-0}" = "1" ] || die "BUNDLE_SIGNING_KEY is not set (set ALLOW_UNSIGNED=1 to produce an unsigned manifest for local testing)"
  sign=0
else
  [ -f "$BUNDLE_SIGNING_KEY" ] || die "BUNDLE_SIGNING_KEY='$BUNDLE_SIGNING_KEY' does not exist"
  [ -f "$pub" ] || die "public key '$pub' not found"
  openssl pkey -in "$BUNDLE_SIGNING_KEY" -noout -text 2>/dev/null | grep -q 'NIST CURVE: P-256' \
    || die "BUNDLE_SIGNING_KEY is not an unencrypted EC P-256 private key"
  sign=1
fi

sha256=$(sha256sum "$bundle" | cut -d' ' -f1)
size=$(stat -c %s "$bundle")
unpacked=$(gzip -dc "$bundle" | wc -c)
[ "$unpacked" -gt 0 ] || die "bundle '$bundle' decompresses to 0 bytes"

rm -f "$manifest" "$sig"
printf '{"format":1,"id":"%s","version":"%s","file":"%s","sha256":"%s","size":%s,"unpacked":%s,"minApp":%s,"built":%s}\n' \
  "$id" "$version" "$asset" "$sha256" "$size" "$unpacked" "$min_app" "$built" > "$manifest"
echo "Manifest: $manifest"
cat "$manifest"

if [ "$sign" = 0 ]; then
  echo "WARNING: ALLOW_UNSIGNED=1 and no BUNDLE_SIGNING_KEY - $manifest is NOT signed" >&2
  exit 0
fi

openssl dgst -sha256 -sign "$BUNDLE_SIGNING_KEY" -out "$sig" "$manifest"
if ! openssl dgst -sha256 -verify "$pub" -signature "$sig" "$manifest"; then
  rm -f "$manifest" "$sig"
  die "signature does not verify with $pub (CI secret and committed public key don't match?)"
fi
echo "Signature: $sig (verified with $pub)"
