#!/bin/bash
# Download a file and verify its SHA256 and, for upstreams that sign releases, its
# detached OpenPGP signature. Used inside the bundle Docker builds (the "strix-scripts"
# build context is copied to /opt/strix-scripts, this file linked as strix-fetch).
#   strix-fetch <url> <sha256> <output-file> [<keyring> <signature-url>]
# <keyring> = name in keys/fingerprints (see verify-sig.sh); bad/missing signature fails.
set -euo pipefail

[ $# -eq 3 ] || [ $# -eq 5 ] || {
  echo "usage: $0 <url> <sha256> <output-file> [<keyring> <signature-url>]" >&2; exit 2; }
url=$1 sha=$2 out=$3

[[ "$sha" =~ ^[0-9a-f]{64}$ ]] || { echo "ERROR: missing/invalid SHA256 '$sha' for $url (see strix/versions.env)" >&2; exit 1; }

dl() { curl -fsSL --retry 5 --retry-delay 5 --connect-timeout 30 -o "$2" "$1"; }

echo "fetch: $url"
dl "$url" "$out"
echo "${sha}  ${out}" | sha256sum -c --strict -
if [ $# -eq 5 ]; then
  dl "$5" "${out}.sig" || { echo "ERROR: cannot download signature $5" >&2; exit 1; }
  "$(dirname "$(readlink -f "$0")")/verify-sig.sh" "$4" "$out" "${out}.sig"
  rm -f "${out}.sig"
fi
