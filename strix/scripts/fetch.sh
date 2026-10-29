#!/bin/bash
# Download a file and verify its SHA256. Used inside the bundle Docker builds
# (copied in via the "strix-scripts" build context as /usr/local/bin/strix-fetch).
#   strix-fetch <url> <sha256> <output-file>
set -euo pipefail

[ $# -eq 3 ] || { echo "usage: $0 <url> <sha256> <output-file>" >&2; exit 2; }
url=$1 sha=$2 out=$3

[[ "$sha" =~ ^[0-9a-f]{64}$ ]] || { echo "ERROR: missing/invalid SHA256 '$sha' for $url (see strix/versions.env)" >&2; exit 1; }

echo "fetch: $url"
curl -fsSL --retry 5 --retry-delay 5 --connect-timeout 30 -o "$out" "$url"
echo "${sha}  ${out}" | sha256sum -c --strict -
