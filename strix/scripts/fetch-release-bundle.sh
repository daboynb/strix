#!/bin/bash
# Download the newest published bundle from the GitHub releases whose tag starts
# with <tag-prefix>, verify manifest signature + sha256 + size, and copy the bundle
# to <dest-file> and its manifest next to it (the app compares the two).
#
#   fetch-release-bundle.sh <repo> <tag-prefix> <manifest-name> <dest-file>
#   e.g. fetch-release-bundle.sh daboynb/strix bundles-msf- ruby-msf-bundle.json \
#          strix/app/src/main/assets/ruby-msf-bundle.tar.gz.bin
#
# Exit codes: 0 ok, 3 no matching release, 1 any other error.
# Needs: gh (GH_TOKEN), jq, openssl. BUNDLE_SIGNING_PUB overrides the public key.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
die() { echo "ERROR: $*" >&2; exit 1; }
[ $# -eq 4 ] || die "usage: $0 <repo> <tag-prefix> <manifest-name> <dest-file>"
repo=$1 prefix=$2 manifest=$3 dest=$4
pub="${BUNDLE_SIGNING_PUB:-${SCRIPT_DIR}/bundle-signing.pub}"

# Releases API is ordered newest first; skip drafts and releases without the manifest.
tag=$(gh api "repos/${repo}/releases?per_page=100" --jq \
  "[.[] | select(.draft | not) | select(.tag_name | startswith(\"${prefix}\"))
        | select(any(.assets[]; .name == \"${manifest}\"))][0].tag_name // empty")
if [ -z "$tag" ]; then
  echo "No release with tag prefix '${prefix}' containing ${manifest} in ${repo}" >&2
  exit 3
fi
echo "Using release ${tag}"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
gh release download "$tag" -R "$repo" -D "$work" -p "$manifest" -p "${manifest}.sig"
openssl dgst -sha256 -verify "$pub" -signature "$work/${manifest}.sig" "$work/${manifest}" \
  || die "manifest signature of ${tag}/${manifest} does not verify with ${pub}"

file=$(jq -er .file "$work/${manifest}")
sha=$(jq -er .sha256 "$work/${manifest}")
size=$(jq -er .size "$work/${manifest}")
[[ "$file" =~ ^[A-Za-z0-9._-]+$ ]] || die "bad file name '$file' in manifest"
gh release download "$tag" -R "$repo" -D "$work" -p "$file"
echo "${sha}  ${work}/${file}" | sha256sum -c --strict -
[ "$(stat -c %s "$work/$file")" = "$size" ] || die "size mismatch for $file"

mkdir -p "$(dirname "$dest")"
cp "$work/$file" "$dest"
cp "$work/$manifest" "$(dirname "$dest")/$manifest"
echo "Installed ${tag}/${file} -> ${dest} ($(jq -r .version "$work/${manifest}"))"
