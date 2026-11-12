#!/bin/bash
# Publish a built bundle (<dist-dir>/<bundle>.tar.gz.bin + .json + .json.sig) as a
# GitHub release. Run from a checkout of <target-sha> (the fingerprint uses HEAD).
#
#   publish-bundle-release.sh <tools|msf> <dist-dir> <target-sha> [tag]
#
# Without [tag]: if a release with the same input fingerprint already exists it is
# reused (idempotent re-runs), otherwise the next free tag is created at <target-sha>.
# With [tag] (tag-push builds): the release for that existing tag is created/updated.
# BUNDLE_RELEASE_DRAFT=true creates the new release as a draft: the app ignores drafts
# (GitHubReleases.kt), so it reaches users only once someone publishes it after a test.
# Writes "tag=<tag>" and "created=true|false" to $GITHUB_OUTPUT when set.
# Needs: gh (GH_TOKEN), jq, openssl, GITHUB_REPOSITORY.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"
[ $# -ge 3 ] && [ $# -le 4 ] || die "usage: $0 <tools|msf> <dist-dir> <target-sha> [tag]"
id=$1 dist=$2 sha=$3 tag=${4:-}
repo=${GITHUB_REPOSITORY:?GITHUB_REPOSITORY not set}
meta="${SCRIPT_DIR}/bundle-meta.sh"
out() { [ -z "${GITHUB_OUTPUT:-}" ] || echo "$1" >> "$GITHUB_OUTPUT"; echo "$1"; }
draft=()
case "${BUNDLE_RELEASE_DRAFT:-false}" in
  true) draft=(--draft) ;;
  false) ;;
  *) die "BUNDLE_RELEASE_DRAFT must be true or false" ;;
esac

case "$id" in tools) base=tools-bundle ;; msf) base=ruby-msf-bundle ;; *) die "unknown id $id" ;; esac
files=("$dist/$base.tar.gz.bin" "$dist/$base.json" "$dist/$base.json.sig")
for f in "${files[@]}"; do [ -s "$f" ] || die "missing $f"; done
[ "$(git -C "$STRIX_DIR" rev-parse HEAD)" = "$sha" ] || die "checkout is not at $sha"

# Never publish anything the app would reject
openssl dgst -sha256 -verify "${SCRIPT_DIR}/bundle-signing.pub" -signature "$dist/$base.json.sig" "$dist/$base.json"
[ "$(jq -er .id "$dist/$base.json")" = "$id" ] || die "manifest id mismatch"
echo "$(jq -er .sha256 "$dist/$base.json")  $dist/$base.tar.gz.bin" | sha256sum -c --strict -

fp=$("$meta" fingerprint "$id")
notes="$(jq -r .version "$dist/$base.json") - built from ${sha}.
Inputs fingerprint: ${fp}"

if [ -z "$tag" ]; then
  existing=$("$meta" released "$id" "$repo")
  if [ -n "$existing" ]; then
    echo "Inputs ${fp} already released as ${existing}; not publishing again"
    out "tag=$existing"; out "created=false"
    exit 0
  fi
  tag=$("$meta" next-tag "$id" "$repo")
  gh release create "$tag" -R "$repo" --target "$sha" --latest=false "${draft[@]}" \
    --title "$tag" --notes "$notes" "${files[@]}"
else
  if gh release view "$tag" -R "$repo" > /dev/null 2>&1; then
    gh release edit "$tag" -R "$repo" --notes "$notes"
  else
    gh release create "$tag" -R "$repo" --verify-tag --latest=false --title "$tag" --notes "$notes"
  fi
  gh release upload "$tag" -R "$repo" --clobber "${files[@]}"
fi
gh release view "$tag" -R "$repo" --json assets --jq '.assets[] | "\(.name) \(.size)"'
out "tag=$tag"; out "created=true"; out "draft=$([ ${#draft[@]} -gt 0 ] && echo true || echo false)"
