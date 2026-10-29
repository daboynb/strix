#!/bin/bash
# Automated update, step 3 (update-track.yml "finish" job), only after every selected
# bundle built and passed its smoke checks. Run from a checkout of <sha>.
#
#   update-finish.sh <msf|deps> <sha> <pr> <tools:true|false> <msf:true|false> <artifacts-dir>
#
# Publishes each built bundle (idempotent, see publish-bundle-release.sh), then marks
# the PR ready and squash-merges it, only if its head is still <sha>.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"
[ $# -eq 6 ] || die "usage: $0 <track> <sha> <pr> <tools> <msf> <artifacts-dir>"
track=$1 sha=$2 pr=$3 build_tools=$4 build_msf=$5 artifacts=$6
repo=${GITHUB_REPOSITORY:?}

ids=()
[ "$build_tools" != true ] || ids+=(tools)
[ "$build_msf" != true ] || ids+=(msf)
for id in "${ids[@]}"; do
  dir="$artifacts/${track}-bundle-${id}"
  [ -d "$dir" ] || die "artifact ${track}-bundle-${id} missing"
  "${SCRIPT_DIR}/publish-bundle-release.sh" "$id" "$dir" "$sha"
done

if [ "$(gh pr view "$pr" -R "$repo" --json isDraft --jq .isDraft)" = true ]; then
  gh pr ready "$pr" -R "$repo"
fi
gh pr merge "$pr" -R "$repo" --squash --delete-branch --match-head-commit "$sha" \
  --subject "chore(bundles): automated ${track} update (#${pr})"
echo "Merged PR #$pr"
