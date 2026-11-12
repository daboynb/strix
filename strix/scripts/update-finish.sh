#!/bin/bash
# Automated update, step 3 (update-track.yml "finish" job), only after every selected
# bundle built and passed its smoke checks. Run from a checkout of <sha>.
#
#   update-finish.sh <msf|deps> <sha> <pr> <tools:true|false> <msf:true|false> <artifacts-dir>
#
# Publishes each built bundle (idempotent, see publish-bundle-release.sh), then marks
# the PR ready and squash-merges it, only if its head is still <sha>.
# The msf bundle is released as a DRAFT: CI cannot run it on Android (only a host load
# test), so users get it only after it was started on a device and the draft published:
#   gh release edit <tag> --draft=false
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
  # actions/download-artifact extracts a pattern that matches a single artifact straight
  # into the path, without the per-artifact subdirectory it creates for multiple matches;
  # when only one bundle was built, fall back to the artifacts root.
  if [ ! -d "$dir" ] && [ "${#ids[@]}" -eq 1 ]; then
    dir="$artifacts"
  fi
  [ -d "$dir" ] || die "artifact ${track}-bundle-${id} missing"
  if [ "$id" = msf ]; then
    BUNDLE_RELEASE_DRAFT=true "${SCRIPT_DIR}/publish-bundle-release.sh" "$id" "$dir" "$sha" | tee /tmp/publish-msf.out
    tag=$(sed -n 's/^tag=//p' /tmp/publish-msf.out | tail -n1)
    if [ "$(sed -n 's/^draft=//p' /tmp/publish-msf.out | tail -n1)" = true ]; then
      msg="MSF bundle ${tag} is a draft: start msfrpcd from it on a device, then publish it with: gh release edit ${tag} -R ${repo} --draft=false"
      echo "::notice title=MSF bundle waiting for a device test::${msg}"
      [ -z "${GITHUB_STEP_SUMMARY:-}" ] || echo "$msg" >> "$GITHUB_STEP_SUMMARY"
    fi
  else
    "${SCRIPT_DIR}/publish-bundle-release.sh" "$id" "$dir" "$sha"
  fi
done

if [ "$(gh pr view "$pr" -R "$repo" --json isDraft --jq .isDraft)" = true ]; then
  gh pr ready "$pr" -R "$repo"
fi
gh pr merge "$pr" -R "$repo" --squash --delete-branch --match-head-commit "$sha" \
  --subject "chore(bundles): automated ${track} update (#${pr})"
echo "Merged PR #$pr"
