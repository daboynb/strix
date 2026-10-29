#!/bin/bash
# Automated update, step 1 (update-track.yml "prepare" job). Run at the tip of <base>.
#
#   update-prepare.sh <msf|deps> <base-branch>
#
# - If the track's bump PR is open and its branch head was pushed by a human
#   (manual fix), build that branch as-is.
# - Otherwise look up upstream (scripts/check-updates.sh <track>); no change -> close a
#   stale bot PR and stop; change -> commit versions.env on automation/<track>-update
#   (force-pushed, always based on <base>) and open/refresh a DRAFT PR.
# - Decide which bundles to build; a bundle whose inputs fingerprint is already
#   released is not rebuilt.
# Outputs (GITHUB_OUTPUT): changed, sha, pr, tools, msf, branch.
# Needs: git (push credentials), gh (GH_TOKEN), GITHUB_REPOSITORY, docker buildx.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"
[ $# -eq 2 ] || die "usage: $0 <msf|deps> <base-branch>"
track=$1 base=$2
case "$track" in msf|deps) ;; *) die "unknown track $track" ;; esac
repo=${GITHUB_REPOSITORY:?}
branch="automation/${track}-update"
bot_email='41898282+github-actions[bot]@users.noreply.github.com'
meta="${SCRIPT_DIR}/bundle-meta.sh"
out() { echo "$1"; [ -z "${GITHUB_OUTPUT:-}" ] || echo "$1" >> "$GITHUB_OUTPUT"; }
summary="${RUNNER_TEMP:-/tmp}/update-${track}.md"
: > "$summary"

cd "$STRIX_DIR/.."
git config user.name 'github-actions[bot]'
git config user.email "$bot_email"
out "branch=$branch"

pr=$(gh pr list -R "$repo" --head "$branch" --base "$base" --state open --json number --jq '.[0].number // empty')
mode=fresh
if [ -n "$pr" ] && git fetch --quiet origin "$branch" \
   && [ "$(git log -1 --format=%ae FETCH_HEAD)" != "$bot_email" ]; then
  mode=existing
fi

if [ "$mode" = existing ]; then
  echo "PR #$pr has manual commits on $branch: building it as-is"
  git checkout --quiet -B "$branch" FETCH_HEAD
  echo "- Building manually fixed branch \`$branch\` as-is" >> "$summary"
else
  lookup_rc=0
  "${SCRIPT_DIR}/check-updates.sh" "$track" "$summary" || lookup_rc=$?
  if git diff --quiet -- strix/versions.env; then
    echo "No ${track} updates"
    if [ -n "$pr" ]; then
      gh pr close "$pr" -R "$repo" --delete-branch --comment "No longer needed: \`${base}\` is up to date."
    fi
    out "changed=false"
    exit "$lookup_rc"
  fi
  if [ "$lookup_rc" -ne 0 ]; then
    echo "::warning::some upstream lookups failed (see log); continuing with the updates that were found"
  fi
  git checkout --quiet -B "$branch"
  git commit --quiet -m "chore(bundles): automated ${track} update" -- strix/versions.env
  git push --quiet --force origin "$branch"
fi
sha=$(git rev-parse HEAD)
out "sha=$sha"

# Bundles affected by this branch vs base: versions.env keys + pipeline paths
git fetch --quiet origin "$base"
mapfile -t paths < <(git diff --name-only "FETCH_HEAD...HEAD")
eval "$("$meta" affected <(git show FETCH_HEAD:strix/versions.env) strix/versions.env | sed 's/^/v_/')"
eval "$("$meta" affected-paths "${paths[@]}" | sed 's/^/p_/')"
for id in tools msf; do
  v="v_$id" p="p_$id" build=false
  if [ "${!v}" = true ] || [ "${!p}" = true ]; then
    existing=$("$meta" released "$id" "$repo")
    if [ -n "$existing" ]; then
      echo "- ${id}: these inputs are already released as \`${existing}\`, not rebuilding" >> "$summary"
    else
      build=true
    fi
  fi
  out "$id=$build"
done

body="${RUNNER_TEMP:-/tmp}/pr-${track}.md"
{
  echo "Automated **${track}** update (\`.github/workflows/update-bundles.yml\`)."
  echo
  cat "$summary"
  echo
  echo "New SHA256 values are computed by downloading the files in CI (trust on first use)."
  echo "This PR stays a draft until the affected bundles built, passed the smoke checks and were"
  echo "released; it is then squash-merged automatically. To fix a failure, push commits to"
  echo "\`${branch}\` and re-run the *Update bundles* workflow: it builds the branch as-is."
} > "$body"
if [ -z "$pr" ]; then
  gh pr create -R "$repo" --draft --base "$base" --head "$branch" \
    --title "Automated ${track} bundle update" --body-file "$body"
  pr=$(gh pr list -R "$repo" --head "$branch" --state open --json number --jq '.[0].number')
elif [ "$mode" = fresh ]; then
  gh pr edit "$pr" -R "$repo" --body-file "$body"
fi
out "pr=$pr"
out "changed=true"
