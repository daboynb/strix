#!/bin/bash
# Automated update, final step (update-bundles.yml "report" job).
#
#   update-report.sh <base-branch> <track>=<result>...   e.g. msf=success deps=failure
#
# On any failed track: put its PR back to draft and open (or comment on) the single
# issue "Automated bundle update failed" with the run link and the failed jobs.
# When every track succeeded or was skipped: close that issue if it is open.
# Needs: gh (GH_TOKEN), GITHUB_REPOSITORY, GITHUB_SERVER_URL, GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT.
set -euo pipefail

[ $# -ge 2 ] || { echo "usage: $0 <base> <track>=<result>..." >&2; exit 2; }
base=$1; shift
repo=${GITHUB_REPOSITORY:?}
run_url="${GITHUB_SERVER_URL:-https://github.com}/${repo}/actions/runs/${GITHUB_RUN_ID:?}"
title="Automated bundle update failed"

failed_tracks=() lines=()
for arg in "$@"; do
  track=${arg%%=*} result=${arg#*=}
  echo "track ${track}: ${result:-not run}"
  [ "$result" = failure ] || [ "$result" = cancelled ] || continue
  failed_tracks+=("$track")
  pr=$(gh pr list -R "$repo" --head "automation/${track}-update" --base "$base" --state open \
       --json number,isDraft --jq '.[0] // empty')
  if [ -n "$pr" ]; then
    n=$(jq -r .number <<< "$pr")
    [ "$(jq -r .isDraft <<< "$pr")" = true ] || gh pr ready "$n" -R "$repo" --undo
    lines+=("- **${track}**: ${result}, PR #${n} left as draft")
  else
    lines+=("- **${track}**: ${result} (no PR was opened)")
  fi
done

issue=$(gh issue list -R "$repo" --state open --search "in:title \"${title}\"" --json number,title \
        --jq "[.[] | select(.title == \"${title}\")][0].number // empty")

if [ "${#failed_tracks[@]}" -eq 0 ]; then
  if [ -n "$issue" ]; then
    gh issue close "$issue" -R "$repo" --comment "Resolved: ${run_url} completed without failures."
  fi
  echo "No failures"
  exit 0
fi

jobs=$(gh api "repos/${repo}/actions/runs/${GITHUB_RUN_ID}/attempts/${GITHUB_RUN_ATTEMPT:-1}/jobs" --paginate \
       --jq '.jobs[] | select(.conclusion == "failure" or .conclusion == "cancelled") | "- `\(.name)` (\(.conclusion)): \(.html_url)"')
body=$(printf '%s\n' "Run: ${run_url}" "" "Tracks:" "${lines[@]}" "" "Failed jobs:" "${jobs:-- (none reported)}" "" \
  "Nothing was published for the failed track(s). Fix by pushing to the \`automation/<track>-update\` branch and re-running *Update bundles* (it builds a manually fixed branch as-is).")

if [ -n "$issue" ]; then
  gh issue comment "$issue" -R "$repo" --body "$body"
else
  gh issue create -R "$repo" --title "$title" --body "$body"
fi
exit 1
