#!/bin/bash
# Generic "latest version" lookups used by upstream.sh: HTML directory listings,
# GitHub releases, git tags. Source it (upstream.sh does).

# listing_latest <url> <regex> <prefix-to-strip> <suffix-to-strip>
listing_latest() {
  local v
  v=$(curl -fsSL "$1" | grep -oE "$2" | sed -e "s|^$3||" -e "s|$4\$||" | sort -uV | tail -n1)
  [ -n "$v" ] || { echo "no match for '$2' at $1" >&2; return 1; }
  echo "$v"
}

# gh_release <owner/repo> <tag-prefix-to-strip>
gh_release() {
  local t
  t=$(gh api "repos/$1/releases/latest" --jq .tag_name)
  echo "${t#"$2"}"
}

# git_tag_latest <git-url> <tag-regex (without refs/tags/)> <prefix-to-strip>
git_tag_latest() {
  local v
  v=$(git ls-remote --tags --refs "$1" | awk '{print $2}' | sed 's|^refs/tags/||' \
      | grep -E "^$2\$" | sed "s|^$3||" | sort -V | tail -n1)
  [ -n "$v" ] || { echo "no tag matching '$2' in $1" >&2; return 1; }
  echo "$v"
}
