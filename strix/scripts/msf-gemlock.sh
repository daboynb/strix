#!/bin/bash
# Metasploit's Gemfile.lock + a CHECKSUMS section (sha256 of every gem), kept in the repo
# as strix/ruby-msf/02-msf/Gemfile.lock. build-msf.sh checks it against MSF's own lockfile,
# copies it over and runs a frozen `bundle install`: Bundler refuses any downloaded .gem
# whose sha256 differs from CHECKSUMS.
#
#   msf-gemlock.sh update                       regenerate the repo lockfile for MSF_COMMIT +
#                                               BUNDLER_VERSION of versions.env (needs curl)
#   msf-gemlock.sh generate <msf.lock> <bundler-version> <out>
#   msf-gemlock.sh check <msf.lock> <repo.lock> repo.lock = msf.lock + a sha256 for every gem
#   msf-gemlock.sh gem <repo.lock> <name>       "<version> <sha256>" of a locked gem
#
# Trust model: the sha256 values come from rubygems.org's compact index (/info/<gem>, the
# same data Bundler checks against) when the lockfile is generated, then they are pinned in
# git: a gem re-published under the same version, a compromised mirror/CDN or a MITM at build
# time fails the build. Generation itself trusts rubygems.org (TOFU); the bump PR shows the
# lockfile diff. The lockfile is otherwise byte-identical to MSF's (check enforces it).
set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }
RUBYGEMS=https://rubygems.org
TMPD=$(mktemp -d)
trap 'rm -rf "$TMPD"' EXIT

# Lockfile minus its CHECKSUMS and BUNDLED WITH sections, one section per paragraph
normalize() {
  awk 'BEGIN { RS=""; ORS="\n\n" } !/^(CHECKSUMS|BUNDLED WITH)\n/' "$1"
}

# "name version" of every spec of a GEM or PATH section (4-space indented lines)
specs() { # <lock> <GEM|PATH>
  awk -v sec="$2" '/^[A-Z]/ { cur=$0 } /^$/ { cur="" }
    cur==sec && /^    [^ ]/ { gsub(/[()]/, ""); print $1, $2 }' "$1"
}

generate() {
  local in=$1 bundler=$2 out=$3 name ver sha
  [[ "$bundler" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "bad bundler version '$bundler'"
  ! grep -qE '^(GIT|PLUGIN SOURCE)$' "$in" || die "$in has GIT/plugin sources (no checksums for those)"
  [ "$(grep -A1 '^GEM$' "$in" | sed -n 's/^  remote: //p' | sort -u)" = "${RUBYGEMS}/" ] \
    || die "$in: every GEM source must be ${RUBYGEMS}/"
  specs "$in" GEM > "$TMPD/gems"
  [ -s "$TMPD/gems" ] || die "no gems in $in"
  cut -d' ' -f1 "$TMPD/gems" | sort -u | xargs -P 8 -n 1 sh -c \
    'curl -fsSL --retry 3 -o "$1/$3.info" "$2/info/$3" || echo "$3" >> "$1/failed"' _ "$TMPD" "$RUBYGEMS"
  [ ! -s "$TMPD/failed" ] || die "compact index fetch failed for: $(tr '\n' ' ' < "$TMPD/failed")"
  {
    while read -r name ver; do
      # compact index line: "<version>[-<platform>] <deps>|checksum:<sha256>,..."
      sha=$(awk -v v="$ver" '$1 == v' "$TMPD/$name.info" | grep -oE 'checksum:[0-9a-f]{64}' | head -n1 | cut -d: -f2)
      [ -n "$sha" ] || die "no rubygems.org checksum for $name ($ver)"
      echo "  $name ($ver) sha256=$sha"
    done < "$TMPD/gems"
    specs "$in" PATH | while read -r name ver; do echo "  $name ($ver)"; done
  } | LC_ALL=C sort > "$TMPD/checksums"
  # Bundler's section order: sources, PLATFORMS, DEPENDENCIES, CHECKSUMS, RUBY VERSION, BUNDLED WITH
  normalize "$in" | awk -v cs="$TMPD/checksums" -v bv="$bundler" '
    function checksums(   l) { print "CHECKSUMS"; while ((getline l < cs) > 0) print l; print "" }
    BEGIN { RS="" }
    /^RUBY VERSION\n/ && !done { checksums(); done=1 }
    { print; print "" }
    END { if (!done) checksums(); print "BUNDLED WITH"; print "   " bv }' > "$out"
  check "$in" "$out"
  local msf_bundler
  msf_bundler=$(awk '/^BUNDLED WITH$/ { getline; print $1 }' "$in")
  [ "$msf_bundler" = "$bundler" ] || echo "note: MSF's lockfile was written by Bundler ${msf_bundler:-?}, pinned BUNDLER_VERSION is $bundler"
}

check() {
  local msf=$1 repo=$2 missing
  diff <(normalize "$msf") <(normalize "$repo") > /dev/null \
    || die "$repo does not match MSF's Gemfile.lock (stale for this MSF_COMMIT?): run strix/scripts/msf-gemlock.sh update"
  missing=$(comm -23 <(specs "$repo" GEM | awk '{ print "  " $1 " (" $2 ") sha256=" }' | LC_ALL=C sort) \
                     <(sed -n '/^CHECKSUMS$/,/^$/p' "$repo" | grep -oE '^  [^ ]+ \([^)]+\) sha256=' | LC_ALL=C sort))
  [ -z "$missing" ] || die "gems without sha256 in $repo CHECKSUMS:"$'\n'"$missing"
  echo "gem lockfile OK: $repo = MSF lockfile + sha256 for all $(specs "$repo" GEM | wc -l) gems"
}

gem_of() { # <repo.lock> <name>
  local line
  line=$(sed -n '/^CHECKSUMS$/,/^$/p' "$1" | grep -E "^  $2 \(" | head -n1)
  [[ "$line" =~ \(([^\)]+)\)\ sha256=([0-9a-f]{64})$ ]] || die "no checksum for gem $2 in $1"
  echo "${BASH_REMATCH[1]} ${BASH_REMATCH[2]}"
}

update() {
  # shellcheck source=lib.sh
  source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
  load_versions
  curl -fsSL --retry 3 -o "$TMPD/msf.lock" \
    "https://raw.githubusercontent.com/rapid7/metasploit-framework/${MSF_COMMIT:?}/Gemfile.lock"
  generate "$TMPD/msf.lock" "${BUNDLER_VERSION:?}" "${STRIX_DIR}/ruby-msf/02-msf/Gemfile.lock"
}

case "${1:-}" in
  update)   [ $# -eq 1 ] || die "usage: $0 update"; update ;;
  generate) [ $# -eq 4 ] || die "usage: $0 generate <msf.lock> <bundler-version> <out>"; generate "$2" "$3" "$4" ;;
  check)    [ $# -eq 3 ] || die "usage: $0 check <msf.lock> <repo.lock>"; check "$2" "$3" ;;
  gem)      [ $# -eq 3 ] || die "usage: $0 gem <repo.lock> <name>"; gem_of "$2" "$3" ;;
  *) die "usage: $0 <update|generate|check|gem> ..." ;;
esac
