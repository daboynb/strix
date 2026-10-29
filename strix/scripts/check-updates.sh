#!/bin/bash
# Compare strix/versions.env with upstream and rewrite it in place for every
# component that has a newer release (new *_VERSION + freshly computed *_SHA256,
# MSF tag + commit, rtmpdump commit, base image digest).
#
#   scripts/check-updates.sh <msf|deps|all> [summary-file]
#
# Tracks: "msf" = MSF_REF/MSF_COMMIT only; "deps" = everything else (tool/lib
# tarballs, rtmpdump commit, base image digest); "all" = both.
#
# Writes a markdown list of changes to summary-file (default: stdout only).
# Exit 0 = all lookups ran (changes or not); exit 1 = at least one lookup failed
# (successful updates are still written). NDK is not checked (manual bump).
# Needs: curl, git, gh (authenticated), docker buildx (base image digest), sha256sum.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"
# shellcheck source=upstream.sh
source "${SCRIPT_DIR}/upstream.sh"
load_versions

TRACK=${1:-}
case "$TRACK" in msf|deps|all) ;; *) die "usage: $0 <msf|deps|all> [summary-file]" ;; esac
SUMMARY=${2:-/dev/null}
want() { [ "$TRACK" = all ] || [ "$TRACK" = "$1" ]; }
: > "$SUMMARY"
ERRORS=0
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

set_var() { sed -i "s|^$1=.*|$1=$2|" "$VERSIONS_FILE"; }
note()    { echo "$*"; echo "- $*" >> "$SUMMARY"; }
fail()    { echo "ERROR: $*" >&2; echo "- :warning: lookup failed: $*" >> "$SUMMARY"; ERRORS=$((ERRORS+1)); }
newer()   { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n1)" = "$2" ]; }

sha_of() { # <url>
  curl -fsSL --retry 3 -o "$TMP/dl" "$1" && sha256sum "$TMP/dl" | cut -d' ' -f1
}

check_tarball() { # <KEY>   (KEY_VERSION + KEY_SHA256 in versions.env)
  local key=$1 cur_var="${1}_VERSION" cur latest year="" url sha
  cur=${!cur_var}
  if ! latest=$(upstream_latest "$key"); then fail "$key"; return 0; fi
  if [ "$key" = SQLITE ]; then year=${latest#* }; latest=${latest% *}; fi
  [[ "$latest" =~ ^[0-9][0-9A-Za-z.]*$ ]] || { fail "$key: unexpected version '$latest'"; return 0; }
  newer "$cur" "$latest" || { echo "up to date: $key $cur"; return 0; }
  url=$(upstream_url "$key" "$latest" "$year")
  if ! sha=$(sha_of "$url"); then fail "$key $latest: download $url"; return 0; fi
  set_var "${key}_VERSION" "$latest"
  set_var "${key}_SHA256" "$sha"
  [ -z "$year" ] || set_var SQLITE_YEAR "$year"
  note "$key: $cur -> $latest (sha256 $sha, from $url)"
}

if want deps; then
for key in NMAP LIBPCAP TCPDUMP LIBNET HYDRA ETTERCAP LIBIDN OPENSSL POSTGRESQL CURL GEOIP LUA \
           LIBSSH2 LIBSSH PCRE2 GPG_ERROR GCRYPT MARIADB LIBMEMCACHED \
           RUBY ZLIB YAML LIBFFI SQLITE LIBXML2 LIBXSLT; do
  check_tarball "$key"
done
fi

# Metasploit: latest x.y.z tag + the commit it points to
if want msf; then
MSF_GIT=https://github.com/rapid7/metasploit-framework.git
if msf=$(git_tag_latest "$MSF_GIT" '[0-9]+\.[0-9]+\.[0-9]+' ''); then
  if newer "$MSF_REF" "$msf"; then
    commit=$(git ls-remote "$MSF_GIT" "refs/tags/${msf}^{}" | awk '{print $1}')
    [ -n "$commit" ] || commit=$(git ls-remote "$MSF_GIT" "refs/tags/${msf}" | awk '{print $1}')
    if [[ "$commit" =~ ^[0-9a-f]{40}$ ]]; then
      set_var MSF_REF "$msf"; set_var MSF_COMMIT "$commit"
      note "MSF: $MSF_REF -> $msf (commit $commit)"
    else
      fail "MSF $msf: could not resolve commit"
    fi
  else
    echo "up to date: MSF $MSF_REF"
  fi
else
  fail MSF
fi

fi

if want deps; then
# librtmp: follow rtmpdump master
if head=$(git ls-remote https://git.ffmpeg.org/rtmpdump.git HEAD | awk '{print $1}') && [[ "$head" =~ ^[0-9a-f]{40}$ ]]; then
  if [ "$head" != "$RTMPDUMP_COMMIT" ]; then
    set_var RTMPDUMP_COMMIT "$head"; note "RTMPDUMP: $RTMPDUMP_COMMIT -> $head"
  fi
else
  fail RTMPDUMP
fi

# Base image: same tag, newest digest (security updates)
base_tag=${BASE_IMAGE%@*}
if digest=$(docker buildx imagetools inspect "$base_tag" --format '{{json .Manifest.Digest}}' | tr -d '"') \
   && [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  if [ "${base_tag}@${digest}" != "$BASE_IMAGE" ]; then
    set_var BASE_IMAGE "${base_tag}@${digest}"; note "BASE_IMAGE: ${BASE_IMAGE} -> ${base_tag}@${digest}"
  fi
else
  fail BASE_IMAGE
fi

fi

echo "lookup errors: $ERRORS"
[ "$ERRORS" -eq 0 ]
