#!/bin/bash
# Bundle bookkeeping for CI (run from the repo root or anywhere inside the checkout).
#
#   bundle-meta.sh affected <old-versions.env> <new-versions.env>
#       -> "tools=true|false" and "msf=true|false" (GITHUB_OUTPUT format) + changed keys on stderr
#   bundle-meta.sh affected-paths <file>...    (changed repo paths, e.g. from git diff)
#   bundle-meta.sh fingerprint <tools|msf>
#       -> sha256 over the inputs of that bundle: its versions.env lines + git trees of
#          the pipeline dir and strix/scripts at HEAD
#   bundle-meta.sh released <tools|msf> <repo>
#       -> tag of an existing release built from the same fingerprint (empty if none)
#   bundle-meta.sh next-tag <tools|msf> <repo>
#       -> next free tag: bundles-msf-<MSF_REF>-r<N> / bundles-tools-r<N>
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

# Which bundle(s) a versions.env key feeds: tools | msf | both
bundle_of_key() {
  case "${1%%_*}" in
    NMAP|TCPDUMP|HYDRA|ETTERCAP|LIBNET|LIBIDN|CURL|GEOIP|LUA|LIBSSH2|LIBSSH|PCRE2|GPG|GCRYPT|MARIADB|CYRUS|LIBMEMCACHED|RTMPDUMP|TOOLS) echo tools ;;
    RUBY|ZLIB|YAML|LIBFFI|SQLITE|LIBXML2|LIBXSLT|MSF|BUNDLER) echo msf ;;
    *) echo both ;;   # BASE_IMAGE, NDK, API_LEVEL, OPENSSL, LIBPCAP, POSTGRESQL, unknown
  esac
}

emit() { echo "tools=$1"; echo "msf=$2"; }

affected() {
  local tools=false msf=false key
  while IFS= read -r key; do
    [ -n "$key" ] || continue
    echo "changed: $key" >&2
    case $(bundle_of_key "$key") in
      tools) tools=true ;; msf) msf=true ;; both) tools=true; msf=true ;;
    esac
  done < <(diff <(grep -E '^[A-Z0-9_]+=' "$1" | sort) <(grep -E '^[A-Z0-9_]+=' "$2" | sort) \
             | sed -nE 's/^[<>] ([A-Z0-9_]+)=.*/\1/p' | sort -u)
  emit "$tools" "$msf"
}

affected_paths() {
  local tools=false msf=false p
  for p in "$@"; do
    case "$p" in
      strix/tools/*) tools=true ;;
      strix/ruby-msf/*) msf=true ;;
      strix/scripts/lib.sh|strix/scripts/fetch.sh|strix/scripts/verify-sig.sh|strix/scripts/keys/*|\
      strix/scripts/sign-bundle.sh|strix/scripts/smoke-*.sh|\
      strix/scripts/tar_safe_extract.py|.github/workflows/bundle-build.yml) tools=true; msf=true ;;
      strix/scripts/msf-gemlock.sh) msf=true ;;
    esac
  done
  emit "$tools" "$msf"
}

fingerprint() {
  local id=$1 dir key line trees
  case "$id" in tools) dir=strix/tools ;; msf) dir=strix/ruby-msf ;; *) die "unknown id $id" ;; esac
  trees=$(git -C "$STRIX_DIR" rev-parse "HEAD:$dir" "HEAD:strix/scripts") \
    || die "fingerprint needs $dir and strix/scripts committed at HEAD"
  {
    while IFS= read -r line; do
      key=${line%%=*}
      case $(bundle_of_key "$key") in "$id"|both) echo "$line" ;; esac
    done < <(grep -E '^[A-Z0-9_]+=' "$VERSIONS_FILE" | sort)
    echo "$trees"
  } | sha256sum | cut -d' ' -f1
}

prefix_of() {
  case "$1" in
    tools) echo "bundles-tools-r" ;;
    msf) load_versions; echo "bundles-msf-${MSF_REF}-r" ;;
    *) die "unknown id $1" ;;
  esac
}

released() {
  local fp prefix
  fp=$(fingerprint "$1"); prefix="bundles-$1-"
  gh api "repos/$2/releases?per_page=100" --paginate --jq \
    ".[] | select(.draft | not) | select(.tag_name | startswith(\"${prefix}\"))
         | select((.body // \"\") | contains(\"fingerprint: ${fp}\")) | .tag_name" | awk 'NR==1'
}

next_tag() {
  local prefix n
  prefix=$(prefix_of "$1")
  n=$(gh api "repos/$2/git/matching-refs/tags/${prefix}" --jq '.[].ref' \
      | sed -nE "s|^refs/tags/${prefix//./\\.}([0-9]+)$|\1|p" | sort -n | tail -n1)
  echo "${prefix}$(( ${n:-0} + 1 ))"
}

cmd=${1:-}; shift || true
case "$cmd" in
  affected)       [ $# -eq 2 ] || die "usage: affected <old> <new>"; affected "$@" ;;
  affected-paths) affected_paths "$@" ;;
  fingerprint)    [ $# -eq 1 ] || die "usage: fingerprint <id>"; fingerprint "$1" ;;
  released)       [ $# -eq 2 ] || die "usage: released <id> <repo>"; released "$@" ;;
  next-tag)       [ $# -eq 2 ] || die "usage: next-tag <id> <repo>"; next_tag "$@" ;;
  *) die "usage: $0 affected|affected-paths|fingerprint|released|next-tag ..." ;;
esac
