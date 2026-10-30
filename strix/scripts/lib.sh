#!/bin/bash
# Shared helpers for the host-side bundle scripts. Source it, don't run it.
#   source "$STRIX_DIR/scripts/lib.sh"

STRIX_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSIONS_FILE="${STRIX_DIR}/versions.env"

die() { echo "ERROR: $*" >&2; exit 1; }

# Export every KEY=VALUE from versions.env into the environment.
load_versions() {
  [ -f "$VERSIONS_FILE" ] || die "missing $VERSIONS_FILE"
  set -a
  # shellcheck source=../versions.env
  source "$VERSIONS_FILE"
  set +a
}

# Fill the array named $1 with --build-arg flags for every key in versions.env.
versions_build_args() {
  local -n _out=$1
  local line
  _out=()
  while IFS= read -r line; do
    [[ "$line" =~ ^[A-Z0-9_]+= ]] || continue
    _out+=(--build-arg "$line")
  done < "$VERSIONS_FILE"
  [ "${#_out[@]}" -gt 0 ] || die "no variables found in $VERSIONS_FILE"
}

# docker buildx build of target "export" whose filesystem lands in $2.
#   bundle_docker_build <context-dir> <output-dir> <log-file>
# Extra buildx flags (e.g. gha cache) can be passed via STRIX_BUILDX_ARGS.
#
# Exported as one tar stream, then extracted: the local exporter sends every
# file over its own gRPC stream and can deadlock forever on large trees
# (moby/buildkit#2950; the msf output is ~32k files and hung CI twice at
# "exporting to client directory / copying files").
bundle_docker_build() {
  local context=$1 out=$2 log=$3
  local -a args extra
  local tmp
  versions_build_args args
  read -r -a extra <<< "${STRIX_BUILDX_ARGS:-}"
  tmp=$(mktemp -d)
  docker buildx build \
    --progress=plain \
    --build-context "strix-scripts=${STRIX_DIR}/scripts" \
    --target export \
    --output "type=tar,dest=${tmp}/export.tar" \
    "${args[@]}" "${extra[@]}" \
    "$context" 2>&1 | tee "$log" || { rm -rf "$tmp"; return 1; }
  mkdir -p "$out"
  tar -xf "${tmp}/export.tar" -C "$out" || { rm -rf "$tmp"; die "cannot extract the build output into $out"; }
  rm -rf "$tmp"
}

# Remove a previous build output directory (fail loudly if we can't).
fresh_dir() {
  local dir=$1
  if [ -e "$dir" ]; then
    rm -rf "$dir" || die "cannot remove stale $dir (root-owned leftovers from an old docker run? remove it with sudo)"
  fi
}
