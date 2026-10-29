#!/bin/bash
# msf-specific part of smoke-bundle.sh (sourced; uses root, require, fail, pass, elf_check, deps_check).
# shellcheck disable=SC2154  # root is set by smoke-bundle.sh

# Print "name version" for every gemspec in the given specification dirs.
gemspec_names() {
  local d f base
  for d in "$@"; do
    [ -d "$d" ] || continue
    for f in "$d"/*.gemspec; do
      [ -e "$f" ] || continue
      base=$(basename "$f" .gemspec)
      [[ "$base" =~ ^(.+)-([0-9][^-]*)$ ]] && echo "${BASH_REMATCH[1]} ${BASH_REMATCH[2]}"
    done
  done
}

smoke_msf() {
  local rb="$root/ruby-android" msf="$root/metasploit-framework" v
  require ruby-android/bin/ruby ruby-android/lib/libpq.so.5 ruby-android/VERSION \
          metasploit-framework/msfconsole metasploit-framework/msfrpcd metasploit-framework/VERSION \
          metasploit-framework/Gemfile.lock

  v=$(cat "$msf/VERSION" 2>/dev/null || true)
  [ "$v" = "$MSF_REF" ] && pass "MSF VERSION $v" || fail "MSF VERSION is '$v', expected $MSF_REF"
  v=$(cat "$rb/VERSION" 2>/dev/null || true)
  [ "$v" = "$RUBY_VERSION" ] && pass "Ruby VERSION $v" || fail "Ruby VERSION is '$v', expected $RUBY_VERSION"

  local vroot ext
  vroot=$(find "$msf/vendor/bundle/ruby" -mindepth 1 -maxdepth 1 -type d -print -quit)
  [ -n "$vroot" ] || { fail "vendor/bundle/ruby/<ver> missing"; return; }
  ext="$vroot/extensions/aarch64-linux-android-android/$(basename "$vroot")"

  # Key native gems: a cross-compiled .so in the extensions dir + build marker
  local g dir
  for g in nokogiri pg sqlite3 pcaprub ffi; do
    dir=$(find "$ext" -mindepth 1 -maxdepth 1 -type d -name "${g}-[0-9]*" -print -quit 2>/dev/null)
    if [ -z "$dir" ]; then fail "no extension dir for gem $g"; continue; fi
    [ -f "$dir/gem.build_complete" ] || fail "$g: gem.build_complete missing"
    find "$dir" -name '*.so' -print -quit | grep -q . && pass "$g native extension ($(basename "$dir"))" \
      || fail "$g: no .so in $(basename "$dir")"
  done

  # Every vendored gem that declares extensions must have its build marker
  local f name missing=0
  while IFS= read -r f; do
    name=$(basename "$f" .gemspec)
    [ -f "$ext/$name/gem.build_complete" ] || { fail "$name declares extensions but has no build marker"; missing=1; }
  done < <(grep -l -E '\.extensions = \["' "$vroot"/specifications/*.gemspec || true)
  [ "$missing" = 1 ] || pass "build markers present for all gems with extensions"

  # No gem name installed in two versions (Ruby's default/bundled gems vs vendor/bundle):
  # RubyGems then warns "Unresolved or ambiguous specs" when msfrpcd starts.
  local rbgems dups
  rbgems=$(find "$rb/lib/ruby/gems" -mindepth 1 -maxdepth 1 -type d -print -quit)
  dups=$(gemspec_names "$rbgems/specifications" "$rbgems/specifications/default" "$vroot/specifications" \
         | grep -v '^bundler ' | sort -u | awk '{c[$1]++; v[$1]=v[$1]" "$2} END {for (n in c) if (c[n]>1) print n":"v[n]}' | sort)
  if [ -n "$dups" ]; then
    while IFS= read -r g; do fail "gem installed in several versions: $g"; done <<< "$dups"
  else
    pass "no gem installed in more than one version"
  fi

  # ELF arch: whole Ruby tree, vendored extensions and every .so of vendored gems
  # (MSF payload data legitimately contains ELFs for other architectures).
  elf_check "$rb" "$vroot/extensions"
  local bad=0 so
  while IFS= read -r -d '' so; do
    file -b "$so" | grep -q 'ARM aarch64' || { fail "non-aarch64 gem library: ${so#"$root"/}"; bad=1; }
  done < <(find "$vroot/gems" -type f \( -name '*.so' -o -name '*.so.*' \) \
             -not -path '*/metasploit-payloads-*' -not -path '*/metasploit_payloads-mettle-*' -print0)
  [ "$bad" = 1 ] || pass "vendored gem .so files are aarch64"

  # DT_NEEDED of our Ruby, its extensions and the cross-compiled gem extensions must be
  # in the bundle or Android system libs (payload gems ship target binaries: excluded)
  deps_check --prune '*/metasploit-payloads-*' --prune '*/metasploit_payloads-mettle-*' "$rb" "$vroot"
}
