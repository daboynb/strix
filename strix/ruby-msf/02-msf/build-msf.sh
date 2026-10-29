#!/bin/bash
# ============================================================
# Metasploit Framework: bundle install + cross-compile native gems
#
# Input:  /opt/ruby-android, /opt/ruby-host, /opt/android-deps, /opt/android-ndk
# Output: /output/metasploit-framework  (pronto per push su device)
#         /output/ruby-android          (copia aggiornata)
#         /output/libpq.so.5            (shared lib per PG)
#
# Strategia:
#   1. Scarica MSF + dipendenze extra (libpcap, sqlite3, libpq, libxml2, libxslt)
#   2. bundle install con Ruby HOST (compila ext native per x86_64)
#   3. Patch RbConfig host -> cross (aarch64-linux-android)
#   4. Ri-compila ogni ext nativa con cross-compiler
#   5. Sostituisci .so x86_64 con .so aarch64 in lib/
#   6. Crea gem.build_complete markers (solo per gem compilate davvero)
#   7. Strip (llvm-strip NDK) + pacchettizza
#
# Runs at image-build time (see ../Dockerfile, stage "msf"); versions, checksums
# and the MSF tag/commit come from strix/versions.env. Any failure aborts.
# ============================================================

set -euo pipefail
: "${ANDROID_NDK_HOME:?}" "${API_LEVEL:?}" "${MSF_REF:?}" "${MSF_COMMIT:?}" \
  "${LIBPCAP_VERSION:?}" "${SQLITE_VERSION:?}" "${SQLITE_YEAR:?}" "${POSTGRESQL_VERSION:?}" \
  "${LIBXML2_VERSION:?}" "${LIBXSLT_VERSION:?}" "${BUNDLER_VERSION:?}" "${BUNDLER_SHA256:?}"

# Download + verify + extract a source tarball into /tmp
fetch_src() { # <url> <sha256> [<keyring> <signature-url>]
    local file
    file="/tmp/$(basename "$1")"
    strix-fetch "$1" "$2" "$file" "${@:3}"
    tar xf "$file" -C /tmp
    rm -f "$file"
}
require_lib() { # <file> <name>
    [ -f "$1" ] || { echo "FAIL: $2 ($1 missing)"; exit 1; }
    echo "PASS: $2"
}

TOOLCHAIN=${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64
DEPS=/opt/android-deps
MSF_DIR=/opt/metasploit-framework
OUTPUT=/output
TARGET=aarch64-linux-android
API=${API_LEVEL}
RUBY_CROSS=/opt/ruby-android
RUBY_HOST=/opt/ruby-host

echo "============================================"
echo "  MSF ANDROID BUILD"
echo "  $(date -u +%Y-%m-%dT%H:%M:%S)"
echo "============================================"

# ============================================================
# FASE 1: Scarica MSF
# ============================================================
echo ""
echo "=== FASE 1: Download MSF ==="
cd /opt
git clone --depth 1 --branch "${MSF_REF}" https://github.com/rapid7/metasploit-framework.git
MSF_HEAD=$(git -C ${MSF_DIR} rev-parse HEAD)
if [ "${MSF_HEAD}" != "${MSF_COMMIT}" ]; then
    echo "FAIL: MSF ${MSF_REF} resolved to ${MSF_HEAD}, expected ${MSF_COMMIT} (strix/versions.env)"
    exit 1
fi
echo "MSF: $(git -C ${MSF_DIR} log --oneline -1)"
# Pinned lockfile = MSF's own + sha256 of every gem (strix/ruby-msf/02-msf/Gemfile.lock,
# scripts/msf-gemlock.sh); refuse a lockfile generated for another MSF commit
GEMLOCK=/opt/msf-Gemfile.lock
strix-msf-gemlock check "${MSF_DIR}/Gemfile.lock" "${GEMLOCK}"
cp "${GEMLOCK}" "${MSF_DIR}/Gemfile.lock"

# ============================================================
# FASE 2: Cross-compile dipendenze extra
# ============================================================
echo ""
echo "=== FASE 2: Dipendenze extra ==="

export CC="${TOOLCHAIN}/bin/${TARGET}${API}-clang"
export CXX="${TOOLCHAIN}/bin/${TARGET}${API}-clang++"
export AR="${TOOLCHAIN}/bin/llvm-ar"
export RANLIB="${TOOLCHAIN}/bin/llvm-ranlib"
export STRIP="${TOOLCHAIN}/bin/llvm-strip"

# libpcap
echo "--- libpcap ${LIBPCAP_VERSION} ---"
fetch_src "https://www.tcpdump.org/release/libpcap-${LIBPCAP_VERSION}.tar.gz" "${LIBPCAP_SHA256}" \
    tcpdump "https://www.tcpdump.org/release/libpcap-${LIBPCAP_VERSION}.tar.gz.sig"
cd /tmp/libpcap-${LIBPCAP_VERSION}
CC="$CC" AR="$AR" RANLIB="$RANLIB" CFLAGS="-fPIC -O2" \
./configure --host=${TARGET} --prefix=${DEPS} --disable-shared --without-libnl
make -j$(nproc)
make install
require_lib ${DEPS}/lib/libpcap.a libpcap

# sqlite3
echo "--- sqlite3 ${SQLITE_VERSION} ---"
fetch_src "https://www.sqlite.org/${SQLITE_YEAR}/sqlite-autoconf-${SQLITE_VERSION}.tar.gz" "${SQLITE_SHA256}"
cd /tmp/sqlite-autoconf-${SQLITE_VERSION}
CC="$CC" AR="$AR" RANLIB="$RANLIB" CFLAGS="-fPIC -O2" \
./configure --host=${TARGET} --prefix=${DEPS} --enable-static --disable-shared
make -j$(nproc)
make install
require_lib ${DEPS}/lib/libsqlite3.a sqlite3

# libpq (PostgreSQL client) — statica per link + shared per runtime
echo "--- libpq ${POSTGRESQL_VERSION} ---"
PG_VER=${POSTGRESQL_VERSION}
fetch_src "https://ftp.postgresql.org/pub/source/v${PG_VER}/postgresql-${PG_VER}.tar.bz2" "${POSTGRESQL_SHA256}"
cd /tmp/postgresql-${PG_VER}
CC="$CC" CXX="$CXX" AR="$AR" RANLIB="$RANLIB" \
CFLAGS="-fPIC -O2 -I${DEPS}/include" LDFLAGS="-L${DEPS}/lib" \
./configure --host=${TARGET} --prefix=${DEPS} \
    --without-readline --with-openssl --without-icu \
    --with-includes=${DEPS}/include --with-libraries=${DEPS}/lib
# Patch: disabilita pthread_exit check (non funziona con bionic)
cd src/interfaces/libpq
perl -0777 -i -pe 's/libpq-refs-stamp:.*?touch \$\@/libpq-refs-stamp: \$(shlib)\n\ttouch \$\@/s' Makefile
make -j$(nproc)
make install
cd /tmp/postgresql-${PG_VER}/src/include && make install
# Salva anche la shared lib per il device (richiesta: RubyExtractor usa lib/libpq.so.5)
PQ_SO=$(find /tmp/postgresql-${PG_VER}/src/interfaces/libpq -name "libpq.so.5.*" -type f -print -quit)
require_lib ${DEPS}/lib/libpq.a "libpq (static)"
[ -n "$PQ_SO" ] || { echo "FAIL: libpq shared (libpq.so.5.*) not built"; exit 1; }
echo "PASS: libpq (shared: $PQ_SO)"

# libxml2
echo "--- libxml2 ${LIBXML2_VERSION} ---"
fetch_src "https://download.gnome.org/sources/libxml2/${LIBXML2_VERSION%.*}/libxml2-${LIBXML2_VERSION}.tar.xz" "${LIBXML2_SHA256}"
cd /tmp/libxml2-${LIBXML2_VERSION}
CC="$CC" AR="$AR" RANLIB="$RANLIB" CFLAGS="-fPIC -O2 -I${DEPS}/include" LDFLAGS="-L${DEPS}/lib" \
./configure --host=${TARGET} --prefix=${DEPS} --enable-static --disable-shared \
    --without-python --without-readline --without-iconv --without-icu \
    --without-lzma --without-http --without-ftp --with-zlib=${DEPS}
make -j$(nproc)
make install
require_lib ${DEPS}/lib/libxml2.a libxml2

# libxslt
echo "--- libxslt ${LIBXSLT_VERSION} ---"
fetch_src "https://download.gnome.org/sources/libxslt/${LIBXSLT_VERSION%.*}/libxslt-${LIBXSLT_VERSION}.tar.xz" "${LIBXSLT_SHA256}"
cd /tmp/libxslt-${LIBXSLT_VERSION}
CC="$CC" AR="$AR" RANLIB="$RANLIB" \
CFLAGS="-fPIC -O2 -I${DEPS}/include -I${DEPS}/include/libxml2" LDFLAGS="-L${DEPS}/lib" \
./configure --host=${TARGET} --prefix=${DEPS} --enable-static --disable-shared \
    --without-python --without-crypto --with-libxml-prefix=${DEPS}
make -j$(nproc)
make install
require_lib ${DEPS}/lib/libxslt.a libxslt

echo ""
echo "Librerie statiche:"
ls ${DEPS}/lib/*.a

# ============================================================
# FASE 3: Bundle install (con Ruby HOST)
# ============================================================
echo ""
echo "=== FASE 3: Bundle install ==="
cd ${MSF_DIR}

# Resetta cross-compiler
unset CC CXX AR RANLIB STRIP C_INCLUDE_PATH LIBRARY_PATH PKG_CONFIG_PATH PKG_CONFIG_LIBDIR

# Pinned Bundler (CHECKSUMS support) from a sha256-verified .gem, no network resolution
strix-fetch "https://rubygems.org/downloads/bundler-${BUNDLER_VERSION}.gem" "${BUNDLER_SHA256}" /tmp/bundler.gem
${RUBY_HOST}/bin/gem install --local --no-doc /tmp/bundler.gem
rm -f /tmp/bundler.gem
BUNDLE_VER=$(bundle --version)
[ "${BUNDLE_VER}" = "Bundler version ${BUNDLER_VERSION}" ] \
    || { echo "FAIL: bundle is '${BUNDLE_VER}', expected ${BUNDLER_VERSION}"; exit 1; }

# frozen: install exactly the pinned lockfile; a gem whose sha256 differs from its
# CHECKSUMS entry aborts the install
bundle config set --local frozen true
bundle config set --local force_ruby_platform true
bundle config set --local path vendor/bundle
bundle config set --local without 'development test coverage'
bundle config set --local jobs $(nproc)

# One retry for transient network errors; the retry must succeed
if ! bundle install; then
    echo "WARN: bundle install failed, retrying once..."
    bundle install
fi
bundle check
cmp -s "${GEMLOCK}" Gemfile.lock || { echo "FAIL: bundle install rewrote the pinned Gemfile.lock"; exit 1; }

TOTAL_GEMS=$(find vendor/bundle -name "*.gemspec" | wc -l)
echo "Gemme installate: ${TOTAL_GEMS}"

# ============================================================
# FASE 4: Patch RbConfig per cross-compilazione
# ============================================================
echo ""
echo "=== FASE 4: RbConfig cross ==="

export CC="${TOOLCHAIN}/bin/${TARGET}${API}-clang"
export CXX="${TOOLCHAIN}/bin/${TARGET}${API}-clang++"
export AR="${TOOLCHAIN}/bin/llvm-ar"
export RANLIB="${TOOLCHAIN}/bin/llvm-ranlib"
export STRIP="${TOOLCHAIN}/bin/llvm-strip"

RBCONFIG_HOST=$(${RUBY_HOST}/bin/ruby -rrbconfig -e 'puts RbConfig::CONFIG["archdir"]')/rbconfig.rb
RBCONFIG_CROSS=$(find ${RUBY_CROSS} -name "rbconfig.rb" -print -quit)
[ -n "${RBCONFIG_CROSS}" ] || { echo "FAIL: cross rbconfig.rb not found in ${RUBY_CROSS}"; exit 1; }
cp ${RBCONFIG_HOST} ${RBCONFIG_HOST}.bak
cp ${RBCONFIG_CROSS} ${RBCONFIG_HOST}
echo "CC: $(${RUBY_HOST}/bin/ruby -rrbconfig -e 'puts RbConfig::CONFIG["CC"]')"

# Installa mini_portile2 (serve per nokogiri extconf)
# (version + sha256 from the pinned lockfile, so it is the same verified gem bundler installed)
read -r MP_VER MP_SHA < <(strix-msf-gemlock gem "${GEMLOCK}" mini_portile2)
strix-fetch "https://rubygems.org/downloads/mini_portile2-${MP_VER}.gem" "${MP_SHA}" /tmp/mini_portile2.gem
${RUBY_HOST}/bin/gem install --local --no-doc /tmp/mini_portile2.gem
rm -f /tmp/mini_portile2.gem

# ============================================================
# FASE 5: Cross-compila ext native
# ============================================================
echo ""
echo "=== FASE 5: Cross-compilazione ext native ==="
# Per-ext failures are recorded in /tmp/gem_<name> (FAIL is sticky across a gem's
# extconfs) and turned into a hard error after the summary below.

export C_INCLUDE_PATH="${DEPS}/include:${DEPS}/include/libxml2"
export LIBRARY_PATH="${DEPS}/lib"
# PKG_CONFIG_LIBDIR (non PATH) forza pkg-config a cercare SOLO nelle cross-deps,
# ignorando le lib x86_64 del sistema host (es. /usr/lib/x86_64-linux-gnu/pkgconfig)
export PKG_CONFIG_LIBDIR="${DEPS}/lib/pkgconfig"
export PKG_CONFIG_PATH="${DEPS}/lib/pkgconfig"
# Nokogiri richiede questa env var oltre al flag --use-system-libraries
export NOKOGIRI_USE_SYSTEM_LIBRARIES=1

RUBY_VER_DIR=$(find vendor/bundle/ruby -mindepth 1 -maxdepth 1 -type d -printf '%f\n' -quit)
[ -n "${RUBY_VER_DIR}" ] || { echo "FAIL: vendor/bundle/ruby is empty"; exit 1; }
GEM_BASE="vendor/bundle/ruby/${RUBY_VER_DIR}/gems"

# The host `bundle install` leaves x86_64 mini_portile builds in the gem trees
# (<gem>/ports/<host>, <gem>/ext/*/ports/<host> + its <name>-<ver>-<host>.installed
# checkpoint, <gem>/ext/*/tmp/<host>: libraries,
# objects, executables like sqlite3's bin/sqlite3). They are host build products,
# not gem content: drop them so nothing x86_64 is shipped or reused by the cross build.
# nokogiri in particular would re-activate its x86_64 libgumbo.a (port path + .installed
# checkpoint named after the host RUBY_PLATFORM) and fail gumbo_parse_with_options;
# without it libgumbo is rebuilt for aarch64 from the gem's gumbo-parser sources with
# $CC/$AR. The gem-root nokogiri ports/ (source archives, unused with
# --use-system-libraries) is what nokogiri's own post-build clean removes.
# (the build host is always x86_64, see ../build.sh; the triplet spelling varies by
# recipe: x86_64-linux, x86_64-linux-gnu, ...)
while IFS= read -r -d '' d; do
    echo "  removing host build ${d#"${GEM_BASE}"/}"
    rm -rf "$d"
done < <(find ${GEM_BASE} -mindepth 2 -maxdepth 5 \( -path '*/ports/*' -o -path '*/ext/*/tmp/*' \) \
             \( \( -type d -name 'x86_64-*' \) -o \( -type f -name '*-x86_64-*.installed' \) \) \
             -not -path '*/metasploit-payloads-*' -not -path '*/metasploit_payloads-mettle-*' \
             -prune -print0)
rm -rf ${GEM_BASE}/nokogiri-*/ports

# Every .so we cross-compile or copy (absolute paths under ${MSF_DIR}): the only
# msf files FASE 6 strips. Gem-shipped binaries (payloads, data) are never touched.
BUILT_SO_LIST=/tmp/built_so.list
: > "${BUILT_SO_LIST}"

CROSS_OK=0
CROSS_FAIL=0
CROSS_SKIP=0
rm -f /tmp/gem_*

mark_gem() { # <gemname> PASS|FAIL  — FAIL is never downgraded to PASS
    if [ "$2" = "PASS" ] && [ "$(cat "/tmp/gem_$1" 2>/dev/null)" = "FAIL" ]; then
        return 0
    fi
    echo "$2" > "/tmp/gem_$1"
}

for gemdir in ${GEM_BASE}/*/; do
    [ -d "${gemdir}ext" ] || continue
    gemname=$(basename "$gemdir")

    while IFS= read -r extconf; do
        extdir=$(dirname "$extconf")
        extbase=$(basename "$extdir")
        cd "${extdir}"
        rm -f Makefile

        if ! ${RUBY_HOST}/bin/ruby extconf.rb \
            --use-system-libraries \
            --with-openssl-dir=${DEPS} \
            --with-zlib-dir=${DEPS} \
            --with-libyaml-dir=${DEPS} \
            --with-yaml-dir=${DEPS} \
            --with-ffi-dir=${DEPS} \
            --with-libffi-dir=${DEPS} \
            --with-sqlite3-dir=${DEPS} \
            --with-pcap-dir=${DEPS} \
            --with-pg-dir=${DEPS} \
            --with-opt-dir=${DEPS} \
            --with-xml2-dir=${DEPS} \
            --with-xslt-dir=${DEPS} \
            --with-xml2-include=${DEPS}/include/libxml2 \
            --with-xml2-lib=${DEPS}/lib \
            --with-xslt-include=${DEPS}/include \
            --with-xslt-lib=${DEPS}/lib \
            --enable-system-libraries \
            || [ ! -f Makefile ]; then
            echo "FAIL: extconf (${gemname}/${extbase})"
            [ -f mkmf.log ] && tail -n 30 mkmf.log
            mark_gem "${gemname}" FAIL
            cd ${MSF_DIR}; continue
        fi

        sed -i 's|-lpthread||g; s|-lrt||g; s|--fix-cortex-a53-843419||g' Makefile
        make clean
        if ! make -j$(nproc); then
            echo "FAIL: make (${gemname}/${extbase})"
            mark_gem "${gemname}" FAIL
            cd ${MSF_DIR}; continue
        fi

        SO_FILES=$(find "$PWD" -name "*.so" -newer Makefile)
        if [ -z "$SO_FILES" ]; then
            echo "OK: ${gemname}/${extbase} (make succeeded, no .so output)"
            mark_gem "${gemname}" PASS
        fi
        while IFS= read -r SO_FILE; do
            [ -n "$SO_FILE" ] || continue
            if file "$SO_FILE" | grep -q "aarch64"; then
                echo "PASS: ${gemname} -> $(basename "$SO_FILE")"
                echo "$SO_FILE" >> "${BUILT_SO_LIST}"
                mark_gem "${gemname}" PASS
            else
                echo "FAIL: ${gemname}/${extbase} produced a non-aarch64 .so: $(file "$SO_FILE")"
                mark_gem "${gemname}" FAIL
            fi
        done <<< "$SO_FILES"

        cd ${MSF_DIR}
    done < <(find "${gemdir}ext" -maxdepth 5 -name "extconf.rb" | sort)
done

# ============================================================
# FASE 5.5: Sostituisci .so x86_64 -> aarch64 in lib/
# ============================================================
echo ""
echo "=== FASE 5.5: Replace .so ==="
for gemdir in ${GEM_BASE}/*/; do
    [ -d "${gemdir}ext" ] && [ -d "${gemdir}lib" ] || continue
    while IFS= read -r so; do
        if file "$so" | grep -q "aarch64"; then
            SO_NAME=$(basename "$so")
            while IFS= read -r target; do
                cp -f "$so" "$target"
                realpath "$target" >> "${BUILT_SO_LIST}"
                echo "  $(basename "$(dirname "$(dirname "$target")")"): $SO_NAME"
            done < <(find "${gemdir}lib" -name "$SO_NAME")
        fi
    done < <(find "${gemdir}ext" -name "*.so")
done

# ============================================================
# FASE 5.55: Verifica nokogiri
# ============================================================
# nokogiri is built by the FASE 5 loop like every other gem (an extconf/make failure
# there is fatal in the summary); here only check that lib/ got the aarch64 .so.
echo ""
echo "=== FASE 5.55: Nokogiri check ==="
NOKO_DIR=$(find ${GEM_BASE} -maxdepth 1 -name "nokogiri-*" -type d -print -quit)
[ -n "$NOKO_DIR" ] || { echo "FAIL: nokogiri gem non trovata"; exit 1; }
NOKO_LIB_SO="${NOKO_DIR}/lib/nokogiri/nokogiri.so"
if [ -f "$NOKO_LIB_SO" ] && file "$NOKO_LIB_SO" | grep -q "aarch64"; then
    echo "nokogiri.so OK: $(file -b "$NOKO_LIB_SO")"
else
    echo "FAIL: ${NOKO_LIB_SO} missing or not aarch64${NOKO_LIB_SO:+: $(file -b "$NOKO_LIB_SO" 2>&1)}"
    exit 1
fi

# ============================================================
# FASE 5.6: Crea gem.build_complete markers
# ============================================================
echo ""
echo "=== FASE 5.6: Extension markers ==="
TARGET_ARCH="aarch64-linux-android-android"
EXT_BASE="vendor/bundle/ruby/${RUBY_VER_DIR}/extensions/${TARGET_ARCH}/${RUBY_VER_DIR}"
MARKER_COUNT=0
SPEC_DIR="vendor/bundle/ruby/${RUBY_VER_DIR}/specifications"
for gemdir in ${GEM_BASE}/*/; do
    [ -d "${gemdir}ext" ] || continue
    gemname=$(basename "$gemdir")
    result=$(cat "/tmp/gem_${gemname}" 2>/dev/null || echo "UNKNOWN")
    if [ "$result" = "UNKNOWN" ]; then
        # No extconf.rb under ext/ (e.g. concurrent-ruby ships Java sources only).
        # Fine only if the gemspec declares no native extensions; otherwise RubyGems
        # would need an extension we never built, so refuse to fake a marker.
        exts=$(${RUBY_HOST}/bin/ruby -e 'puts Gem::Specification.load(ARGV[0]).extensions' "${SPEC_DIR}/${gemname}.gemspec")
        if [ -n "$exts" ]; then
            echo "FAIL: ${gemname} declares extensions (${exts//$'\n'/ }) but none was cross-compiled"
            exit 1
        fi
        echo "  skip ${gemname} (no native extension declared)"
        continue
    fi
    [ "$result" = "PASS" ] || continue   # FAIL: reported (and fatal) in the summary below
    mkdir -p "${EXT_BASE}/${gemname}"
    touch "${EXT_BASE}/${gemname}/gem.build_complete"
    MARKER_COUNT=$((MARKER_COUNT+1))
    # Copia .so aarch64 nella extensions dir
    while IFS= read -r so; do
        if file "$so" | grep -q "aarch64"; then
            cp -f "$so" "${EXT_BASE}/${gemname}/"
            realpath "${EXT_BASE}/${gemname}/$(basename "$so")" >> "${BUILT_SO_LIST}"
        fi
    done < <(find "${gemdir}ext" -name "*.so")
done
echo "Markers: ${MARKER_COUNT}"

# Crea symlink per extension_api_version (Ruby usa "3.3.0-static")
EXT_ARCH_DIR="${MSF_DIR}/vendor/bundle/ruby/${RUBY_VER_DIR}/extensions/${TARGET_ARCH}"
if [ -d "${EXT_ARCH_DIR}" ]; then
    cd "${EXT_ARCH_DIR}"
    if [ -d "${RUBY_VER_DIR}" ] && [ ! -e "${RUBY_VER_DIR}-static" ]; then
        ln -s "${RUBY_VER_DIR}" "${RUBY_VER_DIR}-static"
    fi
fi
# Symlink per Gem::Platform.local (potrebbe essere "aarch64-linux" senza "-android")
EXT_DIR="${MSF_DIR}/vendor/bundle/ruby/${RUBY_VER_DIR}/extensions"
if [ -d "${EXT_DIR}" ]; then
    cd "${EXT_DIR}"
    if [ -d "${TARGET_ARCH}" ] && [ ! -e "aarch64-linux" ]; then
        ln -s "${TARGET_ARCH}" "aarch64-linux"
    fi
fi
cd ${MSF_DIR}

# ============================================================
# RIEPILOGO
# ============================================================
echo ""
echo "============================================"
echo "  RIEPILOGO CROSS-COMPILAZIONE"
echo "============================================"
for gemdir in ${GEM_BASE}/*/; do
    [ -d "${gemdir}ext" ] || continue
    gemname=$(basename "$gemdir")
    result=$(cat "/tmp/gem_${gemname}" 2>/dev/null || echo "UNKNOWN")
    case $result in
        PASS) CROSS_OK=$((CROSS_OK+1)) ;;
        FAIL) CROSS_FAIL=$((CROSS_FAIL+1)) ;;
        *) CROSS_SKIP=$((CROSS_SKIP+1)) ;;
    esac
    printf "  %-7s %s\n" "$result" "$gemname"
done
echo "============================================"
echo "  PASS: ${CROSS_OK}  FAIL: ${CROSS_FAIL}  SKIP: ${CROSS_SKIP}"
echo "============================================"
if [ "${CROSS_FAIL}" -ne 0 ]; then
    echo "FAIL: ${CROSS_FAIL} gem(s) failed to cross-compile (see above)"
    exit 1
fi
[ "${CROSS_OK}" -gt 0 ] || { echo "FAIL: no native gem was cross-compiled"; exit 1; }

# ============================================================
# FASE 6: Pacchettizza
# ============================================================
echo ""
echo "=== FASE 6: Pacchettizzazione ==="

# Ripristina RbConfig host
cp ${RBCONFIG_HOST}.bak ${RBCONFIG_HOST}

rm -rf ${OUTPUT}
mkdir -p ${OUTPUT}

# Ruby cross (da stage 1) + OpenSSL legacy provider se presente
cp -a ${RUBY_CROSS} ${OUTPUT}/ruby-android
if [ -d ${DEPS}/lib/ossl-modules ]; then
    mkdir -p ${OUTPUT}/android-deps/lib
    cp -a ${DEPS}/lib/ossl-modules ${OUTPUT}/android-deps/lib/
fi

# Drop Ruby's own default/bundled gem specs that MSF's Gemfile.lock vendors in a
# different version (e.g. date 3.3.4 vs 3.4.1). With both installed RubyGems warns
# "Unresolved or ambiguous specs" at msfrpcd start; bundler's locked version must win.
# Default gems: only the spec goes (their stdlib files stay as non-gem fallback).
# Bundled gems: spec + gem dir + built extension go. bundler itself is left alone.
echo "Pruning Ruby gems shadowed by vendor/bundle..."
RB_GEMS=$(find ${OUTPUT}/ruby-android/lib/ruby/gems -mindepth 1 -maxdepth 1 -type d -print -quit)
[ -n "${RB_GEMS}" ] || { echo "FAIL: ruby-android/lib/ruby/gems/<ver> missing"; exit 1; }
declare -A VENDOR_GEM=()
for spec in ${MSF_DIR}/vendor/bundle/ruby/${RUBY_VER_DIR}/specifications/*.gemspec; do
    base=$(basename "$spec" .gemspec)
    [[ "$base" =~ ^(.+)-([0-9][^-]*)$ ]] && VENDOR_GEM[${BASH_REMATCH[1]}]=${BASH_REMATCH[2]}
done
PRUNED=0
for spec in "${RB_GEMS}"/specifications/*.gemspec "${RB_GEMS}"/specifications/default/*.gemspec; do
    [ -e "$spec" ] || continue
    base=$(basename "$spec" .gemspec)
    [[ "$base" =~ ^(.+)-([0-9][^-]*)$ ]] || continue
    name=${BASH_REMATCH[1]} ver=${BASH_REMATCH[2]}
    [ "$name" != bundler ] || continue
    vver=${VENDOR_GEM[$name]:-}
    [ -n "$vver" ] && [ "$vver" != "$ver" ] || continue
    rm -f "$spec"
    if [[ "$spec" != */specifications/default/* ]]; then
        rm -rf "${RB_GEMS}/gems/${base}"
        if [ -d "${RB_GEMS}/extensions" ]; then
            find "${RB_GEMS}/extensions" -mindepth 3 -maxdepth 3 -type d -name "${base}" -prune -exec rm -rf {} +
        fi
    fi
    echo "  ${name}: ruby ${ver} removed (vendor/bundle has ${vver})"
    PRUNED=$((PRUNED+1))
done
echo "Pruned: ${PRUNED}"

# MSF
mkdir -p ${OUTPUT}/metasploit-framework
cp -a ${MSF_DIR}/. ${OUTPUT}/metasploit-framework/
rm -rf ${OUTPUT}/metasploit-framework/.git \
       ${OUTPUT}/metasploit-framework/spec \
       ${OUTPUT}/metasploit-framework/test \
       ${OUTPUT}/metasploit-framework/documentation
find ${OUTPUT}/metasploit-framework/vendor/bundle -path "*/extensions/x86_64*" -prune -type d -exec rm -rf {} +

# Copia libpq.so.5 per il device
cp "$PQ_SO" ${OUTPUT}/libpq.so.5

# Strip debug info with the NDK llvm-strip (host `strip` can't handle aarch64 objects),
# only from binaries we built: every aarch64 ELF of our Ruby + libpq, and in MSF exactly
# the .so files listed in ${BUILT_SO_LIST}. Gem-shipped prebuilt files (target payloads
# of metasploit-payloads / metasploit_payloads-mettle, data/) stay byte-for-byte.
echo "Stripping aarch64 ELF files we built..."
STRIPPED=0
strip_elf() { # <file>: must be an aarch64 ELF
    file -b "$1" | grep -q '^ELF 64-bit.*ARM aarch64' \
        || { echo "FAIL: strip target is not an aarch64 ELF: $1 ($(file -b "$1"))"; exit 1; }
    llvm-strip --strip-debug "$1"
    STRIPPED=$((STRIPPED+1))
}
while IFS= read -r -d '' f; do
    if file -b "$f" | grep -q '^ELF '; then strip_elf "$f"; fi
done < <(find ${OUTPUT}/ruby-android ${OUTPUT}/libpq.so.5 -type f -print0)
[ -s "${BUILT_SO_LIST}" ] || { echo "FAIL: ${BUILT_SO_LIST} is empty"; exit 1; }
while IFS= read -r so; do
    out="${OUTPUT}/metasploit-framework/${so#"${MSF_DIR}"/}"
    [ "$out" != "${OUTPUT}/metasploit-framework/${so}" ] || { echo "FAIL: ${so} is outside ${MSF_DIR}"; exit 1; }
    [ -f "$out" ] || { echo "FAIL: built ${so} missing from the output"; exit 1; }
    strip_elf "$out"
done < <(sort -u "${BUILT_SO_LIST}")
echo "Stripped: ${STRIPPED} files"

# C++ extensions (eventmachine) are linked by the NDK clang++ against libc++_shared.so,
# which is not an Android system library: ship the NDK's copy (unmodified) in
# ruby-android/lib, the LD_LIBRARY_PATH of msfrpcd (MsfDaemon), like libpq.so.5.
NEED_CXX=0
while IFS= read -r so; do
    if llvm-readelf -d "$so" | grep -q 'NEEDED.*\[libc++_shared\.so\]'; then
        echo "  $(basename "$so") needs libc++_shared.so"
        NEED_CXX=1
    fi
done < <(sort -u "${BUILT_SO_LIST}")
if [ "${NEED_CXX}" = 1 ]; then
    CXX_SHARED="${TOOLCHAIN}/sysroot/usr/lib/${TARGET}/libc++_shared.so"
    [ -f "${CXX_SHARED}" ] || { echo "FAIL: ${CXX_SHARED} missing"; exit 1; }
    cp "${CXX_SHARED}" ${OUTPUT}/ruby-android/lib/
    echo "Included libc++_shared.so (NDK)"
fi

echo "MSF: $(find ${OUTPUT}/metasploit-framework -type f | wc -l) files, $(du -sh ${OUTPUT}/metasploit-framework | cut -f1)"

# Ensure all output files are world-readable (some gems create 600 archives)
chmod -R a+r ${OUTPUT}

echo ""
echo "============================================"
echo "  DONE — $(date -u +%Y-%m-%dT%H:%M:%S)"
echo "============================================"
