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
#   6. Crea gem.build_complete markers
#   7. Pacchettizza
# ============================================================

set -e

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
git clone --depth 1 https://github.com/rapid7/metasploit-framework.git 2>&1 | tail -3
echo "MSF: $(cd ${MSF_DIR} && git log --oneline -1)"

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
echo "--- libpcap ---"
cd /tmp && wget -q https://www.tcpdump.org/release/libpcap-1.10.5.tar.xz
tar xf libpcap-1.10.5.tar.xz && cd libpcap-1.10.5
CC="$CC" AR="$AR" RANLIB="$RANLIB" CFLAGS="-fPIC -O2" \
./configure --host=${TARGET} --prefix=${DEPS} --disable-shared --without-libnl 2>&1 | tail -1
make -j$(nproc) 2>&1 | tail -1 && make install 2>&1 | tail -1
[ -f ${DEPS}/lib/libpcap.a ] && echo "PASS" || echo "FAIL"

# sqlite3
echo "--- sqlite3 ---"
cd /tmp && wget -q https://www.sqlite.org/2024/sqlite-autoconf-3450100.tar.gz
tar xzf sqlite-autoconf-3450100.tar.gz && cd sqlite-autoconf-3450100
CC="$CC" AR="$AR" RANLIB="$RANLIB" CFLAGS="-fPIC -O2" \
./configure --host=${TARGET} --prefix=${DEPS} --enable-static --disable-shared 2>&1 | tail -1
make -j$(nproc) 2>&1 | tail -1 && make install 2>&1 | tail -1
[ -f ${DEPS}/lib/libsqlite3.a ] && echo "PASS" || echo "FAIL"

# libpq (PostgreSQL client) — statica per link + shared per runtime
echo "--- libpq ---"
cd /tmp
PG_VER=16.2
wget -q https://ftp.postgresql.org/pub/source/v${PG_VER}/postgresql-${PG_VER}.tar.bz2
tar xjf postgresql-${PG_VER}.tar.bz2 && cd postgresql-${PG_VER}
CC="$CC" CXX="$CXX" AR="$AR" RANLIB="$RANLIB" \
CFLAGS="-fPIC -O2 -I${DEPS}/include" LDFLAGS="-L${DEPS}/lib" \
./configure --host=${TARGET} --prefix=${DEPS} \
    --without-readline --with-openssl --without-icu \
    --with-includes=${DEPS}/include --with-libraries=${DEPS}/lib 2>&1 | tail -1
# Patch: disabilita pthread_exit check (non funziona con bionic)
cd src/interfaces/libpq
perl -0777 -i -pe 's/libpq-refs-stamp:.*?touch \$\@/libpq-refs-stamp: \$(shlib)\n\ttouch \$\@/s' Makefile
make -j$(nproc) 2>&1 | tail -1
make install 2>&1 | tail -1
cd /tmp/postgresql-${PG_VER}/src/include && make install 2>&1 | tail -1
# Salva anche la shared lib per il device
PQ_SO=$(find /tmp/postgresql-${PG_VER}/src/interfaces/libpq -name "libpq.so.5.*" | head -1)
[ -f ${DEPS}/lib/libpq.a ] 2>/dev/null && echo "PASS (static)" || echo "WARN: libpq static mancante"
[ -n "$PQ_SO" ] && echo "PASS (shared: $PQ_SO)" || echo "WARN: libpq shared mancante"

# libxml2
echo "--- libxml2 ---"
cd /tmp && wget -q https://download.gnome.org/sources/libxml2/2.12/libxml2-2.12.9.tar.xz
tar xf libxml2-2.12.9.tar.xz && cd libxml2-2.12.9
CC="$CC" AR="$AR" RANLIB="$RANLIB" CFLAGS="-fPIC -O2 -I${DEPS}/include" LDFLAGS="-L${DEPS}/lib" \
./configure --host=${TARGET} --prefix=${DEPS} --enable-static --disable-shared \
    --without-python --without-readline --without-iconv --without-icu \
    --without-lzma --without-http --without-ftp --with-zlib=${DEPS} 2>&1 | tail -1
make -j$(nproc) 2>&1 | tail -1 && make install 2>&1 | tail -1
[ -f ${DEPS}/lib/libxml2.a ] && echo "PASS" || echo "FAIL"

# libxslt
echo "--- libxslt ---"
cd /tmp && wget -q https://download.gnome.org/sources/libxslt/1.1/libxslt-1.1.42.tar.xz
tar xf libxslt-1.1.42.tar.xz && cd libxslt-1.1.42
CC="$CC" AR="$AR" RANLIB="$RANLIB" \
CFLAGS="-fPIC -O2 -I${DEPS}/include -I${DEPS}/include/libxml2" LDFLAGS="-L${DEPS}/lib" \
./configure --host=${TARGET} --prefix=${DEPS} --enable-static --disable-shared \
    --without-python --without-crypto --with-libxml-prefix=${DEPS} 2>&1 | tail -1
make -j$(nproc) 2>&1 | tail -1 && make install 2>&1 | tail -1
[ -f ${DEPS}/lib/libxslt.a ] && echo "PASS" || echo "FAIL"

echo ""
echo "Librerie: $(ls ${DEPS}/lib/*.a 2>/dev/null | wc -l) statiche"
ls ${DEPS}/lib/*.a 2>/dev/null

# ============================================================
# FASE 3: Bundle install (con Ruby HOST)
# ============================================================
echo ""
echo "=== FASE 3: Bundle install ==="
cd ${MSF_DIR}

# Resetta cross-compiler
unset CC CXX AR RANLIB STRIP C_INCLUDE_PATH LIBRARY_PATH PKG_CONFIG_PATH

bundle config set --local force_ruby_platform true
bundle config set --local path vendor/bundle
bundle config set --local without 'development test coverage'
bundle config set --local jobs $(nproc)

bundle install 2>&1 | tail -10
BUNDLE_RC=${PIPESTATUS[0]:-$?}

if [ ${BUNDLE_RC} -ne 0 ]; then
    echo "WARN: bundle install con errori, riprovo senza errori ext native..."
    bundle install 2>&1 | tail -5
fi

TOTAL_GEMS=$(find vendor/bundle -name "*.gemspec" 2>/dev/null | wc -l)
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
RBCONFIG_CROSS=$(find ${RUBY_CROSS} -name "rbconfig.rb" | head -1)
cp ${RBCONFIG_HOST} ${RBCONFIG_HOST}.bak
cp ${RBCONFIG_CROSS} ${RBCONFIG_HOST}
echo "CC: $(${RUBY_HOST}/bin/ruby -rrbconfig -e 'puts RbConfig::CONFIG["CC"]')"

# Installa mini_portile2 (serve per nokogiri extconf)
${RUBY_HOST}/bin/gem install mini_portile2 -v '~> 2.8.2' --no-doc 2>&1 | tail -1

# ============================================================
# FASE 5: Cross-compila ext native
# ============================================================
echo ""
echo "=== FASE 5: Cross-compilazione ext native ==="

set +e

export C_INCLUDE_PATH="${DEPS}/include:${DEPS}/include/libxml2"
export LIBRARY_PATH="${DEPS}/lib"
# PKG_CONFIG_LIBDIR (non PATH) forza pkg-config a cercare SOLO nelle cross-deps,
# ignorando le lib x86_64 del sistema host (es. /usr/lib/x86_64-linux-gnu/pkgconfig)
export PKG_CONFIG_LIBDIR="${DEPS}/lib/pkgconfig"
export PKG_CONFIG_PATH="${DEPS}/lib/pkgconfig"
# Nokogiri richiede questa env var oltre al flag --use-system-libraries
export NOKOGIRI_USE_SYSTEM_LIBRARIES=1

RUBY_VER_DIR=$(ls vendor/bundle/ruby/ | head -1)
GEM_BASE="vendor/bundle/ruby/${RUBY_VER_DIR}/gems"

# Elimina ports x86_64 di nokogiri (libgumbo+libxml2 precompilati per host)
# per forzare ricompilazione per aarch64 target
rm -rf ${GEM_BASE}/nokogiri-*/ports

CROSS_OK=0
CROSS_FAIL=0
CROSS_SKIP=0

for gemdir in ${GEM_BASE}/*/; do
    [ -d "${gemdir}ext" ] || continue
    gemname=$(basename "$gemdir")

    find "${gemdir}ext" -name "extconf.rb" -maxdepth 5 | sort | while read extconf; do
        extdir=$(dirname "$extconf")
        extbase=$(basename "$extdir")
        cd "${extdir}"

        ${RUBY_HOST}/bin/ruby extconf.rb \
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
            2>&1 | tail -3

        if [ ! -f Makefile ]; then
            echo "FAIL: extconf (${gemname}/${extbase})"
            echo "FAIL" > /tmp/gem_${gemname}
            cd ${MSF_DIR}; continue
        fi

        sed -i 's|-lpthread||g; s|-lrt||g; s|--fix-cortex-a53-843419||g' Makefile 2>/dev/null
        make clean 2>/dev/null
        make -j$(nproc) 2>&1 | tail -3

        SO_FILE=$(find . -name "*.so" -newer Makefile 2>/dev/null | head -1)
        if [ -n "$SO_FILE" ] && file "$SO_FILE" | grep -q "aarch64"; then
            echo "PASS: ${gemname} -> $(basename $SO_FILE)"
            echo "PASS" > /tmp/gem_${gemname}
        elif [ $? -eq 0 ]; then
            echo "OK: ${gemname} (no .so output)"
            echo "PASS" > /tmp/gem_${gemname}
        else
            echo "FAIL: ${gemname}"
            echo "FAIL" > /tmp/gem_${gemname}
        fi

        cd ${MSF_DIR}
    done
done

# ============================================================
# FASE 5.5: Sostituisci .so x86_64 -> aarch64 in lib/
# ============================================================
echo ""
echo "=== FASE 5.5: Replace .so ==="
for gemdir in ${GEM_BASE}/*/; do
    [ -d "${gemdir}ext" ] || continue
    find "${gemdir}ext" -name "*.so" 2>/dev/null | while read so; do
        if file "$so" | grep -q "aarch64"; then
            SO_NAME=$(basename "$so")
            find "${gemdir}lib" -name "$SO_NAME" 2>/dev/null | while read target; do
                cp -f "$so" "$target"
                echo "  $(basename $(dirname $(dirname "$target"))): $SO_NAME"
            done
        fi
    done
done

# ============================================================
# FASE 5.55: Verifica e fallback nokogiri
# ============================================================
echo ""
echo "=== FASE 5.55: Nokogiri check ==="
NOKO_DIR=$(find ${GEM_BASE} -maxdepth 1 -name "nokogiri-*" -type d | head -1)
# Risolvi in path assoluto (GEM_BASE è relativo a MSF_DIR)
[ -n "$NOKO_DIR" ] && NOKO_DIR=$(cd ${MSF_DIR} && realpath "${NOKO_DIR}")
if [ -n "$NOKO_DIR" ]; then
    NOKO_LIB_SO=$(find "${NOKO_DIR}/lib" -name "nokogiri.so" | head -1)
    if [ -z "$NOKO_LIB_SO" ] || ! file "$NOKO_LIB_SO" | grep -q "aarch64"; then
        echo "nokogiri.so mancante o x86_64 — ricompilo..."
        cd "${NOKO_DIR}/ext/nokogiri"
        rm -f *.o *.so Makefile
        rm -rf "${NOKO_DIR}/ports"

        # --gumbo-dev: compila gumbo inline (evita ensure_func check che
        # fallisce in cross-compilation per conflitto dichiarazione void vs return type)
        ${RUBY_HOST}/bin/ruby extconf.rb \
            --use-system-libraries \
            --gumbo-dev \
            --with-xml2-dir=${DEPS} \
            --with-xslt-dir=${DEPS} \
            --with-xml2-include=${DEPS}/include/libxml2 \
            --with-xml2-lib=${DEPS}/lib \
            --with-xslt-include=${DEPS}/include \
            --with-xslt-lib=${DEPS}/lib \
            --with-zlib-dir=${DEPS} \
            --with-opt-dir=${DEPS} \
            --enable-system-libraries \
            2>&1

        if [ -f Makefile ]; then
            sed -i 's|-lpthread||g; s|-lrt||g; s|--fix-cortex-a53-843419||g' Makefile
            make clean 2>/dev/null
            make -j$(nproc) V=1 2>&1 | tail -5
            NOKO_SO=$(find . -name "nokogiri.so" 2>/dev/null | head -1)
            if [ -n "$NOKO_SO" ] && file "$NOKO_SO" | grep -q "aarch64"; then
                echo "PASS: nokogiri.so aarch64"
                # Copia nella directory lib corretta (crea se necessario)
                NOKO_LIB_DST=$(find "${NOKO_DIR}/lib" -type d -name "nokogiri" | head -1)
                if [ -z "$NOKO_LIB_DST" ]; then
                    mkdir -p "${NOKO_DIR}/lib/nokogiri"
                    NOKO_LIB_DST="${NOKO_DIR}/lib/nokogiri"
                fi
                cp -f "$NOKO_SO" "${NOKO_LIB_DST}/nokogiri.so"
                echo "  Copied to ${NOKO_LIB_DST}/nokogiri.so"
                # Aggiorna marker per il riepilogo finale
                echo "PASS" > /tmp/gem_$(basename ${NOKO_DIR})
            else
                echo "FAIL: nokogiri cross-compilation fallita"
                [ -n "$NOKO_SO" ] && file "$NOKO_SO"
                echo "--- mkmf.log ---"
                cat mkmf.log 2>/dev/null | tail -30
            fi
        else
            echo "FAIL: extconf.rb non ha generato Makefile"
            echo "--- mkmf.log ---"
            cat mkmf.log 2>/dev/null | tail -30
        fi
        cd ${MSF_DIR}
    else
        echo "nokogiri.so OK: $(file $NOKO_LIB_SO)"
    fi
else
    echo "WARN: nokogiri gem non trovata"
fi

# ============================================================
# FASE 5.6: Crea gem.build_complete markers
# ============================================================
echo ""
echo "=== FASE 5.6: Extension markers ==="
TARGET_ARCH="aarch64-linux-android-android"
EXT_BASE="vendor/bundle/ruby/${RUBY_VER_DIR}/extensions/${TARGET_ARCH}/${RUBY_VER_DIR}"
MARKER_COUNT=0
for gemdir in ${GEM_BASE}/*/; do
    [ -d "${gemdir}ext" ] || continue
    gemname=$(basename "$gemdir")
    result=$(cat /tmp/gem_${gemname} 2>/dev/null || echo "UNKNOWN")
    # Crea marker anche per UNKNOWN (gem con ext opzionali come concurrent-ruby)
    mkdir -p "${EXT_BASE}/${gemname}"
    touch "${EXT_BASE}/${gemname}/gem.build_complete"
    MARKER_COUNT=$((MARKER_COUNT+1))
    # Copia .so aarch64 nella extensions dir
    find "${gemdir}ext" -name "*.so" 2>/dev/null | while read so; do
        if file "$so" | grep -q "aarch64"; then
            cp -f "$so" "${EXT_BASE}/${gemname}/"
        fi
    done
done
echo "Markers: ${MARKER_COUNT}"

# Crea symlink per extension_api_version (Ruby usa "3.3.0-static")
EXT_ARCH_DIR="${MSF_DIR}/vendor/bundle/ruby/${RUBY_VER_DIR}/extensions/${TARGET_ARCH}"
if [ -d "${EXT_ARCH_DIR}" ]; then
    cd "${EXT_ARCH_DIR}"
    [ -d "${RUBY_VER_DIR}" ] && [ ! -e "${RUBY_VER_DIR}-static" ] && \
        ln -s "${RUBY_VER_DIR}" "${RUBY_VER_DIR}-static"
fi
# Symlink per Gem::Platform.local (potrebbe essere "aarch64-linux" senza "-android")
EXT_DIR="${MSF_DIR}/vendor/bundle/ruby/${RUBY_VER_DIR}/extensions"
if [ -d "${EXT_DIR}" ]; then
    cd "${EXT_DIR}"
    [ -d "${TARGET_ARCH}" ] && [ ! -e "aarch64-linux" ] && \
        ln -s "${TARGET_ARCH}" "aarch64-linux"
fi
cd ${MSF_DIR}

set -e

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
    result=$(cat /tmp/gem_${gemname} 2>/dev/null || echo "UNKNOWN")
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

# ============================================================
# FASE 6: Pacchettizza
# ============================================================
echo ""
echo "=== FASE 6: Pacchettizzazione ==="

# Ripristina RbConfig host
cp ${RBCONFIG_HOST}.bak ${RBCONFIG_HOST}

mkdir -p ${OUTPUT}

# MSF
rm -rf ${OUTPUT}/metasploit-framework
cp -a ${MSF_DIR}/. ${OUTPUT}/metasploit-framework/
rm -rf ${OUTPUT}/metasploit-framework/.git \
       ${OUTPUT}/metasploit-framework/spec \
       ${OUTPUT}/metasploit-framework/test \
       ${OUTPUT}/metasploit-framework/documentation
find ${OUTPUT}/metasploit-framework/vendor/bundle -path "*/extensions/x86_64*" -type d -exec rm -rf {} + 2>/dev/null || true

# Copia libpq.so.5 per il device
if [ -n "$PQ_SO" ]; then
    cp "$PQ_SO" ${OUTPUT}/libpq.so.5
fi

echo "MSF: $(find ${OUTPUT}/metasploit-framework -type f | wc -l) files, $(du -sh ${OUTPUT}/metasploit-framework | cut -f1)"

# Ensure all output files are world-readable (some gems create 600 archives)
chmod -R a+r ${OUTPUT}

echo ""
echo "============================================"
echo "  DONE — $(date -u +%Y-%m-%dT%H:%M:%S)"
echo "============================================"
