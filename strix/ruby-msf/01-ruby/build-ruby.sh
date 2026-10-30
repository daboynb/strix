#!/bin/bash
# ============================================================
# Cross-compilazione Ruby 3.3 + dipendenze per aarch64-linux-android
#
# Output:
#   /opt/ruby-android  — Ruby cross-compilato (binario + stdlib + ext)
#   /opt/ruby-host     — Ruby host (x86_64, serve per bundle install)
#   /opt/android-deps  — Librerie statiche cross-compilate
#
# Runs at image-build time (see ../Dockerfile, stage "ruby"); versions and
# checksums come from strix/versions.env via build args. Any failure aborts.
# ============================================================

set -euo pipefail
: "${ANDROID_NDK_HOME:?}" "${API_LEVEL:?}" "${RUBY_VERSION:?}" "${OPENSSL_VERSION:?}" \
  "${ZLIB_VERSION:?}" "${YAML_VERSION:?}" "${LIBFFI_VERSION:?}"

# Download + verify + extract a source tarball into /tmp
fetch_src() { # <url> <sha256> [<keyring> <signature-url>]
    local file
    file="/tmp/$(basename "$1")"
    strix-fetch "$1" "$2" "$file" "${@:3}"
    tar xf "$file" -C /tmp
    rm -f "$file"
}

RUBY_SRC=/opt/ruby-src
NDK=${ANDROID_NDK_HOME}
TOOLCHAIN=${NDK}/toolchains/llvm/prebuilt/linux-x86_64
TARGET=aarch64-linux-android
API=${API_LEVEL}
PREFIX=/opt/ruby-android
HOST_RUBY=/opt/ruby-host
DEPS=/opt/android-deps
OUTPUT=/output

export ANDROID_NDK_ROOT=${NDK}
export PATH=${TOOLCHAIN}/bin:$PATH

echo "============================================"
echo "  RUBY ANDROID CROSS-COMPILATION"
echo "  Ruby: ${RUBY_VERSION} | NDK: ${NDK_VERSION}"
echo "  Target: ${TARGET}${API}"
echo "============================================"

# ============================================================
# FASE 1: Build Ruby host (x86_64)
# ============================================================
echo ""
echo "=== FASE 1: Ruby host ==="
cd ${RUBY_SRC}
./configure --prefix=${HOST_RUBY} --disable-install-doc
make -j$(nproc)
make install
echo "PASS: $(${HOST_RUBY}/bin/ruby --version)"

# ============================================================
# FASE 2: Cross-compile dipendenze (OpenSSL, zlib, libyaml, libffi)
# ============================================================
echo ""
echo "=== FASE 2: Dipendenze ==="

export CC="${TOOLCHAIN}/bin/${TARGET}${API}-clang"
export CXX="${TOOLCHAIN}/bin/${TARGET}${API}-clang++"
export AR="${TOOLCHAIN}/bin/llvm-ar"
export RANLIB="${TOOLCHAIN}/bin/llvm-ranlib"
export STRIP="${TOOLCHAIN}/bin/llvm-strip"

mkdir -p ${DEPS}

# OpenSSL
echo "--- OpenSSL ${OPENSSL_VERSION} ---"
fetch_src "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" "${OPENSSL_SHA256}" \
    openssl "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz.asc"
cd /tmp/openssl-${OPENSSL_VERSION}
./Configure android-arm64 --prefix=${DEPS} -D__ANDROID_API__=${API} no-shared no-tests enable-legacy
make -j$(nproc)
make install_sw
# OpenSSL mette in lib64 su alcune piattaforme
if [ -d ${DEPS}/lib64 ] && [ ! -f ${DEPS}/lib/libssl.a ]; then
    mkdir -p ${DEPS}/lib
    cp -a ${DEPS}/lib64/* ${DEPS}/lib/
fi
[ -f ${DEPS}/lib/libssl.a ] || { echo "FAIL: OpenSSL"; exit 1; }
echo "PASS: OpenSSL"

# zlib
echo "--- zlib ${ZLIB_VERSION} ---"
fetch_src "https://github.com/madler/zlib/releases/download/v${ZLIB_VERSION}/zlib-${ZLIB_VERSION}.tar.gz" "${ZLIB_SHA256}" \
    zlib "https://github.com/madler/zlib/releases/download/v${ZLIB_VERSION}/zlib-${ZLIB_VERSION}.tar.gz.asc"
cd /tmp/zlib-${ZLIB_VERSION}
CHOST=${TARGET} CC="$CC" AR="$AR" RANLIB="$RANLIB" CFLAGS="-fPIC -O2" \
./configure --prefix=${DEPS} --static
make -j$(nproc)
make install
[ -f ${DEPS}/lib/libz.a ] || { echo "FAIL: zlib"; exit 1; }
echo "PASS: zlib"

# libyaml
echo "--- libyaml ${YAML_VERSION} ---"
fetch_src "https://github.com/yaml/libyaml/releases/download/${YAML_VERSION}/yaml-${YAML_VERSION}.tar.gz" "${YAML_SHA256}"
cd /tmp/yaml-${YAML_VERSION}
CC="$CC" AR="$AR" RANLIB="$RANLIB" CFLAGS="-fPIC -O2" \
./configure --host=${TARGET} --prefix=${DEPS} --enable-static --disable-shared
make -j$(nproc)
make install
[ -f ${DEPS}/lib/libyaml.a ] || { echo "FAIL: libyaml"; exit 1; }
echo "PASS: libyaml"

# libffi
echo "--- libffi ${LIBFFI_VERSION} ---"
fetch_src "https://github.com/libffi/libffi/releases/download/v${LIBFFI_VERSION}/libffi-${LIBFFI_VERSION}.tar.gz" "${LIBFFI_SHA256}"
cd /tmp/libffi-${LIBFFI_VERSION}
CC="$CC" CXX="$CXX" AR="$AR" RANLIB="$RANLIB" CFLAGS="-fPIC -O2" \
./configure --host=${TARGET} --prefix=${DEPS} --enable-static --disable-shared
make -j$(nproc)
make install
[ -f ${DEPS}/lib/libffi.a ] || { echo "FAIL: libffi"; exit 1; }
echo "PASS: libffi"

echo ""
echo "Dipendenze: $(ls ${DEPS}/lib/*.a | wc -l) librerie statiche"

# ============================================================
# FASE 3: Cross-compile Ruby con tutte le ext
# ============================================================
echo ""
echo "=== FASE 3: Ruby cross-compile ==="
cd ${RUBY_SRC}
# Reset the tree after the host build so the cross configure starts clean
make distclean

export CFLAGS="-fPIC -O2 -I${DEPS}/include"
export CXXFLAGS="-fPIC -O2 -I${DEPS}/include"
export LDFLAGS="-lm -llog -L${DEPS}/lib"
export PKG_CONFIG_PATH="${DEPS}/lib/pkgconfig"

./configure \
    --host=${TARGET} \
    --target=${TARGET} \
    --prefix=${PREFIX} \
    --enable-load-relative \
    --with-baseruby=${HOST_RUBY}/bin/ruby \
    --disable-install-doc \
    --disable-jit-support \
    --without-gmp \
    --with-static-linked-ext \
    --with-openssl-dir=${DEPS} \
    --with-libffi-dir=${DEPS} \
    --with-zlib-dir=${DEPS} \
    --with-libyaml-dir=${DEPS} \
    --with-out-ext=readline,dbm,gdbm,sdbm \
    ac_cv_func_setpgrp_void=yes \
    ac_cv_func_flock=yes

make -j$(nproc)
rm -rf /tmp/ruby-install
make install DESTDIR=/tmp/ruby-install

RUBY_BIN=/tmp/ruby-install${PREFIX}/bin/ruby
[ -f "$RUBY_BIN" ] || { echo "FAIL: ${RUBY_BIN} not installed"; exit 1; }
file "$RUBY_BIN" | grep -q "aarch64" || { echo "FAIL: not aarch64: $(file "$RUBY_BIN")"; exit 1; }
echo "PASS: $(file "$RUBY_BIN" | cut -d: -f2)"

# Load paths resolved from the binary's location at run time: the app installs
# Ruby under its own filesDir, not ${PREFIX}, and without this needs RUBYLIB,
# which puts the stdlib ahead of the bundled gems (stdlib json 2.7 shadowing
# the json gem Metasploit's Gemfile.lock pins).
RBCONFIG=$(find /tmp/ruby-install${PREFIX}/lib/ruby -name rbconfig.rb | head -1)
grep -q 'CONFIG\["LIBRUBY_RELATIVE"\] = "yes"' "$RBCONFIG" \
    || { echo "FAIL: ruby not built with load-relative paths ($RBCONFIG)"; exit 1; }
grep -rq '^#define LOAD_RELATIVE 1' .ext/include \
    || { echo "FAIL: LOAD_RELATIVE not defined in .ext/include/*/ruby/config.h (dladdr missing?)"; exit 1; }
echo "PASS: load-relative"

# ============================================================
# FASE 4: Verifica ext critiche
# ============================================================
echo ""
echo "=== FASE 4: Verifica ext ==="
EXT_OK=0
for ext_name in openssl fiddle zlib psych socket; do
    if grep -qi "Init_${ext_name}" ext/extinit.c 2>/dev/null; then
        echo "  ${ext_name}: OK (static-linked)"
        EXT_OK=$((EXT_OK+1))
    else
        echo "  ${ext_name}: MISSING"
    fi
done
echo "Ext: ${EXT_OK}/5"
[ "${EXT_OK}" -eq 5 ] || { echo "FAIL: critical static extensions missing"; exit 1; }

# ============================================================
# FASE 5: Pacchettizza output
# ============================================================
echo ""
echo "=== FASE 5: Output ==="
# Fresh output: cp -a into an existing dir would nest (ruby-android/ruby-android)
rm -rf ${OUTPUT}
mkdir -p ${OUTPUT}

# Ruby cross-compilato
cp -a /tmp/ruby-install${PREFIX} ${OUTPUT}/ruby-android
# Ruby host (serve per bundle install nella fase 2)
cp -a ${HOST_RUBY} ${OUTPUT}/ruby-host
# Dipendenze (servono per cross-compilare le gem native)
cp -a ${DEPS} ${OUTPUT}/android-deps

echo "ruby-android: $(find ${OUTPUT}/ruby-android -type f | wc -l) files, $(du -sh ${OUTPUT}/ruby-android | cut -f1)"
echo "ruby-host:    $(find ${OUTPUT}/ruby-host -type f | wc -l) files, $(du -sh ${OUTPUT}/ruby-host | cut -f1)"
echo "android-deps: $(ls ${OUTPUT}/android-deps/lib/*.a | wc -l) static libs"
file ${OUTPUT}/ruby-android/bin/ruby

echo ""
echo "============================================"
echo "  DONE — $(date -u +%Y-%m-%dT%H:%M:%S)"
echo "============================================"
