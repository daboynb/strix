#!/bin/bash
# ============================================================
# Cross-compilazione Ruby 3.3 + dipendenze per aarch64-linux-android
#
# Output:
#   /opt/ruby-android  — Ruby cross-compilato (binario + stdlib + ext)
#   /opt/ruby-host     — Ruby host (x86_64, serve per bundle install)
#   /opt/android-deps  — Librerie statiche cross-compilate
#
# Verifica in 6 fasi con PASS/FAIL per ogni step.
# ============================================================

set -e

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
./configure --prefix=${HOST_RUBY} --disable-install-doc 2>&1 | tail -2
make -j$(nproc) 2>&1 | tail -2
make install 2>&1 | tail -2
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

# OpenSSL 3.2.1
echo "--- OpenSSL ---"
cd /tmp
wget -q https://github.com/openssl/openssl/releases/download/openssl-3.2.1/openssl-3.2.1.tar.gz
tar xzf openssl-3.2.1.tar.gz && cd openssl-3.2.1
./Configure android-arm64 --prefix=${DEPS} -D__ANDROID_API__=${API} no-shared no-tests enable-legacy 2>&1 | tail -1
make -j$(nproc) 2>&1 | tail -1
make install_sw 2>&1 | tail -1
# OpenSSL mette in lib64 su alcune piattaforme
[ -d ${DEPS}/lib64 ] && [ ! -f ${DEPS}/lib/libssl.a ] && cp -a ${DEPS}/lib64/* ${DEPS}/lib/
[ -f ${DEPS}/lib/libssl.a ] && echo "PASS: OpenSSL" || { echo "FAIL: OpenSSL"; exit 1; }

# zlib 1.3.1
echo "--- zlib ---"
cd /tmp
wget -q https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz
tar xzf zlib-1.3.1.tar.gz && cd zlib-1.3.1
CHOST=${TARGET} CC="$CC" AR="$AR" RANLIB="$RANLIB" CFLAGS="-fPIC -O2" \
./configure --prefix=${DEPS} --static 2>&1 | tail -1
make -j$(nproc) 2>&1 | tail -1 && make install 2>&1 | tail -1
[ -f ${DEPS}/lib/libz.a ] && echo "PASS: zlib" || { echo "FAIL: zlib"; exit 1; }

# libyaml 0.2.5
echo "--- libyaml ---"
cd /tmp
wget -q https://github.com/yaml/libyaml/releases/download/0.2.5/yaml-0.2.5.tar.gz
tar xzf yaml-0.2.5.tar.gz && cd yaml-0.2.5
CC="$CC" AR="$AR" RANLIB="$RANLIB" CFLAGS="-fPIC -O2" \
./configure --host=${TARGET} --prefix=${DEPS} --enable-static --disable-shared 2>&1 | tail -1
make -j$(nproc) 2>&1 | tail -1 && make install 2>&1 | tail -1
[ -f ${DEPS}/lib/libyaml.a ] && echo "PASS: libyaml" || { echo "FAIL: libyaml"; exit 1; }

# libffi 3.4.6
echo "--- libffi ---"
cd /tmp
wget -q https://github.com/libffi/libffi/releases/download/v3.4.6/libffi-3.4.6.tar.gz
tar xzf libffi-3.4.6.tar.gz && cd libffi-3.4.6
CC="$CC" CXX="$CXX" AR="$AR" RANLIB="$RANLIB" CFLAGS="-fPIC -O2" \
./configure --host=${TARGET} --prefix=${DEPS} --enable-static --disable-shared 2>&1 | tail -1
make -j$(nproc) 2>&1 | tail -1 && make install 2>&1 | tail -1
[ -f ${DEPS}/lib/libffi.a ] && echo "PASS: libffi" || { echo "FAIL: libffi"; exit 1; }

echo ""
echo "Dipendenze: $(ls ${DEPS}/lib/*.a | wc -l) librerie statiche"

# ============================================================
# FASE 3: Cross-compile Ruby con tutte le ext
# ============================================================
echo ""
echo "=== FASE 3: Ruby cross-compile ==="
cd ${RUBY_SRC}
make clean 2>/dev/null; make distclean 2>/dev/null; true

export CFLAGS="-fPIC -O2 -I${DEPS}/include"
export CXXFLAGS="-fPIC -O2 -I${DEPS}/include"
export LDFLAGS="-lm -llog -L${DEPS}/lib"
export PKG_CONFIG_PATH="${DEPS}/lib/pkgconfig"

./configure \
    --host=${TARGET} \
    --target=${TARGET} \
    --prefix=${PREFIX} \
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
    ac_cv_func_flock=yes \
    2>&1 | tail -5

make -j$(nproc) 2>&1 | tail -5
make install DESTDIR=/tmp/ruby-install 2>&1 | tail -3

RUBY_BIN=$(find /tmp/ruby-install -name "ruby" -type f | head -1)
file "$RUBY_BIN" | grep -q "aarch64" && echo "PASS: $(file $RUBY_BIN | cut -d: -f2)" || { echo "FAIL: not aarch64"; exit 1; }

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

# ============================================================
# FASE 5: Pacchettizza output
# ============================================================
echo ""
echo "=== FASE 5: Output ==="
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
