#!/bin/bash
source "$(dirname "$0")/../env.sh"

echo ""
echo "=== Building curl ${CURL_VERSION} ==="
cd /opt/src/curl-${CURL_VERSION}

[ -f Makefile ] && make distclean 2>/dev/null || true

export CFLAGS="-fPIC -O2 -I${SYSROOT}/include"
export LDFLAGS="-fPIE -pie -static-libstdc++ -L${SYSROOT}/lib"
export CPPFLAGS="-I${SYSROOT}/include"
export PKG_CONFIG_PATH="${SYSROOT}/lib/pkgconfig"

./configure \
  --host=${TARGET} \
  --prefix=${SYSROOT} \
  --with-openssl=${SYSROOT} \
  --disable-shared \
  --enable-static \
  --disable-manual \
  --disable-ldap \
  --disable-ldaps \
  --disable-dict \
  --disable-gopher \
  --disable-imap \
  --disable-pop3 \
  --disable-smtp \
  --disable-telnet \
  --disable-tftp \
  --disable-rtsp \
  --without-libpsl \
  --without-brotli \
  --without-zstd \
  --without-nghttp2 \
  --with-zlib="${TOOLCHAIN}/sysroot/usr" \
  2>&1

make -j$(nproc) 2>&1
make install 2>&1

# Reset flags
export CFLAGS="-fPIC -O2"
export LDFLAGS="-fPIE -pie -static-libstdc++"
unset CPPFLAGS PKG_CONFIG_PATH

echo "=== curl installed to ${SYSROOT} ==="
