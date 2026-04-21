#!/bin/bash
source "$(dirname "$0")/../env.sh"

echo ""
echo "=== Building libssh2 ${LIBSSH2_VERSION} ==="
cd /opt/src/libssh2-${LIBSSH2_VERSION}

[ -f Makefile ] && make distclean 2>/dev/null || true

export CFLAGS="-fPIC -O2 -I${SYSROOT}/include"
export LDFLAGS="-fPIE -pie -static-libstdc++ -L${SYSROOT}/lib"

./configure \
  --host=${TARGET} \
  --prefix=${SYSROOT} \
  --disable-shared \
  --enable-static \
  --with-libssl-prefix=${SYSROOT} \
  --with-crypto=openssl \
  --disable-examples-build \
  2>&1

make -j$(nproc) 2>&1
make install 2>&1

# Reset flags
export CFLAGS="-fPIC -O2"
export LDFLAGS="-fPIE -pie -static-libstdc++"

echo "=== libssh2 installed to ${SYSROOT} ==="
ls -lh ${SYSROOT}/lib/libssh2.a 2>/dev/null
