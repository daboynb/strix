#!/bin/bash
source "$(dirname "$0")/../env.sh"

echo ""
echo "=== Building libgcrypt ${GCRYPT_VERSION} ==="
cd /opt/src/libgcrypt-${GCRYPT_VERSION}

[ -f Makefile ] && make distclean 2>/dev/null || true

export CFLAGS="-fPIC -O2 -I${SYSROOT}/include"
export LDFLAGS="-fPIE -pie -static-libstdc++ -L${SYSROOT}/lib"

./configure \
  --host=${TARGET} \
  --prefix=${SYSROOT} \
  --disable-shared \
  --enable-static \
  --disable-doc \
  --disable-asm \
  --with-libgpg-error-prefix=${SYSROOT} \
  2>&1

make -j$(nproc) 2>&1
make install 2>&1

export CFLAGS="-fPIC -O2"
export LDFLAGS="-fPIE -pie -static-libstdc++"

echo "=== libgcrypt installed to ${SYSROOT} ==="
ls -lh ${SYSROOT}/lib/libgcrypt.a 2>/dev/null
