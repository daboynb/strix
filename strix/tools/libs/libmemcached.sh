#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/../env.sh"

echo ""
echo "=== Building libmemcached ${LIBMEMCACHED_VERSION} ==="
cd /opt/src/libmemcached-${LIBMEMCACHED_VERSION}


# Android NDK deprecated index() — use strchr instead.
# Also fix rpl_malloc/rpl_realloc autotools cross-compilation issue.
export CFLAGS="-fPIC -O2 -I${SYSROOT}/include -Dindex=strchr -Drindex=strrchr"
export CXXFLAGS="-fPIC -O2 -I${SYSROOT}/include -Dindex=strchr -Drindex=strrchr"
export LDFLAGS="-fPIE -pie -static-libstdc++ -L${SYSROOT}/lib"

# SASL is required: hydra's memcached module authenticates only via SASL
# (memcached_set_sasl_auth_data). libsasl2.a is static (cyrus-sasl.sh) and needs
# libcrypto + libdl, which configure's link probe for -lsasl2 must see too.
export LIBSASL_CPPFLAGS="-I${SYSROOT}/include"
export LIBSASL_LDFLAGS="-L${SYSROOT}/lib"
export LIBS="-lcrypto -ldl"

./configure \
  --host=${TARGET} \
  --prefix=${SYSROOT} \
  --disable-shared \
  --enable-static \
  --enable-sasl \
  --without-memcached \
  ac_cv_func_malloc_0_nonnull=yes \
  ac_cv_func_realloc_0_nonnull=yes \
  2>&1

# memflush.cc compares a char* with false, which current clang rejects;
# compare with NULL as intended (same fix as the maintained fork).
sed -i 's/if (opt_servers == false)/if (opt_servers == NULL)/' clients/memflush.cc
if grep -q 'opt_servers == false' clients/memflush.cc; then echo 'memflush.cc patch did not apply' >&2; exit 1; fi

make -j$(nproc) 2>&1
make install 2>&1

# configure only warns when the SASL probe fails; the installed header must say SASL
if ! grep -q '^#define LIBMEMCACHED_WITH_SASL_SUPPORT 1' "${SYSROOT}/include/libmemcached-1.0/configure.h"; then
  echo "FAIL: libmemcached built without SASL support (see config.log)" >&2
  exit 1
fi
unset LIBSASL_CPPFLAGS LIBSASL_LDFLAGS LIBS

export CFLAGS="-fPIC -O2"
export CXXFLAGS="-fPIC -O2"
export LDFLAGS="-fPIE -pie -static-libstdc++"

echo "=== libmemcached installed to ${SYSROOT} ==="
ls -lh ${SYSROOT}/lib/libmemcached.a
ls -d ${SYSROOT}/include/libmemcached*
