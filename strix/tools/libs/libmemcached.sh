#!/bin/bash
source "$(dirname "$0")/../env.sh"

echo ""
echo "=== Building libmemcached ${LIBMEMCACHED_VERSION} ==="
cd /opt/src/libmemcached-${LIBMEMCACHED_VERSION}

[ -f Makefile ] && make distclean 2>/dev/null || true

# Android NDK deprecated index() — use strchr instead.
# Also fix rpl_malloc/rpl_realloc autotools cross-compilation issue.
export CFLAGS="-fPIC -O2 -I${SYSROOT}/include -Dindex=strchr -Drindex=strrchr"
export CXXFLAGS="-fPIC -O2 -I${SYSROOT}/include -Dindex=strchr -Drindex=strrchr"
export LDFLAGS="-fPIE -pie -static-libstdc++ -L${SYSROOT}/lib"

./configure \
  --host=${TARGET} \
  --prefix=${SYSROOT} \
  --disable-shared \
  --enable-static \
  --disable-sasl \
  --without-memcached \
  ac_cv_func_malloc_0_nonnull=yes \
  ac_cv_func_realloc_0_nonnull=yes \
  2>&1

make -j$(nproc) 2>&1 || {
  cd libmemcached
  make -j$(nproc) 2>&1
  cd ..
}
make install 2>&1 || {
  cp libmemcached/.libs/libmemcached.a ${SYSROOT}/lib/ 2>/dev/null || true
  cp -r libmemcached-1.0 ${SYSROOT}/include/ 2>/dev/null || true
  mkdir -p ${SYSROOT}/include/libmemcached
  cp libmemcached/*.h ${SYSROOT}/include/libmemcached/ 2>/dev/null || true
}
# Also copy libhashkit + libmemcachedutil headers — needed by libmemcached's public API
for subdir in libhashkit-1.0 libhashkit libmemcachedutil-1.0; do
  if [ -d "$subdir" ]; then
    mkdir -p ${SYSROOT}/include/$subdir
    cp $subdir/*.h ${SYSROOT}/include/$subdir/ 2>/dev/null || true
  fi
done
# hashkit.h includes need the hashkit-1.0 directory name
if [ ! -d ${SYSROOT}/include/libhashkit-1.0 ] && [ -d libhashkit ]; then
  mkdir -p ${SYSROOT}/include/libhashkit-1.0
  cp libhashkit/*.h ${SYSROOT}/include/libhashkit-1.0/ 2>/dev/null || true
  # Also copy the top-level header
  cp libhashkit-1.0/hashkit.h ${SYSROOT}/include/libhashkit-1.0/ 2>/dev/null || true
fi

export CFLAGS="-fPIC -O2"
export CXXFLAGS="-fPIC -O2"
export LDFLAGS="-fPIE -pie -static-libstdc++"

echo "=== libmemcached installed to ${SYSROOT} ==="
ls -lh ${SYSROOT}/lib/libmemcached.a 2>/dev/null
