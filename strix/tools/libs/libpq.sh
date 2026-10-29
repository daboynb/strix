#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/../env.sh"

echo ""
echo "=== Building libpq from PostgreSQL ${POSTGRESQL_VERSION} ==="
cd /opt/src/postgresql-${POSTGRESQL_VERSION}


export CFLAGS="-fPIC -O2 -I${SYSROOT}/include"
export LDFLAGS="-fPIE -pie -static-libstdc++ -L${SYSROOT}/lib"
export CPPFLAGS="-I${SYSROOT}/include"

# PostgreSQL configure needs pgac_cv overrides for cross-compilation
./configure \
  --host=${TARGET} \
  --prefix=${SYSROOT} \
  --without-readline \
  --without-zlib \
  --with-openssl \
  --without-icu \
  pgac_cv_snprintf_long_long_int_modifier="%lld" \
  pgac_cv_snprintf_size_t_support=yes \
  2>&1

# Build only libpq (client library) — not the full server
cd src/interfaces/libpq
# libpq's "must not call exit" check flags pthread_exit (pulled in by the
# Android libc); upstream master whitelists it (libpq_check.pl), backport that.
sed -i 's/grep -v __cxa_atexit | grep exit/grep -v -e __cxa_atexit -e pthread_exit | grep exit/' Makefile
grep -q 'pthread_exit | grep exit' Makefile
make -j$(nproc) 2>&1
make install 2>&1
# make install only installs headers/shared libs — manually copy static lib
cp libpq.a ${SYSROOT}/lib/
# The bundle links libpq statically (only the tools' own .so files are shipped);
# with the shared library in the sysroot the linker would pick libpq.so.5 and
# hydra would need a library that isn't on the device.
rm -f ${SYSROOT}/lib/libpq.so*

# Also install common headers needed by libpq-fe.h
cd /opt/src/postgresql-${POSTGRESQL_VERSION}/src/include
make install 2>&1

# Build and install libpgport + libpgcommon (needed for static linking)
cd /opt/src/postgresql-${POSTGRESQL_VERSION}/src/port
make -j$(nproc) 2>&1
make install 2>&1
cp libpgport.a ${SYSROOT}/lib/

cd /opt/src/postgresql-${POSTGRESQL_VERSION}/src/common
make -j$(nproc) 2>&1
make install 2>&1
cp libpgcommon.a ${SYSROOT}/lib/

export CFLAGS="-fPIC -O2"
export LDFLAGS="-fPIE -pie -static-libstdc++"
unset CPPFLAGS

echo "=== libpq installed to ${SYSROOT} ==="
ls -lh ${SYSROOT}/lib/libpq.a ${SYSROOT}/lib/libpgport.a ${SYSROOT}/lib/libpgcommon.a
