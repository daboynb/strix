#!/bin/bash
source "$(dirname "$0")/../env.sh"

echo ""
echo "=== Building mariadb-connector-c ${MARIADB_VERSION} ==="
cd /opt/src/mariadb-connector-c-${MARIADB_VERSION}

rm -rf build && mkdir -p build && cd build

# Android NDK lacks 'ushort' typedef and treats -Werror flags strictly.
# Disable -Werror and define ushort.
cmake .. \
  -DCMAKE_SYSTEM_NAME=Linux \
  -DCMAKE_SYSTEM_PROCESSOR=aarch64 \
  -DCMAKE_C_COMPILER="${TOOLCHAIN}/bin/clang" \
  -DCMAKE_C_FLAGS="--target=${TARGET}${API} -fPIC -O2 -I${SYSROOT}/include -Dushort=uint16_t -Wno-error -Wno-deprecated-non-prototype -Wno-unused-command-line-argument" \
  -DCMAKE_EXE_LINKER_FLAGS="--target=${TARGET}${API} -L${SYSROOT}/lib -Wno-unused-command-line-argument" \
  -DCMAKE_SHARED_LINKER_FLAGS="--target=${TARGET}${API} -L${SYSROOT}/lib -Wno-unused-command-line-argument" \
  -DCMAKE_MODULE_LINKER_FLAGS="--target=${TARGET}${API} -L${SYSROOT}/lib -Wno-unused-command-line-argument" \
  -DCMAKE_AR="${TOOLCHAIN}/bin/llvm-ar" \
  -DCMAKE_RANLIB="${TOOLCHAIN}/bin/llvm-ranlib" \
  -DCMAKE_INSTALL_PREFIX=${SYSROOT} \
  -DCMAKE_FIND_ROOT_PATH="${SYSROOT}" \
  -DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY \
  -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY \
  -DWITH_SSL=OPENSSL \
  -DOPENSSL_ROOT_DIR="${SYSROOT}" \
  -DOPENSSL_INCLUDE_DIR="${SYSROOT}/include" \
  -DWITH_EXTERNAL_ZLIB=OFF \
  -DWITH_UNIT_TESTS=OFF \
  -DCLIENT_PLUGIN_DIALOG=STATIC \
  -DCLIENT_PLUGIN_MYSQL_CLEAR_PASSWORD=STATIC \
  -DCLIENT_PLUGIN_CACHING_SHA2_PASSWORD=STATIC \
  -DCLIENT_PLUGIN_SHA256_PASSWORD=STATIC \
  -DCLIENT_PLUGIN_AUTH_GSSAPI_CLIENT=OFF \
  -DCLIENT_PLUGIN_PVIO_NPIPE=OFF \
  -DCLIENT_PLUGIN_PVIO_SHMEM=OFF \
  2>&1

make -j$(nproc) 2>&1
make install 2>&1

# hydra expects libmysqlclient.a — create symlink from mariadb's libmariadb.a
if [ -f ${SYSROOT}/lib/mariadb/libmariadbclient.a ]; then
  cp ${SYSROOT}/lib/mariadb/libmariadbclient.a ${SYSROOT}/lib/libmysqlclient.a
  # Copy headers to standard location
  cp -r ${SYSROOT}/include/mariadb/* ${SYSROOT}/include/ 2>/dev/null || true
elif [ -f ${SYSROOT}/lib/libmariadbclient.a ]; then
  cp ${SYSROOT}/lib/libmariadbclient.a ${SYSROOT}/lib/libmysqlclient.a
fi

echo "=== mariadb-connector-c installed to ${SYSROOT} ==="
ls -lh ${SYSROOT}/lib/libmysqlclient.a 2>/dev/null
