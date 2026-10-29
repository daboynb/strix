#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/../env.sh"
ETTERCAP_SCRIPTS="$(cd "$(dirname "$0")" && pwd)"

echo ""
echo "=== Building ettercap ${ETTERCAP_VERSION} ==="
cd /opt/src/ettercap-${ETTERCAP_VERSION}

source "${ETTERCAP_SCRIPTS}/ettercap-sysroot-compat.sh"

source "${ETTERCAP_SCRIPTS}/ettercap-source-patches.sh"

# INSTALL_PREFIX must match the runtime path on Android device
# ettercap hardcodes this path for etter.conf and plugin locations
ETTERCAP_RUNTIME_PREFIX="/data/data/org.csploit.strix/files/tools"

# Clean previous build
rm -rf build
mkdir -p build && cd build

# Create cmake toolchain file for Android NDK cross-compilation
cat > android-toolchain.cmake << TOOLEOF
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(CMAKE_CROSSCOMPILING TRUE)
set(CMAKE_C_COMPILER "${TOOLCHAIN}/bin/clang")
set(CMAKE_CXX_COMPILER "${TOOLCHAIN}/bin/clang++")
set(CMAKE_AR "${TOOLCHAIN}/bin/llvm-ar" CACHE FILEPATH "Archiver")
set(CMAKE_RANLIB "${TOOLCHAIN}/bin/llvm-ranlib" CACHE FILEPATH "Ranlib")
set(CMAKE_STRIP "${TOOLCHAIN}/bin/llvm-strip" CACHE FILEPATH "Strip")
set(CMAKE_C_FLAGS "--target=${TARGET}${API} -fPIC -O2 -I${SYSROOT}/include -include /opt/src/android_pthread_cancel_compat.h" CACHE STRING "C Flags")
set(CMAKE_EXE_LINKER_FLAGS "--target=${TARGET}${API} -fPIE -pie -static-libstdc++ -L${SYSROOT}/lib -Wl,-rpath,${ETTERCAP_RUNTIME_PREFIX}/lib" CACHE STRING "Linker Flags")
set(CMAKE_SHARED_LINKER_FLAGS "--target=${TARGET}${API} -L${SYSROOT}/lib -lrtmp -lssl -lcrypto -lz -Wl,-rpath,${ETTERCAP_RUNTIME_PREFIX}/lib" CACHE STRING "Shared Linker Flags")
set(CMAKE_MODULE_LINKER_FLAGS "--target=${TARGET}${API} -L${SYSROOT}/lib -lrtmp -lssl -lcrypto -lz -Wl,-rpath,${ETTERCAP_RUNTIME_PREFIX}/lib" CACHE STRING "Module Linker Flags")
set(CMAKE_SYSROOT "${TOOLCHAIN}/sysroot")
set(CMAKE_FIND_ROOT_PATH "${SYSROOT}" "${TOOLCHAIN}/sysroot/usr" "${TOOLCHAIN}/sysroot/usr/lib/${TARGET}/${API}" "${TOOLCHAIN}/sysroot/usr/lib/${TARGET}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_PREFIX_PATH "${SYSROOT}")
TOOLEOF

# Determine OpenSSL lib path (some builds put in lib64)
if [ -f "${SYSROOT}/lib/libssl.a" ]; then
  SSL_LIB_DIR="${SYSROOT}/lib"
elif [ -f "${SYSROOT}/lib64/libssl.a" ]; then
  SSL_LIB_DIR="${SYSROOT}/lib64"
else
  SSL_LIB_DIR="${SYSROOT}/lib"
fi

# Set PKG_CONFIG_PATH so cmake's find modules discover our cross-compiled libs
export PKG_CONFIG_PATH="${SYSROOT}/lib/pkgconfig:${TOOLCHAIN}/sysroot/usr/lib/aarch64-linux-android/pkgconfig"

cmake .. \
  -DCMAKE_TOOLCHAIN_FILE=android-toolchain.cmake \
  -DCMAKE_INSTALL_PREFIX=${ETTERCAP_RUNTIME_PREFIX} \
  -DENABLE_GTK=OFF \
  -DENABLE_CURSES=OFF \
  -DOPENSSL_ROOT_DIR="${SYSROOT}" \
  -DOPENSSL_INCLUDE_DIR="${SYSROOT}/include" \
  -DOPENSSL_CRYPTO_LIBRARY="${SSL_LIB_DIR}/libcrypto.a" \
  -DOPENSSL_SSL_LIBRARY="${SSL_LIB_DIR}/libssl.a" \
  -DENABLE_PLUGINS=ON \
  -DENABLE_GEOIP=ON \
  -DENABLE_IPV6=ON \
  -DENABLE_LUA=OFF \
  -DENABLE_PDF_DOCS=OFF \
  -DENABLE_TESTS=OFF \
  -DZLIB_LIBRARY="${TOOLCHAIN}/sysroot/usr/lib/aarch64-linux-android/libz.a" \
  -DZLIB_INCLUDE_DIR="${TOOLCHAIN}/sysroot/usr/include" \
  -DSYSTEM_CURL=ON \
  -DCURL_LIBRARY="${SYSROOT}/lib/libcurl.a" \
  -DCURL_INCLUDE_DIR="${SYSROOT}/include" \
  -DBUNDLED_LIBS=ON \
  -DBUILD_SHARED_LIBS=OFF \
  -DINSTALL_SYSCONFDIR="${ETTERCAP_RUNTIME_PREFIX}/etc" \
  -DINSTALL_DATADIR="${ETTERCAP_RUNTIME_PREFIX}/share" \
  -DGEOIP_LIBRARY="${SYSROOT}/lib/libGeoIP.a" \
  -DGEOIP_INCLUDE_DIR="${SYSROOT}/include" \
  2>&1

make -j$(nproc) 2>&1

source "${ETTERCAP_SCRIPTS}/ettercap-install.sh"

# Reset flags
export CFLAGS="-fPIC -O2"
export LDFLAGS="-fPIE -pie -static-libstdc++"
unset PKG_CONFIG_PATH
