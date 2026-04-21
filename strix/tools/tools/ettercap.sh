#!/bin/bash
source "$(dirname "$0")/../env.sh"

echo ""
echo "=== Building ettercap ${ETTERCAP_VERSION} ==="
cd /opt/src/ettercap-${ETTERCAP_VERSION}

# --- Patch 1: Android pthread cancellation compatibility ---
# Android bionic does NOT support POSIX thread cancellation at all.
# Missing: pthread_cancel, pthread_setcancelstate, pthread_setcanceltype,
#          pthread_testcancel (hidden behind availability guard),
#          PTHREAD_CANCEL_ENABLE/DISABLE/DEFERRED/ASYNCHRONOUS constants.
# Ettercap uses these in ec_threads.c, ec_ui.c, and via CANCELLATION_POINT() macro.
# Since thread cancellation is impossible on Android, all stubs are safe no-ops.
cat > /opt/src/android_pthread_cancel_compat.h << 'PTHREADEOF'
#ifndef _ANDROID_PTHREAD_CANCEL_COMPAT_H
#define _ANDROID_PTHREAD_CANCEL_COMPAT_H

#include <pthread.h>
#include <errno.h>

/* Android bionic lacks POSIX thread cancellation. Provide no-op stubs. */
#ifndef PTHREAD_CANCEL_ENABLE
#define PTHREAD_CANCEL_ENABLE  0
#endif
#ifndef PTHREAD_CANCEL_DISABLE
#define PTHREAD_CANCEL_DISABLE 1
#endif
#ifndef PTHREAD_CANCEL_DEFERRED
#define PTHREAD_CANCEL_DEFERRED 0
#endif
#ifndef PTHREAD_CANCEL_ASYNCHRONOUS
#define PTHREAD_CANCEL_ASYNCHRONOUS 1
#endif

static inline int pthread_cancel(pthread_t t) { (void)t; return ENOSYS; }
static inline int pthread_setcancelstate(int state, int *old) {
    if (old) *old = PTHREAD_CANCEL_DISABLE;
    (void)state;
    return 0;
}
static inline int pthread_setcanceltype(int type, int *old) {
    if (old) *old = PTHREAD_CANCEL_DEFERRED;
    (void)type;
    return 0;
}
#ifndef pthread_testcancel
static inline void pthread_testcancel(void) { }
#endif

/* Fix autotools cross-compilation: malloc(0)/realloc(0,n) test fails,
   generates rpl_malloc/rpl_realloc stubs that are never defined.
   Android bionic malloc(0) returns non-null, so wrapping is unnecessary.
   Use weak attribute to avoid duplicate symbol errors across TUs. */
#include <stdlib.h>
__attribute__((weak)) void *rpl_malloc(size_t n)  { return malloc(n ? n : 1);  }
__attribute__((weak)) void *rpl_realloc(void *p, size_t n) { return realloc(p, n ? n : 1); }

#endif /* _ANDROID_PTHREAD_CANCEL_COMPAT_H */
PTHREADEOF
echo "  Created Android pthread cancellation + malloc compat header"

# --- Patch 2: libresolv stub ---
# Android bionic includes resolver functions (res_query etc.) in libc.
# Ettercap's dns_spoof/mdns_spoof plugins link against -lresolv which
# doesn't exist as a separate library. Create an empty stub.
${AR} rcs ${SYSROOT}/lib/libresolv.a
echo "  Created empty libresolv.a stub (Android resolv is in libc)"

# --- Patch 3: libdl stub ---
# Android bionic includes dl* functions (dlopen, dlsym, etc.) in libc.
# Bundled LuaJIT's find_library(dl) fails without a separate libdl.
if [ ! -f "${SYSROOT}/lib/libdl.a" ]; then
  ${AR} rcs ${SYSROOT}/lib/libdl.a
  echo "  Created empty libdl.a stub (Android dl is in libc)"
fi

# --- Patch 4: libm ---
# Android NDK has libm in sysroot, but CMake FIND_ROOT_PATH doesn't reach it.
# Bundled LuaJIT's find_library(m) fails without this.
# NDK r27c: libm.a può essere in ${TARGET}/${API}/ o in ${TARGET}/ (senza API)
NDK_LIB_BASE="${TOOLCHAIN}/sysroot/usr/lib/${TARGET}"
NDK_LIBM=""
for candidate in "${NDK_LIB_BASE}/${API}/libm.a" "${NDK_LIB_BASE}/libm.a"; do
  if [ -f "$candidate" ]; then
    NDK_LIBM="$candidate"
    break
  fi
done
if [ -n "${NDK_LIBM}" ]; then
  cp -f "${NDK_LIBM}" "${SYSROOT}/lib/libm.a"
  echo "  Copied libm.a from ${NDK_LIBM} to ${SYSROOT}/lib/"
else
  echo "  WARNING: libm.a not found in NDK sysroot — ettercap/LuaJIT may fail"
  echo "  Searched: ${NDK_LIB_BASE}/${API}/libm.a and ${NDK_LIB_BASE}/libm.a"
  # List what's actually in those directories for debugging
  ls -la "${NDK_LIB_BASE}/${API}/"libm* "${NDK_LIB_BASE}/"libm* 2>/dev/null || true
fi

# --- Patch 5: Android L2 forwarding fallback ---
# Android restricts AF_INET+SOCK_RAW (LIBNET_RAW4_ADV init fails → lnet_IP4=NULL).
# ettercap's forward_unified_sniff() silently drops ALL IPv4 packets when
# lnet_IP4 is NULL, breaking -M arp forwarding entirely.
# Fix: fall back to L2 (AF_PACKET via send_to_L2) which works on Android.
cd /opt/src/ettercap-${ETTERCAP_VERSION}

# Replace the early-return on missing lnet_IP4/IP6 with L2 fallback
cat > src/ec_sniff_unified_android.patch << 'UNIFIEDEOF'
--- a/src/ec_sniff_unified.c
+++ b/src/ec_sniff_unified.c
@@ -105,13 +105,13 @@ void forward_unified_sniff(struct packet_object *po)
 {
-   /* if it was not initialized, no packet are forwardable */
+   int use_l2 = 0;
    switch(ntohs(po->L3.proto)) {
       case LL_TYPE_IP:
-         if(!EC_GBL_LNET->lnet_IP4)
-            return;
+         if(!EC_GBL_LNET->lnet_IP4)
+            use_l2 = 1;
          if(!(EC_GBL_IFACE->has_ipv4))
             return;
          break;
       case LL_TYPE_IP6:
-         if(!EC_GBL_LNET->lnet_IP6)
-            return;
+         if(!EC_GBL_LNET->lnet_IP6)
+            use_l2 = 1;
          if(!(EC_GBL_IFACE->has_ipv6))
             return;
          break;
@@ -132,7 +132,9 @@ void forward_unified_sniff(struct packet_object *po)

    /* don't forward dropped packets */
-   if ((po->flags & PO_DROPPED) == 0)
-      send_to_L3(po);
+   if ((po->flags & PO_DROPPED) == 0) {
+      if (use_l2)
+         send_to_L2(po);
+      else
+         send_to_L3(po);
+   }

     /*
UNIFIEDEOF
# Apply with sed as fallback if patch fails (format differences)
if ! patch -p1 --forward < src/ec_sniff_unified_android.patch 2>/dev/null; then
  echo "  Patch format failed, applying with sed..."
  # Replace the lnet_IP4 early-return with L2 fallback
  sed -i '/void forward_unified_sniff/,/^}/ {
    s/if(!EC_GBL_LNET->lnet_IP4)/if(!EC_GBL_LNET->lnet_IP4) { send_to_L2(po); return; } if(0)/
    s/if(!EC_GBL_LNET->lnet_IP6)/if(!EC_GBL_LNET->lnet_IP6) { send_to_L2(po); return; } if(0)/
  }' src/ec_sniff_unified.c
fi
rm -f src/ec_sniff_unified_android.patch
echo "  Applied Android L2 forwarding fallback patch"

# --- Patch 5b: send_to_L3 fallback to send_to_L2 on Android ---
# Same root cause as Patch 5: lnet_IP4 is NULL on Android (no AF_INET+SOCK_RAW).
# send_to_L3() is also used by plug-ins (notably dns_spoof's send_dns_reply),
# not just the unified forward path. Without this fallback, dns_spoof builds
# the fake reply but it never leaves the device because send_to_L3 returns
# early on l == NULL. The packet object already carries the correct L2 header
# (dst MAC = victim, src MAC = us) so send_to_L2 can ship it as-is.
perl -0777 -i -pe 's/if\(l == NULL\)\s*\n\s*return -E_NOTHANDLED;/if(l == NULL)\n      return send_to_L2(po);/g' src/ec_send.c
if grep -q "return send_to_L2(po);" src/ec_send.c; then
  echo "  Applied send_to_L3 → send_to_L2 fallback patch"
else
  echo "  WARNING: send_to_L3 patch not applied — dns_spoof replies may not leave the device"
fi

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

# Install binary — check multiple possible locations
ETTERCAP_BIN=""
for candidate in ettercap src/ettercap; do
  if [ -f "$candidate" ]; then
    ETTERCAP_BIN="$candidate"
    break
  fi
done

if [ -n "${ETTERCAP_BIN}" ]; then
  cp "${ETTERCAP_BIN}" ${PREFIX}/bin/
  ${STRIP} ${PREFIX}/bin/ettercap
  echo "=== ettercap installed ==="
  ls -lh ${PREFIX}/bin/ettercap
  # Verify it's statically linked (no libettercap.so dependency)
  readelf -d ${PREFIX}/bin/ettercap 2>/dev/null | grep NEEDED || true
else
  echo "WARNING: ettercap build failed — binary not found"
fi

# Copy shared libs (ettercap always builds as dynamic despite BUILD_SHARED_LIBS=OFF)
mkdir -p ${PREFIX}/lib
find . -name "libettercap*.so*" -type f | while read lib; do
  cp "$lib" ${PREFIX}/lib/
  echo "  Copied $(basename $lib) to ${PREFIX}/lib/"
done

# Create SONAME symlinks (ettercap binary links against libettercap.so.0, not .0.8.3.1)
cd ${PREFIX}/lib
for reallib in libettercap*.so.*.*.*; do
  [ -f "$reallib" ] || continue
  # Extract SONAME: libettercap.so.0.8.3.1 -> libettercap.so.0
  soname=$(echo "$reallib" | sed 's/\(\.so\.[0-9]*\)\..*/\1/')
  if [ "$soname" != "$reallib" ] && [ ! -e "$soname" ]; then
    ln -s "$reallib" "$soname"
    echo "  Created SONAME symlink: $soname -> $reallib"
  fi
done
cd -

# Copy ettercap plugins (ec_*.so — dns_spoof, find_ettercap, etc.)
mkdir -p ${PREFIX}/lib/ettercap
find . -name "ec_*.so" -type f | while read plugin; do
  cp "$plugin" ${PREFIX}/lib/ettercap/
  echo "  Copied plugin $(basename $plugin) to ${PREFIX}/lib/ettercap/"
done

# Copy data files — ettercap uses open_data("etc",...) for config/spoof files
# and open_data("share",...) for fingerprint/service data files.
# Path construction: INSTALL_SYSCONFDIR/ettercap/<file> and INSTALL_DATADIR/ettercap/<file>
mkdir -p ${PREFIX}/etc/ettercap ${PREFIX}/share/ettercap
cd /opt/src/ettercap-${ETTERCAP_VERSION}/share
# etter.conf doesn't exist as-is; CMake generates it from etter.conf.v4/v6
if [ -f etter.conf.v4 ]; then
  cp etter.conf.v4 ${PREFIX}/etc/ettercap/etter.conf
  echo "  Created etter.conf from etter.conf.v4"
fi
# Files loaded via open_data("etc",...) — go in etc/ettercap/
for f in etter.dns etter.mdns etter.nbns; do
  [ -f "$f" ] && cp "$f" ${PREFIX}/etc/ettercap/
done
# Files loaded via open_data("share",...) — go in share/ettercap/
for f in etter.fields etter.finger.os etter.finger.mac \
         etter.services etter.filter etter.filter.examples etter.filter.kill \
         etter.filter.ssh etter.mime etterfilter.cnt etterfilter.tbl; do
  [ -f "$f" ] && cp "$f" ${PREFIX}/share/ettercap/
done
echo "  Copied ettercap data files to ${PREFIX}/share/ettercap/"

# Reset flags
export CFLAGS="-fPIC -O2"
export LDFLAGS="-fPIE -pie -static-libstdc++"
unset PKG_CONFIG_PATH
