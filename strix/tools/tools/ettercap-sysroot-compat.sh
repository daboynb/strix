#!/bin/bash
# Sourced by ettercap.sh (same shell: inherits set -euo pipefail, env.sh vars, cwd).
set -euo pipefail
# Sysroot/toolchain compatibility for the Android NDK: pthread-cancel + malloc
# compat header, empty libresolv/libdl stubs, libm copied into SYSROOT.

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
