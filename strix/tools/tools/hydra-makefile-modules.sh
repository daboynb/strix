#!/bin/bash
# Sourced by hydra.sh (same shell: inherits set -euo pipefail, env.sh vars, cwd).
set -euo pipefail
# Points the configure-generated Makefile at every module library found in SYSROOT.

# Force all module support — hydra configure can't cross-compile detection
# tests (ARM64 binary on x86 host). Patch Makefile variables based on
# which libraries were successfully cross-compiled to ${SYSROOT}.
if [ ! -f Makefile ]; then
  echo "FAIL: hydra configure did not generate a Makefile" >&2
  exit 1
fi
if [ -f Makefile ]; then
  # -DHAVE_MATH_H + -lm: hydra's configure can't find math.h when cross-
  # compiling (it greps SDK_PATH which we don't set). Without it, the brute
  # force generator (-x MIN:MAX:CHARSET) is compiled out and prints
  # "math.h is not found at compile time" at runtime.
  HYDRA_XDEFINES="-DLIBOPENSSL -DNO_RSA_LEGACY -DHAVE_MATH_H"
  HYDRA_XLIBS="-lssl -lcrypto -lm"
  HYDRA_XIPATHS="-I${SYSROOT}/include"
  HYDRA_XLIBPATHS="-L${SYSROOT}/lib"

  # SSH (libssh — NOT libssh2)
  if [ -f ${SYSROOT}/lib/libssh.a ]; then
    HYDRA_XDEFINES="$HYDRA_XDEFINES -DLIBSSH"
    HYDRA_XLIBS="-lssh $HYDRA_XLIBS"
    echo "  +ssh: libssh found"
  fi

  # PostgreSQL
  if [ -f ${SYSROOT}/lib/libpq.a ]; then
    HYDRA_XDEFINES="$HYDRA_XDEFINES -DLIBPOSTGRES"
    HYDRA_XLIBS="$HYDRA_XLIBS -lpq -lpgcommon -lpgport"
    if [ -d ${SYSROOT}/include/postgresql ]; then
      HYDRA_XIPATHS="$HYDRA_XIPATHS -I${SYSROOT}/include/postgresql"
    fi
    echo "  +postgres: libpq found"
  fi

  # PCRE2
  if [ -f ${SYSROOT}/lib/libpcre2-8.a ]; then
    HYDRA_XDEFINES="$HYDRA_XDEFINES -DHAVE_PCRE"
    HYDRA_XLIBS="$HYDRA_XLIBS -lpcre2-8"
    echo "  +pcre2: regex support enabled"
  fi

  # libgcrypt (radmin2)
  if [ -f ${SYSROOT}/lib/libgcrypt.a ]; then
    HYDRA_XDEFINES="$HYDRA_XDEFINES -DHAVE_GCRYPT"
    HYDRA_XLIBS="$HYDRA_XLIBS -lgcrypt -lgpg-error"
    echo "  +radmin2: libgcrypt found"
  fi

  # MySQL/MariaDB
  if [ -f ${SYSROOT}/lib/libmysqlclient.a ]; then
    HYDRA_XDEFINES="$HYDRA_XDEFINES -DLIBMYSQLCLIENT -DHAVE_MYSQL_H"
    HYDRA_XLIBS="$HYDRA_XLIBS -lmysqlclient"
    echo "  +mysql5: libmysqlclient found"
  fi

  # Memcached
  if [ -f ${SYSROOT}/lib/libmemcached.a ]; then
    HYDRA_XDEFINES="$HYDRA_XDEFINES -DLIBMCACHED"
    # libmemcached is C++: hydra links with the C driver, so pull in the
    # NDK's static C++ runtime explicitly (-static-libstdc++ only affects clang++).
    # libmemcached is built with SASL (the module authenticates only via SASL): static
    # libsasl2 follows it, then what libsasl2 needs (libcrypto again: static link order).
    if [ ! -f ${SYSROOT}/lib/libsasl2.a ]; then
      echo "FAIL: libmemcached present but libsasl2.a missing (cyrus-sasl.sh)" >&2
      exit 1
    fi
    HYDRA_XLIBS="$HYDRA_XLIBS -lmemcached -lsasl2 -lcrypto -ldl -lc++_static -lc++abi"
    # hydra includes <libmemcached/memcached.h>, already reachable via
    # -I${SYSROOT}/include. Don't add include/libmemcached-1.0: it ships its
    # own limits.h, which would shadow the libc one (INT_MAX undeclared).
    echo "  +memcached: libmemcached + libsasl2 found"
  fi

  # libidn (already compiled in previous stages)
  if [ -f ${SYSROOT}/lib/libidn.a ]; then
    HYDRA_XDEFINES="$HYDRA_XDEFINES -DLIBIDN -DHAVE_PR29_H"
    HYDRA_XLIBS="$HYDRA_XLIBS -lidn"
    echo "  +idn: unicode support enabled"
  fi

  sed -i "s|^XLIBS=.*|XLIBS=$HYDRA_XLIBS|" Makefile
  sed -i "s|^XLIBPATHS=.*|XLIBPATHS=$HYDRA_XLIBPATHS|" Makefile
  sed -i "s|^XIPATHS=.*|XIPATHS=$HYDRA_XIPATHS|" Makefile
  sed -i "s|^XDEFINES=.*|XDEFINES=$HYDRA_XDEFINES|" Makefile
  # Android NDK r27c fortified unistd.h uses SSIZE_MAX in compile-time checks.
  # SSIZE_MAX is defined in limits.h but hydra's SEC flags add -D_FORTIFY_SOURCE=2
  # which triggers the checks before limits.h definitions are visible.
  # Fix: define SSIZE_MAX as a numeric literal (0x7FFFFFFFFFFFFFFF for 64-bit).
  # Fix Android NDK header issues:
  # - SSIZE_MAX: NDK fortified unistd.h uses it in compile-time checks
  # - SCHAR_MIN/SCHAR_MAX: libbson headers need these from limits.h
  # - Include limits.h first to provide all required constants
  # Android NDK r27c: fortified unistd.h and third-party headers (libbson)
  # need limits.h constants (SSIZE_MAX, SCHAR_MIN, etc.) that aren't visible
  # due to NDK's conditional compilation guards.
  # Root cause: NDK limits.h wraps POSIX constants in #if conditions that
  # depend on __STDC_VERSION__ / _POSIX_C_SOURCE which hydra's build doesn't set.
  # Fix: force -std=gnu11 so all limits.h constants are defined, then
  # explicitly define SSIZE_MAX (not in C standard, only POSIX).
  # Android NDK r27c: fortified unistd.h needs SSIZE_MAX, and libbson headers
  # need all limits.h constants. Force __STDC_LIMIT_MACROS + include limits.h.
  sed -i "s|^OPTS=|OPTS=-D__STDC_LIMIT_MACROS -include limits.h -DSSIZE_MAX=0x7FFFFFFFFFFFFFFFL |" Makefile
  # Remove -D_FORTIFY_SOURCE=2 from SEC — causes compile-time assertions
  # that fail during cross-compilation
  sed -i 's|-D_FORTIFY_SOURCE=2||' Makefile
  echo "  Patched Makefile with all detected modules"
fi
