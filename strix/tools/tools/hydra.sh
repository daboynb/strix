#!/bin/bash
source "$(dirname "$0")/../env.sh"

echo ""
echo "=== Building hydra ${HYDRA_VERSION} ==="
cd /opt/src/thc-hydra-${HYDRA_VERSION}

[ -f Makefile ] && make distclean 2>/dev/null || true

# Hydra uses a custom configure that can't cross-compile SSL detection.
# The configure test tries to compile+run an OpenSSL program, which fails
# in cross-compilation (ARM64 binary on x86 host). We run configure first,
# then patch the Makefile to force SSL support with our cross-compiled OpenSSL.
# Android NDK fortified unistd.h needs SSIZE_MAX from limits.h
export CFLAGS="-fPIC -O2 -I${SYSROOT}/include -include limits.h"
export LDFLAGS="-fPIE -pie -static-libstdc++ -L${SYSROOT}/lib"
export CPPFLAGS="-I${SYSROOT}/include"

./configure \
  --prefix=${PREFIX} \
  --disable-xhydra \
  --with-ssl=${SYSROOT} \
  2>&1 || true

# Force all module support — hydra configure can't cross-compile detection
# tests (ARM64 binary on x86 host). Patch Makefile variables based on
# which libraries were successfully cross-compiled to ${SYSROOT}.
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
    HYDRA_XLIBS="$HYDRA_XLIBS -lmemcached"
    if [ -d ${SYSROOT}/include/libmemcached-1.0 ]; then
      HYDRA_XIPATHS="$HYDRA_XIPATHS -I${SYSROOT}/include/libmemcached-1.0"
    elif [ -d ${SYSROOT}/include/libmemcached ]; then
      HYDRA_XIPATHS="$HYDRA_XIPATHS -I${SYSROOT}/include/libmemcached"
    fi
    echo "  +memcached: libmemcached found"
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

# Patch hydra-ssh.c to negotiate legacy host-key + KEX algorithms.
# Modern libssh disables ssh-rsa/ssh-dss host keys and old DH KEXes by
# default, so hydra fails to even connect to vintage SSH servers
# ("kex error: no match for method server host key algo"). Re-enable them
# so SSH brute-forcing actually reaches the auth phase on legacy targets.
if [ -f hydra-ssh.c ] && ! grep -q "SSH_OPTIONS_HOSTKEYS" hydra-ssh.c; then
  perl -i -pe 's|(ssh_options_set\(session, SSH_OPTIONS_COMPRESSION_S_C, "none"\);)|\1\n    ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "ssh-ed25519,ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-dss");\n    ssh_options_set(session, SSH_OPTIONS_KEY_EXCHANGE, "curve25519-sha256,curve25519-sha256\@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1");\n    ssh_options_set(session, SSH_OPTIONS_HMAC_C_S, "hmac-sha2-512-etm\@openssh.com,hmac-sha2-256-etm\@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96");\n    ssh_options_set(session, SSH_OPTIONS_HMAC_S_C, "hmac-sha2-512-etm\@openssh.com,hmac-sha2-256-etm\@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96");\n    ssh_options_set(session, SSH_OPTIONS_CIPHERS_C_S, "chacha20-poly1305\@openssh.com,aes256-gcm\@openssh.com,aes128-gcm\@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,3des-cbc,blowfish-cbc");\n    ssh_options_set(session, SSH_OPTIONS_CIPHERS_S_C, "chacha20-poly1305\@openssh.com,aes256-gcm\@openssh.com,aes128-gcm\@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,3des-cbc,blowfish-cbc");|g' hydra-ssh.c
  echo "  Patched hydra-ssh.c with legacy SSH host-key + KEX + HMAC + cipher algorithms"
fi

# Patch hydra-mod.c to accept legacy TLS for every TLS-using module
# (https-*, ftps, smtps, imaps, pop3s, ldap-S, mssql, etc.).
# OpenSSL 3.x defaults reject SSLv3/TLSv1.0/1.1 and SECLEVEL=2 ciphers,
# so hydra can't even handshake with old targets (SOHO routers, Cisco
# IOS pre-15, Win XP IIS, embedded HTTPS admin panels). Load the
# legacy provider once at init so weak crypto (DES, MD5, etc.) is
# available, drop the TLS floor to SSL3, and use a permissive cipher
# list with SECLEVEL=0.
if [ -f hydra-mod.c ] && ! grep -q "STRIX_TLS_LEGACY" hydra-mod.c; then
  perl -i -pe 's|(SSL_library_init\(\); // \?)|\1\n#define STRIX_TLS_LEGACY 1\n#if OPENSSL_VERSION_NUMBER >= 0x30000000L\n    \{ OSSL_PROVIDER *p; p = OSSL_PROVIDER_load(NULL, "legacy"); (void)p; p = OSSL_PROVIDER_load(NULL, "default"); (void)p; \}\n#endif|g' hydra-mod.c
  perl -i -pe 's|(SSL_CTX_set_options\(sslContext, SSL_OP_ALL\);)|\1\n    SSL_CTX_set_security_level(sslContext, 0);\n    SSL_CTX_set_cipher_list(sslContext, "ALL:\@SECLEVEL=0:eNULL");\n#ifdef SSL_CTX_set_min_proto_version\n    SSL_CTX_set_min_proto_version(sslContext, SSL3_VERSION);\n#endif|g' hydra-mod.c
  perl -i -pe 's|(#include <openssl/ssl\.h>)|\1\n#if OPENSSL_VERSION_NUMBER >= 0x30000000L\n#include <openssl/provider.h>\n#endif|g' hydra-mod.c
  echo "  Patched hydra-mod.c with universal legacy TLS support"
fi

make -j$(nproc) 2>&1

cp hydra ${PREFIX}/bin/
${STRIP} ${PREFIX}/bin/hydra

# Reset flags
export CFLAGS="-fPIC -O2"
export LDFLAGS="-fPIE -pie -static-libstdc++"
unset CPPFLAGS

echo "=== hydra installed ==="
ls -lh ${PREFIX}/bin/hydra
