#!/bin/bash
# Cyrus SASL (libsasl2), static, mechanisms linked in: SASL client for hydra's memcached
# module (libmemcached --enable-sasl). Needs OpenSSL in ${SYSROOT} (DIGEST-MD5/SCRAM).
set -euo pipefail
source "$(dirname "$0")/../env.sh"

echo ""
echo "=== Building cyrus-sasl ${CYRUS_SASL_VERSION} ==="
cd /opt/src/cyrus-sasl-${CYRUS_SASL_VERSION}

# time()/clock() are used without <time.h> in lib/saslutil.c (guarded by HAVE_TIME_H,
# which 2.1.28's configure never defines) and plugins/cram.c (no include at all). glibc
# pulls <time.h> in transitively, bionic doesn't, and current clang rejects implicit
# declarations. Fixed upstream after 2.1.28; same fix as a patch.
patch -p1 --forward < /opt/patches/cyrus-sasl-time-h.patch

export CFLAGS="-fPIC -O2 -I${SYSROOT}/include"
export CPPFLAGS="-I${SYSROOT}/include"
export LDFLAGS="-L${SYSROOT}/lib"

# Static libsasl2 with the client/server mechanisms compiled in (no plugin dlopen):
# PLAIN, LOGIN, CRAM-MD5, DIGEST-MD5, SCRAM-SHA-*. No server-side password backends
# (sasldb, saslauthd, authdaemond, pwcheck, PAM), no GSSAPI/Kerberos, no OTP (MD4 is
# legacy-provider-only in OpenSSL 3), no sample/utils programs.
./configure \
  --host=${TARGET} \
  --prefix=${SYSROOT} \
  --enable-static \
  --disable-shared \
  --enable-plain \
  --enable-login \
  --enable-cram \
  --enable-digest \
  --enable-scram \
  --disable-otp \
  --disable-anon \
  --disable-srp \
  --disable-krb4 \
  --disable-gssapi \
  --disable-ntlm \
  --disable-passdss \
  --disable-sql \
  --disable-ldapdb \
  --disable-sample \
  --disable-checkapop \
  --disable-macos-framework \
  --with-dblib=none \
  --without-saslauthd \
  --without-authdaemond \
  --without-pwcheck \
  --without-pam \
  --with-openssl=${SYSROOT} \
  --with-des=${SYSROOT} \
  2>&1

# Only what a client library needs: headers, libsasl2.a (+ static mechanisms), .pc
make -C include 2>&1
make -C common 2>&1
make -C lib 2>&1
make -C include install 2>&1
make -C lib install 2>&1
make install-pkgconfigDATA 2>&1

# The mechanisms must really be inside the archive (a silently dropped one = no SASL)
SASL_SYMS=$("${TOOLCHAIN}/bin/llvm-nm" -g --defined-only "${SYSROOT}/lib/libsasl2.a")
for sym in plain_client_plug_init login_client_plug_init crammd5_client_plug_init \
           digestmd5_client_plug_init scram_client_plug_init sasl_client_new; do
  if ! grep -qw "${sym}" <<< "${SASL_SYMS}"; then
    echo "FAIL: ${sym} missing from libsasl2.a" >&2
    exit 1
  fi
done

export CFLAGS="-fPIC -O2"
export LDFLAGS="-fPIE -pie -static-libstdc++"
unset CPPFLAGS

echo "=== cyrus-sasl installed to ${SYSROOT} ==="
ls -lh ${SYSROOT}/lib/libsasl2.a ${SYSROOT}/include/sasl/sasl.h
