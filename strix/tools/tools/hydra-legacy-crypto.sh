#!/bin/bash
# Sourced by hydra.sh (same shell: inherits set -euo pipefail, env.sh vars, cwd).
set -euo pipefail
# Source patches so hydra still negotiates with legacy SSH and TLS targets.

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
