# check=skip=InvalidDefaultArgInFrom
# Tools bundle: nmap, hydra, ettercap, tcpdump, arpspoof (+ libs) for aarch64-linux-android.
#
# Build with ./build.sh (it passes every value of strix/versions.env as --build-arg,
# the "strix-scripts" build context, and exports the "export" stage to ./output).
# All builds happen at image-build time; any failing step fails the build.

ARG BASE_IMAGE
FROM ${BASE_IMAGE} AS build

SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
ENV DEBIAN_FRONTEND=noninteractive
ENV ANDROID_NDK_HOME=/opt/android-ndk
ENV TARGET=aarch64-linux-android
ENV TOOLCHAIN=${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64
ENV OUTPUT=/opt/output

# Build tools
RUN apt-get update && apt-get install -y \
    build-essential autoconf automake libtool \
    wget curl git pkg-config zip unzip cmake \
    bison flex file \
    gpgv \
    && rm -rf /var/lib/apt/lists/*

# Download helper + signature verifier + pinned release-signing keys (strix/scripts)
COPY --from=strix-scripts fetch.sh verify-sig.sh /opt/strix-scripts/
COPY --from=strix-scripts keys /opt/strix-scripts/keys
RUN ln -s /opt/strix-scripts/fetch.sh /usr/local/bin/strix-fetch

# Android NDK
ARG NDK_VERSION
ARG NDK_SHA256
RUN cd /tmp && \
    strix-fetch "https://dl.google.com/android/repository/android-ndk-${NDK_VERSION}-linux.zip" "${NDK_SHA256}" ndk.zip && \
    unzip -q ndk.zip && \
    mv "android-ndk-${NDK_VERSION}" "${ANDROID_NDK_HOME}" && \
    rm ndk.zip

# Upstream sources (versions + checksums from strix/versions.env)
ARG API_LEVEL
ARG NMAP_VERSION
ARG NMAP_SHA256
ARG LIBPCAP_VERSION
ARG LIBPCAP_SHA256
ARG TCPDUMP_VERSION
ARG TCPDUMP_SHA256
ARG LIBNET_VERSION
ARG LIBNET_SHA256
ARG HYDRA_VERSION
ARG HYDRA_SHA256
ARG RTMPDUMP_COMMIT
ARG LIBIDN_VERSION
ARG LIBIDN_SHA256
ARG OPENSSL_VERSION
ARG OPENSSL_SHA256
ARG ETTERCAP_VERSION
ARG ETTERCAP_SHA256
ARG CURL_VERSION
ARG CURL_SHA256
ARG GEOIP_VERSION
ARG GEOIP_SHA256
ARG LUA_VERSION
ARG LUA_SHA256
ARG LIBSSH2_VERSION
ARG LIBSSH2_SHA256
ARG LIBSSH_VERSION
ARG LIBSSH_SHA256
ARG PCRE2_VERSION
ARG PCRE2_SHA256
ARG POSTGRESQL_VERSION
ARG POSTGRESQL_SHA256
ARG GPG_ERROR_VERSION
ARG GPG_ERROR_SHA256
ARG GCRYPT_VERSION
ARG GCRYPT_SHA256
ARG MARIADB_VERSION
ARG MARIADB_SHA256
ARG CYRUS_SASL_VERSION
ARG CYRUS_SASL_SHA256
ARG LIBMEMCACHED_VERSION
ARG LIBMEMCACHED_SHA256

RUN : "${API_LEVEL:?}" "${RTMPDUMP_COMMIT:?}" && \
    mkdir -p /opt/src && cd /opt/src && \
    get() { strix-fetch "$@" && tar xf "$3" && rm "$3"; } && \
    get "https://nmap.org/dist/nmap-${NMAP_VERSION}.tar.bz2" "${NMAP_SHA256}" nmap.tar.bz2 \
        nmap "https://nmap.org/dist/sigs/nmap-${NMAP_VERSION}.tar.bz2.asc" && \
    get "https://www.tcpdump.org/release/libpcap-${LIBPCAP_VERSION}.tar.gz" "${LIBPCAP_SHA256}" libpcap.tar.gz \
        tcpdump "https://www.tcpdump.org/release/libpcap-${LIBPCAP_VERSION}.tar.gz.sig" && \
    get "https://www.tcpdump.org/release/tcpdump-${TCPDUMP_VERSION}.tar.gz" "${TCPDUMP_SHA256}" tcpdump.tar.gz \
        tcpdump "https://www.tcpdump.org/release/tcpdump-${TCPDUMP_VERSION}.tar.gz.sig" && \
    get "https://github.com/libnet/libnet/releases/download/v${LIBNET_VERSION}/libnet-${LIBNET_VERSION}.tar.gz" "${LIBNET_SHA256}" libnet.tar.gz && \
    get "https://github.com/vanhauser-thc/thc-hydra/archive/refs/tags/v${HYDRA_VERSION}.tar.gz" "${HYDRA_SHA256}" hydra.tar.gz && \
    get "https://ftp.gnu.org/gnu/libidn/libidn-${LIBIDN_VERSION}.tar.gz" "${LIBIDN_SHA256}" libidn.tar.gz \
        libidn "https://ftp.gnu.org/gnu/libidn/libidn-${LIBIDN_VERSION}.tar.gz.sig" && \
    get "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" "${OPENSSL_SHA256}" openssl.tar.gz \
        openssl "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz.asc" && \
    get "https://github.com/Ettercap/ettercap/archive/refs/tags/v${ETTERCAP_VERSION}.tar.gz" "${ETTERCAP_SHA256}" ettercap.tar.gz && \
    get "https://curl.se/download/curl-${CURL_VERSION}.tar.gz" "${CURL_SHA256}" curl.tar.gz \
        curl "https://curl.se/download/curl-${CURL_VERSION}.tar.gz.asc" && \
    get "https://github.com/maxmind/geoip-api-c/releases/download/v${GEOIP_VERSION}/GeoIP-${GEOIP_VERSION}.tar.gz" "${GEOIP_SHA256}" geoip.tar.gz && \
    get "https://www.lua.org/ftp/lua-${LUA_VERSION}.tar.gz" "${LUA_SHA256}" lua.tar.gz && \
    get "https://github.com/libssh2/libssh2/releases/download/libssh2-${LIBSSH2_VERSION}/libssh2-${LIBSSH2_VERSION}.tar.gz" "${LIBSSH2_SHA256}" libssh2.tar.gz \
        libssh2 "https://github.com/libssh2/libssh2/releases/download/libssh2-${LIBSSH2_VERSION}/libssh2-${LIBSSH2_VERSION}.tar.gz.asc" && \
    get "https://www.libssh.org/files/${LIBSSH_VERSION%.*}/libssh-${LIBSSH_VERSION}.tar.xz" "${LIBSSH_SHA256}" libssh.tar.xz \
        libssh "https://www.libssh.org/files/${LIBSSH_VERSION%.*}/libssh-${LIBSSH_VERSION}.tar.xz.asc" && \
    get "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${PCRE2_VERSION}/pcre2-${PCRE2_VERSION}.tar.gz" "${PCRE2_SHA256}" pcre2.tar.gz \
        pcre2 "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${PCRE2_VERSION}/pcre2-${PCRE2_VERSION}.tar.gz.sig" && \
    get "https://ftp.postgresql.org/pub/source/v${POSTGRESQL_VERSION}/postgresql-${POSTGRESQL_VERSION}.tar.bz2" "${POSTGRESQL_SHA256}" postgresql.tar.bz2 && \
    get "https://gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-${GPG_ERROR_VERSION}.tar.bz2" "${GPG_ERROR_SHA256}" libgpg-error.tar.bz2 \
        gnupg "https://gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-${GPG_ERROR_VERSION}.tar.bz2.sig" && \
    get "https://gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-${GCRYPT_VERSION}.tar.bz2" "${GCRYPT_SHA256}" libgcrypt.tar.bz2 \
        gnupg "https://gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-${GCRYPT_VERSION}.tar.bz2.sig" && \
    get "https://archive.mariadb.org/connector-c-${MARIADB_VERSION}/mariadb-connector-c-${MARIADB_VERSION}-src.tar.gz" "${MARIADB_SHA256}" mariadb.tar.gz \
        mariadb "https://archive.mariadb.org/connector-c-${MARIADB_VERSION}/mariadb-connector-c-${MARIADB_VERSION}-src.tar.gz.asc" && \
    get "https://github.com/cyrusimap/cyrus-sasl/releases/download/cyrus-sasl-${CYRUS_SASL_VERSION}/cyrus-sasl-${CYRUS_SASL_VERSION}.tar.gz" "${CYRUS_SASL_SHA256}" cyrus-sasl.tar.gz \
        cyrus-sasl "https://github.com/cyrusimap/cyrus-sasl/releases/download/cyrus-sasl-${CYRUS_SASL_VERSION}/cyrus-sasl-${CYRUS_SASL_VERSION}.tar.gz.sig" && \
    get "https://launchpad.net/libmemcached/1.0/${LIBMEMCACHED_VERSION}/+download/libmemcached-${LIBMEMCACHED_VERSION}.tar.gz" "${LIBMEMCACHED_SHA256}" libmemcached.tar.gz && \
    echo "=== rtmpdump (librtmp) @ ${RTMPDUMP_COMMIT} ===" && \
    # Fetch the pinned commit directly: a full clone of git.ffmpeg.org's
    # rtmpdump repo fails ("upload-pack: not our ref 0000...").
    git init -q rtmpdump && \
    git -C rtmpdump fetch -q --depth 1 https://git.ffmpeg.org/rtmpdump.git "${RTMPDUMP_COMMIT}" && \
    git -C rtmpdump checkout -q --detach FETCH_HEAD && \
    test "$(git -C rtmpdump rev-parse HEAD)" = "${RTMPDUMP_COMMIT}" && \
    echo "=== All sources downloaded and verified ==="

WORKDIR /opt

COPY patches /opt/patches
COPY env.sh /opt/env.sh
COPY build-all.sh /opt/build-all.sh
COPY libs /opt/libs
COPY tools /opt/tools
RUN chmod +x /opt/build-all.sh /opt/env.sh /opt/libs/*.sh /opt/tools/*.sh && \
    rm -rf "${OUTPUT}" && /opt/build-all.sh

FROM scratch AS export
COPY --from=build /opt/output/ /
