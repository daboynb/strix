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
    && rm -rf /var/lib/apt/lists/*

COPY --from=strix-scripts fetch.sh /usr/local/bin/strix-fetch

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
ARG LIBMEMCACHED_VERSION
ARG LIBMEMCACHED_SHA256

RUN : "${API_LEVEL:?}" "${RTMPDUMP_COMMIT:?}" && \
    mkdir -p /opt/src && cd /opt/src && \
    get() { strix-fetch "$1" "$2" "$3" && tar xf "$3" && rm "$3"; } && \
    get "https://nmap.org/dist/nmap-${NMAP_VERSION}.tar.bz2" "${NMAP_SHA256}" nmap.tar.bz2 && \
    get "https://www.tcpdump.org/release/libpcap-${LIBPCAP_VERSION}.tar.gz" "${LIBPCAP_SHA256}" libpcap.tar.gz && \
    get "https://www.tcpdump.org/release/tcpdump-${TCPDUMP_VERSION}.tar.gz" "${TCPDUMP_SHA256}" tcpdump.tar.gz && \
    get "https://github.com/libnet/libnet/releases/download/v${LIBNET_VERSION}/libnet-${LIBNET_VERSION}.tar.gz" "${LIBNET_SHA256}" libnet.tar.gz && \
    get "https://github.com/vanhauser-thc/thc-hydra/archive/refs/tags/v${HYDRA_VERSION}.tar.gz" "${HYDRA_SHA256}" hydra.tar.gz && \
    get "https://ftp.gnu.org/gnu/libidn/libidn-${LIBIDN_VERSION}.tar.gz" "${LIBIDN_SHA256}" libidn.tar.gz && \
    get "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" "${OPENSSL_SHA256}" openssl.tar.gz && \
    get "https://github.com/Ettercap/ettercap/archive/refs/tags/v${ETTERCAP_VERSION}.tar.gz" "${ETTERCAP_SHA256}" ettercap.tar.gz && \
    get "https://curl.se/download/curl-${CURL_VERSION}.tar.gz" "${CURL_SHA256}" curl.tar.gz && \
    get "https://github.com/maxmind/geoip-api-c/releases/download/v${GEOIP_VERSION}/GeoIP-${GEOIP_VERSION}.tar.gz" "${GEOIP_SHA256}" geoip.tar.gz && \
    get "https://www.lua.org/ftp/lua-${LUA_VERSION}.tar.gz" "${LUA_SHA256}" lua.tar.gz && \
    get "https://github.com/libssh2/libssh2/releases/download/libssh2-${LIBSSH2_VERSION}/libssh2-${LIBSSH2_VERSION}.tar.gz" "${LIBSSH2_SHA256}" libssh2.tar.gz && \
    get "https://www.libssh.org/files/${LIBSSH_VERSION%.*}/libssh-${LIBSSH_VERSION}.tar.xz" "${LIBSSH_SHA256}" libssh.tar.xz && \
    get "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${PCRE2_VERSION}/pcre2-${PCRE2_VERSION}.tar.gz" "${PCRE2_SHA256}" pcre2.tar.gz && \
    get "https://ftp.postgresql.org/pub/source/v${POSTGRESQL_VERSION}/postgresql-${POSTGRESQL_VERSION}.tar.bz2" "${POSTGRESQL_SHA256}" postgresql.tar.bz2 && \
    get "https://gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-${GPG_ERROR_VERSION}.tar.bz2" "${GPG_ERROR_SHA256}" libgpg-error.tar.bz2 && \
    get "https://gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-${GCRYPT_VERSION}.tar.bz2" "${GCRYPT_SHA256}" libgcrypt.tar.bz2 && \
    get "https://github.com/mariadb-corporation/mariadb-connector-c/archive/refs/tags/v${MARIADB_VERSION}.tar.gz" "${MARIADB_SHA256}" mariadb.tar.gz && \
    get "https://github.com/awesomized/libmemcached/archive/refs/tags/${LIBMEMCACHED_VERSION}.tar.gz" "${LIBMEMCACHED_SHA256}" libmemcached.tar.gz && \
    echo "=== rtmpdump (librtmp) @ ${RTMPDUMP_COMMIT} ===" && \
    git clone https://git.ffmpeg.org/rtmpdump.git && \
    git -C rtmpdump checkout --detach "${RTMPDUMP_COMMIT}" && \
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
