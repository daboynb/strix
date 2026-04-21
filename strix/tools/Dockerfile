FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV NDK_VERSION=r27c
ENV API_LEVEL=29
ENV ANDROID_NDK_HOME=/opt/android-ndk
ENV TARGET=aarch64-linux-android
ENV TOOLCHAIN=${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64
ENV OUTPUT=/opt/output

# Versions — official upstream releases (downloaded at build time)
ENV NMAP_VERSION=7.98
ENV LIBPCAP_VERSION=1.10.5
ENV LIBNET_VERSION=1.3
ENV CARES_VERSION=1.34.4
ENV TCPDUMP_VERSION=4.99.5
ENV HYDRA_VERSION=9.5
ENV ETTERCAP_VERSION=0.8.3.1
ENV CURL_VERSION=8.6.0
ENV GEOIP_VERSION=1.6.12
ENV LUA_VERSION=5.4.7
ENV LIBSSH2_VERSION=1.11.1
ENV LIBSSH_VERSION=0.10.6
ENV PCRE2_VERSION=10.43
ENV POSTGRESQL_VERSION=16.2
ENV GPG_ERROR_VERSION=1.49
ENV GCRYPT_VERSION=1.10.3
ENV MARIADB_VERSION=3.3.8
ENV LIBMEMCACHED_VERSION=1.0.18

# Build tools
RUN apt-get update && apt-get install -y \
    build-essential autoconf automake libtool \
    wget curl git pkg-config zip unzip cmake \
    bison flex \
    && rm -rf /var/lib/apt/lists/*

# Android NDK
RUN cd /tmp && \
    wget -q https://dl.google.com/android/repository/android-ndk-${NDK_VERSION}-linux.zip && \
    unzip -q android-ndk-${NDK_VERSION}-linux.zip && \
    mv android-ndk-${NDK_VERSION} ${ANDROID_NDK_HOME} && \
    rm android-ndk-${NDK_VERSION}-linux.zip

# Download official upstream sources
RUN mkdir -p /opt/src && cd /opt/src && \
    echo "=== Downloading nmap ===" && \
    wget -q https://nmap.org/dist/nmap-${NMAP_VERSION}.tar.bz2 && \
    tar xjf nmap-${NMAP_VERSION}.tar.bz2 && rm nmap-${NMAP_VERSION}.tar.bz2 && \
    echo "=== Downloading libpcap ===" && \
    wget -q https://www.tcpdump.org/release/libpcap-${LIBPCAP_VERSION}.tar.gz && \
    tar xzf libpcap-${LIBPCAP_VERSION}.tar.gz && rm libpcap-${LIBPCAP_VERSION}.tar.gz && \
    echo "=== Downloading tcpdump ===" && \
    wget -q https://www.tcpdump.org/release/tcpdump-${TCPDUMP_VERSION}.tar.gz && \
    tar xzf tcpdump-${TCPDUMP_VERSION}.tar.gz && rm tcpdump-${TCPDUMP_VERSION}.tar.gz && \
    echo "=== Downloading libnet ===" && \
    wget -q https://github.com/libnet/libnet/releases/download/v${LIBNET_VERSION}/libnet-${LIBNET_VERSION}.tar.gz && \
    tar xzf libnet-${LIBNET_VERSION}.tar.gz && rm libnet-${LIBNET_VERSION}.tar.gz && \
    echo "=== Downloading c-ares ===" && \
    wget -q https://github.com/c-ares/c-ares/releases/download/v${CARES_VERSION}/c-ares-${CARES_VERSION}.tar.gz && \
    tar xzf c-ares-${CARES_VERSION}.tar.gz && rm c-ares-${CARES_VERSION}.tar.gz && \
    echo "=== Downloading hydra ===" && \
    wget -q https://github.com/vanhauser-thc/thc-hydra/archive/refs/tags/v${HYDRA_VERSION}.tar.gz -O hydra-${HYDRA_VERSION}.tar.gz && \
    tar xzf hydra-${HYDRA_VERSION}.tar.gz && rm hydra-${HYDRA_VERSION}.tar.gz && \
    echo "=== Downloading rtmpdump (librtmp) ===" && \
    git clone --depth 1 https://git.ffmpeg.org/rtmpdump.git && \
    echo "=== Downloading libidn ===" && \
    wget -q https://ftp.gnu.org/gnu/libidn/libidn-1.42.tar.gz && \
    tar xzf libidn-1.42.tar.gz && rm libidn-1.42.tar.gz && \
    echo "=== Downloading openssl ===" && \
    wget -q https://github.com/openssl/openssl/releases/download/openssl-3.2.1/openssl-3.2.1.tar.gz && \
    tar xzf openssl-3.2.1.tar.gz && rm openssl-3.2.1.tar.gz && \
    echo "=== Downloading ettercap ===" && \
    wget -q https://github.com/Ettercap/ettercap/archive/refs/tags/v${ETTERCAP_VERSION}.tar.gz -O ettercap-${ETTERCAP_VERSION}.tar.gz && \
    tar xzf ettercap-${ETTERCAP_VERSION}.tar.gz && rm ettercap-${ETTERCAP_VERSION}.tar.gz && \
    echo "=== Downloading curl ===" && \
    wget -q https://curl.se/download/curl-${CURL_VERSION}.tar.gz && \
    tar xzf curl-${CURL_VERSION}.tar.gz && rm curl-${CURL_VERSION}.tar.gz && \
    echo "=== Downloading GeoIP (legacy C API) ===" && \
    wget -q https://github.com/maxmind/geoip-api-c/releases/download/v${GEOIP_VERSION}/GeoIP-${GEOIP_VERSION}.tar.gz && \
    tar xzf GeoIP-${GEOIP_VERSION}.tar.gz && rm GeoIP-${GEOIP_VERSION}.tar.gz && \
    echo "=== Downloading Lua ===" && \
    wget -q https://www.lua.org/ftp/lua-${LUA_VERSION}.tar.gz && \
    tar xzf lua-${LUA_VERSION}.tar.gz && rm lua-${LUA_VERSION}.tar.gz && \
    echo "=== Downloading libssh2 ===" && \
    wget -q https://github.com/libssh2/libssh2/releases/download/libssh2-${LIBSSH2_VERSION}/libssh2-${LIBSSH2_VERSION}.tar.gz && \
    tar xzf libssh2-${LIBSSH2_VERSION}.tar.gz && rm libssh2-${LIBSSH2_VERSION}.tar.gz && \
    echo "=== Downloading libssh ===" && \
    wget -q https://www.libssh.org/files/0.10/libssh-${LIBSSH_VERSION}.tar.xz && \
    tar xJf libssh-${LIBSSH_VERSION}.tar.xz && rm libssh-${LIBSSH_VERSION}.tar.xz && \
    echo "=== Downloading pcre2 ===" && \
    wget -q https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${PCRE2_VERSION}/pcre2-${PCRE2_VERSION}.tar.gz && \
    tar xzf pcre2-${PCRE2_VERSION}.tar.gz && rm pcre2-${PCRE2_VERSION}.tar.gz && \
    echo "=== Downloading PostgreSQL (for libpq) ===" && \
    wget -q https://ftp.postgresql.org/pub/source/v${POSTGRESQL_VERSION}/postgresql-${POSTGRESQL_VERSION}.tar.gz && \
    tar xzf postgresql-${POSTGRESQL_VERSION}.tar.gz && rm postgresql-${POSTGRESQL_VERSION}.tar.gz && \
    echo "=== Downloading libgpg-error ===" && \
    wget -q https://gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-${GPG_ERROR_VERSION}.tar.bz2 && \
    tar xjf libgpg-error-${GPG_ERROR_VERSION}.tar.bz2 && rm libgpg-error-${GPG_ERROR_VERSION}.tar.bz2 && \
    echo "=== Downloading libgcrypt ===" && \
    wget -q https://gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-${GCRYPT_VERSION}.tar.bz2 && \
    tar xjf libgcrypt-${GCRYPT_VERSION}.tar.bz2 && rm libgcrypt-${GCRYPT_VERSION}.tar.bz2 && \
    echo "=== Downloading mariadb-connector-c ===" && \
    wget -q https://github.com/mariadb-corporation/mariadb-connector-c/archive/refs/tags/v${MARIADB_VERSION}.tar.gz -O mariadb-connector-c-${MARIADB_VERSION}.tar.gz && \
    tar xzf mariadb-connector-c-${MARIADB_VERSION}.tar.gz && rm mariadb-connector-c-${MARIADB_VERSION}.tar.gz && \
    echo "=== Downloading libmemcached ===" && \
    wget -q https://github.com/awesomized/libmemcached/archive/refs/tags/${LIBMEMCACHED_VERSION}.tar.gz -O libmemcached-${LIBMEMCACHED_VERSION}.tar.gz && \
    tar xzf libmemcached-${LIBMEMCACHED_VERSION}.tar.gz && rm libmemcached-${LIBMEMCACHED_VERSION}.tar.gz && \
    echo "=== All official sources downloaded ==="

WORKDIR /opt

COPY patches /opt/patches
COPY env.sh /opt/env.sh
COPY build.sh /opt/build.sh
COPY libs /opt/libs
COPY tools /opt/tools
COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/build.sh /opt/entrypoint.sh /opt/env.sh /opt/libs/*.sh /opt/tools/*.sh

ENTRYPOINT ["/opt/entrypoint.sh"]
CMD ["/opt/build.sh"]
