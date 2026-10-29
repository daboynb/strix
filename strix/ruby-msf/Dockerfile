# check=skip=InvalidDefaultArgInFrom
# Ruby + Metasploit Framework bundle inputs for aarch64-linux-android.
#
# Build with ./build.sh: it passes every value of strix/versions.env as --build-arg,
# the "strix-scripts" build context, and exports the "export" stage to ./output.
# Stage "ruby" runs exactly once and is consumed by stage "msf" (no local image tags,
# no second Ruby build). Any failing step fails the whole build.

ARG BASE_IMAGE

# ============================================================
# Stage 1: Ruby host + cross Ruby + static deps
# ============================================================
FROM ${BASE_IMAGE} AS ruby

SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
ENV DEBIAN_FRONTEND=noninteractive
ENV ANDROID_NDK_HOME=/opt/android-ndk

RUN apt-get update && apt-get install -y \
    build-essential autoconf bison flex libtool \
    ruby wget curl git pkg-config zip unzip file \
    libssl-dev libreadline-dev zlib1g-dev libyaml-dev libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=strix-scripts fetch.sh /usr/local/bin/strix-fetch

ARG NDK_VERSION
ARG NDK_SHA256
RUN cd /tmp && \
    strix-fetch "https://dl.google.com/android/repository/android-ndk-${NDK_VERSION}-linux.zip" "${NDK_SHA256}" ndk.zip && \
    unzip -q ndk.zip && \
    mv "android-ndk-${NDK_VERSION}" "${ANDROID_NDK_HOME}" && \
    rm ndk.zip

ARG RUBY_VERSION
ARG RUBY_SHA256
RUN cd /tmp && \
    strix-fetch "https://cache.ruby-lang.org/pub/ruby/${RUBY_VERSION%.*}/ruby-${RUBY_VERSION}.tar.gz" "${RUBY_SHA256}" ruby.tar.gz && \
    tar xzf ruby.tar.gz && \
    mv "ruby-${RUBY_VERSION}" /opt/ruby-src && \
    rm ruby.tar.gz

ARG API_LEVEL
ARG OPENSSL_VERSION
ARG OPENSSL_SHA256
ARG ZLIB_VERSION
ARG ZLIB_SHA256
ARG YAML_VERSION
ARG YAML_SHA256
ARG LIBFFI_VERSION
ARG LIBFFI_SHA256
ENV NDK_VERSION=${NDK_VERSION} API_LEVEL=${API_LEVEL} RUBY_VERSION=${RUBY_VERSION}

WORKDIR /opt/ruby-src
COPY 01-ruby/build-ruby.sh /opt/build-ruby.sh
RUN chmod +x /opt/build-ruby.sh && /opt/build-ruby.sh

# ============================================================
# Stage 2: MSF bundle install + cross-compile native gems
# ============================================================
FROM ${BASE_IMAGE} AS msf

SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
ENV DEBIAN_FRONTEND=noninteractive
ENV TARGET=aarch64-linux-android
ENV ANDROID_NDK_HOME=/opt/android-ndk

# Build tools + host dev libs (for the native host bundle install)
RUN apt-get update && apt-get install -y \
    build-essential ruby ruby-dev bundler \
    wget curl git pkg-config file perl \
    libssl-dev libreadline-dev zlib1g-dev libyaml-dev libffi-dev \
    libsqlite3-dev libpq-dev libxml2-dev libxslt1-dev \
    libpcap-dev flex bison xz-utils \
    && rm -rf /var/lib/apt/lists/*

COPY --from=strix-scripts fetch.sh /usr/local/bin/strix-fetch

# Artifacts from stage 1
COPY --from=ruby /output/ruby-android /opt/ruby-android
COPY --from=ruby /output/ruby-host /opt/ruby-host
COPY --from=ruby /output/android-deps /opt/android-deps
COPY --from=ruby /opt/android-ndk /opt/android-ndk

ENV TOOLCHAIN=${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64
ENV PATH="/opt/ruby-host/bin:${TOOLCHAIN}/bin:${PATH}"

ARG API_LEVEL
ARG LIBPCAP_VERSION
ARG LIBPCAP_SHA256
ARG SQLITE_VERSION
ARG SQLITE_YEAR
ARG SQLITE_SHA256
ARG POSTGRESQL_VERSION
ARG POSTGRESQL_SHA256
ARG LIBXML2_VERSION
ARG LIBXML2_SHA256
ARG LIBXSLT_VERSION
ARG LIBXSLT_SHA256
ARG MSF_REF
ARG MSF_COMMIT
ENV API_LEVEL=${API_LEVEL}

COPY 02-msf/build-msf.sh /opt/build-msf.sh
RUN chmod +x /opt/build-msf.sh && /opt/build-msf.sh

FROM scratch AS export
COPY --from=msf /output/ /
