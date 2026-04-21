FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV RUBY_VERSION=3.3.6
ENV NDK_VERSION=r27c
ENV API_LEVEL=29
ENV ANDROID_NDK_HOME=/opt/android-ndk

# Build tools
RUN apt-get update && apt-get install -y \
    build-essential autoconf bison flex libtool \
    ruby wget curl git pkg-config zip unzip \
    libssl-dev libreadline-dev zlib1g-dev libyaml-dev libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Android NDK
RUN cd /tmp && \
    wget -q https://dl.google.com/android/repository/android-ndk-${NDK_VERSION}-linux.zip && \
    unzip -q android-ndk-${NDK_VERSION}-linux.zip && \
    mv android-ndk-${NDK_VERSION} ${ANDROID_NDK_HOME} && \
    rm android-ndk-${NDK_VERSION}-linux.zip

# Ruby source
RUN cd /tmp && \
    wget -q https://cache.ruby-lang.org/pub/ruby/3.3/ruby-${RUBY_VERSION}.tar.gz && \
    tar xzf ruby-${RUBY_VERSION}.tar.gz && \
    mv ruby-${RUBY_VERSION} /opt/ruby-src && \
    rm ruby-${RUBY_VERSION}.tar.gz

WORKDIR /opt/ruby-src

COPY build-ruby.sh /opt/build-ruby.sh
RUN chmod +x /opt/build-ruby.sh

CMD ["/opt/build-ruby.sh"]
