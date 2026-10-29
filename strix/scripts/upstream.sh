#!/bin/bash
# Upstream knowledge for scripts/check-updates.sh: where each pinned component's
# latest version is discovered and the tarball URL for a given version.
# Source it. URL templates MUST match tools/Dockerfile, ruby-msf/01-ruby/build-ruby.sh
# and ruby-msf/02-msf/build-msf.sh.

# Latest version string (same format as the *_VERSION value) for a component key.
upstream_latest() {
  case "$1" in
    NMAP)         listing_latest https://nmap.org/dist/ 'nmap-[0-9]+\.[0-9]+(\.[0-9]+)?\.tar\.bz2' 'nmap-' '.tar.bz2' ;;
    LIBPCAP)      listing_latest https://www.tcpdump.org/release/ 'libpcap-[0-9]+\.[0-9]+\.[0-9]+\.tar\.gz' 'libpcap-' '.tar.gz' ;;
    TCPDUMP)      listing_latest https://www.tcpdump.org/release/ 'tcpdump-[0-9]+\.[0-9]+\.[0-9]+\.tar\.gz' 'tcpdump-' '.tar.gz' ;;
    LIBNET)       gh_release libnet/libnet v ;;
    HYDRA)        gh_release vanhauser-thc/thc-hydra v ;;
    ETTERCAP)     gh_release Ettercap/ettercap v ;;
    LIBIDN)       listing_latest https://ftp.gnu.org/gnu/libidn/ 'libidn-[0-9]+\.[0-9]+(\.[0-9]+)?\.tar\.gz' 'libidn-' '.tar.gz' ;;
    # Same major.minor series only (minor bumps of these need a human decision)
    OPENSSL)      git_tag_latest https://github.com/openssl/openssl.git "openssl-${OPENSSL_VERSION%.*}\\.[0-9]+" 'openssl-' ;;
    POSTGRESQL)   listing_latest https://ftp.postgresql.org/pub/source/ "v${POSTGRESQL_VERSION%%.*}\\.[0-9]+/" 'v' '/' ;;
    RUBY)         listing_latest "https://cache.ruby-lang.org/pub/ruby/${RUBY_VERSION%.*}/" "ruby-${RUBY_VERSION%.*}\\.[0-9]+\\.tar\\.gz" 'ruby-' '.tar.gz' ;;
    CURL)         gh_release curl/curl curl- | tr '_' '.' ;;
    GEOIP)        gh_release maxmind/geoip-api-c v ;;
    LUA)          listing_latest https://www.lua.org/ftp/ 'lua-[0-9]+\.[0-9]+\.[0-9]+\.tar\.gz' 'lua-' '.tar.gz' ;;
    LIBSSH2)      gh_release libssh2/libssh2 libssh2- ;;
    LIBSSH)       local d; d=$(listing_latest https://www.libssh.org/files/ 'href="[0-9]+\.[0-9]+/"' 'href="' '/"') &&
                  listing_latest "https://www.libssh.org/files/${d}/" 'libssh-[0-9]+\.[0-9]+\.[0-9]+\.tar\.xz' 'libssh-' '.tar.xz' ;;
    PCRE2)        gh_release PCRE2Project/pcre2 pcre2- ;;
    GPG_ERROR)    listing_latest https://gnupg.org/ftp/gcrypt/libgpg-error/ 'libgpg-error-[0-9]+\.[0-9]+\.tar\.bz2' 'libgpg-error-' '.tar.bz2' ;;
    GCRYPT)       listing_latest https://gnupg.org/ftp/gcrypt/libgcrypt/ 'libgcrypt-[0-9]+\.[0-9]+\.[0-9]+\.tar\.bz2' 'libgcrypt-' '.tar.bz2' ;;
    CYRUS_SASL)   gh_release cyrusimap/cyrus-sasl cyrus-sasl- ;;
    MARIADB)      git_tag_latest https://github.com/mariadb-corporation/mariadb-connector-c.git 'v3\.[0-9]+\.[0-9]+' 'v' ;;
    ZLIB)         gh_release madler/zlib v ;;
    YAML)         gh_release yaml/libyaml '' ;;
    LIBFFI)       gh_release libffi/libffi v ;;
    SQLITE)       curl -fsSL https://www.sqlite.org/download.html \
                    | grep -oE 'PRODUCT,[0-9.]+,[0-9]{4}/sqlite-autoconf-[0-9]{7}\.tar\.gz' \
                    | sed -E 's|.*,([0-9]{4})/sqlite-autoconf-([0-9]{7}).*|\2 \1|' | awk 'NR==1' ;;
    LIBXML2|LIBXSLT)
                  local n d; n=$(tr 'A-Z' 'a-z' <<< "$1")
                  d=$(listing_latest "https://download.gnome.org/sources/${n}/" 'href="[0-9]+\.[0-9]+/"' 'href="' '/"') &&
                  listing_latest "https://download.gnome.org/sources/${n}/${d}/" "${n}-[0-9]+\\.[0-9]+\\.[0-9]+\\.tar\\.xz" "${n}-" '.tar.xz' ;;
    *) echo "upstream_latest: unknown component $1" >&2; return 1 ;;
  esac
}

# Download URL of component $1 at version $2 (SQLite: $3 = year directory).
upstream_url() {
  local v=$2
  case "$1" in
    NMAP)         echo "https://nmap.org/dist/nmap-${v}.tar.bz2" ;;
    LIBPCAP)      echo "https://www.tcpdump.org/release/libpcap-${v}.tar.gz" ;;
    TCPDUMP)      echo "https://www.tcpdump.org/release/tcpdump-${v}.tar.gz" ;;
    LIBNET)       echo "https://github.com/libnet/libnet/releases/download/v${v}/libnet-${v}.tar.gz" ;;
    HYDRA)        echo "https://github.com/vanhauser-thc/thc-hydra/archive/refs/tags/v${v}.tar.gz" ;;
    ETTERCAP)     echo "https://github.com/Ettercap/ettercap/archive/refs/tags/v${v}.tar.gz" ;;
    LIBIDN)       echo "https://ftp.gnu.org/gnu/libidn/libidn-${v}.tar.gz" ;;
    OPENSSL)      echo "https://github.com/openssl/openssl/releases/download/openssl-${v}/openssl-${v}.tar.gz" ;;
    POSTGRESQL)   echo "https://ftp.postgresql.org/pub/source/v${v}/postgresql-${v}.tar.bz2" ;;
    RUBY)         echo "https://cache.ruby-lang.org/pub/ruby/${v%.*}/ruby-${v}.tar.gz" ;;
    CURL)         echo "https://curl.se/download/curl-${v}.tar.gz" ;;
    GEOIP)        echo "https://github.com/maxmind/geoip-api-c/releases/download/v${v}/GeoIP-${v}.tar.gz" ;;
    LUA)          echo "https://www.lua.org/ftp/lua-${v}.tar.gz" ;;
    LIBSSH2)      echo "https://github.com/libssh2/libssh2/releases/download/libssh2-${v}/libssh2-${v}.tar.gz" ;;
    LIBSSH)       echo "https://www.libssh.org/files/${v%.*}/libssh-${v}.tar.xz" ;;
    PCRE2)        echo "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${v}/pcre2-${v}.tar.gz" ;;
    GPG_ERROR)    echo "https://gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-${v}.tar.bz2" ;;
    GCRYPT)       echo "https://gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-${v}.tar.bz2" ;;
    CYRUS_SASL)   echo "https://github.com/cyrusimap/cyrus-sasl/releases/download/cyrus-sasl-${v}/cyrus-sasl-${v}.tar.gz" ;;
    MARIADB)      echo "https://archive.mariadb.org/connector-c-${v}/mariadb-connector-c-${v}-src.tar.gz" ;;
    ZLIB)         echo "https://github.com/madler/zlib/releases/download/v${v}/zlib-${v}.tar.gz" ;;
    YAML)         echo "https://github.com/yaml/libyaml/releases/download/${v}/yaml-${v}.tar.gz" ;;
    LIBFFI)       echo "https://github.com/libffi/libffi/releases/download/v${v}/libffi-${v}.tar.gz" ;;
    SQLITE)       echo "https://www.sqlite.org/${3}/sqlite-autoconf-${v}.tar.gz" ;;
    LIBXML2)      echo "https://download.gnome.org/sources/libxml2/${v%.*}/libxml2-${v}.tar.xz" ;;
    LIBXSLT)      echo "https://download.gnome.org/sources/libxslt/${v%.*}/libxslt-${v}.tar.xz" ;;
    *) echo "upstream_url: unknown component $1" >&2; return 1 ;;
  esac
}

# "<keyring> <signature-url>" for components whose releases are OpenPGP-signed (keyring
# = name in keys/fingerprints); nothing for the rest. MUST match the Dockerfile/build
# script strix-fetch calls.
upstream_sig() {
  local u; u=$(upstream_url "$1" "$2") || return 1
  case "$1" in
    NMAP)               echo "nmap https://nmap.org/dist/sigs/nmap-${2}.tar.bz2.asc" ;;
    LIBPCAP|TCPDUMP)    echo "tcpdump ${u}.sig" ;;
    LIBIDN)             echo "libidn ${u}.sig" ;;
    OPENSSL)            echo "openssl ${u}.asc" ;;
    CURL)               echo "curl ${u}.asc" ;;
    LIBSSH2)            echo "libssh2 ${u}.asc" ;;
    LIBSSH)             echo "libssh ${u}.asc" ;;
    PCRE2)              echo "pcre2 ${u}.sig" ;;
    GPG_ERROR|GCRYPT)   echo "gnupg ${u}.sig" ;;
    ZLIB)               echo "zlib ${u}.asc" ;;
    MARIADB)            echo "mariadb ${u}.asc" ;;
    CYRUS_SASL)         echo "cyrus-sasl ${u}.sig" ;;
  esac
}

# listing_latest <url> <regex> <prefix-to-strip> <suffix-to-strip>
listing_latest() {
  local v
  v=$(curl -fsSL "$1" | grep -oE "$2" | sed -e "s|^$3||" -e "s|$4\$||" | sort -uV | tail -n1)
  [ -n "$v" ] || { echo "no match for '$2' at $1" >&2; return 1; }
  echo "$v"
}

# gh_release <owner/repo> <tag-prefix-to-strip>
gh_release() {
  local t
  t=$(gh api "repos/$1/releases/latest" --jq .tag_name)
  echo "${t#"$2"}"
}

# git_tag_latest <git-url> <tag-regex (without refs/tags/)> <prefix-to-strip>
git_tag_latest() {
  local v
  v=$(git ls-remote --tags --refs "$1" | awk '{print $2}' | sed 's|^refs/tags/||' \
      | grep -E "^$2\$" | sed "s|^$3||" | sort -V | tail -n1)
  [ -n "$v" ] || { echo "no tag matching '$2' in $1" >&2; return 1; }
  echo "$v"
}
