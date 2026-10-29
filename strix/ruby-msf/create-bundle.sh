#!/bin/bash
# ============================================================
# Create ruby-msf-bundle.tar.gz for APK assets
#
# Uses output from ./build.sh (BUILD_OUTPUT, default ruby-msf/output/):
#   ruby-android/         → Ruby ARM64 (already stripped with NDK llvm-strip)
#   metasploit-framework/ → MSF + vendor gems
#   libpq.so.5            → PostgreSQL client lib
#
# Output:  ruby-msf-bundle.tar.gz            → copied to app/src/main/assets/ruby-msf-bundle.tar.gz.bin
#          ruby-msf-bundle.json(.sig)        → signed manifest (scripts/sign-bundle.sh;
#                                              BUNDLE_SIGNING_KEY or ALLOW_UNSIGNED=1)
# ============================================================
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=../scripts/lib.sh
source "${SCRIPT_DIR}/../scripts/lib.sh"
load_versions
BUILD_OUTPUT=${BUILD_OUTPUT:-${SCRIPT_DIR}/output}
BUNDLE_STAGING="${SCRIPT_DIR}/bundle-staging"
BUNDLE_FILE="${SCRIPT_DIR}/ruby-msf-bundle.tar.gz"
ASSET_DIR="${SCRIPT_DIR}/../app/src/main/assets"

echo "============================================"
echo "  Creating Ruby+MSF bundle for APK"
echo "============================================"

# Verify build artifacts exist
for p in ruby-android metasploit-framework libpq.so.5; do
  [ -e "${BUILD_OUTPUT}/${p}" ] || die "${BUILD_OUTPUT}/${p} not found. Run ./build.sh first."
done

# Clean staging area
rm -rf "${BUNDLE_STAGING}"
mkdir -p "${BUNDLE_STAGING}"

echo ""
echo "=== Copying Ruby ==="
cp -a "${BUILD_OUTPUT}/ruby-android" "${BUNDLE_STAGING}/ruby-android"

# Add VERSION file for System.getLocalRubyVersion()
# (the aarch64 ruby can't run on the host: read the version from the cross rbconfig.rb)
RBCONFIG=$(find "${BUILD_OUTPUT}/ruby-android/lib/ruby" -name rbconfig.rb -print -quit)
[ -n "$RBCONFIG" ] || die "rbconfig.rb not found under ${BUILD_OUTPUT}/ruby-android/lib/ruby"
rbcfg() { sed -nE "s/^[[:space:]]*CONFIG\\[\"$1\"\\] = \"([0-9]+)\".*/\\1/p" "$RBCONFIG"; }
RUBY_VER="$(rbcfg MAJOR).$(rbcfg MINOR).$(rbcfg TEENY)"
[[ "$RUBY_VER" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "could not read MAJOR/MINOR/TEENY from $RBCONFIG (got '$RUBY_VER')"
[ "$RUBY_VER" = "$RUBY_VERSION" ] || die "built Ruby is ${RUBY_VER}, versions.env says ${RUBY_VERSION}"
echo "${RUBY_VER}" > "${BUNDLE_STAGING}/ruby-android/VERSION"
echo "Ruby version: ${RUBY_VER}"

cp "${BUILD_OUTPUT}/libpq.so.5" "${BUNDLE_STAGING}/ruby-android/lib/"
echo "Included libpq.so.5"

# Copy OpenSSL legacy provider (needed for DES-CBC in SMB/NTLM)
if [ -f "${BUILD_OUTPUT}/android-deps/lib/ossl-modules/legacy.so" ]; then
  mkdir -p "${BUNDLE_STAGING}/ruby-android/lib/ossl-modules"
  cp "${BUILD_OUTPUT}/android-deps/lib/ossl-modules/legacy.so" "${BUNDLE_STAGING}/ruby-android/lib/ossl-modules/"
  echo "Included OpenSSL legacy provider"
fi

# Create openssl.cnf to activate legacy provider at runtime
mkdir -p "${BUNDLE_STAGING}/ruby-android/ssl"
cat > "${BUNDLE_STAGING}/ruby-android/ssl/openssl.cnf" << 'SSLCNF_EOF'
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
legacy = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1
SSLCNF_EOF
echo "Created openssl.cnf with legacy provider"

# (debug symbols are stripped inside the build container with the NDK llvm-strip)

RUBY_SIZE=$(du -sh "${BUNDLE_STAGING}/ruby-android" | awk '{print $1}')
echo "Ruby size: ${RUBY_SIZE}"

echo ""
echo "=== Copying MSF ==="
# (build-msf.sh already made the output world-readable)
cp -a "${BUILD_OUTPUT}/metasploit-framework" "${BUNDLE_STAGING}/metasploit-framework"

# Add VERSION file for System.getLocalMsfVersion()
# version.rb: `VERSION = "6.4.125"` (double quotes; later lines interpolate, so take the first literal)
MSF_VERSION_RB="${BUILD_OUTPUT}/metasploit-framework/lib/metasploit/framework/version.rb"
[ -f "$MSF_VERSION_RB" ] || die "$MSF_VERSION_RB not found"
MSF_VER=$(sed -nE '/^[[:space:]]*VERSION = "[0-9]/{s/^[[:space:]]*VERSION = "([0-9][^"]*)".*/\1/p;q;}' "$MSF_VERSION_RB")
[ -n "$MSF_VER" ] || die "could not extract VERSION from $MSF_VERSION_RB"
[ "$MSF_VER" = "$MSF_REF" ] || die "MSF version.rb says ${MSF_VER}, versions.env MSF_REF is ${MSF_REF}"
echo "${MSF_VER}" > "${BUNDLE_STAGING}/metasploit-framework/VERSION"
echo "MSF version: ${MSF_VER}"

# Remove what is never used at runtime: VCS metadata, docs, tests, dev tooling.
# Keep data/ (exploit resources and default wordlists are .txt files read by
# modules), external/ (sources some modules load from the install root) and every
# LICENSE/COPYING file (required when redistributing the gems).
echo "Trimming MSF bundle..."
cd "${BUNDLE_STAGING}/metasploit-framework"
rm -rf .git .github .gitignore .rubocop* .yardopts
rm -rf documentation/ docs/ docker/ test/ spec/ features/
rm -rf tools/dev/
find . -type f -name "*.md" -not -name "Gemfile*" -delete
find . -type f -name "CHANGELOG*" -delete
# Remove .o and .a files from gem native extensions (only .so needed)
find . -type f \( -name "*.o" -o -name "*.a" \) -delete

# Create msfrpcd compatibility script (MSF 6.x removed standalone msfrpcd)
if [ ! -f "${BUNDLE_STAGING}/metasploit-framework/msfrpcd" ]; then
  cat > "${BUNDLE_STAGING}/metasploit-framework/msfrpcd" << 'MSFRPCD_EOF'
#!/usr/bin/env ruby
# msfrpcd - MSF RPC Daemon (compatibility wrapper for MSF 6.x)
# Starts the Metasploit MSGRPC plugin as a standalone daemon.

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), 'lib')))
require 'msfenv'

opts = {
  'ServerHost' => '0.0.0.0',
  'ServerPort' => 55553,
  'User' => 'msf',
  'Pass' => 'msf',
  'SSL' => true,
}

i = 0
while i < ARGV.length
  case ARGV[i]
  when '-a' then i += 1; opts['ServerHost'] = ARGV[i]
  when '-p' then i += 1; opts['ServerPort'] = ARGV[i].to_i
  when '-U' then i += 1; opts['User'] = ARGV[i]
  when '-P' then i += 1; opts['Pass'] = ARGV[i]
  when '-S' then opts['SSL'] = false
  end
  i += 1
end

$0 = 'msfrpcd'
$stderr.puts "[*] MSGRPC starting on #{opts['ServerPort']} (#{opts['SSL'] ? 'SSL' : 'NO SSL'})..."
$stderr.flush

framework = Msf::Simple::Framework.create
framework.plugins.load('msgrpc', opts)

$stderr.puts "[*] MSGRPC ready at #{opts['ServerHost']}:#{opts['ServerPort']}"
$stderr.flush

begin
  while true
    sleep 60
  end
rescue Interrupt, SignalException
  $stderr.puts "[*] Shutting down msfrpcd..."
end
MSFRPCD_EOF
  chmod +x "${BUNDLE_STAGING}/metasploit-framework/msfrpcd"
  echo "Created msfrpcd compatibility script"
fi

MSF_SIZE=$(du -sh "${BUNDLE_STAGING}/metasploit-framework" | awk '{print $1}')
echo "MSF size (trimmed): ${MSF_SIZE}"

echo ""
echo "=== Creating tar.gz ==="
cd "${BUNDLE_STAGING}"
rm -f "${BUNDLE_FILE}"
tar czf "${BUNDLE_FILE}" ruby-android/ metasploit-framework/
cd "${SCRIPT_DIR}"

BUNDLE_SIZE=$(du -sh "${BUNDLE_FILE}" | awk '{print $1}')
echo "Bundle: ${BUNDLE_SIZE}"

# Manifest + signature (release assets: ruby-msf-bundle.tar.gz.bin, ruby-msf-bundle.json, ruby-msf-bundle.json.sig)
"${SCRIPT_DIR}/../scripts/sign-bundle.sh" msf "msf ${MSF_VER}" "${MSF_BUNDLE_MIN_APP}" \
  "${BUNDLE_FILE}" ruby-msf-bundle.tar.gz.bin "${SCRIPT_DIR}/ruby-msf-bundle.json"

# Copy to APK assets (renamed to .bin to prevent AGP decompression)
mkdir -p "${ASSET_DIR}"
cp "${BUNDLE_FILE}" "${ASSET_DIR}/ruby-msf-bundle.tar.gz.bin"
echo "Copied to ${ASSET_DIR}/ruby-msf-bundle.tar.gz.bin"

# Cleanup
rm -rf "${BUNDLE_STAGING}"

echo ""
echo "============================================"
echo "  Bundle created: ${BUNDLE_SIZE}"
echo "  Ruby: ${RUBY_SIZE}"
echo "  MSF:  ${MSF_SIZE}"
echo "============================================"
