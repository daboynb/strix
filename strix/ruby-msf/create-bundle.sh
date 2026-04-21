#!/bin/bash
# ============================================================
# Create ruby-msf-bundle.tar.gz for APK assets
#
# Uses output from Docker build pipeline:
#   /tmp/ruby-android-output/ruby-android/        → Ruby 3.3.6 ARM64
#   /tmp/ruby-android-output/metasploit-framework/ → MSF 6.4 + vendor gems
#   /tmp/ruby-android-output/libpq.so.5            → PostgreSQL client lib
#
# Output:  ruby-msf-bundle.tar.gz → copied to app/cSploit/assets/
# ============================================================
set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
BUILD_OUTPUT=${BUILD_OUTPUT:-/tmp/ruby-android-output}
BUNDLE_STAGING="${SCRIPT_DIR}/bundle-staging"
BUNDLE_FILE="${SCRIPT_DIR}/ruby-msf-bundle.tar.gz"
ASSET_DIR="${SCRIPT_DIR}/../app/src/main/assets"

echo "============================================"
echo "  Creating Ruby+MSF bundle for APK"
echo "============================================"

# Verify build artifacts exist
if [ ! -d "${BUILD_OUTPUT}/ruby-android" ]; then
  echo "ERROR: ${BUILD_OUTPUT}/ruby-android not found"
  echo "Run the Docker build first: cd ruby-android && ./build-all.sh"
  exit 1
fi

if [ ! -d "${BUILD_OUTPUT}/metasploit-framework" ]; then
  echo "ERROR: ${BUILD_OUTPUT}/metasploit-framework not found"
  echo "Run the Docker build first: cd ruby-android && ./build-all.sh"
  exit 1
fi

# Clean staging area
rm -rf "${BUNDLE_STAGING}"
mkdir -p "${BUNDLE_STAGING}"

echo ""
echo "=== Copying Ruby ==="
cp -a "${BUILD_OUTPUT}/ruby-android" "${BUNDLE_STAGING}/ruby-android"

# Add VERSION file for System.getLocalRubyVersion()
RUBY_VER=$(${BUILD_OUTPUT}/ruby-android/bin/ruby --version 2>/dev/null | awk '{print $2}' || true)
[ -z "$RUBY_VER" ] && RUBY_VER="3.3.6"
echo "${RUBY_VER}" > "${BUNDLE_STAGING}/ruby-android/VERSION"
echo "Ruby version: ${RUBY_VER}"

# Copy libpq if available
if [ -f "${BUILD_OUTPUT}/libpq.so.5" ]; then
  cp "${BUILD_OUTPUT}/libpq.so.5" "${BUNDLE_STAGING}/ruby-android/lib/"
  echo "Included libpq.so.5"
fi

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

# Strip debug symbols to reduce size
find "${BUNDLE_STAGING}/ruby-android" -name "*.so" -exec strip --strip-debug {} \; 2>/dev/null || true
find "${BUNDLE_STAGING}/ruby-android/bin" -type f -exec strip --strip-debug {} \; 2>/dev/null || true

RUBY_SIZE=$(du -sh "${BUNDLE_STAGING}/ruby-android" | awk '{print $1}')
echo "Ruby size: ${RUBY_SIZE}"

echo ""
echo "=== Copying MSF ==="
# Fix permissions on Docker build output (some gems have 600 archives)
docker run --rm -v "${BUILD_OUTPUT}:/data" alpine chmod -R a+r /data 2>/dev/null || true
cp -a "${BUILD_OUTPUT}/metasploit-framework" "${BUNDLE_STAGING}/metasploit-framework"

# Add VERSION file for System.getLocalMsfVersion()
MSF_VER="6.4.123-dev"
if [ -f "${BUILD_OUTPUT}/metasploit-framework/lib/metasploit/framework/version.rb" ]; then
  MSF_VER=$(grep -o "'[0-9][^']*'" "${BUILD_OUTPUT}/metasploit-framework/lib/metasploit/framework/version.rb" | head -1 | tr -d "'" || echo "6.4.123-dev")
fi
echo "${MSF_VER}" > "${BUNDLE_STAGING}/metasploit-framework/VERSION"
echo "MSF version: ${MSF_VER}"

# Remove unnecessary files to reduce size
echo "Trimming MSF bundle..."
cd "${BUNDLE_STAGING}/metasploit-framework"
rm -rf .git .github .gitignore .rubocop* .yardopts
rm -rf documentation/ docs/ docker/ test/ spec/ features/
rm -rf external/ tools/dev/ tools/exploit/
find . -name "*.md" -not -name "Gemfile*" -delete 2>/dev/null || true
find . -name "*.txt" -not -name "*.txt.erb" -delete 2>/dev/null || true
find . -name "CHANGELOG*" -o -name "LICENSE*" -o -name "COPYING*" | xargs rm -f 2>/dev/null || true
# Remove .o and .a files from gem native extensions (only .so needed)
find . -name "*.o" -delete 2>/dev/null || true
find . -name "*.a" -delete 2>/dev/null || true
# Strip native extension .so files
find . -name "*.so" -exec strip --strip-debug {} \; 2>/dev/null || true

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
tar czf "${BUNDLE_FILE}" ruby-android/ metasploit-framework/

BUNDLE_SIZE=$(du -sh "${BUNDLE_FILE}" | awk '{print $1}')
echo "Bundle: ${BUNDLE_SIZE}"

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
