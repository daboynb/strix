#!/bin/bash
# Probe (emulator-probe.yml): can an x86_64 Android emulator run the msf bundle's
# aarch64 Ruby as a plain executable, through the system image's ARM translation?
# Runs on the CI host with the emulator up (adb); pushes only ruby-android/.
#
#   emulator-ruby-probe.sh <ruby-msf-bundle.tar.gz.bin>
#
# Prints the device ABI/translation properties, then runs `ruby -v` and loads the
# static stdlib openssl as root. Exit 0 only if Ruby runs.
set -euo pipefail
[ $# -eq 1 ] || { echo "usage: $0 <ruby-msf-bundle.tar.gz.bin>" >&2; exit 2; }
bundle=$1
work=$(mktemp -d)
dev=/data/local/tmp/strix-ruby

adb wait-for-device
adb root > /dev/null
adb wait-for-device
echo "== device"
for p in ro.build.version.release ro.build.version.sdk ro.product.cpu.abilist \
         ro.dalvik.vm.native.bridge ro.enable.native.bridge.exec; do
  echo "$p=$(adb shell getprop "$p" | tr -d '\r')"
done
adb shell 'ls /proc/sys/fs/binfmt_misc/ 2>/dev/null' | tr -d '\r' | sed 's/^/binfmt_misc: /' || true

echo "== extract ruby-android"
tar -xzf "$bundle" -C "$work" ruby-android
file "$work/ruby-android/bin/ruby"

echo "== push"
adb shell "rm -rf $dev"
adb push "$work/ruby-android" "$dev" > /dev/null
adb shell "chmod 755 $dev/bin/ruby"

run() { # <ruby args...>: run the bundle's Ruby on the device as root, like the app's env
  adb shell "cd $dev && LD_LIBRARY_PATH=$dev/lib HOME=/data/local/tmp ./bin/ruby $*"
}
echo "== ruby -v"
run -v
echo "== static openssl"
run -e "'require \"openssl\"; puts OpenSSL::VERSION, OpenSSL::OPENSSL_LIBRARY_VERSION'"
echo "PASS: the aarch64 Ruby runs on this emulator"
