#!/bin/bash
# Run an msf bundle on an Android emulator the way the app does, and check its RPC.
# CI host side (emulator-msf-test.yml), emulator already booted (adb). The emulator is
# x86_64: the bundle's aarch64 binaries run through the image's ARM translation.
#
#   emulator-msf-test.sh <ruby-msf-bundle.tar.gz.bin> [timeout seconds, default 1800]
#
# 1. extract as the app installs it (ruby-android/ -> ruby/, metasploit-framework/ -> msf/)
# 2. apply the app's own post-install patches (MsfBundleStageTest -> MsfBundlePatches)
# 3. push to /data/local/tmp/strix, start msfrpcd with the app's command + env as root
#    (emulator-msf-device.sh), then auth.login/core.version/core.module_stats
#    (emulator-rpc-check.rb). Exit 0 only if all of it works.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
STRIX_DIR="$(dirname "$SCRIPT_DIR")"
[ $# -ge 1 ] && [ $# -le 2 ] || { echo "usage: $0 <bundle.tar.gz.bin> [timeout s]" >&2; exit 2; }
bundle=$(realpath "$1") limit=${2:-1800}
dev=/data/local/tmp/strix
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

echo "== stage the bundle as the app installs it"
mkdir -p "$work/stage"
tar -xzf "$bundle" -C "$work/stage" ruby-android metasploit-framework
mv "$work/stage/ruby-android" "$work/stage/ruby"
mv "$work/stage/metasploit-framework" "$work/stage/msf"

echo "== app post-install patches (MsfBundlePatches via MsfBundleStageTest)"
(cd "$STRIX_DIR" && STRIX_MSF_STAGE="$work/stage" ./gradlew --no-daemon -q \
  :app:testDebugUnitTest --tests 'org.csploit.strix.data.MsfBundleStageTest' --rerun)
grep -q 'compatibility wrapper' "$work/stage/msf/msfrpcd" \
  || { echo "FAIL: msfrpcd wrapper not written, patches did not run"; exit 1; }
tar -cf "$work/stage.tar" -C "$work/stage" ruby msf
rm -rf "$work/stage"

echo "== install on the emulator"
adb wait-for-device
adb root > /dev/null
adb wait-for-device
echo "Android $(adb shell getprop ro.build.version.release | tr -d '\r'), ABIs $(adb shell getprop ro.product.cpu.abilist | tr -d '\r')"
adb shell "rm -rf $dev && mkdir -p $dev"
adb push "$work/stage.tar" "$dev/stage.tar" > /dev/null
adb shell "cd $dev && tar -xf stage.tar && rm stage.tar"
adb push "$SCRIPT_DIR/emulator-msf-device.sh" "$SCRIPT_DIR/emulator-rpc-check.rb" "$dev/" > /dev/null

echo "== start msfrpcd like the app and check the RPC"
pass=$(openssl rand -hex 12)
adb shell "sh $dev/emulator-msf-device.sh $dev 55553 $pass $limit"
