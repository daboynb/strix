#!/system/bin/sh
# Device side of emulator-msf-test.sh (Android toybox sh, as root): start msfrpcd from
# an installed msf bundle exactly like the app (MsfrpcdLaunch.kt: command + env), wait
# for it, then check the RPC with emulator-rpc-check.rb. Prints the daemon log.
#
#   sh emulator-msf-device.sh <base dir with ruby/ msf/> <port> <password> <timeout s>
base=$1 port=$2 pass=$3 limit=$4
ruby=$base/ruby msf=$base/msf log=$base/msfrpcd.log
api=
for d in "$ruby"/lib/ruby/[0-9]*.[0-9]*.[0-9]*; do
  [ -d "$d" ] && api=${d##*/}
done
[ -n "$api" ] || { echo "FAIL: no ruby API dir in $ruby/lib/ruby"; exit 1; }
mkdir -p "$base/msf-home"

# The app adds RUBYLIB only for non load-relative Rubies; smoke checks require load-relative.
export HOME="$base/msf-home"
export PATH="$ruby/bin:$msf:/system/bin:/system/xbin"
export LD_LIBRARY_PATH="$ruby/lib"
export GEM_HOME="$msf/vendor/bundle/ruby/$api"
export GEM_PATH="$msf/vendor/bundle/ruby/$api:$ruby/lib/ruby/gems/$api"
export OPENSSL_CONF="$ruby/ssl/openssl.cnf"
export OPENSSL_MODULES="$ruby/lib/ossl-modules"

"$ruby/bin/ruby" "$msf/msfrpcd" -f -a 127.0.0.1 -p "$port" -U msf -P "$pass" > "$log" 2>&1 &
pid=$!
echo "msfrpcd pid $pid, waiting up to ${limit}s for MSGRPC ready"

waited=0 rc=1
while :; do
  if grep -q 'MSGRPC ready' "$log"; then
    echo "msfrpcd ready after ${waited}s"
    "$ruby/bin/ruby" "$base/emulator-rpc-check.rb" "$port" "$pass"
    rc=$?
    break
  fi
  if ! kill -0 "$pid" 2> /dev/null; then
    echo "FAIL: msfrpcd exited before being ready"
    break
  fi
  if [ "$waited" -ge "$limit" ]; then
    echo "FAIL: msfrpcd not ready after ${limit}s"
    break
  fi
  sleep 5
  waited=$((waited + 5))
done

kill "$pid" 2> /dev/null
echo "----- msfrpcd log -----"
cat "$log"
exit "$rc"
