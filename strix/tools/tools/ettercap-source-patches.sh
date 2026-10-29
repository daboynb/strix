#!/bin/bash
# Sourced by ettercap.sh (same shell: inherits set -euo pipefail, env.sh vars, cwd).
set -euo pipefail
# Android-specific source patches to ettercap (raw IPv4 socket fallbacks).

# --- Patch 5: Android L2 forwarding fallback ---
# Android restricts AF_INET+SOCK_RAW (LIBNET_RAW4_ADV init fails → lnet_IP4=NULL).
# ettercap's forward_unified_sniff() silently drops ALL IPv4 packets when
# lnet_IP4 is NULL, breaking -M arp forwarding entirely.
# Fix: fall back to L2 (AF_PACKET via send_to_L2) which works on Android.
cd /opt/src/ettercap-${ETTERCAP_VERSION}

patch -p1 --forward < /opt/patches/ettercap-l2-forward.patch
grep -q "send_to_L2(po);" src/ec_sniff_unified.c || { echo "FAIL: L2 forwarding patch not applied" >&2; exit 1; }
echo "  Applied Android L2 forwarding fallback patch"

# --- Patch 5b: send_to_L3 fallback to send_to_L2 on Android ---
# Same root cause as Patch 5: lnet_IP4 is NULL on Android (no AF_INET+SOCK_RAW).
# send_to_L3() is also used by plug-ins (notably dns_spoof's send_dns_reply),
# not just the unified forward path. Without this fallback, dns_spoof builds
# the fake reply but it never leaves the device because send_to_L3 returns
# early on l == NULL. The packet object already carries the correct L2 header
# (dst MAC = victim, src MAC = us) so send_to_L2 can ship it as-is.
perl -0777 -i -pe 's/if\(l == NULL\)\s*\n\s*return -E_NOTHANDLED;/if(l == NULL)\n      return send_to_L2(po);/g' src/ec_send.c
if grep -q "return send_to_L2(po);" src/ec_send.c; then
  echo "  Applied send_to_L3 → send_to_L2 fallback patch"
else
  echo "FAIL: send_to_L3 patch not applied — dns_spoof replies would not leave the device" >&2
  exit 1
fi
