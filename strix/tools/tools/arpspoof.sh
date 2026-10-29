#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/../env.sh"

echo ""
echo "=== Building arpspoof_strix (custom dsniff-compatible, 400ms interval) ==="

# We ship our own minimal arpspoof instead of dsniff's:
#  - no legacy libnet dependency
#  - configurable sleep (default 400ms so aggressive Linux re-ARP clients
#    stay poisoned; dsniff's hardcoded 2s loses the race)
#  - single translation unit, no autotools
# Source: arpspoof_strix.c next to this script (copied to /opt/tools with it).
cp "$(dirname "$0")/arpspoof_strix.c" /opt/src/arpspoof_strix.c

${CC} ${CFLAGS} -O2 -o ${PREFIX}/bin/arpspoof /opt/src/arpspoof_strix.c
${STRIP} ${PREFIX}/bin/arpspoof

echo "=== arpspoof installed ==="
ls -lh ${PREFIX}/bin/arpspoof
file ${PREFIX}/bin/arpspoof | grep -o 'ARM aarch64'
