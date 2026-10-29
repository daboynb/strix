#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/../env.sh"
HYDRA_SCRIPTS="$(cd "$(dirname "$0")" && pwd)"

echo ""
echo "=== Building hydra ${HYDRA_VERSION} ==="
cd /opt/src/thc-hydra-${HYDRA_VERSION}


# Hydra uses a custom configure that can't cross-compile SSL detection.
# The configure test tries to compile+run an OpenSSL program, which fails
# in cross-compilation (ARM64 binary on x86 host). We run configure first,
# then patch the Makefile to force SSL support with our cross-compiled OpenSSL.
# Android NDK fortified unistd.h needs SSIZE_MAX from limits.h
export CFLAGS="-fPIC -O2 -I${SYSROOT}/include -include limits.h"
export LDFLAGS="-fPIE -pie -static-libstdc++ -L${SYSROOT}/lib"
export CPPFLAGS="-I${SYSROOT}/include"

./configure \
  --prefix=${PREFIX} \
  --disable-xhydra \
  --with-ssl=${SYSROOT} \
  2>&1 || echo "  NOTE: hydra configure exited non-zero (its run-time probes can't work when cross-compiling); Makefile is checked below"

source "${HYDRA_SCRIPTS}/hydra-makefile-modules.sh"

source "${HYDRA_SCRIPTS}/hydra-legacy-crypto.sh"

make -j$(nproc) 2>&1

cp hydra ${PREFIX}/bin/
${STRIP} ${PREFIX}/bin/hydra

# Reset flags
export CFLAGS="-fPIC -O2"
export LDFLAGS="-fPIE -pie -static-libstdc++"
unset CPPFLAGS

echo "=== hydra installed ==="
ls -lh ${PREFIX}/bin/hydra
