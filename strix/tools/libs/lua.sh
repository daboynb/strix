#!/bin/bash
source "$(dirname "$0")/../env.sh"

echo ""
echo "=== Building Lua ${LUA_VERSION} ==="
cd /opt/src/lua-${LUA_VERSION}

make clean 2>/dev/null || true

# Lua's Makefile uses MYCFLAGS/MYLDFLAGS for custom flags.
# Build as a static library for Android ARM64.
make \
  CC="${CC}" \
  AR="${AR} rcu" \
  RANLIB="${RANLIB}" \
  MYCFLAGS="-fPIC -O2 -DLUA_USE_POSIX -DLUA_USE_DLOPEN" \
  MYLDFLAGS="-fPIE -pie" \
  linux -j$(nproc) 2>&1

# Install headers and static lib to sysroot
cp src/lua.h src/luaconf.h src/lualib.h src/lauxlib.h ${SYSROOT}/include/
cp src/liblua.a ${SYSROOT}/lib/

echo "=== Lua installed to ${SYSROOT} ==="
ls -lh ${SYSROOT}/lib/liblua.a 2>/dev/null
