#!/bin/bash
# Entrypoint that fixes output file ownership.
# Build runs as root (needed for cross-compilation) but output files
# are chowned to the host user so mounted volumes don't end up as root.

# Auto-detect host UID/GID from the mounted output directory
if [ -z "${HOST_UID}" ] && [ -d /opt/output ]; then
  HOST_UID=$(stat -c '%u' /opt/output)
  HOST_GID=$(stat -c '%g' /opt/output)
fi

"$@"
exit_code=$?

if [ -n "${HOST_UID}" ] && [ "${HOST_UID}" != "0" ]; then
  chown -R "${HOST_UID}:${HOST_GID}" /opt/output 2>/dev/null || true
fi

exit $exit_code
