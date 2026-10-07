#!/usr/bin/env bash
# Stops the local stack. Chain data is kept; use `stack-up.sh --reset` to wipe it.
set -euo pipefail
here="$(cd "$(dirname "$0")" && { pwd -W 2>/dev/null || pwd; })"
root="$(cd "$here/../.." && { pwd -W 2>/dev/null || pwd; })"
if [ -z "${WITNESS_VENDOR_DIR:-}" ] && [ -f "$here/.env" ]; then
  WITNESS_VENDOR_DIR="$(sed -n 's/^WITNESS_VENDOR_DIR=//p' "$here/.env" | tail -n 1 | tr -d '\r')"
fi
tangle="${WITNESS_VENDOR_DIR:-$root/vendor}/iota-tangle/docker/main"

# The Witness overlay first (by project name: its compose file needs deploy/compose/.env).
docker compose -p witness down
docker compose -f "$here/docker-compose.aerios.yml" down
docker compose -f "$here/inx-poi.yml" down
docker compose -f "$here/messages-api.yml" down
[ -d "$tangle" ] && docker compose -f "$tangle/hornet-main.yaml" -f "$here/hornet-loopback.yml" down
