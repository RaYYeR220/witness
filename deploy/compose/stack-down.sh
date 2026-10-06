#!/usr/bin/env bash
# Stops the local stack. Chain data is kept; use `stack-up.sh --reset` to wipe it.
set -euo pipefail
here="$(cd "$(dirname "$0")" && { pwd -W 2>/dev/null || pwd; })"
root="$(cd "$here/../.." && { pwd -W 2>/dev/null || pwd; })"
tangle="$root/vendor/iota-tangle/docker/main"

docker compose -f "$here/docker-compose.aerios.yml" down
docker compose -f "$here/inx-poi.yml" down
docker compose -f "$here/messages-api.yml" down
[ -d "$tangle" ] && docker compose -f "$tangle/hornet-main.yaml" down
