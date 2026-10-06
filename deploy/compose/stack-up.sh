#!/usr/bin/env bash
# Brings up the local aeriOS IOTA stack (Git Bash / Linux / macOS).
#   ./stack-up.sh           start (bootstraps the private Tangle on first run)
#   ./stack-up.sh --reset   wipe chain data and bootstrap a fresh Tangle
set -euo pipefail

here="$(cd "$(dirname "$0")" && { pwd -W 2>/dev/null || pwd; })"
root="$(cd "$here/../.." && { pwd -W 2>/dev/null || pwd; })"
vendor="$root/vendor"
tangle="$vendor/iota-tangle/docker/main"
reset=0
[ "${1:-}" = "--reset" ] && reset=1

# MSYS rewrites container paths in docker args under Git Bash; we only use compose files, but be safe.
export MSYS_NO_PATHCONV=1
if netstat -ano 2>/dev/null | grep -q "127.0.0.1:${RELAY_PORT:-5555} .*LISTENING"; then echo "warn: 127.0.0.1:${RELAY_PORT:-5555} is taken by another process (adb/emulator?); set RELAY_PORT"; fi

fetch() {
  local name="$1"
  if [ -d "$vendor/$name/.git" ]; then
    git -C "$vendor/$name" pull --ff-only --quiet || echo "warn: could not update $name, using local copy"
  else
    mkdir -p "$vendor"
    git clone --depth 1 "https://github.com/eclipse-aerios/$name" "$vendor/$name"
  fi
}

fetch iota-tangle
fetch iota-messages-api
fetch trust-manager

if [ "$reset" = 1 ]; then
  echo "== reset: stopping stack and wiping chain data"
  "$here/stack-down.sh" || true
  docker run --rm -v "$tangle:/w" alpine sh -c 'rm -rf /w/privatedb /w/snapshots'
fi

cd "$tangle"
if [ ! -d privatedb/hornet ] || [ -z "$(ls -A privatedb/hornet 2>/dev/null)" ]; then
  echo "== bootstrapping private Tangle"
  # Their bootstrap.sh needs root + chown and refuses to run on Windows; these are its steps.
  mkdir -p snapshots/hornet privatedb/hornet privatedb/state
  docker compose -f startup.yaml run --rm create-snapshots
  docker compose -f startup.yaml run --rm bootstrap-network
else
  echo "== privatedb exists, skipping bootstrap"
fi

echo "== HORNET + coordinator + dashboard"
docker compose -f hornet-main.yaml up -d

echo "== messages relay"
docker compose -f "$here/messages-api.yml" up -d

echo "== inx-poi"
docker compose -f "$here/inx-poi.yml" up -d

echo "== Orion-LD, Mongo, Trust Manager, Postgres, Mosquitto"
docker compose -f "$here/docker-compose.aerios.yml" up -d

echo "== waiting for HORNET REST"
for _ in $(seq 1 60); do
  curl -sf http://localhost:14265/api/core/v2/info >/dev/null && break
  sleep 2
done
curl -s http://localhost:14265/api/core/v2/info | head -c 400; echo
