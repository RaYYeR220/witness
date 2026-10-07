#!/usr/bin/env bash
# Brings up the local aeriOS IOTA stack (Git Bash / Linux / macOS).
#   ./stack-up.sh             start (bootstraps the private Tangle on first run)
#   ./stack-up.sh --reset     wipe chain data and bootstrap a fresh Tangle
#   ./stack-up.sh --witness   also build and start the Witness overlay
#                             (docker-compose.witness.yml; replaces the stock Trust Manager)
set -euo pipefail

here="$(cd "$(dirname "$0")" && { pwd -W 2>/dev/null || pwd; })"
root="$(cd "$here/../.." && { pwd -W 2>/dev/null || pwd; })"
# WITNESS_VENDOR_DIR (environment, else deploy/compose/.env) shares one set of upstream
# checkouts, and so one chain, between worktrees.
if [ -z "${WITNESS_VENDOR_DIR:-}" ] && [ -f "$here/.env" ]; then
  WITNESS_VENDOR_DIR="$(sed -n 's/^WITNESS_VENDOR_DIR=//p' "$here/.env" | tail -n 1 | tr -d '\r')"
fi
vendor="${WITNESS_VENDOR_DIR:-$root/vendor}"
tangle="$vendor/iota-tangle/docker/main"
reset=0
witness=0
for arg in "$@"; do
  case "$arg" in
    --reset) reset=1 ;;
    --witness) witness=1 ;;
    *) echo "usage: $0 [--reset] [--witness]" >&2; exit 2 ;;
  esac
done

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
docker compose -f hornet-main.yaml -f "$here/hornet-loopback.yml" up -d

echo "== messages relay"
docker compose -f "$here/messages-api.yml" up -d

echo "== inx-poi"
docker compose -f "$here/inx-poi.yml" up -d

echo "== secrets (broker passwords, tokens, relay key; existing ones are kept)"
"$here/setup-secrets.sh"

if [ "$witness" = 1 ]; then
  echo "== Orion-LD, Mongo, Postgres, Mosquitto (the Witness overlay brings its own Trust Manager)"
  docker compose -f "$here/docker-compose.aerios.yml" stop trustmanager
  docker compose -f "$here/docker-compose.aerios.yml" up -d mongo-db orion-ld init-orion postgres mosquitto
else
  echo "== Orion-LD, Mongo, Trust Manager, Postgres, Mosquitto"
  docker compose -f "$here/docker-compose.aerios.yml" up -d
fi

echo "== waiting for HORNET REST"
for _ in $(seq 1 60); do
  curl -sf http://localhost:14265/api/core/v2/info >/dev/null && break
  sleep 2
done
curl -s http://localhost:14265/api/core/v2/info | head -c 400; echo

if [ "$witness" = 1 ]; then
  echo "== Witness overlay (the patched Trust Manager replaces the stock one)"
  # One image at a time: parallel builds need more memory than small machines have.
  for svc in witness-relay witness-api witness-indexer witness-anchor witness-console trust-manager-witness; do
    docker compose -f "$here/docker-compose.witness.yml" build "$svc"
  done
  docker compose -f "$here/docker-compose.witness.yml" up -d --wait --wait-timeout 300
  docker compose -f "$here/docker-compose.witness.yml" ps
fi
