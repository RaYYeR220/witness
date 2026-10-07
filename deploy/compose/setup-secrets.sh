#!/usr/bin/env bash
# Generates the run-time secrets of the compose stack into secrets/ (gitignored, never baked
# into an image). Idempotent: passwords, tokens and keys that exist are kept; files derived
# from them are rewritten.
#
#   deploy/compose/setup-secrets.sh        # WITNESS_SECRETS_DIR overrides <repo>/secrets
#
# Creates, when missing:
#   mosquitto/{relay,indexer,observer}.password   broker passwords (random)
#   tokens/{ingest,report,posture,anchor-admin}.token
#   relay/sig-1.pem                               relay signing key as PKCS#8 (from sig-1.jwk.json)
#   relay/search.key                              blind-index key for sealed tags (random)
# Rewrites:
#   mosquitto/passwd                              hashed broker passwords (when a password changed)
#   relay/recipients.json                         public X25519 key of the domain (from deploy/identity)
#   compose/{relay,indexer,api,anchor}.env        credentials each container gets, nothing more
#
# Component signing keys (<component>/sig-1.jwk.json) come from anchor/scripts/bootstrap-identities.ts.
# Helper containers (the broker image for hashing, python:3.12-slim for the rest) only compute
# and print; every file is written here, by the invoking user. Only file names are printed.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
# Same settings as docker compose: the environment first, then deploy/compose/.env.
from_env_file() { [ -f "$here/.env" ] && sed -n "s/^$1=//p" "$here/.env" | tail -n 1 | tr -d '\r'; true; }
: "${WITNESS_SECRETS_DIR:=$(from_env_file WITNESS_SECRETS_DIR)}"
: "${WITNESS_REBASED_NETWORK:=$(from_env_file WITNESS_REBASED_NETWORK)}"
secrets="${WITNESS_SECRETS_DIR:-$root/secrets}"
case "$secrets" in
  /* | [A-Za-z]:*) ;;
  *) secrets="$here/$secrets" ;; # relative paths are relative to deploy/compose, as in compose
esac
# Docker on Windows wants native paths; Git Bash's MSYS must not rewrite container paths.
export MSYS_NO_PATHCONV=1
native() { (cd "$1" && { pwd -W 2>/dev/null || pwd; }); }

umask 077
mkdir -p "$secrets/mosquitto" "$secrets/tokens" "$secrets/compose" "$secrets/relay"
secrets_n="$(native "$secrets")"
identity_n="$(native "$root/deploy/identity")"

random_token() { head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n'; }

keep_random() {
  if [ ! -s "$1" ]; then
    random_token >"$1"
    echo "created ${1#"$secrets"/}"
  fi
}

for user in relay indexer observer; do keep_random "$secrets/mosquitto/$user.password"; done
for token in ingest report posture anchor-admin; do keep_random "$secrets/tokens/$token.token"; done

# The broker's hashed password file, rebuilt when a password is newer than it. The plain
# passwords travel on stdin, never on a command line.
rebuild=0
[ -s "$secrets/mosquitto/passwd" ] || rebuild=1
for user in relay indexer observer; do
  if [ "$secrets/mosquitto/$user.password" -nt "$secrets/mosquitto/passwd" ]; then rebuild=1; fi
done
if [ "$rebuild" = 1 ]; then
  for user in relay indexer observer; do
    printf '%s:%s\n' "$user" "$(cat "$secrets/mosquitto/$user.password")"
  done | docker run --rm -i --network none --entrypoint sh eclipse-mosquitto:2 -c \
    'cat > /tmp/passwd && mosquitto_passwd -U /tmp/passwd 2>/dev/null && cat /tmp/passwd' \
    >"$secrets/mosquitto/passwd.new"
  [ -s "$secrets/mosquitto/passwd.new" ] || { echo "error: hashing the broker passwords failed" >&2; exit 1; }
  mv "$secrets/mosquitto/passwd.new" "$secrets/mosquitto/passwd"
  echo "wrote mosquitto/passwd"
fi

# Keys and env files, with the Python standard library only. The container reads secrets/
# read-only and returns the files as a tar stream on stdout; messages go to stderr.
docker run --rm --network none -e WITNESS_REBASED_NETWORK="${WITNESS_REBASED_NETWORK:-testnet}" \
  -v "$secrets_n:/s:ro" -v "$identity_n:/identity:ro" python:3.12-slim python -c "$(cat <<'PY'
import base64
import io
import json
import os
import secrets
import sys
import tarfile
import time

S = "/s"
network = os.environ["WITNESS_REBASED_NETWORK"]
out = tarfile.open(fileobj=sys.stdout.buffer, mode="w|")


def b64u_decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def exists(path):
    return os.path.exists(os.path.join(S, path))


def read(path):
    with open(os.path.join(S, path), encoding="utf-8") as f:
        return f.read().strip()


def emit(path, text, verb="created"):
    data = text.encode("utf-8")
    info = tarfile.TarInfo(path)
    info.size, info.mode, info.mtime = len(data), 0o600, int(time.time())
    out.addfile(info, io.BytesIO(data))
    print(f"{verb} {path}", file=sys.stderr)


def jwk(component):
    path = os.path.join(S, component, "sig-1.jwk.json")
    if not os.path.exists(path):
        # The base stack needs no component keys; the Witness overlay does.
        print(f"warning: no {component}/sig-1.jwk.json (anchor/scripts/bootstrap-identities.ts "
              "creates it); the Witness overlay needs it", file=sys.stderr)
        return None
    with open(path, encoding="utf-8") as f:
        key = json.load(f)
    if key.get("kty") != "OKP" or key.get("crv") != "Ed25519" or "d" not in key or "#" not in key.get("kid", ""):
        sys.exit(f"{component}/sig-1.jwk.json is not an Ed25519 private JWK with a kid")
    return key


# relay/sig-1.pem: the relay reads PKCS#8 PEM. PKCS#8 of an Ed25519 seed is a fixed prefix + seed.
relay = jwk("relay")
if relay is not None and not exists("relay/sig-1.pem"):
    seed = b64u_decode(relay["d"])
    if len(seed) != 32:
        sys.exit("relay key: an Ed25519 seed is 32 bytes")
    der = bytes.fromhex("302e020100300506032b657004220420") + seed
    emit("relay/sig-1.pem", "-----BEGIN PRIVATE KEY-----\n" + base64.encodebytes(der).decode()
         + "-----END PRIVATE KEY-----\n")

if not exists("relay/search.key"):
    emit("relay/search.key", base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=") + "\n")

# Sealed payloads are encrypted to the domain's key-agreement key (public, deploy/identity).
with open(f"/identity/{network}.json", encoding="utf-8") as f:
    identity = json.load(f)
domain = next(e for e in identity["identities"] if e["name"] == "domain")
kex = next(k for k in domain["keys"] if k["type"] == "X25519")
emit("relay/recipients.json", json.dumps([{**kex["publicKeyJwk"], "kid": kex["kid"]}], indent=2) + "\n",
     "wrote")

anchor = jwk("anchor")
mqtt = "mqtt://{user}:{password}@witness-mosquitto:1883"
env = {
    "relay": {
        "RELAY_MQTT_URL": mqtt.format(user="relay", password=read("mosquitto/relay.password")),
        "RELAY_EXPLORER_TOKEN": read("tokens/ingest.token"),
    },
    "indexer": {
        "WITNESS_MQTT": mqtt.format(user="indexer", password=read("mosquitto/indexer.password")),
    },
    "api": {
        "WITNESS_INGEST_TOKEN": read("tokens/ingest.token"),
        "WITNESS_REPORT_TOKEN": read("tokens/report.token"),
        "WITNESS_POSTURE_TOKEN": read("tokens/posture.token"),
    },
    "anchor": {
        "ANCHOR_ADMIN_TOKEN": read("tokens/anchor-admin.token"),
    },
}
if relay is not None:
    env["relay"].update(RELAY_DID=relay["kid"].partition("#")[0], RELAY_KID=relay["kid"])
if anchor is not None:
    env["indexer"]["WITNESS_ANCHOR_DID"] = anchor["kid"].partition("#")[0]
for service, values in env.items():
    lines = [f"# generated by deploy/compose/setup-secrets.sh; credentials of {service} only"]
    lines += [f"{k}={v}" for k, v in values.items()]
    emit(f"compose/{service}.env", "\n".join(lines) + "\n", "wrote")
out.close()
PY
)" | tar -x -f - -C "$secrets"
