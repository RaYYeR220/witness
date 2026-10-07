# Operations: local aeriOS stack

Everything runs in Docker. Scripts are bash (Git Bash on Windows).

## Bring-up

```bash
deploy/compose/stack-up.sh             # first run bootstraps a private Tangle
deploy/compose/stack-up.sh --witness   # the same, plus the Witness overlay (see Deployment)
deploy/compose/stack-up.sh --reset     # wipe chain data and bootstrap from scratch
deploy/compose/stack-down.sh           # stop everything, keep chain data
```

`stack-up.sh` clones `iota-tangle`, `iota-messages-api` and `trust-manager` from
`eclipse-aerios` into `vendor/` (gitignored), then starts, in order: HORNET +
inx-coordinator + inx-dashboard, the messages relay (`messages-api.yml`),
inx-poi (`inx-poi.yml`), the run-time secrets (`setup-secrets.sh`, see below) and
the rest (`docker-compose.aerios.yml`: Mongo, Orion-LD, Trust Manager, Postgres,
Mosquitto). All containers share the `iota-net` network. The compose files use
separate project names so the stacks can be restarted independently. Settings
come from `deploy/compose/.env` (copy `.env.example`); `WITNESS_VENDOR_DIR` lets
several checkouts share one `vendor/`, and so one chain.

Trust Manager runs from `eclipseaerios/trust-manager:latest` with
`deploy/compose/manager.ini` mounted over its config: `scoreInterval = 1`
(minutes) and the relay/HORNET addresses pointed at the local containers.
`init-orion` seeds three sample InfrastructureElements. A `trust.score` block
shows up within a minute or two.

## Ports

| Service | Host port |
| --- | --- |
| HORNET REST (also `/api/poi/v1`, `/api/debug/v1`) | 14265 |
| HORNET INX | 9029 |
| inx-dashboard (admin / admin) | 31011 |
| Messages relay (`POST /upload?node=iota-hornet`) | 5555 (`RELAY_PORT` to change) |
| inx-poi | 9687 |
| Orion-LD | 1026 |
| Mongo | 27017 |
| Trust Manager | 3100 (container 3000) |
| Postgres (`witness-postgres`; owner password in `secrets/postgres/postgres.password`) | 5432 |
| Mosquitto (`witness-mosquitto`, logins only) | 1883 MQTT, 9001 websockets |
| Witness console (overlay) | 8080 |
| Witness API (overlay; also `:14265/api/witness/v1`) | 7200 |
| Witness relay (overlay, `POST /upload?node=iota-hornet`) | 5557 (`WITNESS_RELAY_PORT`) |
| Witness anchor (overlay: `/resolve`, `/checkpoints`) | 7300 |
| Trust Manager, producer-signing (overlay) | 3101 (container 3000) |

Every port is published on the loopback interfaces only, 127.0.0.1 and ::1
(`localhost` resolves to ::1 first on some hosts). The organisers' HORNET compose
publishes on all interfaces; `hornet-loopback.yml` overrides that.

Check it is alive: `curl -s localhost:14265/api/core/v2/info` and watch
`confirmedMilestone.index` grow about every 5 seconds. `isHealthy` stays
`false` on this single-node private Tangle; that is expected.

## Test vectors

`uv run python scripts/capture_vectors.py` (needs the stack up; set
`RELAY_URL` if the relay is not on 5555) submits ten tagged blocks, waits for
confirmation and rewrites `core/tests/vectors/*.json`. It asserts as it goes:
`blockId == BLAKE2b-256(raw)`, the white-flag list of every milestone
reproduces its `inclusionMerkleRoot`, `whiteFlagIndex` equals the position in
that list, and each milestone id equals the next milestone's
`previousMilestoneId`. Captured data is real node output.

Protocol facts learned while capturing (relevant for the parsers):

- A block wrapping a payload is `u8 protocolVersion(2) | u8 parentCount |
  parents | u32 payloadLength | payload | u64 nonce` (little endian).
- `GET /milestones/by-index/{i}` with the raw `Accept` header returns the
  payload without the `u32` length prefix: `u32 type(7) | essence | u8 sigCount |
  sigs`. The essence excludes the type word.
- milestone id = BLAKE2b-256(essence). Each coordinator signs that 32-byte id
  with Ed25519 (checked with `cryptography` against both keys).
- The milestone's block id is not exposed by the API. Rebuild the block from the
  milestone JSON (`parents`, nonce 0 on this network) and hash it; the node
  serves the same bytes back.
- A milestone M's block is referenced by milestone M+1 (`whiteFlagIndex` 0),
  and `/blocks/{id}/metadata` of that block reports `milestoneIndex` = M.
- Debug cone: `GET /api/debug/v1/block-cones/{blockId}` returns the blocks that
  are not yet referenced by earlier milestones, ending at `blockId`, in
  white-flag order.

### Does a milestone's cone include the milestone block itself?

No. The blocks referenced by milestone M (whose white-flag order hashes to
`inclusionMerkleRoot`) do not contain M's own block. They start with the
previous milestone's block (position 0), then the
tagged blocks. M's own block is position 0 of milestone M+1. To get the list for M,
call the debug cone for each of M's `parents` in order and concatenate without
duplicates (`cones.json` is built this way). Calling the cone endpoint on M's
own block returns only that block, since its parents are already referenced.

## Indexer

```bash
# Credentials go in the environment, not on the command line (`ps` shows arguments): the
# database DSN and the broker URL with the `indexer` login, from secrets/compose/indexer.env.
set -a; . secrets/compose/indexer.env; set +a
export WITNESS_DB="${WITNESS_DB/@witness-postgres:/@127.0.0.1:}"
export WITNESS_MQTT="${WITNESS_MQTT/@witness-mosquitto:/@127.0.0.1:}"
uv run witness-indexer --schema witness --policy deploy/policy.json \
  [--source inx|rest] [--validate] [--no-incidents]
```

`--db` defaults to `$WITNESS_DB`, `--mqtt` (submission records) to `$WITNESS_MQTT`,
`--alerts-mqtt` to `$WITNESS_ALERTS_MQTT`, else the `--mqtt` broker. The broker takes logins
only: the `indexer` login may read `aerios/iota/submissions/#` and write `witness/alerts/#`.

- `--source inx` (default) streams confirmed milestones over INX (`127.0.0.1:9029`)
  and reads each cone with `ReadMilestoneCone`. If INX does not answer within
  `--inx-timeout` seconds at startup, the indexer logs it and polls the REST API
  instead. The choice is made once: if INX drops later, the indexer keeps
  reconnecting to INX (restart it to switch).
- `--source rest` polls `/api/core/v2/info` every `--poll` seconds and rebuilds
  each cone from block metadata (`referencedByMilestoneIndex`,
  `whiteFlagIndex`), walking back from the milestone's parents. It needs only the
  core routes, not the debug API.
- Every milestone is one database transaction: milestone, cone blocks, messages
  with verdicts, blind tokens, trust-score lineage, alerts, then the cursor and
  the events. After a crash or reconnect it resumes at cursor + 1; replaying a
  milestone changes nothing.
- Before that transaction a milestone must continue the stored chain (its
  `previousMilestoneId` is the stored milestone before it), its cone must hash to
  its inclusion Merkle root, and every signing key it uses must resolve (at the
  milestone's time). Otherwise nothing is written and the milestone is retried.
- A writer policy is required: `--policy policy.json` (same format as the relay's),
  or `--allow-any-writer` for development, which logs a warning. Signers missing
  from the policy get `UNAUTHORIZED_WRITER`.
- `--mqtt` stores the Messages API's submission records; `--validate` checks each
  submitted block against the node.
- Signing keys are resolved by the anchor service (`--resolver`, default
  `http://127.0.0.1:7300`; `did:key` needs no registry). The integrity rules run on
  every stored message, every `--periodic-s` (30 s: drift against Orion `--orion`,
  stale scores, anchors, shadow writes) and every `--rescan-s` (300 s: up to
  `--rescan-batch` indexed milestones are re-read from the node and any tagged block
  missing from the database is reported as `MISSING_IN_DB`). The periodic passes run
  in their own tasks, never inside a milestone transaction. An empty `--orion` turns
  the Orion rules off.
- Key lookups: only envelopes that pass verify's own pre-checks (structure, tag
  binding, kid belongs to iss) are looked up. A DID longer than 128 characters, a 404
  or any other definitive 4xx from the registry means "no such key" and the message is
  `FORGED`. Timeouts, connection errors, 5xx, 408 and 429 stall the milestone instead
  (no verdict is guessed), retried with backoff. An empty `--resolver` disables DID
  resolution on purpose: `did:iota` signers are then `FORGED` and the status says
  `resolver: disabled`.
- Ctrl+C / SIGTERM lets the milestone being written (and a rules pass) finish, then exits.

### Incident Explorer

The incident engine (`indexer/src/witness_indexer/incidents.py`) runs after the rules on
every stored message and every periodic pass. It groups trust events per IE into incidents,
served by the API at `GET /incidents` and `GET /incidents/{id}`.

- **Opening an incident.** Any of these opens one:
  - a trust score drop of `--incident-drop` (0.2) below the IE's previous score;
  - a self-orchestrator `errorCode` other than 0 or empty;
  - an LLO "Service component failed";
  - a `self-security` message;
  - a critical or high alert on a proven or relayed block;
  - a FORGED, REPLAY, UNAUTHORIZED_WRITER or REVOKED_KEY alert on a message that names an
    IE Orion lists, directly or through a service component Orion places on it. A made-up
    IE, or any IE while Orion has never answered, leaves the alert alert-only: it can join
    an incident already open on that IE but never opens one;
  - an integrity alert (DB_TAMPER, MISSING_IN_DB, ANCHOR_MISMATCH, CONTENT_MISMATCH,
    NOT_FOUND, ORPHANED). These go into one `ledger` incident unless they name an IE.
- **Joining an incident.** An event joins an open incident when it shares the incident's IE,
  service component or issuer and happened within `--incident-window-s` (600 s) of the
  incident's latest event. LLO reports reach their IE through the `infrastructureElement`
  of Orion's ServiceComponent entity. Orion's IE list and components are read with
  `--orion` (at most 2 MiB per listing), cached for 60 s, and never read inside a milestone
  transaction. Without Orion, the component id is the key.
- **Trust.** Evidence is *proven* (PRODUCER_SIGNED), *relayed* (RELAY_ATTESTED, or unsigned
  with a submission from the Messages API) or *untrusted* (anything else, including blocks
  with an UNSIGNED or SHADOW alert). Only proven events set the recovery target, add
  correlation keys, remediate or close. Relayed events may open an incident or join one as a
  trigger, but keep it alive at most one window past its last proven activity. Untrusted
  content only joins as `alert` evidence.
- **Closing an incident.** An incident closes as `closed:recovered` when a proven trust
  score is back at the level the first drop fell from. It closes as `closed:quiet` after
  `--incident-quiet-s` (1800 s) without events.
- **Alerts.** Each change is an `incident` event on the SSE stream. With a broker, it is
  also sent as a compact JSON message on `witness/alerts/{critical|high|medium|low}`
  (QoS 1) once its milestone commits.
  - `--alerts-mqtt URL` (or `$WITNESS_ALERTS_MQTT`) picks the broker. The default is the
    `--mqtt` broker; `--alerts-mqtt ""` turns publishing off.
  - A broker outage delays alerts but never stops indexing. Delivery resumes from a cursor
    kept in the database.
- `--no-incidents` turns the engine off.

```bash
mosquitto_sub -h 127.0.0.1 -u observer -P "$(cat secrets/mosquitto/observer.password)" -t 'witness/alerts/#' -v
```

Health shows up in `Store.stats()`, and so in `GET /stats` under `services` (row counts are
under `counts`):

| Key | Values |
| --- | --- |
| `indexer` | `ok`; `retrying (<inx\|rest\|database> unavailable)`; `retrying (resolver unreachable)`; `retrying milestone N (<reason>, attempt k)`; `stuck at N (<reason>)` after 5 failed attempts on the same milestone (e.g. `cone root mismatch`); `network changed` when the node serves a different Tangle than the database holds |
| `resolver` | `unreachable` while signing keys cannot be resolved (no verdicts are written meanwhile; after 5 failures on the same key `indexer` shows `stuck at N (resolver: <kid>)`), `ok` once it recovers, `disabled` without `--resolver`. Written by the indexer only; the rules' own lookups report as `resolver(rules)` |
| `policy` | `file`, `allow-any`, or `none` (library default: every signed writer is unauthorized) |
| `rules`, `orion`, `anchor`, `shadow`, `ledger` | reported by the rules engine (see `indexer/src/witness_indexer/rules.py`) |
| `incident-engine` | `ok`; `error` for 10 minutes after a correlation step failed (the detail says which step; indexing goes on); `disabled` with `--no-incidents` |
| `incident-orion` | `ok`; `unreachable` when the incident engine could not refresh Orion's IEs and components (refused, slow, larger than 2 MiB or 50 000 entities); it keeps the last answer, and without one attack alerts only join open incidents |
| `alerts-mqtt` | `ok`; `unreachable` while the alert broker refuses or times out (alerts wait, nothing is lost); `error` if the events log cannot be read; `disabled` without a broker |

Messages nested more than 64 levels deep keep their raw bytes only (no JSON copy);
a witness envelope that deep is `MALFORMED` ("nesting too deep"). An issuer's
`seq` may arrive out of order (white-flag order is not issue order); a message is
`REPLAY` only if another block already used the same `seq` or nonce for that
issuer.

INX also lets a plugin mount REST routes on the node: `RegisterAPIRoute` with
route `witness/v1` makes `http://<node>:14265/api/witness/v1/*` proxy to the
given host and port. HORNET runs in Docker, so the host must be reachable from
the container (`host.docker.internal` with Docker Desktop); a server bound to
`127.0.0.1` on the host works through it.

The Python INX stubs in `indexer/src/witness_indexer/inx_proto/` are generated
from `iotaledger/inx` (branch `production`, the Stardust protocol HORNET 2.x
speaks) by `scripts/gen_inx.sh`; rerun it only to bump the pinned commit.

Live checks: `WITNESS_LIVE=1 uv run pytest indexer/tests/test_source_inx_live.py`
(streams real milestones, compares INX with REST, proxies a test route, and
indexes a block written straight to HORNET into a throwaway schema; needs
`WITNESS_TEST_PG`). The live MQTT tests (`relay/tests/test_relay_live.py`,
`test_alerts_reach_mosquitto` in `indexer/tests/test_incidents.py`) log in to the broker:
`WITNESS_LIVE_MQTT` is the broker (default `mqtt://127.0.0.1:1883`) and the `relay`,
`indexer` and `observer` passwords are read from `WITNESS_LIVE_MQTT_SECRETS` (default
`secrets/mosquitto`). They publish with the relay or indexer login (alerts under
`witness/alerts/test-<id>`) and read with the observer login. The relay test writes one
relay-attested `trust.score` block to the node, which a running explorer indexes.

## Signed audit reports

`POST /reports` posts each report's hash as a producer-signed `audit.report`
message through a witness-relay (`WITNESS_RELAY_URL`; there is no default, and
the API refuses a URL whose `GET /healthz` does not identify a witness-relay, so
the legacy Messages API is never used by mistake). The relay's writer policy
must allow the signer DID on `audit.report`.

- **Give reports a signer DID of their own.** Each post claims the envelope
  sequence number `max(now in ms, last claimed + 1)`, continuing from the
  `reports` table. Another producer signing with the same DID would advance the
  relay's sequence for that issuer behind the API's back, and the relay would
  refuse later reports as replays.
- **Run one API instance that writes reports.** Posts are serialised inside one
  process; two instances writing reports could claim the same sequence number.
- A report is stored as **not anchored** before it is posted and marked
  anchored with its block id once the relay accepts it. A failed post leaves
  the report listed with `anchored: false`, and its HTML page says "NOT
  anchored".

## Console

The console verifies every proof in the browser against the pins built into it
(`console/src/config/verifier.json`, written by `pnpm --filter console fixture`
from the stack's protocol config, `deploy/identity/testnet.json`,
`ANCHOR_TRAIL_ID` and, optionally, `WITNESS_REBASED_RPC`,
`IOTA_AUDIT_TRAIL_ORIGINAL_PKG_ID`, `ANCHOR_WRITER_ADDRESS`). Regenerate it
whenever the anchor service starts a new Audit Trail, or step 5 fails with
"anchor trail is not the pinned trail".

It talks to three places:

| What | Where | Setting |
| --- | --- | --- |
| witness-api (messages, bundles, stream) | `/api` | `VITE_API_URL` |
| issuer keys for step 4 | `/anchor/resolve/{did}` on the anchor service | `VITE_RESOLVER_URL` (base, default `/anchor`) |
| anchor record for step 5 | the pinned IOTA Rebased RPC, straight from the browser | `rebasedRpc` in `verifier.json` |

Step 4 trusts the anchor service operated with this explorer: it resolves the
issuer's did:iota document (and its key history) from IOTA Rebased, and the
browser takes its answer. That is not an independent read of the chain, unlike
step 5. A resolver that does not answer within 15 s, or answers with a
redirect, leaves step 4 unresolved (PARTIAL).

`vite dev` and `vite preview` proxy `/api` to `WITNESS_API_TARGET`
(default `http://127.0.0.1:7200`) and only `/anchor/resolve/` to
`WITNESS_ANCHOR_TARGET` (default `http://127.0.0.1:7300`). A deployment must do
the same: put the console, `/api` and `/anchor/resolve/` on one origin and
proxy **only** `/anchor/resolve/` to the anchor service, never `/anchor/*`.
The anchor service's admin endpoints (`POST /checkpoints/run`) must not be
reachable from the browser.

A replay build (`pnpm --filter console build:replay`) serves a snapshot
recorded by `node console/scripts/record-replay.mjs --out <dist>/replay` from a
running stack. It needs no API; step 4 uses the DID documents recorded with the
snapshot (the screen says so) and step 5 still reads IOTA Rebased live.

## Deployment: the Witness overlay

`deploy/compose/docker-compose.witness.yml` (project `witness`) runs the explorer next to
the base stack, on `iota-net`. HORNET is reached only there, by name: REST
`iota-hornet:14265`, INX `iota-hornet:9029`.

| Service | Image (Dockerfile) | Does |
| --- | --- | --- |
| `witness-relay` | `deploy/docker/python.Dockerfile`, target `relay` | the Messages API (`/upload`): producer signatures, writer policy, receipts; forwards every submission over MQTT and HTTP `/ingest` |
| `witness-indexer` | same, target `indexer` | INX milestones and cones, verdicts, rules, incidents; **the only validator** (`--validate`) |
| `witness-api` | same, target `api` | REST API on 7200, also mounted on the node as `/api/witness/v1`; `WITNESS_VALIDATE=0` |
| `witness-anchor` | `anchor/Dockerfile` | DID resolver for relay and indexer; checkpoints on IOTA Rebased; `witness.anchor` mirror through the relay |
| `witness-console` | `console/Dockerfile` | the app in live mode behind nginx: `/api/` proxied to the API, only `/anchor/resolve/` to the anchor; trail and writer pinned at build time |
| `trust-manager-witness` | `deploy/compose/trust-manager-witness/Dockerfile` | the aeriOS Trust Manager signing its own `trust.score` (key `trust-manager`) |

```bash
cp deploy/compose/.env.example deploy/compose/.env   # set the keystore file, wallet address
deploy/compose/stack-up.sh --witness                 # or, on a running base stack:
deploy/compose/setup-secrets.sh
docker stop trustmanager
docker compose -f deploy/compose/docker-compose.witness.yml up -d --build
```

- **Trust Manager.** The patched one replaces the stock one: both would score the same
  Infrastructure Elements and write Orion's `trustScore`, and the stock one writes
  unsigned `trust.score` that the writer policy rejects. `stack-up.sh --witness` leaves
  the stock one stopped; the stock one stays defined in `docker-compose.aerios.yml`.
- **Secrets.** `setup-secrets.sh` writes, into `secrets/` (gitignored): database and broker
  passwords, the broker's hashed password file, service tokens, the relay key as PEM, the
  relay's search key and recipients, and one env file per service (`secrets/compose/*.env`)
  holding only that service's credentials, database URL included. Existing values are kept. Component keys
  (`secrets/<component>/sig-1.jwk.json`) come from `anchor/scripts/bootstrap-identities.ts`.
  Each container gets read-only mounts of the files it needs and nothing else; images hold
  no key material. The anchor mounts only the IOTA keystore file (`WITNESS_IOTA_KEYSTORE`),
  never the directory around it.
- **Database.** No password is committed. A fresh setup gets a random owner password
  (`secrets/postgres/postgres.password`, read by Postgres when it first creates the
  database). A base stack created before that keeps the password it was created with:
  `setup-secrets.sh` takes it from `WITNESS_PG_PASSWORD` in `.env` (`witness` for the old
  local stack) or from the existing container. The indexer and the API use the owner login;
  the relay has its own, `witness_relay`, which owns the `relay` schema and nothing else (no
  CREATE on the database, no access to the explorer's schema). The one-shot
  `witness-db-init` service creates or updates it (`deploy/compose/db-init.sql`) before the
  relay starts.
- **Mosquitto.** No anonymous clients. `relay` may write `aerios/iota/submissions/#`,
  `indexer` may read it and write `witness/alerts/#`, `observer` may read both
  (`deploy/compose/mosquitto.acl`). The legacy messages API does not use MQTT.
- **Containers** run as unprivileged users with a read-only root filesystem, no
  capabilities, `no-new-privileges`, a memory limit and a health check each. The anchor
  waits for a healthy API and relay; the indexer, the console and the Trust Manager start
  after the services they call.
- **Trail.** With `WITNESS_TRAIL_ID` empty the anchor creates an Audit Trail on its first
  window and keeps it in the `anchor-state` volume (`docker logs witness-anchor` prints
  `trail created`). Put the id into `.env` and run `up -d --build` again: the API serves it
  in `/config/verifier` and the console image pins it (`ANCHOR_TRAIL_ID` build argument).
  Each window is one trail record; `WITNESS_ANCHOR_EVERY=720` (about an hour) keeps gas low,
  12 suits a demo.
- **Policy.** `deploy/policy.json` is the writer policy relay, indexer, API and anchor share
  (`WITNESS_POLICY_FILE` to use another); it equals `chaos/demo-policy.json`, the policy of the
  fault-injection evaluation.
- **Low memory.** `up --build` builds images in parallel; `stack-up.sh --witness` builds them
  one at a time.
- **File permissions.** Containers run as uid 10001 (Python services, Trust Manager), 1000
  (anchor) and 101 (console). `setup-secrets.sh` makes the files they mount 0640 (directories
  0750), group-owned by the user who runs it, and writes that group id to `.env` as
  `WITNESS_SECRETS_GID`; the overlay adds the group to every container (`group_add`). On Linux
  the IOTA keystore file needs the same: `chgrp "$(id -g)" iota.keystore && chmod 0640 iota.keystore`.
  Docker Desktop ignores host permissions.

### Helm

`deploy/helm/witness` follows the aeriOS chart layout: one Deployment per component, a
values block per component (`tier`, `image`, `resources`, `nodeSelector`, ...), the
HORNET REST/INX endpoints under `iota.hornet`, and secrets only by reference to Secrets
that exist before the release:

```bash
# Database URLs: postgres/*.dsn from setup-secrets.sh, edited for the cluster's database host.
# Create the relay's role there first: RELAY_DB_PASSWORD=... psql -f deploy/compose/db-init.sql
kubectl create secret generic witness-db --from-file=dsn=secrets/postgres/explorer.dsn
kubectl create secret generic witness-relay-db --from-file=dsn=secrets/postgres/relay.dsn
kubectl create secret generic witness-relay-env --from-env-file=secrets/compose/relay.env
kubectl create secret generic witness-relay-keys --from-file=secrets/relay/sig-1.pem \
  --from-file=secrets/relay/recipients.json --from-file=secrets/relay/search.key
kubectl create secret generic witness-indexer-env --from-env-file=secrets/compose/indexer.env
kubectl create secret generic witness-api-env --from-env-file=secrets/compose/api.env
kubectl create secret generic witness-anchor-env --from-env-file=secrets/compose/anchor.env
kubectl create secret generic witness-domain-key --from-file=secrets/domain/sig-1.jwk.json
kubectl create secret generic witness-anchor-key --from-file=secrets/anchor/sig-1.jwk.json
kubectl create secret generic witness-trust-manager-key --from-file=secrets/trust-manager/sig-1.jwk.json
kubectl create secret generic witness-anchor-wallet --from-file=iota.keystore=<keystore file>
kubectl create configmap witness-policy --from-file=policy.json=deploy/policy.json
helm install witness deploy/helm/witness --set anchor.loop=true --set anchor.address=0x...
```

Values from files, never from the command line (`--from-literal` leaves passwords in the
shell history and the process list). The broker URLs inside the env files name
`witness-mosquitto`; point them at the cluster's broker. The database URL in the env files is
overridden by the chart's database Secrets. Images are built from the Dockerfiles above and pushed to your
registry (`<component>.image.repository`); CI builds them but publishes nothing.

## Troubleshooting

- **`bootstrap.sh` refuses to run on Windows.** The upstream script wants root
  and `chown`. `stack-up.sh` performs its steps directly (create dirs, run
  `create-snapshots`, `bootstrap-network`, then `hornet-main.yaml up`).
- **Relay returns "empty reply" on 5555.** Android Studio emulators (adb) listen
  on `127.0.0.1:5555` and shadow Docker's mapping. Use
  `RELAY_PORT=5556 deploy/compose/stack-up.sh` and `RELAY_URL=http://localhost:5556`.
- **Port 3000 busy.** Trust Manager is published on 3100 for that reason.
- **Start over.** `deploy/compose/stack-up.sh --reset`.
- **Container name conflicts** after renaming compose projects:
  `docker rm -f` the stale container, then run `stack-up.sh` again.
