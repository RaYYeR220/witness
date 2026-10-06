# Operations: local aeriOS stack

Everything runs in Docker. Scripts are bash (Git Bash on Windows).

## Bring-up

```bash
deploy/compose/stack-up.sh           # first run bootstraps a private Tangle
deploy/compose/stack-up.sh --reset   # wipe chain data and bootstrap from scratch
deploy/compose/stack-down.sh         # stop everything, keep chain data
```

`stack-up.sh` clones `iota-tangle`, `iota-messages-api` and `trust-manager` from
`eclipse-aerios` into `vendor/` (gitignored), then starts, in order: HORNET +
inx-coordinator + inx-dashboard, the messages relay (`messages-api.yml`),
inx-poi (`inx-poi.yml`) and the rest (`docker-compose.aerios.yml`: Mongo,
Orion-LD, Trust Manager, Postgres, Mosquitto). All containers share the
`iota-net` network. The compose files use separate project names so the stacks
can be restarted independently.

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
| Postgres (`witness-postgres`, password `witness`) | 5432 |
| Mosquitto (`witness-mosquitto`, anonymous) | 1883 MQTT, 9001 websockets |

Our compose files publish ports on 127.0.0.1 only. The organisers' own HORNET compose (vendored, not ours) publishes 14265, 9029 and 31011 on all interfaces; keep that in mind for any deployment.

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
uv run witness-indexer --db postgresql://postgres:witness@127.0.0.1:5432/postgres \
  --schema witness --policy policy.json \
  [--source inx|rest] [--mqtt mqtt://127.0.0.1:1883] [--validate]
```

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

Health shows up in `Store.stats()` (and so in the API's stats):

| Key | Values |
| --- | --- |
| `indexer` | `ok`; `retrying (<inx\|rest\|database> unavailable)`; `retrying (resolver unreachable)`; `retrying milestone N (<reason>, attempt k)`; `stuck at N (<reason>)` after 5 failed attempts on the same milestone (e.g. `cone root mismatch`); `network changed` when the node serves a different Tangle than the database holds |
| `resolver` | `unreachable` while signing keys cannot be resolved (no verdicts are written meanwhile; after 5 failures on the same key `indexer` shows `stuck at N (resolver: <kid>)`), `ok` once it recovers, `disabled` without `--resolver`. Written by the indexer only; the rules' own lookups report as `resolver(rules)` |
| `policy` | `file`, `allow-any`, or `none` (library default: every signed writer is unauthorized) |
| `rules`, `orion`, `anchor`, `shadow`, `ledger` | reported by the rules engine (see `indexer/src/witness_indexer/rules.py`) |

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
`WITNESS_TEST_PG`).

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
