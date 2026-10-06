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
  once you know it.
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
