# Witness

**An IOTA Advanced Explorer for Eclipse aeriOS.** Every message submitted through the
modified Messages API (witness-relay) is forwarded to the explorer (best effort, see
[Limits](#limits)). Every confirmed tagged-data block is stored in a parallel PostgreSQL
database and searchable over REST. Submitted blocks are also checked against HORNET (solid,
and byte-for-byte the bytes that were sent). Each block is provable from raw bytes up to a
checkpoint on public IOTA Rebased.

Replay console, nothing to install: [https://rayyer220.github.io/witness/](https://rayyer220.github.io/witness/)
· Two-minute demo video: [youtu.be/ArWoH4ses8Q](https://youtu.be/ArWoH4ses8Q)
· Judges start here: [JUDGES.md](JUDGES.md)
· Every claim with its evidence: [CLAIMS.md](CLAIMS.md)

**394/400 injected attacks detected across 20 pre-registered classes (19 classes 20/20; Orion drift 14/20), 0 false positives on 599 genuine messages over 30 minutes, positive control 40/40.** [Results and method](docs/eval.md#results)

## Challenge brief → where it is

| Brief | Where | Status |
|---|---|---|
| App 1 sends messages to the Tangle through the HORNET API, starting from the aeriOS Messages API | [`relay/`](relay/src/witness_relay/app.py): a drop-in for `eclipse-aerios/iota-messages-api` (same `POST /upload?node=` request and response shape), posting tagged-data blocks to `POST /api/core/v2/blocks` | ✅ |
| App 2 stores every message in a parallel database with enriched, searchable metadata | [`indexer/`](indexer/src/witness_indexer/) + PostgreSQL 16 ([schema](indexer/src/witness_indexer/migrations/0001_init.sql)): tag, kind, issuer, verdict, IE id, milestone, white-flag position, received/issued/confirmed times, canonical hash, lifecycle | ✅ |
| (a) The Messages API forwards every submission to the explorer | [`relay/src/witness_relay/forward.py`](relay/src/witness_relay/forward.py): a submission record (message as received, exact bytes sent, block id, HORNET status, relay verdict) for every well-formed upload, including those the relay refuses and those HORNET rejects, over MQTT `aerios/iota/submissions/{tag}` (QoS 1) and HTTP `POST /ingest` | ✅ |
| (b) REST retrieval and search, at least by id, date and tag | `GET /messages?block_id=&date_from=&date_to=&tag=` (also issuer, verdict, kind, IE, milestone range, full text, JSON path), `GET /messages/{blockId}`; [docs/api.md](docs/api.md), OpenAPI at `/docs` | ✅ |
| (c) Each block is valid and solid per `GET /api/core/v2/blocks/{id}/metadata` | [`indexer/src/witness_indexer/validator.py`](indexer/src/witness_indexer/validator.py): polls the metadata until a milestone references the block; every answer is kept; shown as `checks.solid` on `GET /messages/{blockId}`; `POST /messages/{blockId}/verify` asks again | ✅ |
| (d) The stored content is the content on the Tangle, per `GET /api/core/v2/blocks/{id}` | same validator: fetches the raw block, requires `BLAKE2b-256(raw) == blockId`, then compares tag and data byte for byte with what the Messages API sent; `checks.content`, alert `CONTENT_MISMATCH`; later re-verification raises `DB_TAMPER` if the database copy was altered | ✅ |
| Idea 1: MQTT broker fed by the Messages API, explorer subscribes | Eclipse Mosquitto with logins and ACLs ([`mosquitto.acl`](deploy/compose/mosquitto.acl)); the relay publishes, the indexer subscribes; alerts go out on `witness/alerts/{severity}` | ✅ |
| Idea 2: explorer UI for the enriched, solid messages | [`console/`](console/src/screens.ts) (Vue 3): Live, Search, Verify (runs the five proof checks in the browser), Lineage, Flows, Integrity (alerts and incidents), Identity, Anchors, Posture, Reports; replay build for a static demo | ✅ |
| Idea 3: trace related messages of one flow, user or sensor | signed `prev` (per-issuer hash chain) and `corr` (correlation id) in the [envelope](docs/envelope-spec.md); `GET /flows?by=issuer\|ie\|service\|corr`, `GET /flows/{by}/{key}` with chain links, gaps and forks; alerts `CHAIN_GAP`, `CHAIN_FORK`; console Flows screen | ✅ |
| Idea 4: Incident Explorer: correlated trust events on a timeline, each verified against its block id, real-time alerts | [`indexer/src/witness_indexer/incidents.py`](indexer/src/witness_indexer/incidents.py); `GET /incidents`, `GET /incidents/{id}` (each event with verdict, lifecycle status and proof link); SSE `GET /stream` and MQTT `witness/alerts/#`; console Integrity screen | ✅ |

Beyond the brief: signed `witness/v1` envelopes with did:iota identities and a writer policy,
self-contained proof bundles verified the same way in Python, TypeScript and the browser,
checkpoints of the milestone history on an IOTA Rebased Audit Trail, a fault-injection
evaluation with an answer key committed before the run, a node posture scanner, signed audit
reports, a CLI, an MCP server, a producer SDK and a Helm chart.

## Why

aeriOS writes trust scores and orchestration events to its Tangle so they cannot be changed
later. In the deployed code nobody can check that afterwards: the Messages API returns the
block id inside a string and no aeriOS writer keeps it, messages are unsigned, anyone who can
reach the API or the node can write any `trust.score`, and the private Tangle's coordinator
signs with IOTA's published sample keys. Details, with file and line, in
[docs/findings.md](docs/findings.md).

So the explorer does not just mirror what a node says. It records what the Messages API was
given, checks it against the node, says who signed each message, and hands out proofs that a
third party verifies without trusting the explorer: block hash, Merkle path to the milestone,
coordinator signatures, the signer's key, and a checkpoint on a public ledger that the
private Tangle's keys cannot rewrite. See [docs/architecture.md](docs/architecture.md).

## Architecture

Solid arrows run in our deployment (`deploy/compose/stack-up.sh --witness`); dotted ones are
optional or used only by tools and the evaluation.

```mermaid
flowchart LR
  subgraph producers [aeriOS producers]
    TM["Trust Manager<br/>(patched: signs its trust.score)"]
    LLO["LLO, self-orchestrator<br/>(unmodified, unsigned)"]
  end
  subgraph tangle [Private Tangle, organisers' iota-tangle config]
    HORNET[("HORNET 2.0")]
    COO[inx-coordinator]
    POI[inx-poi]
  end
  RELAY["witness-relay<br/>modified Messages API<br/>verify / attest / policy"]
  LEGACY["stock iota-messages-api"]
  MQ[(Mosquitto)]
  PG[(PostgreSQL 16)]
  IDX["witness-indexer<br/>INX cones, verdicts,<br/>checks c and d, rules, incidents"]
  API["witness-api<br/>REST, SSE, OpenAPI"]
  ANCHOR["witness-anchor<br/>DID resolver, checkpoints"]
  REBASED[("IOTA Rebased<br/>DIDs + Audit Trail")]
  ORION[(Orion-LD)]
  CONSOLE["console<br/>browser verifier"]
  TOOLS["CLI, MCP"]

  TM -->|"POST /upload"| RELAY
  LLO -.->|"POST /upload"| RELAY
  LLO -.->|"bypass"| LEGACY
  LEGACY -.-> HORNET
  RELAY -->|"POST /api/core/v2/blocks"| HORNET
  COO -->|milestones| HORNET
  RELAY -->|"aerios/iota/submissions/#"| MQ
  RELAY -->|"POST /ingest"| API
  MQ --> IDX
  HORNET -->|"INX: milestones, cones"| IDX
  IDX -->|"GET /blocks/{id}/metadata, /blocks/{id}"| HORNET
  IDX --> PG
  IDX -->|"witness/alerts/#"| MQ
  IDX -->|"Orion vs ledger"| ORION
  TM --> ORION
  PG --> API
  API -->|"INX RegisterAPIRoute: /api/witness/v1"| HORNET
  IDX -->|"resolve DIDs, read checkpoints"| ANCHOR
  RELAY -->|"resolve DIDs"| ANCHOR
  ANCHOR -->|"proposed window"| API
  ANCHOR -->|"re-derive milestones"| HORNET
  ANCHOR -->|"DIDs, trail records"| REBASED
  ANCHOR -->|"witness.anchor mirror"| RELAY
  CONSOLE --> API
  CONSOLE -->|"step 4: /anchor/resolve"| ANCHOR
  CONSOLE -->|"step 5: read record"| REBASED
  TOOLS -.-> API
  TOOLS -.->|"step 5"| REBASED
  TOOLS -.->|"second opinion: /api/poi/v1/validate"| POI
  POI -->|INX| HORNET
```

| Component | Language | Does |
|---|---|---|
| [`core`](core/src/witness_core) | Python | Stardust block and milestone codec, TIP-4 Merkle, JCS, `witness/v1` envelopes, JWE and blind index, commitments, proof bundles and the five-step verifier, Rebased record reader. No I/O except the record reader |
| [`relay`](relay/src/witness_relay) | Python, FastAPI | the modified Messages API |
| [`indexer`](indexer/src/witness_indexer) | Python | INX (REST fallback) ingestion, verdicts, the brief's checks (c) and (d), integrity rules, incidents |
| [`api`](api/src/witness_api) | Python, FastAPI | REST + SSE, proof bundles, posture scan, audit reports; also served on the node at `/api/witness/v1` |
| [`anchor`](anchor/src) | TypeScript | did:iota identities, DID resolver, checkpoints to an IOTA Rebased Audit Trail, `witness.anchor` mirror |
| [`packages/verify`](packages/verify/src) | TypeScript | the verifier ported from `core`, for the browser and Node, with parity vectors |
| [`console`](console/src) | Vue 3 | explorer UI, live and replay modes |
| [`cli`](cli/src/witness_cli/main.py), [`mcp`](mcp/src/witness_mcp/server.py), [`sdk`](sdk/src/witness_sdk) | Python | `witness verify/search/lookup/lineage/report/posture/keys`; MCP tools; producer signing and the Trust Manager patch |
| [`chaos`](chaos/src/witness_chaos) | Python | fault injection, answer key, traffic generator, scorecard |
| [`deploy`](deploy) | Compose, Helm | overlay on the organisers' `iota-net`, secrets, Helm chart in the aeriOS layout |

## Quick start

Needs Docker with Compose v2, bash (Linux, macOS, or Git Bash on Windows), Node 22 with pnpm
(identity bootstrap), and an IOTA Rebased testnet address with a little gas in an IOTA CLI
keystore, because the overlay signs with did:iota identities and anchors to an Audit Trail.

```bash
git clone https://github.com/RaYYeR220/witness && cd witness
cp deploy/compose/.env.example deploy/compose/.env   # WITNESS_IOTA_KEYSTORE, WITNESS_ANCHOR_ADDRESS
# once per clone: your own DIDs and keys (docs/operations.md, "A fresh clone with your own identities")
deploy/compose/stack-up.sh --witness
```

`stack-up.sh` clones `iota-tangle`, `iota-messages-api` and `trust-manager` from
`eclipse-aerios` into `vendor/`, bootstraps the private Tangle on first run, runs
`deploy/compose/setup-secrets.sh` (random passwords, tokens and per-service env files under
`secrets/`, which is gitignored), starts the aeriOS services and then builds and starts the
Witness overlay one image at a time. Everything is published on loopback only:

| What | Where |
|---|---|
| Console (live mode) | http://localhost:8080 |
| Explorer API, OpenAPI UI | http://localhost:7200/docs, also http://localhost:14265/api/witness/v1 |
| Witness relay (modified Messages API) | `POST http://localhost:5557/upload?node=iota-hornet` |
| Anchor service | http://localhost:7300 (`/resolve/{did}`, `/checkpoints`) |
| HORNET REST, INX | http://localhost:14265, localhost:9029 |
| inx-dashboard | http://localhost:31011 |
| Stock Messages API | `POST http://localhost:5555/upload?node=iota-hornet` (`RELAY_PORT`) |
| Mosquitto, PostgreSQL, Orion-LD | 1883, 5432, 1026 |

The patched Trust Manager writes a signed `trust.score` within a minute or two; it shows up on
the Live screen with its verdict and checks.

## Configuration

The compose stack reads `deploy/compose/.env` ([template](deploy/compose/.env.example)). The
settings you are most likely to touch:

| Variable | Default | Meaning |
|---|---|---|
| `WITNESS_IOTA_KEYSTORE` | none | IOTA CLI keystore file of the anchor wallet (mounted read-only into the anchor) |
| `WITNESS_ANCHOR_ADDRESS` | none | keystore entry that pays gas and writes trail records |
| `WITNESS_REBASED_NETWORK` | `testnet` | IOTA Rebased network of the DIDs and the trail |
| `WITNESS_TRAIL_ID` | empty | Audit Trail to anchor to; empty: the anchor creates one and logs its id |
| `WITNESS_ANCHOR_EVERY` | `720` | milestones per checkpoint (about an hour; 12 for a demo) |
| `WITNESS_POLICY_FILE` | `../policy.json` | writer policy shared by relay, indexer, API and anchor |
| `WITNESS_RELAY_ENCRYPT_TAGS` | `audit.report` | tags on which the relay seals legacy (unsigned) writes; set it empty to seal nothing |
| `WITNESS_VERIFY_TOKEN` | empty | bearer token for `POST /messages/{id}/verify` (empty: open) |
| `RELAY_PORT`, `WITNESS_*_PORT` | see table above | host ports |

Every component also runs on its own with `WITNESS_*` / `RELAY_*` / `ANCHOR_*` variables
([api](api/.env.example), [relay](relay/.env.example), [anchor](anchor/.env.example)). The
full list, the indexer flags, the Helm chart and troubleshooting are in
[docs/operations.md](docs/operations.md).

## Tests

<!-- TEST-COUNTS -->
Counted by collection at commit `34fd911` (`uv run pytest --collect-only -q -m "not live"
<pkg>/tests` for each Python package, `pnpm --filter <pkg> exec vitest list` for TypeScript):

| Suite | Tests |
|---|---:|
| `core` | 375 |
| `indexer` | 398 |
| `api` | 96 |
| `relay` | 85 |
| `sdk` | 12 |
| `cli` | 42 |
| `mcp` | 36 |
| `chaos` | 191 |
| `packages/verify` (TypeScript) | 372 |
| `anchor` (TypeScript) | 156 |
| `console` (TypeScript) | 183 |
| **Total** | **1946** |
<!-- /TEST-COUNTS -->

```bash
uv sync --all-packages
bash scripts/test-db.sh && export WITNESS_TEST_PG=postgresql://postgres:witness@localhost:55432/postgres
uv run pytest -m "not live" core/tests     # one package at a time
pnpm install && pnpm --filter @witness/verify build && pnpm -r test
```

Tests that need the database skip without `WITNESS_TEST_PG`. Nine Python tests are marked
`live` and run only against a running stack (`WITNESS_LIVE=1`). The block, milestone, cone
and REST vectors in [`core/tests/vectors`](core/tests/vectors) were captured from a local
HORNET 2.0.2 by [`scripts/capture_vectors.py`](scripts/capture_vectors.py); the envelope,
bundle and sealed-payload vectors are built from them with fixed test keys. The Python and
TypeScript verifiers run the same vector files.

The fault-injection evaluation (20 attack classes, a positive control and a genuine-traffic
trap, answer key committed first) is described in [docs/eval.md](docs/eval.md).

## Limits

What is live, what is modelled and what is not claimed is itemised in [CLAIMS.md](CLAIMS.md).
The ones that matter most:

- **Sample coordinator keys.** We run the organisers' `iota-tangle` configuration unchanged:
  one HORNET node, coordinator keys from IOTA's public sample set. Anyone can sign a milestone
  that passes check ③; the vector `valid_anchored` in `core/tests/vectors/bundles.json` is one.
  Check ⑤ is what tells them apart, and only for milestones inside an anchored window.
- **Anchoring bounds the forgery window, it does not close it.** A milestone newer than the
  last checkpoint is protected only by the coordinator keys until the next checkpoint
  (`WITNESS_ANCHOR_EVERY`). A checkpoint's `msgCount` is the indexer's count, not re-derived
  from the node.
- **Testnet.** DIDs and the Audit Trail are on IOTA Rebased testnet. <!-- MAINNET -->
- **Step ④ trusts our resolver.** In the browser, and in the CLI with `--resolver`, the
  signer's DID document comes from the explorer's own anchor service, which reads IOTA
  Rebased; that is not an independent read of the chain (step ⑤ is: the record comes straight
  from the pinned Rebased RPC). The CLI can pin a DID document instead (`--did-snapshot`).
- **The indexer trusts its node for milestones.** It checks that each milestone continues
  the stored chain and that its cone hashes to the inclusion root, not the coordinator
  signatures; the proof verifier and the anchor do check them against pinned keys.
- **One producer signs.** Only the Trust Manager is patched to sign
  ([`sdk/patches/trust-manager-witness.patch`](sdk/patches/trust-manager-witness.patch)). LLO
  and self-orchestrator messages are relay-attested: the relay vouches that it received them,
  not who wrote them. In our deployment that traffic comes from the evaluation's traffic
  generator, in the message shapes those components' source code writes; we did not run them.
- **Hot keys.** The anchor's gas address controls the domain DID and holds the Audit Trail's
  admin capability ([`anchor/SECURITY.md`](anchor/SECURITY.md)).
- **Blind index tokens are deterministic.** Equal IE ids or tags give equal tokens, so anyone
  reading the Tangle can tell which sealed messages share one, though not which value it is.
- **Forwarding is best effort.** Submission records wait in a bounded in-memory queue per sink;
  a relay restart or a long outage loses them. The INX side still sees every confirmed block
  and reports one that no submission names as `SHADOW`.
- **Not measured:** lookup latency at 100k messages, in-browser verification time.
- **Where it ran.** The full stack ran on Windows 11 with Docker Desktop and Git Bash. CI on
  Ubuntu runs the tests, builds every image, lints and renders the Helm chart and validates
  the compose files; the chart has not been deployed to a Kubernetes cluster.

## Licence

[Apache-2.0](LICENSE), as the `eclipse-aerios` repositories.
