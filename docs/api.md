# Explorer API

The witness-api serves the explorer's parallel database. This page summarises the routes; the
OpenAPI document the server publishes is the reference, with every schema:

- interactive: `http://localhost:7200/docs`, raw: `http://localhost:7200/openapi.json`
- the same API on the node: `http://localhost:14265/api/witness/v1/...` (mounted through INX
  `RegisterAPIRoute`)

Conventions:

- Bytes are lowercase `0x` hex. Block ids are `0x` + 64 hex digits.
- Times come twice: epoch milliseconds (`…Ms`) and ISO 8601 UTC. Query parameters for dates
  take either ISO 8601 (`2026-10-06`, `2026-10-06T10:46:19Z`, offsets allowed, no offset
  means UTC) or epoch milliseconds (11 to 16 digits). Ranges are inclusive to the
  millisecond; a bare date in `date_to` covers the whole day.
- Lists are newest first. Paged lists return an opaque `nextCursor`; pass it back as `cursor`.
- Errors are JSON `{"detail": "..."}`.
- Nothing the API returns is a verdict you have to trust: a message's `verdict` is what the
  indexer recorded, and every message has a proof bundle (`/proofs/{blockId}`) to check
  yourself.

## Authentication

Reads need no credentials. Four write or load-bearing routes take a bearer token
(`Authorization: Bearer <token>`), each its own setting; an unset token disables the route
(fails closed), except for verification, which is then open.

| Route | Setting | Unset |
|---|---|---|
| `POST /ingest` | `WITNESS_INGEST_TOKEN` (the Messages API presents it) | 403, HTTP ingest off (MQTT still works) |
| `POST /posture/scan` | `WITNESS_POSTURE_TOKEN` | 403 |
| `POST /reports` | `WITNESS_REPORT_TOKEN` | 403 |
| `POST /messages/{blockId}/verify` | `WITNESS_VERIFY_TOKEN` | open |

Tokens are at least 16 characters. `deploy/compose/setup-secrets.sh` writes them to
`secrets/tokens/`.

## Messages (the brief's (b), (c), (d))

### `GET /messages`

Search stored messages. The brief's criteria are `block_id`, `date_from`/`date_to` and `tag`;
all parameters combine.

| Parameter | Meaning |
|---|---|
| `block_id` | message (block) id |
| `tag` | exact tag, e.g. `trust.score` |
| `date_from`, `date_to` | when the Messages API received it, else when a milestone confirmed it |
| `iss` | issuer DID |
| `verdict` | `PRODUCER_SIGNED`, `RELAY_ATTESTED`, `UNSIGNED_LEGACY`, `FORGED`, `UNAUTHORIZED_WRITER`, `REPLAY`, `REVOKED_KEY`, `MALFORMED` |
| `kind` | message kind from the schema registry (`trust.score`, `llo.k8s`, `llo.docker`, `self-orchestrator`, `witness.anchor`, `audit.report`, `unknown`) |
| `ie` | Infrastructure Element id, e.g. `MyDomain:fa163ed55867` |
| `ms_from`, `ms_to` | milestone index range |
| `q` | full-text search in the JSON body |
| `jsonpath` | `path=value`: the body's value at the dotted path equals `value`, e.g. `event=Service component failed` |
| `cursor`, `limit` | paging; `limit` 1 to 500, default 50 |

```bash
curl -s "localhost:7200/messages?tag=trust.score&date_from=2026-10-07&limit=1"
```

```json
{"items": [{
  "blockId": "0x355306b01bf04c93d6549bf6637c9a60e15594b74724801343386312bb364de7",
  "tag": "trust.score", "kind": "trust.score",
  "verdict": "PRODUCER_SIGNED", "status": "CONTENT_VERIFIED",
  "ieId": "MyDomain:fa163ed55867",
  "iss": "did:iota:testnet:0x15eb8c4d90fa4fff1d49f3ae8b1676a61e09c883303acd383cbfaacb538db9ba",
  "kid": "did:iota:testnet:0x15eb…db9ba#sig-1",
  "seq": 1791332997848, "prev": "0xf9674179…bb519427", "corr": null,
  "msIndex": 2870, "wfIndex": 3,
  "receivedAt": "2026-10-07T01:57:33.757Z", "confirmedAt": "2026-10-07T01:57:34.000Z",
  "canonHash": "0x2478876e…10be07b4",
  "json": {"id": "MyDomain:fa163ed55867", "score": 0.053424256924272794},
  "links": {"self": "/messages/0x3553…", "lifecycle": "/messages/0x3553…/lifecycle",
            "proof": "/proofs/0x3553…"}
}], "nextCursor": "WzEsIDI4…", "limit": 1}
```

`status` is the lifecycle status (below); `null` for a block that no submission names.

### `GET /messages/{blockId}`

One message with its exact bytes (`dataHex`), the submission record the Messages API
forwarded, and the latest answer of each brief check. A block known only from a submission
(not confirmed yet) comes back with `indexed: false`. 404 for an unknown id.

```json
{
  "blockId": "0x355306b0…bb364de7", "verdict": "PRODUCER_SIGNED", "status": "CONTENT_VERIFIED",
  "indexed": true, "dataHex": "0x7b22617474223a…",
  "submission": {"subId": "8a22f7ab-…", "source": "mqtt", "receivedAt": "2026-10-07T01:57:33.757Z",
                 "message": {"w": 1, "tag": "trust.score", "...": "..."},
                 "hornetStatus": 201, "relayVerdict": "PRODUCER_SIGNED"},
  "checks": {
    "solid":   {"check": "c", "via": "GET /api/core/v2/blocks/{blockId}/metadata", "ok": true,
                "isSolid": true, "referencedByMilestoneIndex": 2870,
                "ledgerInclusionState": "noTransaction", "checkedAt": "2026-10-07T01:57:34.357Z"},
    "content": {"check": "d", "via": "GET /api/core/v2/blocks/{blockId}", "ok": true,
                "result": "MATCH", "diff": null, "checkedAt": "2026-10-07T01:57:34.365Z"}
  }
}
```

### `GET /messages/{blockId}/lifecycle`

The lifecycle `RECEIVED → SUBMITTED → SOLID → CONFIRMED → CONTENT_VERIFIED | CONTENT_MISMATCH |
NOT_FOUND` (or `ORPHANED`) with its transitions, every metadata answer of the node (check c;
paged: newest `limit` first, older ones with `cursor=validationsCursor`) and the newest 50
content comparisons (check d). A mismatch carries a field diff and a canonical-JSON diff.

### `POST /messages/{blockId}/verify`

Asks the node now: `GET /api/core/v2/blocks/{id}/metadata`, then, once a milestone references
the block, `GET /api/core/v2/blocks/{id}` compared byte for byte with what was received.
Stored like the background checks; `calls` lists what the node answered during this run.

| Status | When |
|---|---|
| 200 | checks ran, or `cached: true` when the node answered about this block less than `WITNESS_VERIFY_COOLDOWN_S` (20 s) ago |
| 401 | `WITNESS_VERIFY_TOKEN` is set and the bearer is wrong |
| 404 | unknown block |
| 409 | no stored copy of the content to compare |
| 429 | too many checks running (`WITNESS_VERIFY_CONCURRENCY`, 4); see `Retry-After` |
| 503 | no node configured (`WITNESS_HORNET_URL` empty) |

Waits at most `WITNESS_VERIFY_TIMEOUT_S` (10 s) for an unconfirmed block.

## Lookup

### `POST /lookup`

"Was this exact message stored?" Post any JSON value (up to 256 KiB). It is canonicalised
(RFC 8785), so key order and whitespace do not matter, and matched against every stored body;
a posted `witness/v1` envelope is matched by its body as well. Each match links to its proof.

```bash
curl -s -X POST localhost:7200/lookup -H 'content-type: application/json' \
  -d '{"score": 0.053424256924272794, "id": "MyDomain:fa163ed55867"}'
```

```json
{"canonHash": "0x2478876e…10be07b4", "bodyCanonHash": null,
 "matches": [{"blockId": "0x…", "tag": "trust.score", "verdict": "PRODUCER_SIGNED", "...": "..."}]}
```

400 when the body is not JSON or cannot be canonicalised, 413 when it is too large.

### `POST /lookup/blind`

Find sealed messages by blind index token. Tokens are
`b64u(HMAC-SHA256(K_search, "ie:" + id))` or `… "tag:" + tag)`; compute them where the search
key lives and post them. The key never reaches the explorer.

```json
{"tokens": ["PaITfGG18DlzZ7Hde2GcHN2ty0J4yxp1muRSJ-vL14k"]}
```

## Ingest

### `POST /ingest` (token)

The HTTP path of the brief's (a): the modified Messages API posts the same submission record
it publishes on MQTT `aerios/iota/submissions/{tag}`.

| Field | Type |
|---|---|
| `subId` | string, unique per upload |
| `receivedAtMs` | integer |
| `tag` | string |
| `message` | the message as received |
| `dataHex` | exact bytes sent to the node, or `null` |
| `blockId` | the node's block id, or `null` when the node did not accept the block |
| `hornetStatus` | the node's HTTP status, or `null` |
| `relay` | `{verdict, iss, seq}` as the relay decided |

202 for a new record (stored, lifecycle opened, queued for the Tangle checks); 200 with
`duplicate: true` for one already received by `subId`, or by `blockId` over MQTT; 400 not a
record; 401 wrong token; 403 ingest disabled; 413 over 256 KiB.

## Proofs

### `GET /proofs/{blockId}`

A self-contained `witness-proof/v1` bundle: raw block, milestone essence and signatures, the
Merkle audit path to the milestone's inclusion root, the recorded envelope verdict with a DID
document snapshot (information only), and, when a checkpoint covers the milestone, the
checkpoint with the milestone's membership path and the Rebased trail, record and
transaction. Verify it with `witness verify`, `node packages/verify/dist/cli.js` or the
console; the format and the checks are in [architecture.md](architecture.md#the-proof-ladder).

`?format=inx-poi` returns the shape of inx-poi's `/api/poi/v1/create` instead, which inx-poi's
`/api/poi/v1/validate` accepts. 404 when the block is not in an indexed milestone cone, 409
when the stored bytes do not hash to the block id.

### `GET /config/verifier`

The configuration this explorer would have a verifier pin:

```json
{"bundleVersion": 1, "network": "private_tangle1",
 "trustedCoordinatorKeys": ["0xed3c3f1a…b3b1248c", "0xf6752f5f…28ef349c"], "threshold": 2,
 "rebasedNetwork": "testnet",
 "trailId": "0x0715cfc56779f78cea48a3afb75dd44d7b9694008286acdb27a16f2c6e3ab313"}
```

Informational. A verifier should take its pins from a source it trusts, not from the server
whose proofs it checks; the console and the CLI do.

### `GET /milestones?from=&to=`

Ids of the indexed milestones in the range, in index order, with `complete` (all indexed) and
`msgCount` (tagged-data messages they reference). This is the window the anchor service
proposes for a checkpoint, before it re-derives every id from the node.

## Traceability

### `GET /ie`, `GET /ie/{ieId}/lineage`

Infrastructure Elements that have ledger messages, and one IE's score history in milestone
order with the latest score the ledger vouches for, Orion's current `trustScore`, and `drift`
(`true` beyond `WITNESS_DRIFT_EPSILON`, `null` when Orion cannot be asked). `limit` up to
10 000.

### `GET /flows?by=`, `GET /flows/{by}/{key}`

Related messages grouped `by` `issuer` (default), `ie`, `service` (service component) or
`corr` (correlation id). One flow lists its messages in order (issuer flows by `seq`, others
by time); issuer flows also report their hash chain: `links` (messages whose `prev` is the
previous message), `gaps` and `forks`.

```bash
curl -s "localhost:7200/flows/issuer/did:iota:testnet:0x15eb8c4d90fa4fff1d49f3ae8b1676a61e09c883303acd383cbfaacb538db9ba?limit=5"
```

## Integrity

### `GET /alerts`

Filters: `rule`, `severity` (`critical`, `high`, `medium`, `low`), `ie`, `block_id`, `since`,
`limit` (default 200). Each alert has `rule`, `severity`, `blockId`, `ieId`, `evidence` and
time. The rules are listed in [architecture.md](architecture.md#verdicts-lifecycle-alerts).

### `GET /incidents`, `GET /incidents/{id}`

Incidents (filters `status`, `severity`, `ie`, `since`). One incident returns its events in
time order, each with its role, verdict, lifecycle status and proof link, and the alerts that
joined it; `limit` per page, with `eventsAfter` / `alertsAfter` cursors.

### `GET /anchors`

Checkpoints, newest first: window, `msRoot`, the checkpoint, its hash, the Rebased network,
transaction and record, and `status` (`pending`, `anchored`, `failed`, `mismatch`).

## Identity, posture, reports

### `GET /identity`

The component DIDs with their public keys (as the anchor service publishes them) and a summary
of the writer policy, with the policy hash every checkpoint commits to.

### `GET /posture`, `POST /posture/scan?active=` (token)

Findings of the last scan of the node this explorer watches: id, severity, evidence (no
address or secret), fix. The scan is passive by default (`GET`/`HEAD`/`OPTIONS` and a TCP
connect to INX). With `active=true` it also sends an invalid `POST` to a protected route and
tries the dashboard's default login, but only against loopback hosts or those listed in
`WITNESS_POSTURE_ALLOW_ACTIVE_HOSTS`. The findings are explained in [findings.md](findings.md).

### `POST /reports` (token), `GET /reports`, `GET /reports/{hash}`, `GET /reports/{hash}.html`

`POST` builds an audit report over the stored data (optionally `{"ie", "msFrom", "msTo"}`),
stores its JSON and a self-contained HTML page, and posts the report's hash to the Tangle as a
producer-signed `audit.report` message through the witness-relay. The report is stored first
as not anchored and marked anchored with its block id once the relay accepts it.

| Status | When |
|---|---|
| 201 | built and anchored |
| 200 | identical report already anchored |
| 400 | `msFrom` after `msTo` |
| 401 / 403 | wrong token / report writing disabled |
| 502 | the relay refused or is unreachable; the report stays stored, not anchored |
| 503 | signing or relay not configured, or the relay URL is not a witness-relay |

`GET /reports/{hash}` returns the report and its anchoring state; the report's BLAKE2b-256
over its RFC 8785 form is `reportHash`, the value in the on-chain `audit.report` at `blockId`.

## Live events

### `GET /stream`

Server-Sent Events: `message`, `milestone`, `alert`, `anchor`, `posture`, `submission`,
`lifecycle`, `incident`. `types=` filters (comma-separated), `limit=` closes after that many
events. Every event has an id; resume without gaps or duplicates with the `Last-Event-ID`
header or `?after=<id>`. A comment line every 15 s keeps the connection alive. Open streams
are capped (`WITNESS_STREAM_MAX_SUBSCRIBERS`, 200; 503 beyond).

```
id: 6886
event: milestone
data: {"id":6886,"type":"milestone","at":"2026-10-07T02:15:24.086Z","payload":{"index":3084,"id":"0xca230d06…","blocks":1,"messages":0}}
```

The same alerts and incident changes are published on MQTT `witness/alerts/{severity}`.

## System

- `GET /healthz`: `{"status": "ok", "db": "ok", "network": "private_tangle1", "version": "0.1.0"}`;
  503 when the database is unreachable.
- `GET /stats`: row counts, the indexer cursor, validation backlog, node mount state, open
  streams, and each component's status (`indexer`, `resolver`, `policy`, `rules`, `orion`,
  `anchor`, `shadow`, `incident-engine`, `alerts-mqtt`, …; meanings in
  [operations.md](operations.md#indexer)).

## Other services

The relay and the anchor service have small HTTP surfaces of their own.

**witness-relay** (`relay/src/witness_relay/app.py`, port 5557 in compose):

| Route | Does |
|---|---|
| `POST /upload?node=<name>` | the Messages API. Body `{"tag": str, "message": any}`. 200 with the legacy `{"return_payload", "status_code"}` plus `witness: {blockId, verdict, iss, seq, subId}`; 400 unknown node or bad body, or the legacy text `Hornet node not found…` when the node cannot be reached; 403 refused by verification or policy (`{"error", "verdict"}`); 413 over the block size; 502 the node rejected the block; 503 the signer's key cannot be resolved right now (with `Retry-After`) or the receipt store is down |
| `GET /receipts?tag=&iss=&limit=` | receipts of accepted blocks: block id, issuer, key, sequence number, verdict, caller |
| `GET /healthz` | status, the relay's DID, database and forwarding queue state |

**witness-anchor** (`anchor/src/server.ts`, port 7300):

| Route | Does |
|---|---|
| `GET /resolve/{did}` | a did:iota document as `{doc, version, keys: [{kid, type, publicKeyHex, revokedAtMs}], historyComplete}`, keys with their revocation times (cached) |
| `GET /identities` | the published identity file |
| `GET /checkpoints?limit=`, `GET /checkpoints/{seq}` | checkpoints; a single one is read from the trail record on chain (`source: "chain"`, `addedBy`, `tx`, `txVerified`, explorer links); 502 when the chain cannot be read or disagrees |
| `POST /checkpoints/run` | admin bearer (`ANCHOR_ADMIN_TOKEN`): run one anchoring tick now |
| `GET /healthz` | loop health; 503 when degraded |

Only `/anchor/resolve/` is exposed to browsers (through the console's origin); the admin route
must not be reachable from them.
