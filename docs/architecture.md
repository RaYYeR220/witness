# Architecture

Witness runs next to the organisers' aeriOS IOTA stack on the same Docker network
(`iota-net`) without changing its configuration. Producers write through the witness-relay, a
compatible replacement for the Messages API (the stock one keeps running), and the stock Trust
Manager is replaced by the same image with a signing patch. HORNET, inx-coordinator,
inx-dashboard, Orion-LD and Mongo run as shipped; our compose override only publishes their
ports on loopback.

The diagram and the component table are in the [README](../README.md#architecture); the
operational detail (flags, ports, secrets, Helm) is in [operations.md](operations.md).

## Components

| Component | Code | Role |
|---|---|---|
| **witness-relay** | `relay/` | The modified Messages API. Same `POST /upload?node=` contract. Verifies producer-signed envelopes and passes them through; wraps anything else in an envelope signed by the relay (`att.mode = "relay"`); enforces the writer policy and per-issuer sequence numbers; optionally seals bodies; keeps receipts; forwards a submission record of every well-formed upload to the explorer. |
| **witness-indexer** | `indexer/` | The explorer's writer. Streams confirmed milestones and their cones over INX (REST polling as fallback), stores milestones, blocks and messages in PostgreSQL, gives every tagged-data message one verdict, runs the brief's checks (c) and (d) on every submission, runs the integrity rules and the incident engine, publishes events and alerts. |
| **witness-api** | `api/` | Read side over the same database: search, lifecycle, proof bundles, lineage, flows, alerts, incidents, anchors, identity, posture, reports, SSE. Mounted on the node through INX `RegisterAPIRoute`. It never states that a proof is valid; it hands out the bytes. |
| **witness-anchor** | `anchor/` | TypeScript, on the IOTA SDK. Creates and controls the did:iota identities, resolves DIDs with their key history for relay, indexer and console, and every `ANCHOR_EVERY` milestones writes a checkpoint of the milestone history to an IOTA Rebased Audit Trail, then mirrors it into the Tangle as a signed `witness.anchor` message. |
| **core** / **@witness/verify** | `core/`, `packages/verify/` | The formats and the verifier, in Python and TypeScript, held equal by shared vectors. |
| **console** | `console/` | Vue 3 UI; verifies every proof in the browser with `@witness/verify` against pins compiled into the build. |
| **cli**, **mcp**, **sdk** | `cli/`, `mcp/`, `sdk/` | Offline verification and queries; MCP tools over the API (verification runs locally with pinned config); producer-side signing. |

## Data flow

1. **Submit.** A producer posts `{tag, message}` to the relay. A `witness/v1` envelope is
   verified against the signer's key (resolved through the anchor service), the writer
   policy and the issuer's last sequence number; a plain message is wrapped and signed by
   the relay. The relay posts a tagged-data block to HORNET (`POST /api/core/v2/blocks`) and
   answers in the legacy shape plus a `witness` object with the block id.
2. **Forward.** Whatever happened (accepted, refused, rejected by the node), the relay
   publishes a submission record to Mosquitto (`aerios/iota/submissions/{tag}`, QoS 1) and
   posts it to `POST /ingest`: the message as received, the exact bytes sent (`dataHex`), the
   block id or null, HORNET's status, the relay's verdict, issuer and sequence number. The
   explorer stores it once (deduplicated by submission id and block id): lifecycle `RECEIVED`,
   then `SUBMITTED` when it carries a block id.
3. **Check (c) and (d).** The indexer's validator polls `GET /api/core/v2/blocks/{id}/metadata`
   with backoff (`SOLID`, then `CONFIRMED` once `referencedByMilestoneIndex` is set), then
   fetches `GET /api/core/v2/blocks/{id}` as raw bytes and requires `BLAKE2b-256(raw) == id`
   and the tag and data byte-for-byte equal to `dataHex`: `CONTENT_VERIFIED`,
   `CONTENT_MISMATCH` or `NOT_FOUND`; no confirmation in time: `ORPHANED`. Every answer is
   stored. Later passes compare the stored copies with the Tangle again (`DB_TAMPER`).
4. **Index.** Independently, the indexer receives each confirmed milestone over INX, reads
   its cone in white-flag order, and accepts it only if it continues the stored milestone
   chain and the cone's Merkle root equals the milestone's `inclusionMerkleRoot`. Every
   tagged-data payload is classified against the schema registry and judged (one verdict,
   see [envelope-spec.md](envelope-spec.md#7-verdicts)). All of a milestone is one database
   transaction; signing keys are resolved before it opens, and an unreachable resolver
   stalls the milestone instead of producing a verdict.
5. **Rules and incidents.** Per message and periodically the rules compare sources: the
   submission against the Tangle, the ledger score against Orion's `trustScore`, stored
   milestone ids against the on-chain checkpoint, confirmed blocks against submissions
   (`SHADOW`), issuers' `prev` chains (`CHAIN_GAP`, `CHAIN_FORK`). The incident engine groups
   trust events per IE. Events go to SSE (`GET /stream`, backed by an events table) and
   alerts to MQTT `witness/alerts/{severity}` once their milestone commits.
6. **Anchor.** The anchor service asks the API for the next window of milestone ids
   (`GET /milestones`), re-reads every one of them from HORNET as raw bytes, recomputes each
   id, checks at least `threshold` signatures by distinct pinned coordinator keys and the
   previous-milestone link to the last anchored milestone, and only then writes the
   checkpoint (`msRoot` over the window's milestone ids, `prev` = hash of the previous
   checkpoint, `policyHash`, `msgCount`) as one Audit Trail record. It mirrors it into the
   Tangle as a `witness.anchor` envelope through the relay.
7. **Prove.** `GET /proofs/{blockId}` assembles a `witness-proof/v1` bundle from stored raw
   bytes: the block, the milestone essence and signatures, the Merkle path, a DID snapshot
   for display, and the checkpoint with the milestone's membership path. The client runs
   the ladder below.

## The proof ladder

`core/src/witness_core/bundle.py` and `packages/verify/src/bundle.ts`. Each step is ok, failed
or not checked. The bundle is VALID only when all five are ok, INVALID when any failed,
otherwise PARTIAL. The verifier holds only its pinned configuration; everything in the bundle
is recomputed or cross-checked, and the explorer's recorded verdict is ignored.

| Step | Checks | Proves | Does not prove |
|---|---|---|---|
| ① `block_hash` | `BLAKE2b-256(raw) == block.id`, and `raw` parses as a Stardust block | these bytes are the block with this id | that any node ever saw it |
| ② `inclusion` | the TIP-4 audit path from the block id reaches the `inclusionMerkleRoot` in the milestone essence (the root is taken from the essence, never from the bundle's claims) | the milestone's white-flag cone contains the block | that the milestone is genuine |
| ③ `milestone_signatures` | bundle network equals the pinned network; milestone id = `BLAKE2b-256(essence)`; at least `threshold` valid Ed25519 signatures over the id by distinct pinned coordinator keys (small-order keys never count) | holders of the pinned coordinator keys confirmed the block | anything, if those keys are public, as on the organisers' Tangle |
| ④ `envelope` | the payload is a well-formed `witness/v1` envelope bound to the block's tag; `kid` belongs to `iss`; the key comes from the trusted resolver, not the bundle; the signature verifies; the key was in force through the whole second of the milestone's timestamp; the bundle's DID snapshot, if any, agrees with the resolver | who wrote the message, and that the key was valid when it was confirmed | anything about an unsigned (legacy) message: not checked |
| ⑤ `anchor` | the checkpoint is well formed and names the pinned network; the milestone's index is in its window and its id is under `msRoot` by the membership path; the bundle names the pinned trail and Rebased network; the record is read from the pinned RPC, of the pinned Audit Trail package, written by the pinned anchor address, and its checkpoint hash equals the bundle's checkpoint | the milestone existed when that record was written to a public ledger that the private Tangle's keys do not control | milestones newer than the last checkpoint (not checked); gaps or reordering elsewhere in the trail (one record is read) |

The CLI and the MCP tool run the same Python ladder; the console runs the TypeScript one. A
client that fetched a bundle by block id also compares the bundle's block id with the one it
asked for, so an API cannot answer with the valid proof of a different block.

## Trust boundaries

What each part relies on, and what it deliberately does not.

| Part | Relies on | Does not rely on |
|---|---|---|
| Proof verifier (CLI, MCP, console) | its pinned config: network label, coordinator public keys and threshold, Rebased network, trail id, Rebased RPC, Audit Trail package id, anchor writer address; a DID resolver for step ④; the pinned Rebased RPC for step ⑤ | anything in the bundle (recomputed or cross-checked), the bundle's DID snapshot (display only, may only contradict), the explorer's verdict, `GET /config/verifier` (the console's pins are compiled in; the CLI requires a local file) |
| Console in the browser | as above; step ④ asks the anchor service (`/anchor/resolve/`, proxied on the console's origin); step ⑤ reads the RPC directly | the API for any verdict |
| Indexer | its HORNET node for milestones and cones (chain link and cone root are checked; coordinator signatures are not); the anchor service as DID resolver; the writer policy file; Orion for the drift and unknown-IE rules only; the anchor service's reading of the on-chain record for R11 | submission records (compared with the node), message content, the `witness.anchor` mirror for R11 (only the on-chain record counts), mirrors not signed by the pinned anchor DID |
| Relay | its configuration: allowed node names, writer policy, its own signing key; the anchor service for producer keys; its own schema for sequence claims | the caller's `node` value (a name, not a URL), anything a caller says about itself without a valid signature or Keycloak token |
| Anchor | HORNET and the pinned coordinator keys and threshold; its keystore | the indexer's database and the API: they only propose a window, every id is re-derived from HORNET. Exception: `msgCount` is taken as reported |
| API | the database | nothing is asserted to clients beyond what is stored; proofs are for clients to check |

## Threat model

Who can do what in the aeriOS stack as shipped, and what the explorer makes of it. The
attacks marked with an eval class are part of the [fault-injection evaluation](eval.md).

| Adversary | Can | Witness shows |
|---|---|---|
| Anyone who can reach the Messages API or a node (no authentication on either) | write any tag and content, name any IE | unsigned on a tag that requires signatures: `UNSIGNED`; a forged signature or someone else's DID: `FORGED` (A01); a DID not on the writer policy: `UNAUTHORIZED_WRITER` (A04); written to the node directly, around the Messages API: `SHADOW` (A17); an IE Orion does not know: `UNKNOWN_IE` (A12) |
| A replayer with a captured envelope | post it again, or under another tag | `REPLAY` (A03: same `seq` or nonce for the issuer); `FORGED` under another tag, since the tag is signed (A02) |
| Holder of a revoked key | keep signing | `REVOKED_KEY`, decided against the milestone's second (A05) |
| A component writing nonsense with a valid key | a body that breaks its tag's schema | `MALFORMED` (A15) |
| Holder of the coordinator keys (on this Tangle: anyone, they are IOTA's sample keys) | sign milestones that nodes accept; present another history | ③ passes; ⑤ fails for anchored windows (A09); `ANCHOR_MISMATCH` when stored milestone ids no longer hash to the on-chain root. Not caught: milestones newer than the last checkpoint |
| Someone who can write the explorer's database | change stored content or delete rows | `DB_TAMPER` when a stored copy no longer matches the Tangle (A19); `MISSING_IN_DB` when a confirmed block is missing; proofs are recomputed from raw bytes, so altered bytes fail ① or ② |
| A Messages API (or anything between it and the node) that alters bytes or invents blocks | report one thing, send another | `CONTENT_MISMATCH` (A16), `ORPHANED` (A18), `NOT_FOUND` |
| Someone who overwrites Orion's `trustScore` | change what the portal shows | `DRIFT` against the ledger score (A06) |
| A compromised explorer API | serve false verdicts or another block's proof | verdicts are recomputed by the client; a proof of another block is refused. Withholding data is not detected |
| A compromised anchor resolver | lie about keys | not detected in the browser or the indexer; the CLI can pin a DID document (`--did-snapshot`) |
| The operator of the pinned Rebased RPC | lie about a record | not detected; pin a fullnode you run (`--rebased-rpc`) |
| A thief of the anchor's gas key | add trail records; with the admin capability, shorten the delete lock and delete records | records by another writer fail ⑤; checking that sequence numbers are contiguous and `prev` links hold is listed in [anchor/SECURITY.md](../anchor/SECURITY.md) and not done by the ladder |

Confidentiality is a separate concern: by default every payload on the Tangle is public and
replicated to every peer. Tags listed in `RELAY_ENCRYPT_TAGS` are sealed by the relay (JWE to
the domain's X25519 key) with blind index tokens for lookup; see
[envelope-spec.md](envelope-spec.md#5-sealed-bodies-blind-indexes-commitments).

## Verdicts, lifecycle, alerts

- **Verdict** (one per message, from the block alone plus key, policy and issuer history):
  `PRODUCER_SIGNED`, `RELAY_ATTESTED`, `UNSIGNED_LEGACY`, `FORGED`, `UNAUTHORIZED_WRITER`,
  `REPLAY`, `REVOKED_KEY`, `MALFORMED`. Definitions in
  [envelope-spec.md](envelope-spec.md#7-verdicts).
- **Lifecycle** (per submitted block, from the node's answers): `RECEIVED` → `SUBMITTED` →
  `SOLID` → `CONFIRMED` → `CONTENT_VERIFIED` | `CONTENT_MISMATCH` | `NOT_FOUND`, or `ORPHANED`.
- **Alerts** (rule, severity, evidence; deduplicated):

| Rule | Severity | Raised when |
|---|---|---|
| R1 `FORGED`, R2 `UNAUTHORIZED_WRITER`, R3 `REPLAY`, R9 `MALFORMED`, R10 `REVOKED_KEY` | critical, high, high, low, high | the verdict says so |
| R4 `UNSIGNED` | medium | unsigned message on a tag whose policy requires signatures |
| R5 `DRIFT` | medium | Orion's `trustScore` differs from the latest ledger score beyond epsilon for longer than the grace period |
| R6 `UNKNOWN_IE` | low | message about an IE Orion does not list |
| R7 `ANOMALY` | medium | score jump beyond the threshold with no trusted security event shortly before |
| R8 `STALE` | low | no ledger score for an IE within a multiple of the score interval |
| R11 `ANCHOR_MISMATCH` | critical | stored milestone ids of an anchored window no longer hash to the on-chain `msRoot`, or the mirror disagrees with the chain |
| R12 `CLOCK_SKEW` | low | the signer's `iat` far from the milestone timestamp |
| R13 `ORPHANED` | high | a submitted block id is never confirmed |
| R14 `SHADOW` | high | a confirmed block that no submission names |
| R15 `CHAIN_GAP`, R16 `CHAIN_FORK` | medium, high | an issuer's `prev` skips its last block, or two messages continue the same `prev` |
| R17 `CONTENT_MISMATCH` | critical | the Tangle holds other bytes than the Messages API sent |
| R18 `DB_TAMPER` | critical | a stored copy no longer matches the Tangle |
| `NOT_FOUND`, `MISSING_IN_DB`, `ANCHOR_UNVERIFIABLE` | critical, critical, low | a confirmed block the node no longer serves; a confirmed block the database lacks; an anchor that cannot be checked for too long |

Rules never change a verdict and never conclude from a service they could not ask.

## Incidents

`indexer/src/witness_indexer/incidents.py`. An incident opens on a trust-score drop, a
self-orchestrator error code, an LLO "Service component failed", a `self-security` message, a
critical or high alert on a proven or relayed block, an attack alert on a message naming an IE Orion
knows, or an alert about the explorer's own records. Events join an open incident that shares
its IE, service component or issuer within a time window. Evidence has three trust levels:
*proven* (producer-signed by an allowed writer) may shape and close an incident; *relayed*
(relay-attested, or unsigned through the Messages API) may open or join one but not close it;
*untrusted* content counts only through the alert raised about it. An incident closes as
`closed:recovered` when a proven score returns to its level before the drop, or
`closed:quiet` after a quiet period.

## Storage

PostgreSQL 16, plain SQL migrations in `indexer/src/witness_indexer/migrations/`: `milestones`,
`blocks` (raw bytes), `messages` (raw data, JSON copy with a GIN index and a full-text
`tsvector`, verdict, issuer, sequence, `prev`, `corr`, canonical hash), `blind_index`,
`ie_scores`, `alerts`, `anchors`, `submissions`, `validations` and `content_checks` (every
node answer), `lifecycle`, `incidents`, `incident_events`, `incident_alerts`, `reports`,
`events` (the SSE log), `cursor`, `service_status`. The relay keeps its receipts and sequence
claims in its own schema under its own database login.
