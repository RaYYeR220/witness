# Claims ledger

Every public claim about Witness, with what backs it. Tags:

- **REPRODUCIBLE**: re-run it from this repository (tests, vectors, CLI), no access to our
  machines needed.
- **VERIFIED-LIVE**: observed on our running deployment or written to a public ledger. Ledger
  artefacts link to the IOTA explorer; local observations name the command that shows them on
  a stack started with `deploy/compose/stack-up.sh --witness`.
- **MODELED**: implemented and tested, but against simulated inputs or simplified conditions,
  not against the real aeriOS component or in production conditions.
- **NOT-CLAIMED**: we do not claim this, even where it might be assumed.

Paths are relative to the repository root. Test counts and commands: [README](README.md#tests).

## The challenge brief

| # | Claim | Tag | Evidence |
|---|---|---|---|
| B1 | The relay is a drop-in for `eclipse-aerios/iota-messages-api`: same `POST /upload?node=` request, same success response (`status_code`, `return_payload`, rendered as Flask's `jsonify` renders it) | REPRODUCIBLE | `relay/tests/test_legacy_contract.py::test_legacy_contract_golden` against `core/tests/vectors/legacy_upload_response.json`, captured from the stock image |
| B2 | It refuses a `node` value that is not configured (the stock API builds its URL from it) | REPRODUCIBLE | `relay/src/witness_relay/app.py` (`allowed_nodes`), `relay/tests/test_relay.py` |
| B3 | Every well-formed upload (a JSON `{tag, message}` for a configured node), including those the relay refuses and those HORNET rejects, is forwarded to the explorer as a submission record over MQTT and HTTP `POST /ingest` | REPRODUCIBLE | `relay/src/witness_relay/app.py` (`finally: relay.forward.submit(...)`), `relay/tests/test_forwarding.py`, `api/tests/test_api_ingest.py` |
| B4 | In our deployment those records arrive over MQTT and are joined to the block | VERIFIED-LIVE | `GET /messages/{blockId}` shows `submission.source: "mqtt"` for Trust Manager blocks |
| B5 | Stored messages are searchable over REST by block id, date and tag, and by issuer, verdict, kind, IE, milestone range, full text and JSON path | REPRODUCIBLE | `api/tests/test_api.py::test_search_by_block_id_date_tag`, `::test_messages_filters_and_cursor`; [docs/api.md](docs/api.md) |
| B6 | Each submitted block is checked with `GET /api/core/v2/blocks/{id}/metadata` until a milestone references it; every answer is stored | REPRODUCIBLE | `indexer/tests/test_validator.py::test_happy_path_lifecycle`, `::test_solid_lag_retry_backoff`, `::test_orphan_timeout` |
| B7 | The content is checked with `GET /api/core/v2/blocks/{id}`: the raw block must hash to its id and carry exactly the tag and data bytes the Messages API sent | REPRODUCIBLE | `indexer/tests/test_validator.py::test_content_mismatch`, `::test_tag_mismatch`, `::test_wrong_block_for_id` |
| B8 | Both checks pass on live Trust Manager traffic | VERIFIED-LIVE | `GET /messages/{blockId}`: `checks.solid.isSolid: true`, `checks.content.result: "MATCH"`, `status: "CONTENT_VERIFIED"` |
| B9 | The explorer API is also served by the node itself, at `/api/witness/v1`, through INX `RegisterAPIRoute` | VERIFIED-LIVE | `curl localhost:14265/api/routes` lists `witness/v1`; `curl localhost:14265/api/witness/v1/healthz`; `api/tests/test_node_mount.py` |
| B10 | MQTT runs on Eclipse Mosquitto with logins and topic ACLs, no anonymous clients | REPRODUCIBLE | `deploy/compose/mosquitto.conf`, `deploy/compose/mosquitto.acl`; live tests `relay/tests/test_relay_live.py`, `indexer/tests/test_incidents.py::test_alerts_reach_mosquitto` (need the stack) |
| B11 | The console shows live messages, searches them and runs the five proof checks in the browser | REPRODUCIBLE | `console/src/views/*.test.ts`, `console/src/verify/ladder.test.ts`; replay build: <!-- REPLAY-URL -->not published yet<!-- /REPLAY-URL --> |
| B12 | Related messages are traced by issuer hash chain (`prev`), correlation id (`corr`), IE and service component, with gaps and forks reported | REPRODUCIBLE | `api/src/witness_api/routes_flows.py`, `indexer/src/witness_indexer/rules.py` (R15, R16), `indexer/tests/test_rules.py` |
| B13 | The Incident Explorer groups trust events per IE into incidents with a timeline, each event carrying its verdict, lifecycle status and proof link; changes go out over SSE and MQTT | REPRODUCIBLE | `indexer/src/witness_indexer/incidents.py`, `indexer/tests/test_incidents.py`, `api/tests/test_api_incidents.py` |
| B14 | Incident triggers from LLO failures, self-orchestrator errors and self-security alerts | MODELED | message shapes taken from the upstream sources (`llo-docker-operator/internal/iota/iotaTangle.go`, `self-orchestrator/script.js`); exercised by tests and the traffic generator (`chaos/src/witness_chaos/traffic.py`), not by running those components |

## Proofs and verification

| # | Claim | Tag | Evidence |
|---|---|---|---|
| P1 | A proof bundle is verified from raw bytes in five steps (block hash, Merkle inclusion, coordinator signatures, envelope signature, anchor); the explorer's own verdict is never input | REPRODUCIBLE | `core/src/witness_core/bundle.py`, `core/tests/test_bundle.py` |
| P2 | Python and TypeScript (the build the console ships, run under jsdom) reach the same result on every step for the same 47 bundle cases | REPRODUCIBLE | `core/tests/vectors/bundles.json` run by `core/tests/test_bundle.py` and `packages/verify/test/bundle.test.ts` (jsdom, with `jose`'s browser build: `packages/verify/vitest.config.ts`); the console runs `@witness/verify` |
| P3 | A Trust Manager `trust.score` from our private Tangle verifies VALID on all five steps, with step 5 read from IOTA Rebased testnet (checkpoint record 4) | VERIFIED-LIVE | `witness verify <blockId> --from-api --config console/src/config/verifier.json --resolver http://127.0.0.1:7300` on block `0x355306b0…bb364de7` (milestone 2870); record: [tx E7onRs…](https://explorer.iota.org/txblock/E7onRsfrvhy5yBmamkXHKJmWeWkKJcQNFDcz9Dn9uKsz?network=testnet). The block itself lives on our private Tangle and in the replay snapshot |
| P4 | A milestone made offline with the public sample coordinator keys passes steps 1 to 3; only step 5 can tell it apart | REPRODUCIBLE | vector `valid_anchored` in `core/tests/vectors/bundles.json` (see [JUDGES.md](JUDGES.md#2-verify-a-bundle-yourself)); `chaos/src/witness_chaos/forge.py` |
| P5 | One flipped byte, a replaced Merkle sibling, a dropped signature, a doctored checkpoint each turn exactly their step red | REPRODUCIBLE | bundle cases `raw_byte_flipped`, `path_hash_corrupted`, `one_signature_threshold_2`, `anchor_mismatch` |
| P6 | Our Merkle proofs are accepted by inx-poi: 4 of 4 valid, 4 of 4 rejected with the leaf altered | VERIFIED-LIVE | [docs/eval.md](docs/eval.md#proof-compatibility); offline: `core/tests/test_poi_compat.py` |
| P7 | A client that fetches a bundle by block id refuses a valid proof of another block | REPRODUCIBLE | `cli/tests/test_cli.py::test_verify_from_api_refuses_a_proof_for_another_block`, `console/src/verify/binding.test.ts` |
| P8 | Small-order and non-canonical Ed25519 public keys never verify anything | REPRODUCIBLE | `core/src/witness_core/ed25519.py`; envelope cases `identity_key_zero_sig`, `identity_key_noncanonical`; bundle cases `small_order_*` |
| P9 | Hostile nesting gets the same verdict on every platform and in both languages (caps 2500 for JSON text, 500 for canonicalisation) | REPRODUCIBLE | `core/src/witness_core/nesting.py`, `packages/verify/src/json.ts`; bundle cases `*_hostile_nesting`, `envelope_nested_past_jcs_cap` |
| P10 | Step 4 in the browser is an independent read of the chain | NOT-CLAIMED | the browser takes the DID document from our anchor service (`/anchor/resolve`); see [architecture](docs/architecture.md#trust-boundaries) |

## Identities, signatures, policy

| # | Claim | Tag | Evidence |
|---|---|---|---|
| I1 | Six did:iota identities on IOTA Rebased testnet: a domain DID and five component DIDs it controls | VERIFIED-LIVE | table below; public keys in `deploy/identity/testnet.json` |
| I2 | The Trust Manager signs its own `trust.score` with its component key and adds a salted commitment (`cmt`) for each sub-score it holds | VERIFIED-LIVE | `sdk/patches/trust-manager-witness.patch`; live envelope on `GET /messages/{blockId}` (`submission.message.cmt`, verdict `PRODUCER_SIGNED`) |
| I3 | The relay refuses unknown keys, unauthorised writers, revoked keys and replayed sequence numbers before anything reaches the node | REPRODUCIBLE | `relay/src/witness_relay/policy_gate.py`, `relay/tests/test_relay.py` |
| I4 | The explorer gives every message exactly one verdict, decided from the block bytes, the resolved key, the writer policy and the issuer's history | REPRODUCIBLE | `indexer/src/witness_indexer/classify.py` (`judge`), `indexer/tests/test_pipeline.py`; [envelope spec](docs/envelope-spec.md#7-verdicts) |
| I5 | Revocation is time-aware to the milestone second and fails closed inside it | REPRODUCIBLE | bundle cases `key_revoked_at_inclusion`, `key_revoked_same_second_after`, `key_revoked_next_second`, `key_replaced_within_second` |
| I6 | Every checkpoint commits to the hash of the writer policy in force | VERIFIED-LIVE | `policyHash` `0x3528f872…9c70be4e` in records 1 to 4 equals `BLAKE2b-256(JCS(deploy/policy.json))` (`witness_core.policy.policy_hash`). Records written while the evaluation ran commit to the hash of the eval policy the stack ran on then (`chaos/demo-policy.json` plus the run's producer, see [docs/eval.md](docs/eval.md#method)), not to `deploy/policy.json` |
| I7 | Unmodified aeriOS producers (LLO, self-orchestrator) are authenticated | NOT-CLAIMED | their messages are relay-attested: the relay signs that it received them (caller `anonymous` unless a Keycloak token is sent) |

## Anchoring on IOTA Rebased

| # | Claim | Tag | Evidence |
|---|---|---|---|
| A1 | The anchor service commits each window of milestones to an Audit Trail record, after re-deriving every milestone id from HORNET and checking the coordinator signatures against pinned keys | REPRODUCIBLE | `anchor/src/loop.ts`, `anchor/test/loop.test.ts` ("checks every window against the node before anchoring…", "refuses to anchor … when the node disagrees"); [anchor/SECURITY.md](anchor/SECURITY.md) |
| A2 | Four checkpoints of our private Tangle (milestones 1 to 2880) are on testnet, each linked to the previous one by `prev`, all written by the anchor's address | VERIFIED-LIVE | table below; read them yourself with `witness_core.rebased.fetch_record` ([JUDGES.md](JUDGES.md#3-the-proof-on-iota-rebased)) |
| A3 | The explorer raises `ANCHOR_MISMATCH` when stored milestone ids no longer hash to the on-chain root, comparing with the Rebased record, never with the private-Tangle mirror | REPRODUCIBLE | `indexer/src/witness_indexer/rules.py` (R11), `indexer/tests/test_rules.py`, `indexer/tests/test_anchors.py` |
| A4 | Only `witness.anchor` mirrors signed by the pinned anchor DID are ingested | REPRODUCIBLE | `indexer/tests/test_anchors.py::test_only_the_pinned_anchor_producer_signed_well_formed_counts` |
| A5 | Anchoring on IOTA Rebased mainnet | <!-- MAINNET -->NOT-CLAIMED | not done: DIDs and the Audit Trail are on testnet<!-- /MAINNET --> |
| A6 | Anchoring prevents forged milestones | NOT-CLAIMED | it bounds them: a milestone newer than the last checkpoint is protected only by the coordinator keys until the next window is anchored |

### On-chain artefacts (IOTA Rebased testnet)

Audit Trail [`0x0715cfc5…6e3ab313`](https://explorer.iota.org/object/0x0715cfc56779f78cea48a3afb75dd44d7b9694008286acdb27a16f2c6e3ab313?network=testnet),
created 2026-10-06 23:54:19 UTC by
[tx Cqk277…](https://explorer.iota.org/txblock/Cqk277ujj9ciaB4R3jMZCQ6HmiNoi6drvoYhRDQDnghQ?network=testnet)
from the anchor address
[`0xd40892da…d8c940c8`](https://explorer.iota.org/address/0xd40892daf5c81e3d67ffe9806575970b973ecf6625eb8a88562afae0d8c940c8?network=testnet).
Record 0 is the trail's initial record; records 1 onward are checkpoints of the private
Tangle `private_tangle1`, domain `did:iota:testnet:0x6b9a693e…28a6f7a2`.

| Record | Milestones | Messages | Checkpoint hash | Transaction (UTC) |
|---:|---|---:|---|---|
| 1 | 1 to 720 | 175 | `0xf425f2721a73511c9dee7b45b4559712e9dc8535c5426c675a2b7ff5fa0d0b13` | [7L4icm…](https://explorer.iota.org/txblock/7L4icmUm2Y3cwRUWxEQxSRMeiCc3C7ptoLrpDkoayABr?network=testnet) 2026-10-06 23:54:32 |
| 2 | 721 to 1440 | 143 | `0xa5317ece87d9f3a0236968f61c257527dee22b9317a6becaa971784e74b8a8fe` | [5K3CqS…](https://explorer.iota.org/txblock/5K3CqSHNQR7t3yuuUqjZYxk2cRmDPwtPHuHYQhy7coj5?network=testnet) 2026-10-06 23:58:31 |
| 3 | 1441 to 2160 | 267 | `0x7aec4a3790796c3af428a1f96b2cda02703a82db66f61ec7b9477ebc2ead51b2` | [3ucWZU…](https://explorer.iota.org/txblock/3ucWZULXkxkRkAvt4P7xA4NpjNEFV99JBNbfXVdWQefs?network=testnet) 2026-10-07 00:58:34 |
| 4 | 2161 to 2880 | 169 | `0xcd595dd00bef4129702c323ae002441ca0757d5890a2949f8731f899a052a82d` | [E7onRs…](https://explorer.iota.org/txblock/E7onRsfrvhy5yBmamkXHKJmWeWkKJcQNFDcz9Dn9uKsz?network=testnet) 2026-10-07 01:58:40 |

Each record's `prev` is the previous record's checkpoint hash (record 1: `null`), and its
`added_by` is the anchor address above.

Identities ([`deploy/identity/testnet.json`](deploy/identity/testnet.json)), each an
`identity::Identity` object; component DIDs are controlled by the domain DID:

| Name | DID object | Created |
|---|---|---|
| domain | [`0x6b9a693e…28a6f7a2`](https://explorer.iota.org/object/0x6b9a693ebf2ac6fb771a75d25b1284ba75aeb0ae16618eaf5d41d24828a6f7a2?network=testnet) | [tx 5SpNx1…](https://explorer.iota.org/txblock/5SpNx1Rcix5XB6doa3w4bHYme7PqrMXcunLWHfUaNwrX?network=testnet) 2026-10-06 14:30 UTC |
| trust-manager | [`0x15eb8c4d…538db9ba`](https://explorer.iota.org/object/0x15eb8c4d90fa4fff1d49f3ae8b1676a61e09c883303acd383cbfaacb538db9ba?network=testnet) | [tx HXAvVS…](https://explorer.iota.org/txblock/HXAvVS9R5p4tz8jpCuMeXhrLFHVLsRvCvAatNdXgKkD8?network=testnet) |
| llo-k8s | [`0x5a50c4a6…4698e715`](https://explorer.iota.org/object/0x5a50c4a62cd8281d82f2f9526a6593248bd404657cf01130221839154698e715?network=testnet) | [tx CCfvxd…](https://explorer.iota.org/txblock/CCfvxdxiNSWSGBbBtnJdaHhDUafVqSgAPH1y2CJcpQmj?network=testnet) |
| self-orchestrator | [`0x7cb4f7bd…fd9d9472`](https://explorer.iota.org/object/0x7cb4f7bd777e7c90e26640bdb47efa9f9fe95f1dce64e9bb0edc7c32fd9d9472?network=testnet) | [tx CJTm7r…](https://explorer.iota.org/txblock/CJTm7r3HmXoutZZLpkJoApTXxXXAznntCNWAFWobuP7x?network=testnet) |
| relay | [`0xe6cf1bf1…152f0459`](https://explorer.iota.org/object/0xe6cf1bf1e06f82d7956585085306fc23daee082cc75120459f7d39bb152f0459?network=testnet) | [tx AWcqKh…](https://explorer.iota.org/txblock/AWcqKhqixKGf8sk4txHKBKku65ydAtzSKsYnugeqVuhE?network=testnet) |
| anchor | [`0x6b5cef6e…9ce12d59`](https://explorer.iota.org/object/0x6b5cef6e575705bd1e3486fee9929d695fbc0a06650b8a2ef4d252f69ce12d59?network=testnet) | [tx 3J6qEz…](https://explorer.iota.org/txblock/3J6qEzk8YJmxF4ehFQ6nvYCGfV2MNVAh7V8iwz3p4NzY?network=testnet) |

The `previous` entries in the same file are an earlier set, retired the same day when the
component DIDs were moved under the domain DID's control.

Mainnet: <!-- MAINNET -->none; everything above is on testnet.<!-- /MAINNET -->

## Confidentiality

| # | Claim | Tag | Evidence |
|---|---|---|---|
| C1 | A body can be sealed for one or more X25519 recipients (JWE, ECDH-ES+A256KW with A256GCM, nothing else accepted); the signature covers the ciphertext | REPRODUCIBLE | `core/src/witness_core/sealed.py`, `core/tests/test_sealed.py`, `core/tests/vectors/sealed.json` |
| C2 | Sealed messages are found by keyed blind tokens without the explorer holding the key | REPRODUCIBLE | `POST /lookup/blind`; `core/tests/test_sealed.py`, `api/tests/test_api.py` |
| C3 | Salted commitments let a producer disclose a sub-score later, checkably | REPRODUCIBLE | `core/src/witness_core/commit.py`, `core/tests/test_commit.py` |
| C4 | Our deployment seals regular aeriOS traffic | NOT-CLAIMED | only legacy `audit.report` writes are sealed by default; producer-signed envelopes and all other tags are in clear |
| C5 | Blind tokens hide which sealed messages share a value | NOT-CLAIMED | tokens are deterministic per value and key |

## Integrity rules and the evaluation

| # | Claim | Tag | Evidence |
|---|---|---|---|
| E1 | Integrity rules R1 to R18 plus `MISSING_IN_DB`, `NOT_FOUND` and `ANCHOR_UNVERIFIABLE` raise alerts with severity and evidence | REPRODUCIBLE | `indexer/src/witness_indexer/rules.py`, `validator.py`; `indexer/tests/test_rules.py`, `test_validator.py`, `test_maintenance.py` |
| E2 | A rewritten copy in the parallel database is detected against the Tangle (`DB_TAMPER`) | REPRODUCIBLE | `indexer/src/witness_indexer/validator.py` (`reverify_all`), `indexer/tests/test_validator.py::test_reverify_detects_db_tamper` |
| E3 | The evaluation's answer key was committed before the attacks were run | REPRODUCIBLE | `git log -- chaos/src/witness_chaos/answer_key.yaml` (first commit `7286519`, 2026-10-06 20:31 CEST); amendments are listed in the file |
| E4 | Detection rate and false positives | VERIFIED-LIVE | 394/400 injected attacks detected across 20 pre-registered classes (19 classes 20/20; Orion drift 14/20), 0 false positives on 599 genuine messages over 30 minutes, positive control 40/40. Full run: [results/eval-final/full/scorecard.md](results/eval-final/full/scorecard.md); A19 run separately: [results/eval-final/a19/scorecard.md](results/eval-final/a19/scorecard.md); run on the build before the final review fixes, not re-run since (method and caveats: [docs/eval.md](docs/eval.md#results)). |
| E5 | The genuine-traffic trap uses real aeriOS components | MODELED | the trap's LLO and self-orchestrator traffic comes from `chaos/src/witness_chaos/traffic.py`; `trust.score` is signed by the same SDK code the patched Trust Manager runs |
| E6 | Lookup latency at 100k messages, in-browser verification time | NOT-CLAIMED | not measured |

## Findings in the aeriOS IOTA stack

| # | Claim | Tag | Evidence |
|---|---|---|---|
| F | Each finding in [docs/findings.md](docs/findings.md) cites the upstream file and line at a named commit | REPRODUCIBLE | read the cited lines; findings observed on our own local stack say so |
| F-live | Of these, observed on our own loopback stack: unauthenticated `GET /api/core/v2/peers` (200), public debug API (`/api/debug/v1/requests` 200), the Werkzeug debugger page of the stock Messages API | VERIFIED-LIVE | commands in [docs/findings.md](docs/findings.md) |
| F-probe | Active probes against anyone else's node | NOT-CLAIMED | the posture scanner is passive by default and probes actively only loopback or allow-listed hosts (`api/src/witness_api/posture.py`, `api/tests/test_posture.py`) |

## Deployment

| # | Claim | Tag | Evidence |
|---|---|---|---|
| D1 | After a one-time identity bootstrap, one command brings up the organisers' stack plus the explorer; all ports on loopback only | REPRODUCIBLE | `deploy/compose/stack-up.sh`, `deploy/compose/hornet-loopback.yml`, `deploy/compose/docker-compose.witness.yml`; the bootstrap: [docs/operations.md](docs/operations.md#a-fresh-clone-with-your-own-identities) |
| D2 | Containers run unprivileged, read-only, without capabilities, each with only its own secrets | REPRODUCIBLE | `deploy/compose/docker-compose.witness.yml`, `deploy/compose/setup-secrets.sh` |
| D3 | Every image builds and the Helm chart lints and renders in CI | REPRODUCIBLE | `.github/workflows/ci.yml` |
| D4 | The Helm chart runs on a Kubernetes cluster | NOT-CLAIMED | not deployed to a cluster |
| D5 | A multi-node or production Tangle | NOT-CLAIMED | single HORNET node with the organisers' configuration |
| D6 | Changes merged into the eclipse-aerios repositories | NOT-CLAIMED | the upstream checkouts in `vendor/` run unchanged; the Trust Manager patch is applied in our own image (`deploy/compose/trust-manager-witness/Dockerfile`) |
