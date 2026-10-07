# Evaluation

## Proof compatibility

`witness_core.poi_compat.to_inx_poi` emits the inx-poi proof JSON
(`{"l": .., "r": ..}` with `{"h": ..}` for hashed subtrees and `{"value": ..}`
for the proven leaf). Two checks against real HORNET 2.0.2 captures:

- Offline: for every entry in `poi_create.json`, `to_inx_poi(cone, index)` is
  structurally equal to the proof inx-poi itself produced, and the decoded path
  verifies against the milestone's `inclusionMerkleRoot`.
- Live: each of the 4 captured `{milestone, block, proof}` bodies was POSTed to
  `http://127.0.0.1:14265/api/poi/v1/validate` with `proof` replaced by our
  `to_inx_poi` output. Result: `{"valid":true}` for 4/4. With the leaf value
  altered in the same proof, 4/4 returned `{"valid":false}`.

## Graded fault-injection evaluation

The headline number is a scorecard: **detected X/Y attacks, F/N false positives**. It comes
from injecting known attacks into a running local stack (HORNET, the witness relay, the
indexer, the API, the anchor service, Orion-LD) and checking, for every injection, whether
the explorer showed exactly what an answer key written in advance says it must show.

### Pre-registration

`chaos/src/witness_chaos/answer_key.yaml` was committed before any attack was run. It names,
for each of the 20 attack classes, the attack function, the channel it travels through, one
expected observation (a verdict, an alert with its severity, or a red step of the proof
ladder), the alerts that may legitimately come along with it (`allowed_side_alerts`), a
timeout and 20 trials. It also holds one positive control (C01) and the trap profile (genuine
traffic that must raise nothing). Changes made before the first run are listed in its
`amendments` trail; expectations are never changed after a run. Each results directory
records the SHA-256 of the answer key, the git commit and a hash of the run configuration.

| Class | Attack | Channel | Expected | Timeout |
|---|---|---|---|---|
| A01 | trust-manager envelope signed with an attacker key | HORNET direct | verdict FORGED | 15 s |
| A02 | valid envelope replayed under another block tag | HORNET direct | verdict FORGED | 15 s |
| A03 | second envelope reusing an (iss, seq) pair | HORNET direct | verdict REPLAY | 15 s |
| A04 | signed by a resolvable DID the writer policy does not list | HORNET direct | verdict UNAUTHORIZED_WRITER | 15 s |
| A05 | signed with a revoked key | HORNET direct | verdict REVOKED_KEY | 15 s |
| A06 | Orion `trustScore` overwritten, ledger unchanged | Orion | alert DRIFT (medium) | 240 s |
| A07 | one bit flipped in the block's payload | bundle, offline | ladder `block_hash` red, block still parses | 5 s |
| A08 | sibling hash of the inclusion path replaced | bundle, offline | ladder `inclusion` red | 5 s |
| A09 | fake block + milestone signed with the public sample coordinator keys | bundle, offline | ladder `anchor` red | 5 s |
| A10 | doctored anchor checkpoint | bundle, offline | ladder `anchor` red | 5 s |
| A11 | sealed `audit.report`, read without the key | relay | RELAY_ATTESTED, stored sealed, found by blind token | 15 s |
| A12 | score about an IE Orion does not know | HORNET direct | alert UNKNOWN_IE (low) | 30 s |
| A13 | score jump 0.9 to 0.1 with no security event | HORNET direct | alert ANOMALY (medium) | 30 s |
| A14 | IE scored once, then never again | HORNET direct | alert STALE (low) | 240 s |
| A15 | signed body breaking the schema | HORNET direct | verdict MALFORMED | 15 s |
| A16 | forwarded record carries other bytes than the block | relay record | alert CONTENT_MISMATCH (critical) | 30 s |
| A17 | genuine signed block posted around the Messages API | HORNET direct | alert SHADOW (high), verdict PRODUCER_SIGNED | 90 s |
| A18 | record naming a block that never existed | relay record | alert ORPHANED (high) | 120 s |
| A19 | stored content of a verified message rewritten in the database | database | alert DB_TAMPER (critical) | 120 s |
| A20 | one message of a `prev` chain dropped | relay | alert CHAIN_GAP (medium) | 30 s |
| C01 | control: A17's twin sent through the Messages API | relay | no alert at all | 90 s |
| trap | genuine Trust Manager and LLO traffic, at least 30 min and 500 messages | relay | 0 alerts; verdicts PRODUCER_SIGNED, RELAY_ATTESTED, UNSIGNED_LEGACY | |

### Method

`witness-chaos run` (`chaos/src/witness_chaos/runner.py`) runs four phases.

**Identities.** The run signs with keys of its own, never a live component's.
`witness-chaos keys` creates the producer (a fresh `did:key`, private key kept in
`secrets/chaos/`) and an eval policy: `chaos/demo-policy.json` with that DID added to the
`trust.score` writers and nothing else changed. The stack runs with that policy for the
evaluation (`WITNESS_POLICY_FILE`), so the live Trust Manager keeps writing its own chain next
to the run, untouched. The outsider (A04) is a `did:key` derived from the seed, on no policy;
the revoked identity (A05) is `chaos-revoked`, a DID on IOTA Rebased controlled by the domain
DID whose `#sig-1` was removed right after creation (`deploy/identity/testnet.json`, under
`eval`, records the revocation transaction).

**Preflight.** API, relay, HORNET and Orion must answer. The producer must not be any DID
in `deploy/identity/*.json` or published by the anchor service, and the writer policy the API
reports must allow it on `trust.score`; otherwise the run does not start. It also refuses to
start when something else signed `trust.score` with the producer's DID in the last two
minutes (two signers with one key interleave their `prev` chains, which the explorer rightly
reports as CHAIN_GAP).

**Trap.** `chaos/src/witness_chaos/traffic.py` sends genuine traffic through the relay at 20
messages a minute: half `trust.score` signed by the SDK's `WitnessSigner` (the code the
patched Trust Manager runs: `prev` chain, salted commitments to the sub-scores, the score
written to Orion first), the rest `LLO-K8s` / `LLO-Docker` deployment events and
`self-orchestrator` status reports (`errorCode` 0), all legacy and attested by the relay. The
trap IEs are registered in Orion for the run (without `internalIpAddress`, so the stock
Trust Manager leaves them alone), every IE is scored at least every 30 s and a score moves by
at most 0.03 at a time. After the traffic stops the harness waits 70 s (long enough for
SHADOW, which needs 30 s of grace plus a 30 s rule pass, and short enough that the trap IEs
cannot be STALE yet), then counts as false positives every alert on a trap block or a trap IE
raised up to that moment, and every trap message whose verdict is outside the answer key's
list. Alerts about anything else raised in the same window are listed as context, not scored.

**Attacks.** For each class, `trials` injections through its function in `attacks.py`. Each
trial uses fresh Infrastructure Elements, registered in Orion before the class starts (so a
score about them is not UNKNOWN_IE) and given the trial's baseline score as the Trust Manager
would; they are removed from Orion after the trial. Envelope attacks go straight to HORNET,
because the relay would refuse them; that also makes them SHADOW writes, an allowed side
alert. Two-block attacks (A03, A13, A20) wait until the explorer has indexed the first block
before sending the second, so the order the explorer sees is the order they were sent in.
While A06 waits for DRIFT, the producer keeps scoring the IE with the unchanged ledger score,
as a live Trust Manager would, so the IE does not go STALE first. A19 rewrites only a stored
message the run's producer signed, never one it already rewrote, and the run restores every
rewritten row when it ends (the bit flip is its own inverse; the alerts stay). The indexer
compares every stored copy with the Tangle every `--reverify-every-s` (60 s in the compose
stack), which is what A19's 120 s window relies on.

After each injection the harness polls the API (`/messages/{id}`, `/alerts?block_id=`, and for
classes with per-trial IEs `/alerts?ie=`) once a second until every assertion of the class
holds or its timeout runs out. An alert of the expected rule with another severity than the
pre-registered one does not count. A trial is detected only if all its assertions hold; what
was seen instead goes into the confusion matrix. Other alerts on the injected block are
reported per class, split into the pre-registered side alerts and unexpected ones; alerts that
arrive after the trial window are collected once at the end and reported separately,
unscored. A trial the harness could not inject (a service refused it) is reported as not run,
never counted as detected.

A11's `sealed` assertion reads "no plaintext body" over everything the explorer serves for the
block: the stored envelope must carry `enc` and no `body`, decrypting it without the recipient
key must fail, and neither value of the plaintext the harness posted may appear anywhere in
the `/messages/{id}` answer, the forwarded submission record in it included. (The check
first looked at the stored envelope only; the expectation is unchanged, the check is
stricter.)

**Bundle classes.** A07-A10 tamper with a genuine proof bundle and never touch a node. The
genuine bundle is an anchored block taken from the live explorer (`/proofs/{id}`), with the
on-chain checkpoint record read through the anchor service; if none is available the captured
private-Tangle vectors are used, and the scorecard says which. Each tampered bundle is
checked by `witness_core.bundle.verify` and by the TS verifier CLI
(`node packages/verify/dist/cli.js`): the trial counts only if the expected step is red and
both verifiers agree on the overall result and on every step. The untampered bundle must
verify green in both before any bundle trial runs.

**Control.** C01 sends the A17 block's genuine twin through the relay and watches its block
and IE for the full 90 s; it passes if nothing alerts.

**Latency** is insertion to detection: for alert classes the server's alert time minus the
moment of injection; for verdict classes the poll that first saw the verdict (an upper bound,
within one poll interval).

**Determinism.** `--seed` fixes the IE ids, scores, tamper positions and the keys of the
attacker and of the `did:key` outsider; envelope nonces and timestamps are fresh by design.

**Preconditions.** A class whose setup is missing is reported as not run, never as detected:
A05 needs a revoked identity (`--revoked-key`, a private JWK whose method was removed from
its DID on IOTA Rebased: `secrets/chaos-revoked/sig-1.jwk.json`); A11 needs `audit.report` in
the relay's `RELAY_ENCRYPT_TAGS` (the compose default) and the blind-index key
(`--search-key-file`); A19 needs a database DSN (`WITNESS_CHAOS_DB`, test
stack only); A16 and A18 need the ingest token or the relay's broker login.

### Reproduce

```sh
pnpm install && pnpm --filter @witness/verify build   # TS verifier, for bundle parity
uv sync --all-packages
uv run witness-chaos keys --out secrets/chaos          # run-only producer + eval policy
# A05's revoked identity, once per network (anchor/.env with the wallet, as for the
# component identities; about 0.01 testnet IOTA): secrets/chaos-revoked/sig-1.jwk.json
pnpm --filter @witness/anchor bootstrap:identities --chaos-revoked
# Run the stack on the eval policy: relay, indexer, API and anchor all read WITNESS_POLICY_FILE
# (absolute, or relative to deploy/compose). The runner refuses to start until the API's
# /identity shows the producer on trust.score.
WITNESS_POLICY_FILE="$PWD/secrets/chaos/eval-policy.json" \
  docker compose -f deploy/compose/docker-compose.witness.yml up -d
# A19 rewrites rows as the database owner: the DSN setup-secrets.sh wrote (random password
# on a fresh setup), pointed at the port the base stack publishes on loopback.
WITNESS_CHAOS_DB="$(sed 's/@witness-postgres:/@127.0.0.1:/' secrets/postgres/explorer.dsn)" \
uv run witness-chaos run \
  --api http://127.0.0.1:7200 --relay http://127.0.0.1:5557 --relay-node iota-hornet \
  --hornet http://127.0.0.1:14265 --orion http://127.0.0.1:1026 --anchor http://127.0.0.1:7300 \
  --secrets-dir secrets --env-file secrets/compose/api.env --env-file secrets/compose/relay.env \
  --mqtt-host 127.0.0.1 --search-key-file secrets/relay/search.key \
  --revoked-key secrets/chaos-revoked/sig-1.jwk.json \
  --trials 20 --parallel 10 --out results/
uv run witness-chaos score results/                    # rebuild the scorecard from the logs
# afterwards: back to the deployment policy
docker compose -f deploy/compose/docker-compose.witness.yml up -d
```

The results directory holds `scorecard.json` and `scorecard.md`, `trials.jsonl` (one line per
trial: the injection, every alert seen, latency, both ladders and parity for bundles),
`trap.json`, `trap.jsonl` and `trap-sent.jsonl` (every trap message with its verdict and
alerts) and `run.json` (commit, configuration with secrets masked, hashes, preflight).

### Results

> **PLACEHOLDER: no full run yet.** This section is filled in from `results/scorecard.md`
> after the pre-registered run (20 trials per class, 30-minute trap). Until then nothing here
> is a result.

- Headline: detected __/__ attacks, __/__ false positives
- Per-class detection, confusion matrix, latency p50/p95: _pending_
- Positive control C01: _pending_
- Python / TS verifier parity on the bundle classes: _pending_

Not measured here: lookup p95 at 100k messages and in-browser verification time.
