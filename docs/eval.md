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

**394/400 injected attacks detected across 20 pre-registered classes (19 classes 20/20; Orion drift 14/20), 0 false positives on 599 genuine messages over 30 minutes, positive control 40/40.**

The numbers come from two runs of the same build, because the first one could not include A19
(see Provenance). The answer key (SHA-256 `63fa160cdf480c25...`) is the same in both, and every
figure below can be recomputed from the committed logs.

| Class | Name | Expected | Detected | p50 | p95 |
|---|---|---|---|---|---|
| A01 | FORGED_SIGNATURE | FORGED | 20/20 | 5.2 s | 5.2 s |
| A02 | CROSS_TAG_REPLAY | FORGED | 20/20 | 5.2 s | 5.2 s |
| A03 | SEQ_REPLAY | REPLAY | 20/20 | 5.2 s | 5.2 s |
| A04 | UNAUTHORIZED_WRITER | UNAUTHORIZED_WRITER | 20/20 | 5.2 s | 5.5 s |
| A05 | REVOKED_KEY | REVOKED_KEY | 20/20 | 5.2 s | 5.2 s |
| A06 | ORION_DRIFT | DRIFT | **14/20** | 161.8 s | 162.4 s |
| A07 | BLOCK_BYTE_FLIP | ladder:block_hash | 20/20 | - | - |
| A08 | BAD_MERKLE_PATH | ladder:inclusion | 20/20 | - | - |
| A09 | SAMPLE_KEY_FORGED_MILESTONE | ladder:anchor | 20/20 | - | - |
| A10 | ANCHOR_MISMATCH | ladder:anchor | 20/20 | - | - |
| A11 | SEALED_WITHOUT_KEY | RELAY_ATTESTED | 20/20 | 5.2 s | 5.4 s |
| A12 | UNKNOWN_IE | UNKNOWN_IE | 20/20 | 3.7 s | 4.9 s |
| A13 | SCORE_JUMP | ANOMALY | 20/20 | 4.3 s | 4.9 s |
| A14 | STALE_IE | STALE | 20/20 | 141.9 s | 150.1 s |
| A15 | MALFORMED_PAYLOAD | MALFORMED | 20/20 | 5.2 s | 5.2 s |
| A16 | CONTENT_MISMATCH | CONTENT_MISMATCH | 20/20 | 3.6 s | 3.7 s |
| A17 | SHADOW | SHADOW | 20/20 | 59.5 s | 59.7 s |
| A18 | ORPHANED | ORPHANED | 20/20 | 60.0 s | 60.0 s |
| A19 | DB_TAMPER | DB_TAMPER | 20/20 (separate run) | 59.8 s | 60.2 s |
| A20 | CHAIN_GAP | CHAIN_GAP | 20/20 | 4.4 s | 4.8 s |

19 classes x 20 + 14 = 394 of 400. The full run alone scored 374/380 (A19 was not run in it);
the separate A19 run scored 20/20. The bundle classes A07-A10 have no latency: they are
checked offline on the bundle, not on the live system.

**Unexpected alerts.** The full run reports 2 alerts on injected blocks that the answer key
does not allow, both in A06 (ANOMALY, see below). The A19 run reports 0. Every other alert on
an injected block was a pre-registered side alert (for example SHADOW on the envelope attacks
that go straight to HORNET). Alerts that arrived after a trial ended (mostly STALE and SHADOW
on the test IEs) are listed in `scorecard.md` and are not scored.

**Latency.** Insertion to detection over the full run: p50 5.2 s, p95 150.2 s. Most classes
are detected on arrival, in 3.6 to 5.5 s (the harness polls once a second). A few are slow by
design, because the rule has to wait before it may conclude:

- STALE (A14), ~142 s: no new score for an IE within `stale_after_s` (120 s in the compose
  stack), checked on the 30 s periodic pass;
- SHADOW (A17) and ORPHANED (A18), ~60 s: the grace period before a confirmed block that no
  submission names, or a submitted block that is never confirmed, counts as such;
- DRIFT (A06), ~162 s: the 150 s grace period of R5 plus the periodic pass.

The p95 of 150.2 s comes from these classes; the other classes finish within about 5.5 s.

**Positive control C01.** Genuine blocks sent through the relay were indexed as
PRODUCER_SIGNED with no alert: 20/20 in the full run and 20/20 in the A19 run, 40/40 in total.

**Trap.** 599 genuine messages over 30 minutes (1802 s) on four trap IEs: 0 alerts on any of
them; verdicts PRODUCER_SIGNED 341, RELAY_ATTESTED 258; 0 not indexed, 0 failed sends.
`trap.json` also lists one CHAIN_GAP alert raised somewhere in the same time window
(`all_alerts_in_window`); it is not attached to any trap message. It is mentioned here so it
is not hidden.

**Parity.** On the bundle classes A07-A10, 80/80 trials: core `bundle.verify` (Python) and
the TypeScript verifier CLI agreed on every step. The genuine bundle was taken from the API.

**A06 ORION_DRIFT, 14/20.** Observed outcomes: DRIFT 14, ANOMALY 2, no alert within the 240 s
timeout 4. This is a miss.

Why it is slow. R5 does not compare once. The periodic pass (every `--periodic-s`, 30 s)
opens an episode the first time Orion's `trustScore` differs from the latest ledger score by
more than `drift_epsilon` (0.01), and raises DRIFT only when the divergence has lasted longer
than `drift_grace_s` (150 s, `indexer/src/witness_indexer/rules.py`). The grace period is
there so that the normal lag between a score landing on the ledger and Orion being updated
does not alert. Detection therefore cannot come before about 150 s, and with the pass
interval it lands at 150 to 180 s. The 14 detections took 161.4 to 162.4 s.

Why some trials failed. The episode is dropped as soon as one pass finds the IE no longer
diverging (or absent from the list Orion returned), and the 150 s clock then restarts. The
logs do not show whether that happened in the four trials with no alert (trials 12, 13, 16
and 17): they ran the whole 240 s without a DRIFT, and I have not diagnosed them, so no cause
is claimed here. In the two ANOMALY trials (4 and 5), R7 raised ANOMALY on the seeded
baseline block about 3 s after injection, which the answer key does not allow for A06, and no
DRIFT followed within the timeout either. Those are the 2 unexpected alerts. Nothing about
the class was changed after seeing this: the pre-registered 240 s timeout and 20 trials
stand, and the result is 14/20.

**Provenance.**

- Full run: 2026-10-07, 04:19 to 05:29 UTC. Runner at repo commit `cd985fe` (the services
  were built from the same code; that commit differs only in docs), 20 classes x 20 trials
  planned, config hash `33da8531c039e1ba`. A19 was not run in that invocation because no
  database DSN was passed (`--db-dsn` / `WITNESS_CHAOS_DB`); the scorecard says so ("20
  planned trials not run: A19"). Its own headline reads "detected 374/380 attacks, 2
  unexpected alerts, 0/599 false positives".
- A19 run: 2026-10-07, 05:30 to 05:53 UTC, same build, runner at commit `c94618c` (docs-only
  difference), `--classes A19 --no-trap` with a loopback DSN for the database owner. 20/20
  DB_TAMPER detected, 0 unexpected alerts, C01 20/20. All 20 rewritten rows were restored and
  verified (`restoreFailed` is empty in `run.json`). A19 was run separately because it needs
  that DSN and the first invocation did not have it; it was run right after on the same
  stack, and the 30-minute trap was not repeated.
- Logs: [`results/eval-final/full/`](../results/eval-final/full/scorecard.md) and
  [`results/eval-final/a19/`](../results/eval-final/a19/scorecard.md): `scorecard.md`,
  `scorecard.json`, `run.json`, `trials.jsonl` (and `trap.json` for the full run). The
  per-message trap logs (`trap.jsonl`, `trap-sent.jsonl`) are not committed.
- Rescore from the logs: `uv run witness-chaos score results/eval-final/full` (and
  `results/eval-final/a19`).

**Changes after the evaluation.** The evaluation ran on the build before the final review
fixes. Behaviour changes made after it:

- R7 ANOMALY is no longer suppressed by reports with error code 0, and self-security events
  corroborate a jump;
- R5 DRIFT ignores SHADOW and UNSIGNED scores;
- the anchor's DID-resolution cache is 2 s by default (was 60 s; 5 s in our deployment);
- the relay refuses envelopes nested past 64 levels, and refuses a reused seq or nonce before
  posting;
- verification step 4 refuses non-canonical `did:iota` DIDs and resolves `did:key` locally;
- a DID document that cannot be used is answered with 422.

None of the pre-registered expectations changed. The evaluation has not been re-run on the
post-fix build, so the numbers above describe the earlier build.

Not measured here: lookup p95 at 100k messages and in-browser verification time.
