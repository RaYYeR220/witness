# For the judges

Two paths: five minutes in a browser and a terminal, nothing to install but `uv`; or the whole
stack on your machine. What each check proves is in
[docs/architecture.md](docs/architecture.md#the-proof-ladder); every claim and its evidence is
in [CLAIMS.md](CLAIMS.md).

No time at all? A two-minute walkthrough of the same console: [youtu.be/ArWoH4ses8Q](https://youtu.be/ArWoH4ses8Q).

## Five minutes

### 1. The replay console

Open the replay console at [https://rayyer220.github.io/witness/](https://rayyer220.github.io/witness/).

It serves a snapshot recorded from our running stack, with no backend. The proofs in it are
still checked in your browser against the pins built into the console
([`console/src/config/verifier.json`](console/src/config/verifier.json)): step ④ uses the
issuers' DID documents recorded with the snapshot (the screen says so), and step ⑤ reads the
checkpoint record from IOTA Rebased testnet live.

- **Landing page, "Flip one byte".** Change any byte of the sample block and the BLAKE2b-256 hash
  no longer equals the block id: that is check ①.
- **A forged message.** In Search, type `FORGED` and open a result, or open
  [this one](https://rayyer220.github.io/witness/m/0xc28899293cca00d7233727df3ba380564f24b403c026ae190f210bd2a35f54a5)
  directly: an evaluation trial of class A02, a valid `trust.score` envelope replayed under the
  `LLO-K8s` tag (listed in [`results/eval-final/full/trials.jsonl`](results/eval-final/full/trials.jsonl)).
  The Verify screen shows two
  verdicts: the one the explorer recorded when it indexed the block, and the five checks your
  browser just ran from the bundle's bytes. Expect ①, ② and ③ green (the block is real and a
  milestone confirmed it) and ④ red: the envelope does not verify for the issuer it names.
- **A genuine one.** Search `trust.score`, open a `PRODUCER_SIGNED` message from the Trust
  Manager whose milestone is anchored. All five checks are green; ⑤ shows the hash of the
  checkpoint it read from the chain. "Download bundle" saves the exact proof the browser
  checked.
- **A forged milestone.** On Verify, "Try a forged proof"
  ([direct link](https://rayyer220.github.io/witness/verify/forged-milestone)) runs the same checks on a bundle made
  offline with IOTA's public sample coordinator keys (a test-vector bundle like `forged-ms.json`
  in section 2, pointed at record 1 of our trail): ① to ④ green, ⑤ red, because the record your
  browser reads from IOTA Rebased commits to another checkpoint.

### 2. Verify a bundle yourself

From a clone of this repository (`uv` installed). The bundle and the pins come from the shared
test vectors; nothing is fetched from us.

```bash
uv run python -c "import json; v=json.load(open('core/tests/vectors/bundles.json')); c={x['name']: x for x in v['cases']}; [json.dump(o, open(f, 'w')) for o, f in ((c['partial_real_no_anchor']['bundle'], 'real.json'), (c['partial_real_no_anchor']['config'], 'pins.json'), (c['valid_anchored']['bundle'], 'forged-ms.json'), (c['raw_byte_flipped']['bundle'], 'flipped.json'), (v['resolvers']['registry'], 'dids.json'))]; json.dump(next(iter(v['resolvers']['registry'].values())), open('did.json', 'w'))"

uv run --package witness-cli witness verify real.json --config pins.json --no-anchor
uv run --package witness-cli witness verify forged-ms.json --config pins.json --did-snapshot did.json --no-anchor
uv run --package witness-cli witness verify flipped.json --config pins.json --did-snapshot did.json --no-anchor
```

| Bundle | What it is | Result |
|---|---|---|
| `real.json` | a block captured from our private Tangle, with its milestone and Merkle path | ① ② ③ ok; ④ not checked (unsigned legacy message); ⑤ not checked (no anchor in this bundle). `PARTIAL`, exit 2 |
| `forged-ms.json` | a block and a milestone made offline, signed with IOTA's public sample coordinator keys, the keys the organisers' Tangle uses | ① ② ③ ④ ok. `PARTIAL`, exit 2: three checks cannot tell a forged milestone from a real one. Only ⑤, a checkpoint on a ledger the sample keys do not control, can |
| `flipped.json` | the same bundle with one byte of the block changed | ① FAILED. `INVALID`, exit 1 |

The TypeScript verifier that the console runs gives the same ladder:
`pnpm install && pnpm --filter @witness/verify build && node packages/verify/dist/cli.js flipped.json --config pins.json --resolver dids.json`.

### 3. The proof on IOTA Rebased

Our private Tangle's history is checkpointed on an IOTA Rebased testnet Audit Trail:
[`0x0715cfc5…6e3ab313`](https://explorer.iota.org/object/0x0715cfc56779f78cea48a3afb75dd44d7b9694008286acdb27a16f2c6e3ab313?network=testnet).
Records 1 to 4 cover milestones 1 to 2880; the transactions, the six did:iota identities and
the checkpoint hashes are listed in [CLAIMS.md](CLAIMS.md#on-chain-artefacts-iota-rebased-testnet).
Mainnet: <!-- MAINNET -->none; the trail and the identities are on testnet.<!-- /MAINNET -->

Read a checkpoint straight from a public fullnode, without our services (`3` is the record
number):

```bash
uv run --package witness-core python -c "from witness_core import rebased; import json; print(json.dumps(rebased.fetch_record('https://api.testnet.iota.cafe', '0x0715cfc56779f78cea48a3afb75dd44d7b9694008286acdb27a16f2c6e3ab313', 3, package_id='0x51368931f28620c7f65b4ae2c5167b42390e69729357a6347be378755b46e7df'), indent=1))"
```

It checks that the object is an Audit Trail of the pinned package, reads the record from the
trail's records table, recomputes the checkpoint hash from the record's data and prints the
checkpoint (window, `msRoot`, `prev`, `policyHash`) with the address that added it.

### 4. The scorecard

**394/400 injected attacks detected across 20 pre-registered classes (19 classes 20/20; Orion drift 14/20), 0 false positives on 599 genuine messages over 30 minutes, positive control 40/40.** [Results and method](docs/eval.md#results)

The method, the 20 attack classes, the positive control and the genuine-traffic trap are in
[docs/eval.md](docs/eval.md); the answer key is
[`chaos/src/witness_chaos/answer_key.yaml`](chaos/src/witness_chaos/answer_key.yaml), first
committed before any attack ran.

## Run it yourself

About ten minutes of commands; the first image builds take longer on a cold machine.

1. **Prerequisites.** Docker with Compose v2, bash (Linux, macOS, or Git Bash on Windows),
   `uv`, Node 22 with `pnpm`, the IOTA CLI, and an IOTA Rebased testnet address with some gas
   from the faucet.
2. **Identities.** The repository pins our DIDs; you sign with your own. In
   `deploy/compose/.env` (copy of `.env.example`) set `WITNESS_IOTA_KEYSTORE` and
   `WITNESS_ANCHOR_ADDRESS`, then follow
   [docs/operations.md, "A fresh clone with your own identities"](docs/operations.md#a-fresh-clone-with-your-own-identities):
   `bootstrap:identities` creates the six DIDs and writes the private keys under `secrets/`,
   `scripts/make_policy.py` rewrites the writer policy.
3. **Up.** `deploy/compose/stack-up.sh --witness`. When the anchor logs `trail created`, put
   the trail id in `WITNESS_TRAIL_ID` and rebuild the overlay so the API and the console pin
   it (step 4 of the same section).
4. **Look.** Console on http://localhost:8080, API on http://localhost:7200/docs. The patched
   Trust Manager writes a signed `trust.score` every minute.
5. **The brief's checks on one message.**
   ```bash
   curl -s "localhost:7200/messages?tag=trust.score&limit=1"        # (b) search
   curl -s "localhost:7200/messages/<blockId>"                       # checks.solid (c), checks.content (d)
   curl -s -X POST "localhost:7200/messages/<blockId>/verify"         # ask the node again
   ```
6. **Write around the explorer.** Post an unsigned score through the stock Messages API, which
   forwards nothing:
   ```bash
   curl -s -X POST "localhost:5555/upload?node=iota-hornet" -H 'content-type: application/json' \
     -d '{"tag":"trust.score","message":{"score":1.0,"id":"MyDomain:00000000beef"}}'
   ```
   The block is indexed as `UNSIGNED_LEGACY` with an `UNSIGNED` alert (the writer policy
   requires signatures on `trust.score`) and an `UNKNOWN_IE` alert; within about a minute it
   also gets `SHADOW`: confirmed on the Tangle, never received through the Messages API.
   `curl -s "localhost:7200/alerts?block_id=<blockId>"`.
7. **Verify end to end from the terminal**, step ⑤ read from IOTA Rebased, for a message whose
   milestone is anchored (`GET /anchors` lists the windows):
   ```bash
   # pins of your stack (protocol config, your identities, your trail) into console/src/config/verifier.json
   pnpm install && ANCHOR_TRAIL_ID=<your trail id> pnpm --filter console fixture
   uv run --package witness-cli witness verify <blockId> --from-api --config console/src/config/verifier.json \
     --resolver http://127.0.0.1:7300
   ```
   Five `ok` lines and `VALID`. `--from-api` refuses a bundle that proves some other block.
8. **The evaluation.** [docs/eval.md](docs/eval.md#reproduce) runs every attack class against
   your stack and writes the scorecard.
