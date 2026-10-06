# Anchor service: trust and key custody

What a holder of each key can do, and what verifiers have to check because of it.

## Keys

| Key | Where | Controls |
|---|---|---|
| Gas / sender address (`ANCHOR_ADDRESS` in the IOTA keystore) | anchor host | the domain DID's ControllerCap, the Audit Trail's initial-admin capability, the trail's `writer` capability, gas |
| Domain identity | on chain | the ControllerCaps of every component DID (`trust-manager`, `llo-k8s`, `self-orchestrator`, `relay`, `anchor`) |
| Component `#sig-1` / `#kex-1` | `${SECRETS_DIR}/<component>/` | signing envelopes / receiving encrypted payloads for that component only |

Component DIDs are controlled by the domain identity, not by any address. Changing a component
document (rotating or revoking a key) goes through the domain identity
(`accessSubIdentity`), so it needs a controller of the domain DID. Today the only controller of
the domain DID is the gas address. Whoever holds that key can therefore rewrite every
component document. Moving the domain DID to a multi-controller threshold, or to a cold key, is
the next hardening step.

## Audit Trail admin capability on a hot key

The trail is created with a 100-year time-based record delete lock, an infinite trail delete
lock and no write lock. The `writer` role may only add records. The **initial-admin
capability, however, also sits on the gas address**, which is an online key. With it, an attacker could:

- create a role with locking and delete permissions, issue it to themselves, shorten the delete
  window and delete records;
- issue extra writer capabilities and add records of their own.

They cannot change or reorder existing records, and sequence numbers are never reused.

**Verifiers must therefore:**

1. check that record sequence numbers are contiguous from the genesis record (0) up to the
   checkpoint they verify, since a deleted record leaves a gap;
2. check `added_by` of every checkpoint record against the anchor's known writer address;
3. check that each checkpoint's `prev` hash links to the previous record's checkpoint.

The admin capability should move to a cold key once the deployment is stable.

## Resolver guarantees

`GET /resolve/:did` dates a revoked key at the checkpoint time of the transaction that removed
it. When that transaction cannot be identified (pruned object versions, the page cap, or index
lag), the date is the **earliest** time the removal could have happened, never a later one. The
response then carries `historyComplete: false`. A key replaced under the same id counts as
revoked at the replacement time. A deactivated document revokes all of its keys.

## Trust boundary of a checkpoint

What the anchor trusts when it builds a checkpoint: the HORNET node at `ANCHOR_HORNET_URL` and the
pinned coordinator keys and threshold (`ANCHOR_COORDINATOR_KEYS`, `ANCHOR_COORDINATOR_THRESHOLD`).
What it does not trust: the indexer database and the witness-api in front of it. The API only
proposes a window (the milestone ids from..to and the message count). Before anything is
written, every milestone of the window is read from HORNET as raw bytes, its id is recomputed
(BLAKE2b-256 of the essence, with @witness/verify), and the anchor requires the same index and id,
at least `threshold` valid signatures by distinct pinned coordinator keys, and an unbroken
previous-milestone link back to the last anchored milestone. Any disagreement refuses the window,
logs an error and turns `/healthz` to `degraded` (503) until a window verifies again. A HORNET
that cannot be reached also refuses the window, without the alarm.

`msgCount` is not re-derived from the node (that would need the full cones); it is the
indexer's count, committed as reported.

## Checkpoints

Each checkpoint is one trail record. Its data is the checkpoint's JCS text (the exact bytes its
BLAKE2b-256 hash covers); its metadata is `{"kind":"witness.checkpoint","seq":N,"checkpointHash":"0x…"}`,
so the chain alone says which record holds checkpoint `N`. `GET /checkpoints/:seq` reads that
record from the trail (a read is served again for at most `ANCHOR_CHECKPOINT_CACHE_MS`, 10 s at
most, and the reply carries `readAtMs`) and answers 502 when it cannot; it never serves a stored
copy as if it came from the chain. It also answers 502 when the record's metadata does not name
that seq, when the record was added by another address than the anchor's writer, when the state
places the checkpoint on another trail than the configured one, or when the chain names another
transaction for the record than the state. The transaction is confirmed on chain once and then
remembered (`txVerified`). Error bodies carry short reasons; raw node errors go to the log only.
On top of the trail checks above, verifiers should still check `addedBy` themselves.

The instance that runs the loop is the one to point the indexer's R11 at: its state maps seqs to
records. A read-only instance without that state file answers 404 for every seq.

`msgCount` is the number of tagged-data messages referenced by milestones `from`..`to`, as
indexed (witness-api `/milestones` reports it). A window whose source does not report it is not
anchored; `ANCHOR_ALLOW_MISSING_MSGCOUNT=1` commits 0 instead and exists only for development
against the HORNET stub, which cannot count messages.

The loop state (`ANCHOR_STATE_PATH`) only maps seqs to records and keeps the mirror chain; it holds
no key material. A signed `add_record` transaction is saved there before it is submitted, so a
restart settles that very transaction (by digest, or by resubmitting the same bytes) instead of
anchoring the window again. If the state file is lost, the loop rebuilds the chain from the
records our writer address added. The `witness.anchor` mirror on the private Tangle is signed with
the anchor component's `#sig-1` key; it is a convenience copy, and R11 compares the indexed
milestones with the on-chain record, never with the mirror.

**Honest limit:** anchoring bounds the forgery window to the anchor interval. Milestones newer than
the last anchored window are not protected yet.

Only one loop may run per state file: it takes `${ANCHOR_STATE_PATH}.lock` with an exclusive
create and refuses to start while a live process on the same host holds it (a lock left by a dead
process is taken over). State writes are flushed (file, then directory where the OS allows it)
before the next step relies on them.
