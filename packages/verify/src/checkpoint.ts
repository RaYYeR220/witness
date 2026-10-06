/**
 * Anchor checkpoints: a Merkle commitment to a contiguous milestone window.
 * `msRoot` is the TIP-4 root over the milestone ids from `from` to `to`
 * inclusive, so any milestone in the window can later be proven a member.
 */

import { isBytes, toHex } from "./bytes.js";
import { canonHash } from "./jcs.js";
import { get, has, isDict, isUint } from "./json.js";
import { auditPath, merkleRoot, type PathStep } from "./merkle.js";

export const CHECKPOINT_KIND = "witness.checkpoint";
export const CHECKPOINT_VERSION = 1;

const H32 = /^0x[0-9a-f]{64}$/;
const FIELDS = ["v", "kind", "network", "domain", "from", "to", "msRoot", "msgCount", "policyHash", "prev"];

export interface CheckpointBound {
  index: number;
  id: string;
}

export interface Checkpoint {
  v: 1;
  kind: typeof CHECKPOINT_KIND;
  network: string;
  domain: string;
  from: CheckpointBound;
  to: CheckpointBound;
  msRoot: string;
  msgCount: number;
  policyHash: string;
  prev: string | null;
}

export interface BuildCheckpointInput {
  network: string;
  domain: string;
  from: { index: number; id: Uint8Array };
  to: { index: number; id: Uint8Array };
  /** Exactly the window `from..to`, in order. */
  milestoneIds: readonly Uint8Array[];
  msgCount: number;
  policyHash: Uint8Array;
  prevHash: Uint8Array | null;
}

function need32(b: unknown, field: string): void {
  if (!isBytes(b, 32)) throw new RangeError(`${field} must be 32 bytes`);
}

/** Checkpoint over `milestoneIds` (Python `checkpoint.build`). */
export function buildCheckpoint(input: BuildCheckpointInput): Checkpoint {
  const { from, to, milestoneIds: ids } = input;
  if (ids.length === 0) throw new RangeError("a checkpoint needs at least one milestone");
  ids.forEach((mid, i) => need32(mid, `milestone_ids[${i}]`));
  need32(input.policyHash, "policy_hash");
  if (input.prevHash !== null) need32(input.prevHash, "prev_hash");
  if (!(isUint(from.index) && isUint(to.index) && isUint(input.msgCount))) {
    throw new RangeError("indexes and msg_count must be unsigned integers");
  }
  if (to.index - from.index + 1 !== ids.length) {
    throw new RangeError(`window ${from.index}..${to.index} does not match ${ids.length} milestone ids`);
  }
  if (toHex(ids[0]!) !== toHex(from.id) || toHex(ids[ids.length - 1]!) !== toHex(to.id)) {
    throw new RangeError("from/to ids must be the first and last milestone ids of the window");
  }
  return {
    v: CHECKPOINT_VERSION,
    kind: CHECKPOINT_KIND,
    network: input.network,
    domain: input.domain,
    from: { index: from.index, id: toHex(from.id) },
    to: { index: to.index, id: toHex(to.id) },
    msRoot: toHex(merkleRoot(ids)),
    msgCount: input.msgCount,
    policyHash: toHex(input.policyHash),
    prev: input.prevHash === null ? null : toHex(input.prevHash),
  };
}

/** BLAKE2b-256 over the JCS form of the checkpoint: what the anchor writes on chain. */
export function checkpointHash(cp: unknown): Uint8Array {
  return canonHash(cp);
}

/** Audit path proving milestone `indexInWindow` is under `msRoot`. */
export function membershipPath(milestoneIds: readonly Uint8Array[], indexInWindow: number): PathStep[] {
  return auditPath(milestoneIds, indexInWindow);
}

function boundError(v: unknown, name: string): string | null {
  if (!isDict(v) || Object.keys(v).length !== 2 || !has(v, "index") || !has(v, "id")) return `${name} must be {index, id}`;
  if (!isUint(get(v, "index"))) return `${name}.index must be an unsigned integer`;
  const id = get(v, "id");
  if (typeof id !== "string" || !H32.test(id)) return `${name}.id must be a 32-byte lowercase hex id`;
  return null;
}

/** First structural problem of a checkpoint, or null if well formed. */
export function checkpointShapeError(cp: unknown): string | null {
  if (!isDict(cp)) return "checkpoint is not an object";
  const keys = Object.keys(cp);
  if (keys.length !== FIELDS.length || !FIELDS.every((f) => keys.includes(f))) {
    return "checkpoint fields do not match witness.checkpoint v1";
  }
  if (!isUint(cp.v) || cp.v !== CHECKPOINT_VERSION || cp.kind !== CHECKPOINT_KIND) return "not a witness.checkpoint v1";
  for (const name of ["network", "domain"]) {
    if (typeof cp[name] !== "string") return `${name} must be a string`;
  }
  for (const name of ["from", "to"]) {
    const problem = boundError(cp[name], name);
    if (problem) return problem;
  }
  if ((cp.from as unknown as CheckpointBound).index > (cp.to as unknown as CheckpointBound).index) {
    return "from.index is after to.index";
  }
  for (const name of ["msRoot", "policyHash"]) {
    const v = cp[name];
    if (typeof v !== "string" || !H32.test(v)) return `${name} must be 32-byte lowercase hex`;
  }
  if (!isUint(cp.msgCount)) return "msgCount must be an unsigned integer";
  const prev = cp.prev;
  if (prev !== null && !(typeof prev === "string" && H32.test(prev))) return "prev must be null or 32-byte lowercase hex";
  return null;
}
