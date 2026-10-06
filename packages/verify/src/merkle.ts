/** TIP-4 Merkle tree (RFC 6962 shape) over BLAKE2b-256. */

import { blake2b256 } from "./blake2b.js";
import { bytesEqual, concatBytes, isBytes } from "./bytes.js";

/** One audit-path step; `side` is where the *sibling* sits. */
export interface PathStep {
  side: "L" | "R";
  hash: Uint8Array;
}

const LEAF = Uint8Array.of(0);
const NODE = Uint8Array.of(1);

export function leafHash(value: Uint8Array): Uint8Array {
  return blake2b256(concatBytes(LEAF, value));
}

export function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return blake2b256(concatBytes(NODE, left, right));
}

/** Largest power of two strictly less than n (n >= 2). */
function splitPoint(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function rootOf(values: readonly Uint8Array[], lo: number, hi: number): Uint8Array {
  const n = hi - lo;
  if (n === 0) return blake2b256(new Uint8Array(0));
  if (n === 1) return leafHash(values[lo]!);
  const k = splitPoint(n);
  return nodeHash(rootOf(values, lo, lo + k), rootOf(values, lo + k, hi));
}

/** Root over `values` in order; the empty tree hashes to BLAKE2b-256(""). */
export function merkleRoot(values: readonly Uint8Array[]): Uint8Array {
  return rootOf(values, 0, values.length);
}

/** Sibling steps from leaf `index` up to the root. Throws RangeError when out of range. */
export function auditPath(values: readonly Uint8Array[], index: number): PathStep[] {
  if (!Number.isInteger(index) || index < 0 || index >= values.length) {
    throw new RangeError(`index ${index} out of range for ${values.length} leaves`);
  }
  const steps: PathStep[] = [];
  let lo = 0;
  let hi = values.length;
  while (hi - lo > 1) {
    const k = splitPoint(hi - lo);
    if (index < lo + k) {
      steps.push({ side: "R", hash: rootOf(values, lo + k, hi) });
      hi = lo + k;
    } else {
      steps.push({ side: "L", hash: rootOf(values, lo, lo + k) });
      lo += k;
    }
  }
  return steps.reverse();
}

/** True iff `path` leads from the 32-byte leaf `value` to `root`. Never throws. */
export function verifyPath(value: unknown, path: unknown, root: unknown): boolean {
  if (!isBytes(value, 32) || !isBytes(root, 32) || !Array.isArray(path)) return false;
  let h = leafHash(value);
  for (const step of path as unknown[]) {
    if (typeof step !== "object" || step === null) return false;
    const { side, hash } = step as { side?: unknown; hash?: unknown };
    if (!isBytes(hash, 32)) return false;
    if (side === "L") h = nodeHash(hash, h);
    else if (side === "R") h = nodeHash(h, hash);
    else return false;
  }
  return bytesEqual(h, root);
}
