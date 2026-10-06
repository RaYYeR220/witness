/**
 * Plain-words copy for the landing page, filled with values read from the
 * sample's inputs. These sentences say what each check compares; whether it
 * passed is only ever shown from the library's result. The DID document and
 * the anchor record are recorded copies from the test vectors, and the copy
 * says so: the landing page never reads IOTA Rebased live.
 */

/** Shown wherever the landing page's checks are. */
export const SAMPLE_NOTE = "Sample from the test vectors \u2014 DID and anchor records are recorded copies, not live reads.";

import { fromHex } from "@witness/verify";

import { inputs, readTrustMessage, shortHex, type Which } from "@/verify/sample";

interface BundleShape {
  block: { id: string; raw: string };
  milestone: { index: number; signatures: unknown[] };
  inclusion: { path: unknown[]; leafIndex: number; leafCount: number };
  anchor: { checkpoint: { from: { index: number }; to: { index: number } }; rebased: { record: number } };
}

export function bundleFacts(which: Which) {
  const t = inputs(which);
  const b = t.bundle as unknown as BundleShape;
  const raw = fromHex(b.block.raw);
  const msg = readTrustMessage(raw);
  return {
    id: b.block.id,
    bytes: raw.length,
    msIndex: b.milestone.index,
    signatures: b.milestone.signatures.length,
    pinnedKeys: t.config.trustedCoordinatorKeys.length,
    threshold: t.config.threshold,
    pathSteps: b.inclusion.path.length,
    leafIndex: b.inclusion.leafIndex,
    leafCount: b.inclusion.leafCount,
    anchorFrom: b.anchor.checkpoint.from.index,
    anchorTo: b.anchor.checkpoint.to.index,
    record: b.anchor.rebased.record,
    ...msg,
  };
}

export type BundleFacts = ReturnType<typeof bundleFacts>;

export function glosses(f: BundleFacts): string[] {
  const key = f.kid?.split("#")[1];
  return [
    `BLAKE2b-256 of the block's ${f.bytes} raw bytes, against its id ${shortHex(f.id)}.`,
    `A ${f.pathSteps}-step Merkle path from the block to the inclusion root of milestone ${f.msIndex}.`,
    `${f.signatures} coordinator signatures over milestone ${f.msIndex}, against ${f.pinnedKeys} pinned keys; ${f.threshold} needed.`,
    `The envelope's Ed25519 signature, against key #${key ?? "?"} of ${f.issuer ?? "the issuer"} in the sample's recorded DID document.`,
    `The checkpoint of milestones ${f.anchorFrom} to ${f.anchorTo}, against the sample's recorded anchor record (record ${f.record}, test vectors).`,
  ];
}
