// Regenerates core/tests/vectors/witness_anchor.json: witness.anchor mirrors sealed by the
// anchor's MirrorSigner, for the Python reference to verify (core/tests/test_anchor_vectors.py).
//
//   pnpm --filter @witness/anchor exec tsx test/vectors/make-anchor-envelope.ts
//
// The signing key is a fixed test key (seed 0x5a…5a), not a deployed identity.
import { createPrivateKey } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { fromHex, jcs, toHex } from "@witness/verify";
import { buildCheckpoint, checkpointHashHex } from "../../src/checkpoint.js";
import { ANCHOR_TAG, MirrorSigner, mirrorBody } from "../../src/mirror.js";
import type { CheckpointEntry } from "../../src/state.js";

const DID = `did:iota:testnet:0x${"a1".repeat(32)}`;
const SEED = new Uint8Array(32).fill(0x5a);
const TRAIL = `0x${"7a".repeat(32)}`;
const TXS = ["8L3KZB5SN8Dd7UTorJ6sUqC3DFyuatJ6WPvuSQZummtu", "5SpNx1Rcix5XB6doa3w4bHYme7PqrMXcunLWHfUaNwrX"];

const PKCS8_ED25519 = Buffer.from("302e020100300506032b657004220420", "hex");
const jwk = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, SEED]), format: "der", type: "pkcs8" }).export({ format: "jwk" }) as Record<string, string>;
const signer = MirrorSigner.fromJwk({ ...jwk, kid: `${DID}#sig-1` });

const vectors = JSON.parse(readFileSync(new URL("./checkpoint.json", import.meta.url), "utf8"));
const entries: CheckpointEntry[] = vectors.checkpoints.slice(0, 2).map((v: any, i: number) => {
  const ids = (v.input.milestoneIds as string[]).map((h) => fromHex(h));
  const cp = buildCheckpoint({
    network: v.input.network,
    domain: v.input.domain,
    from: { index: v.input.first, id: ids[0]! },
    to: { index: v.input.first + ids.length - 1, id: ids.at(-1)! },
    milestoneIds: ids,
    msgCount: v.input.msgCount,
    policyHash: fromHex(v.input.policyHash),
    prevHash: v.input.prevHash === null ? null : fromHex(v.input.prevHash),
  });
  return {
    seq: i + 1,
    checkpoint: cp,
    checkpointHash: checkpointHashHex(cp),
    trail: TRAIL,
    record: 4 + i,
    tx: TXS[i]!,
    timestampMs: 0,
    addedBy: "0x00",
    anchoredAt: "",
    mirror: null,
  };
});

let prev: string | null = null;
const messages = entries.map((e) => {
  const env = signer.seal(ANCHOR_TAG, mirrorBody(e, "testnet"), e.seq, prev);
  // A stand-in for the block id the relay would get back, so the second message chains to the first.
  prev = `0x${(e.seq.toString(16).padStart(2, "0")).repeat(32)}`;
  return { envelope: env, data: jcs(env) };
});

const out = {
  _source: "anchor/test/vectors/make-anchor-envelope.ts (MirrorSigner + mirrorBody, fixed test key)",
  tag: ANCHOR_TAG,
  kid: signer.kid,
  publicKeyHex: toHex(Buffer.from(signer.publicX, "base64url")),
  messages,
};
const target = new URL("../../../core/tests/vectors/witness_anchor.json", import.meta.url);
writeFileSync(target, `${JSON.stringify(out, null, 2)}\n`);
console.log(`wrote ${target.pathname}`);
