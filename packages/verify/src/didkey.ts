/**
 * did:key signers resolved locally: the DID is its own Ed25519 public key
 * (Python `witness_core.didkey`, held to it by core/tests/vectors/did_key.json).
 *
 * The indexer and the relay never ask a registry about a did:key, and the
 * anchor service only resolves did:iota. `didKeyDocument` answers in the
 * anchor's resolve shape, the reply the indexer builds for a did:key, and
 * `withDidKey` puts it in front of any other `resolveDid`.
 */

import { toHex } from "./bytes.js";

export const DID_KEY_PREFIX = "did:key:";
/** Longer DIDs are refused everywhere (indexer, relay, anchor). */
export const DID_KEY_MAX_LENGTH = 128;
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const ED25519_PUB = [0xed, 0x01]; // multicodec ed25519-pub, as an unsigned varint

function b58decode(s: string): Uint8Array | null {
  let n = 0n;
  for (const ch of s) {
    const digit = B58.indexOf(ch);
    if (digit < 0) return null;
    n = n * 58n + BigInt(digit);
  }
  const body: number[] = [];
  while (n > 0n) {
    body.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  let zeros = 0;
  while (zeros < s.length && s[zeros] === "1") zeros++;
  return Uint8Array.from([...new Array<number>(zeros).fill(0), ...body]);
}

/** The Ed25519 public key a did:key encodes, or null (not a did:key, or not Ed25519). */
export function didKeyPublic(did: string): Uint8Array | null {
  if (typeof did !== "string" || did.length > DID_KEY_MAX_LENGTH || !did.startsWith(`${DID_KEY_PREFIX}z`)) return null;
  const raw = b58decode(did.slice(DID_KEY_PREFIX.length + 1));
  if (raw === null || raw.length !== 34 || raw[0] !== ED25519_PUB[0] || raw[1] !== ED25519_PUB[1]) return null;
  return raw.slice(2);
}

/**
 * The resolve reply for a did:key; null for any other DID. One Ed25519 key,
 * never revoked, under the key's own fragment (`did:key:z…#z…`) and under the
 * bare DID, the two kids the indexer accepts. A did:key that encodes no
 * Ed25519 key gets no keys: nothing it names verifies (the indexer judges it
 * FORGED).
 */
export function didKeyDocument(did: string): Record<string, unknown> | null {
  if (typeof did !== "string" || !did.startsWith(DID_KEY_PREFIX)) return null;
  const pub = didKeyPublic(did);
  const keys: Record<string, unknown>[] = [];
  if (pub !== null) {
    const key = { type: "Ed25519", publicKeyHex: toHex(pub), revokedAtMs: null };
    keys.push({ kid: `${did}#${did.slice(DID_KEY_PREFIX.length)}`, ...key }, { kid: did, ...key });
  }
  return { doc: { id: did }, version: null, keys, historyComplete: true };
}

/**
 * `resolveDid` with every did:key answered locally (never forwarded). Without
 * a resolver, any other DID resolves to null (step 4 not evaluated).
 */
export function withDidKey(
  resolveDid?: ((did: string) => unknown) | null,
): (did: string) => Promise<unknown> {
  return async (did: string) => {
    const local = didKeyDocument(did);
    if (local !== null) return local;
    return resolveDid ? resolveDid(did) : null;
  };
}
