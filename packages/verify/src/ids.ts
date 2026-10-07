/** The canonical did:iota form (Python `witness_core.ids`). */

/** Reason given for a signer whose did:iota DID is not in canonical form. */
export const NON_CANONICAL_DID = "non-canonical DID";

// A did:iota DID names its Identity object: `did:iota:[<network>:]0x<64 lowercase hex>`, as
// the anchor service writes it (mainnet DIDs omit the network).
const CANONICAL_IOTA_DID = /^did:iota:(?:[a-z0-9]{1,8}:)?0x[0-9a-f]{64}$/;

/**
 * False for a did:iota DID not in canonical form (upper-case hex, wrong length, ...); true
 * for any other string. A non-canonical did:iota DID is never looked up: the anchor would
 * normalise it and answer for another spelling, which no caller can match.
 */
export function isCanonicalDid(did: string): boolean {
  return !did.startsWith("did:iota:") || CANONICAL_IOTA_DID.test(did);
}
