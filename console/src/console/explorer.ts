/**
 * Links to the public IOTA explorer for things on IOTA Rebased: an object (a
 * trail, a DID's Identity object), a transaction, an address.
 *
 * Links are built here from ids, never taken from an answer: the network is
 * the one pinned into this console, each id must look like what it claims to
 * be, and the result must be an https URL on the explorer's host. Anything
 * else gives null and the screen shows the id without a link.
 */

import { PINNED } from "@/verify/pinned";

export const EXPLORER_ORIGIN = "https://explorer.iota.org";

const NETWORK = /^[a-z][a-z0-9-]{0,31}$/;
const OBJECT_ID = /^0x[0-9a-fA-F]{1,64}$/;
/** Base58 transaction digest (32 bytes: 43 or 44 characters). */
const DIGEST = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

function link(kind: "object" | "txblock" | "address", id: string, network: string | null | undefined): string | null {
  if (!network || !NETWORK.test(network)) return null;
  const url = new URL(`${EXPLORER_ORIGIN}/${kind}/${encodeURIComponent(id)}`);
  url.searchParams.set("network", network);
  return url.protocol === "https:" && url.origin === EXPLORER_ORIGIN ? url.href : null;
}

/** An object on Rebased (Audit Trail, Identity object), or null. */
export function explorerObject(id: unknown, network: string | null = PINNED.rebasedNetwork): string | null {
  return typeof id === "string" && OBJECT_ID.test(id) ? link("object", id, network) : null;
}

/** A Rebased transaction by digest, or null. */
export function explorerTx(digest: unknown, network: string | null = PINNED.rebasedNetwork): string | null {
  return typeof digest === "string" && DIGEST.test(digest) ? link("txblock", digest, network) : null;
}

/** A Rebased address, or null. */
export function explorerAddress(address: unknown, network: string | null = PINNED.rebasedNetwork): string | null {
  return typeof address === "string" && OBJECT_ID.test(address) ? link("address", address, network) : null;
}

/** The object id inside a `did:iota[:network]:0x…` DID, or null. */
export function didObjectId(did: unknown): string | null {
  if (typeof did !== "string") return null;
  const m = /^did:iota:(?:[a-z0-9]+:)?(0x[0-9a-fA-F]{64})$/.exec(did);
  return m ? m[1]! : null;
}
