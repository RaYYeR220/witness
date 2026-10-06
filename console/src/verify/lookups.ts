/**
 * The two trusted lookups the ladder needs besides the bundle and the pins:
 * the issuer's DID document (step 4) and the anchor record on IOTA Rebased
 * (step 5). Neither ever comes from the explorer's API.
 *
 *   issuer keys   the anchor service's DID resolver (`/resolve/{did}`, which
 *                 reads did:iota documents and their history from IOTA
 *                 Rebased), at VITE_RESOLVER_URL. A replay build has no
 *                 resolver: it uses the copies recorded with the snapshot,
 *                 and says so.
 *   anchor record read by the browser itself from the pinned Rebased RPC
 *                 (verify/pinned.ts), live in both modes.
 */

import type { VerifyOptions } from "@witness/verify";

import { anchorFetcher, PINNED } from "./pinned";

export interface TrustedLookups {
  resolveDid: NonNullable<VerifyOptions["resolveDid"]>;
  fetchAnchorRecord: VerifyOptions["fetchAnchorRecord"];
  /** Where issuer keys come from, in words. */
  didSource: string;
  /** Where the anchor record comes from, in words. */
  anchorSource: string;
  /** True when issuer keys are recorded copies rather than a live read. */
  recordedDids: boolean;
}

async function getJson(url: string, fetchImpl: typeof fetch): Promise<unknown> {
  const res = await fetchImpl(url, { headers: { accept: "application/json" } });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`${url} answered ${res.status}`);
  return res.json();
}

export function createLookups(env: Record<string, string | undefined> = import.meta.env, fetchImpl?: typeof fetch): TrustedLookups {
  const f = fetchImpl ?? ((input: RequestInfo | URL, init?: RequestInit) => globalThis.fetch(input, init));
  const anchorSource = PINNED.rebasedRpc
    ? `the pinned Audit Trail, read from IOTA Rebased ${PINNED.rebasedNetwork ?? ""} at ${PINNED.rebasedRpc}`.replace("  ", " ")
    : "nowhere: the console pins no Rebased RPC";
  if (env.VITE_MODE === "replay" || env.MODE === "replay") {
    const root = (env.VITE_REPLAY_ROOT ?? `${import.meta.env.BASE_URL}replay/`).replace(/\/?$/, "/");
    return {
      // file names as scripts/record-replay.mjs writes them: anything but [A-Za-z0-9._-] becomes "_"
      resolveDid: (did) => getJson(`${root}dids/${did.replace(/[^A-Za-z0-9._-]/g, "_")}.json`, f),
      fetchAnchorRecord: anchorFetcher(undefined, fetchImpl),
      didSource: "copies recorded from the anchor service's resolver with this snapshot (not a live read)",
      anchorSource,
      recordedDids: true,
    };
  }
  const base = (env.VITE_RESOLVER_URL ?? "/anchor").replace(/\/+$/, "");
  return {
    resolveDid: (did) => getJson(`${base}/resolve/${encodeURIComponent(did)}`, f),
    fetchAnchorRecord: anchorFetcher(undefined, fetchImpl),
    didSource: `the anchor service's DID resolver at ${base}, which reads did:iota from IOTA Rebased`,
    anchorSource,
    recordedDids: false,
  };
}
