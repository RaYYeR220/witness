/**
 * The two trusted lookups the ladder needs besides the bundle and the pins:
 * the issuer's DID document (step 4) and the anchor record on IOTA Rebased
 * (step 5). Neither ever comes from the explorer's API.
 *
 *   issuer keys   a did:key is its own key: decoded here, never asked of
 *                 anyone (`withDidKey`, as the indexer does). A did:iota is
 *                 asked of the anchor service operated with this explorer
 *                 (`{VITE_RESOLVER_URL}/resolve/{did}`). That service reads
 *                 the did:iota document and its key history from IOTA
 *                 Rebased; the browser trusts its answer. This is an
 *                 assumption, not an independent read of the chain. A replay
 *                 build has no resolver: it uses the copies recorded with the
 *                 snapshot, and says so.
 *   anchor record read by the browser itself from the pinned Rebased RPC
 *                 (verify/pinned.ts), live in both modes: no service of this
 *                 explorer is trusted for step 5.
 */

import { withDidKey, type VerifyOptions } from "@witness/verify";

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

/** How long the issuer's DID document may take before step 4 is left unresolved. */
export const RESOLVE_TIMEOUT_MS = 15_000;

/**
 * GET a JSON document: null on 404; throws on any other failure, a redirect
 * or the timeout. The ladder reads a throw as "signer identity not resolved"
 * (step 4 not evaluated, PARTIAL), never as a pass.
 */
async function getJson(url: string, fetchImpl: typeof fetch, timeoutMs: number): Promise<unknown> {
  const res = await fetchImpl(url, { headers: { accept: "application/json" }, redirect: "error", signal: AbortSignal.timeout(timeoutMs) });
  if (res.status === 404) {
    void res.body?.cancel().catch(() => undefined);
    return null;
  }
  if (!res.ok) {
    void res.body?.cancel().catch(() => undefined);
    throw new Error(`${url} answered ${res.status}`);
  }
  return res.json();
}

export function createLookups(
  env: Record<string, string | undefined> = import.meta.env,
  fetchImpl?: typeof fetch,
  { timeoutMs = RESOLVE_TIMEOUT_MS }: { timeoutMs?: number } = {},
): TrustedLookups {
  const f: typeof fetch = fetchImpl ?? ((input, init) => globalThis.fetch(input, init));
  const anchorSource = PINNED.rebasedRpc
    ? `the pinned Audit Trail, read from IOTA Rebased ${PINNED.rebasedNetwork ?? ""} at ${PINNED.rebasedRpc}`.replace("  ", " ")
    : "nowhere: the console pins no Rebased RPC";
  if (env.VITE_MODE === "replay" || env.MODE === "replay") {
    const root = (env.VITE_REPLAY_ROOT ?? `${import.meta.env.BASE_URL}replay/`).replace(/\/?$/, "/");
    return {
      // file names as scripts/record-replay.mjs writes them: anything but [A-Za-z0-9._-] becomes "_"
      resolveDid: withDidKey((did) => getJson(`${root}dids/${did.replace(/[^A-Za-z0-9._-]/g, "_")}.json`, f, timeoutMs)),
      fetchAnchorRecord: anchorFetcher(undefined, fetchImpl),
      didSource: "copies recorded with this snapshot from the anchor service operated with this explorer: not a live read, and not an independent read of the chain",
      anchorSource,
      recordedDids: true,
    };
  }
  const resolver = (env.VITE_RESOLVER_URL ?? "/anchor").replace(/\/+$/, "");
  return {
    resolveDid: withDidKey((did) => getJson(`${resolver}/resolve/${encodeURIComponent(did)}`, f, timeoutMs)),
    fetchAnchorRecord: anchorFetcher(undefined, fetchImpl),
    didSource: `the anchor service operated with this explorer (${resolver}/resolve), which reads did:iota from IOTA Rebased: not an independent read of the chain`,
    anchorSource,
    recordedDids: false,
  };
}
