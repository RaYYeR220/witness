/**
 * The console's pinned verifier config: network, coordinator keys, threshold,
 * the Rebased network and anchor trail, and where step 5 reads the trail
 * (RPC, Audit Trail package, the address that writes the records). Generated
 * from the stack's configuration by scripts/make-fixture.mjs into
 * src/config/verifier.json and shipped inside the build.
 *
 * Proofs fetched from an API are verified against these pins only. A config
 * served by the API (`WitnessData.verifierConfig()`) is never used to verify:
 * an API that could choose the pins could approve its own forgeries.
 */

import { makeRebasedFetcher, type VerifierConfig, type VerifyOptions } from "@witness/verify";

import pinned from "@/config/verifier.json";

export interface PinnedConfig {
  readonly network: string;
  readonly trustedCoordinatorKeys: readonly string[];
  readonly threshold: number;
  readonly rebasedNetwork: string | null;
  readonly trailId: string | null;
  readonly rebasedRpc: string | null;
  readonly auditTrailPackage: string | null;
  readonly anchorWriter: string | null;
}

const str = (v: unknown): string | null => (typeof v === "string" && v ? v : null);

export const PINNED: PinnedConfig = Object.freeze({
  network: pinned.network,
  trustedCoordinatorKeys: Object.freeze([...pinned.trustedCoordinatorKeys]),
  threshold: pinned.threshold,
  rebasedNetwork: str(pinned.rebasedNetwork),
  trailId: str(pinned.trailId),
  rebasedRpc: str((pinned as { rebasedRpc?: unknown }).rebasedRpc),
  auditTrailPackage: str((pinned as { auditTrailPackage?: unknown }).auditTrailPackage),
  anchorWriter: str((pinned as { anchorWriter?: unknown }).anchorWriter),
});

/** A fresh copy of the pinned config for one verification run. */
export function pinnedConfig(): VerifierConfig {
  return {
    network: PINNED.network,
    trustedCoordinatorKeys: [...PINNED.trustedCoordinatorKeys],
    threshold: PINNED.threshold,
    rebasedNetwork: PINNED.rebasedNetwork,
    trailId: PINNED.trailId,
    rebasedRpc: PINNED.rebasedRpc,
    auditTrailPackage: PINNED.auditTrailPackage,
    anchorWriter: PINNED.anchorWriter,
  };
}

/** Whether step 5 can read the chain at all: trail, network, RPC and package all pinned. */
export function anchorPinned(cfg: VerifierConfig = pinnedConfig()): boolean {
  return Boolean(cfg.trailId && cfg.rebasedNetwork && cfg.rebasedRpc && cfg.auditTrailPackage);
}

/**
 * Step 5's record fetcher: reads the pinned trail on the pinned Rebased RPC
 * directly from the browser. Null when the pins are incomplete, so the ladder
 * reports the anchor as not checked (PARTIAL), never as VALID.
 */
export function anchorFetcher(cfg: VerifierConfig = pinnedConfig(), fetchImpl?: typeof fetch): VerifyOptions["fetchAnchorRecord"] {
  if (!anchorPinned(cfg)) return null;
  return makeRebasedFetcher(cfg, fetchImpl ? { fetch: fetchImpl } : {});
}
