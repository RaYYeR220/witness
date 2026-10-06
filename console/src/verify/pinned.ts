/**
 * The console's pinned verifier config: network, coordinator keys, threshold,
 * Rebased network and anchor trail, generated from the stack's configuration
 * by scripts/make-fixture.mjs into src/config/verifier.json and shipped inside
 * the build.
 *
 * Proofs fetched from an API are verified against these pins only. A config
 * served by the API (`WitnessData.verifierConfig()`) is never used to verify:
 * an API that could choose the pins could approve its own forgeries.
 */

import type { VerifierConfig } from "@witness/verify";

import pinned from "@/config/verifier.json";

export interface PinnedConfig {
  readonly network: string;
  readonly trustedCoordinatorKeys: readonly string[];
  readonly threshold: number;
  readonly rebasedNetwork: string | null;
  readonly trailId: string | null;
}

export const PINNED: PinnedConfig = Object.freeze({
  network: pinned.network,
  trustedCoordinatorKeys: Object.freeze([...pinned.trustedCoordinatorKeys]),
  threshold: pinned.threshold,
  rebasedNetwork: pinned.rebasedNetwork ?? null,
  trailId: (pinned.trailId as string | null) ?? null,
});

/** A fresh copy of the pinned config for one verification run. */
export function pinnedConfig(): VerifierConfig {
  return {
    network: PINNED.network,
    trustedCoordinatorKeys: [...PINNED.trustedCoordinatorKeys],
    threshold: PINNED.threshold,
    rebasedNetwork: PINNED.rebasedNetwork,
    trailId: PINNED.trailId,
  };
}
