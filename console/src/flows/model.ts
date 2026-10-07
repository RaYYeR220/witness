/**
 * IoT flow traceability: how each message of a producer's flow links to the
 * one before it. Every signed envelope names the producer's previous message
 * (`prev`); a flow in `seq` order is a hash chain, and a message whose `prev`
 * is not the message before it (a gap), or a `prev` two messages claim (a
 * fork), is flagged. The chain is made of the producer's proven messages only
 * (producer signed or relay attested): any other message naming the producer
 * as issuer only claims it, and neither links, breaks nor forks the chain. The
 * explorer's chain view covers the whole flow; this reads it for the page on
 * screen.
 */

import type { Alert, Flow, FlowBy, FlowItem } from "@/api/client";

export type LinkState = "linked" | "gap" | "fork" | "start" | "earlier" | "none" | "claims";

export const LINK_TEXT: Record<LinkState, string> = {
  linked: "follows the message before it",
  gap: "gap: its prev is not the message before it",
  fork: "fork: another message claims the same prev",
  start: "starts the chain",
  earlier: "follows a message older than this page",
  none: "names no previous message",
  claims: "claims this issuer: not producer signed or relay attested, so outside the chain",
};

/** Verdicts that prove who issued a message; only these build a producer's chain. */
export const PROVEN_VERDICTS: ReadonlySet<string> = new Set(["PRODUCER_SIGNED", "RELAY_ATTESTED"]);

/**
 * Whether a message of an issuer flow only claims its issuer. The explorer marks
 * such rows (`claimsIssuer`); an older answer without the mark is read from the
 * recorded verdict.
 */
export function claimsIssuer(item: Pick<FlowItem, "verdict" | "claimsIssuer">): boolean {
  if (typeof item.claimsIssuer === "boolean") return item.claimsIssuer;
  return !(item.verdict !== null && PROVEN_VERDICTS.has(item.verdict));
}

export const FLOW_TITLES: Record<FlowBy, { tab: string; key: string; gloss: string }> = {
  issuer: { tab: "Producer chain", key: "Producer", gloss: "Every message naming this producer as issuer; only signed or attested ones are verified, and only they form the chain, in sequence order, linked by the prev hash each envelope carries." },
  corr: { tab: "Correlation id", key: "Correlation id", gloss: "Every message that carries the same correlation id, across producers, in time order." },
  ie: { tab: "Infrastructure Element", key: "IE", gloss: "Every message about one aeriOS Infrastructure Element, in time order." },
  service: { tab: "Service component", key: "Service component", gloss: "Every message about one aeriOS service component, in time order." },
};

/**
 * How each message of an issuer flow links to the one before it (flow order: oldest first).
 * Messages that only claim the issuer are marked as such and skipped: a proven message links
 * to the proven message before it.
 */
export function linkStates(flow: Pick<Flow, "items" | "chain" | "total">): Map<string, LinkState> {
  const out = new Map<string, LinkState>();
  const gaps = new Set(flow.chain?.gaps.map((g) => g.toLowerCase()) ?? []);
  const forks = new Set(flow.chain?.forks.map((f) => f.toLowerCase()) ?? []);
  const complete = flow.items.length >= flow.total;
  const marked = flow.items.some((i) => typeof i.claimsIssuer === "boolean");
  // An answer without the mark may count claimed messages in its forks: on this page, a fork
  // that a claimed message shares holds only if two proven messages share it too.
  const provenPrevs = new Map<string, number>();
  const claimedPrevs = new Set<string>();
  for (const item of flow.items) {
    const prev = item.prev?.toLowerCase();
    if (!prev) continue;
    if (claimsIssuer(item)) claimedPrevs.add(prev);
    else provenPrevs.set(prev, (provenPrevs.get(prev) ?? 0) + 1);
  }
  const isFork = (prev: string) =>
    forks.has(prev) && (marked || !claimedPrevs.has(prev) || (provenPrevs.get(prev) ?? 0) >= 2);
  let before: string | null = null;
  let first = true;
  for (const item of flow.items) {
    if (claimsIssuer(item)) {
      out.set(item.blockId, "claims");
      continue;
    }
    const prev = item.prev?.toLowerCase() ?? null;
    let state: LinkState;
    if (prev !== null && isFork(prev)) state = "fork";
    else if (prev !== null && before !== null && prev === before) state = "linked";
    else if (gaps.has(item.blockId.toLowerCase())) state = "gap";
    else if (prev === null) state = first && complete ? "start" : "none";
    else if (before === null) state = "earlier";
    else state = "gap";
    out.set(item.blockId, state);
    before = item.blockId.toLowerCase();
    first = false;
  }
  return out;
}

/** CHAIN_GAP and CHAIN_FORK alerts by the block they were raised on. */
export function chainAlerts(alerts: readonly Alert[]): Map<string, Alert[]> {
  const out = new Map<string, Alert[]>();
  for (const a of alerts) {
    if ((a.rule !== "CHAIN_GAP" && a.rule !== "CHAIN_FORK") || !a.blockId) continue;
    const k = a.blockId.toLowerCase();
    out.set(k, [...(out.get(k) ?? []), a]);
  }
  return out;
}

/** Newest first, for the screen. */
export const newestFirst = (items: readonly FlowItem[]) => [...items].reverse();
