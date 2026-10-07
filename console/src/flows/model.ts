/**
 * IoT flow traceability: how each message of a producer's flow links to the
 * one before it. Every signed envelope names the producer's previous message
 * (`prev`); a flow in `seq` order is a hash chain, and a message whose `prev`
 * is not the message before it (a gap), or a `prev` two messages claim (a
 * fork), is flagged. The explorer's chain view covers the whole flow; this
 * reads it for the page on screen.
 */

import type { Alert, Flow, FlowBy, FlowItem } from "@/api/client";

export type LinkState = "linked" | "gap" | "fork" | "start" | "earlier" | "none";

export const LINK_TEXT: Record<LinkState, string> = {
  linked: "follows the message before it",
  gap: "gap: its prev is not the message before it",
  fork: "fork: another message claims the same prev",
  start: "starts the chain",
  earlier: "follows a message older than this page",
  none: "names no previous message",
};

export const FLOW_TITLES: Record<FlowBy, { tab: string; key: string; gloss: string }> = {
  issuer: { tab: "Producer chain", key: "Producer", gloss: "Every message one producer signed, in sequence order, linked by the prev hash each envelope carries." },
  corr: { tab: "Correlation id", key: "Correlation id", gloss: "Every message that carries the same correlation id, across producers, in time order." },
  ie: { tab: "Infrastructure Element", key: "IE", gloss: "Every message about one aeriOS Infrastructure Element, in time order." },
  service: { tab: "Service component", key: "Service component", gloss: "Every message about one aeriOS service component, in time order." },
};

/** How each message of an issuer flow links to the one before it (flow order: oldest first). */
export function linkStates(flow: Pick<Flow, "items" | "chain" | "total">): Map<string, LinkState> {
  const out = new Map<string, LinkState>();
  const gaps = new Set(flow.chain?.gaps.map((g) => g.toLowerCase()) ?? []);
  const forks = new Set(flow.chain?.forks.map((f) => f.toLowerCase()) ?? []);
  const complete = flow.items.length >= flow.total;
  flow.items.forEach((item, i) => {
    const prev = item.prev?.toLowerCase() ?? null;
    const before = i > 0 ? flow.items[i - 1]!.blockId.toLowerCase() : null;
    let state: LinkState;
    if (prev !== null && forks.has(prev)) state = "fork";
    else if (gaps.has(item.blockId.toLowerCase())) state = "gap";
    else if (prev === null) state = i === 0 && complete ? "start" : "none";
    else if (before !== null && prev === before) state = "linked";
    else if (before === null) state = "earlier";
    else state = "gap";
    out.set(item.blockId, state);
  });
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
