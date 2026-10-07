/**
 * What the Lineage chart draws, computed from the API's answers: the score
 * series the ledger holds for one IE, what Orion says now, and the alerts and
 * incidents about the IE laid over the same time axis. Pure functions, so the
 * chart, the embeddable widget and the tests share them.
 */

import type { Alert, Incident, Lineage, LineageEntry } from "@/api/client";
import { score2, verdictInfo, type VerdictFamily } from "@/console/format";

export interface SeriesPoint {
  blockId: string;
  atMs: number;
  score: number;
  verdict: string | null;
  family: VerdictFamily;
  msIndex: number | null;
}

/** Entries that carry a score and a time, in time order (milestone order breaks ties). */
export function seriesOf(entries: readonly LineageEntry[]): SeriesPoint[] {
  return entries
    .filter((e) => typeof e.score === "number" && Number.isFinite(e.score) && typeof e.atMs === "number" && Number.isFinite(e.atMs))
    .map((e, i) => ({ e, i }))
    .sort((a, b) => a.e.atMs! - b.e.atMs! || (a.e.msIndex ?? 0) - (b.e.msIndex ?? 0) || (a.e.wfIndex ?? 0) - (b.e.wfIndex ?? 0) || a.i - b.i)
    .map(({ e }) => ({
      blockId: e.blockId,
      atMs: e.atMs!,
      score: e.score!,
      verdict: e.verdict,
      family: verdictInfo(e.verdict).family,
      msIndex: e.msIndex,
    }));
}

/** Points the line joins: signed and legacy scores. A rejected message's score is drawn apart, never joined. */
export const onLine = (p: SeriesPoint) => p.family === "signed" || p.family === "unsigned";

export type OrionKind = "ok" | "unreachable" | "unknown_entity" | "no_score" | "not_configured" | "other";

export interface OrionView {
  kind: OrionKind;
  /** Orion's value, only when it answered with one. */
  value: number | null;
  headline: string;
  detail: string;
  /** Whether a drift badge belongs on screen: only when Orion answered and the API could compare. */
  showDrift: boolean;
  drift: boolean | null;
}

/** Orion's answer in words. No drift is ever claimed unless Orion answered with a value. */
export function orionView(lin: Pick<Lineage, "orion" | "drift" | "ledger" | "epsilon">): OrionView {
  const o = lin.orion;
  const base = { value: null, showDrift: false, drift: null } as const;
  switch (o.status) {
    case "ok": {
      if (typeof o.value !== "number" || !Number.isFinite(o.value)) {
        return { ...base, kind: "other", headline: "Orion answered without a value", detail: "Nothing to compare with the ledger." };
      }
      const showDrift = lin.drift === true || lin.drift === false;
      const ledger = lin.ledger ? score2(lin.ledger.score) : null;
      const detail =
        lin.drift === true
          ? `More than ${lin.epsilon} away from the ledger's ${ledger}: what aeriOS acts on is not what the ledger vouches for.`
          : lin.drift === false
            ? `Within ${lin.epsilon} of the ledger's ${ledger}.`
            : "The ledger vouches for no score of this IE yet, so there is nothing to compare.";
      return { kind: "ok", value: o.value, headline: `Orion reports ${score2(o.value)}`, detail, showDrift, drift: showDrift ? lin.drift : null };
    }
    case "unreachable":
      return {
        ...base,
        kind: "unreachable",
        headline: "Orion unreachable",
        detail: "The explorer could not ask Orion just now. Without its answer there is no comparison, so no drift is claimed either way.",
      };
    case "unknown_entity":
      return { ...base, kind: "unknown_entity", headline: "Orion does not know this IE", detail: `The context broker has no entity ${o.entityId}.` };
    case "no_score":
      return { ...base, kind: "no_score", headline: "Orion holds no trust score", detail: `The entity ${o.entityId} exists in Orion but carries no trustScore.` };
    case "not_configured":
      return { ...base, kind: "not_configured", headline: "Orion not connected", detail: "This explorer is not configured to ask Orion." };
    default:
      return { ...base, kind: "other", headline: "Orion's answer is not one the console knows", detail: `Status ${String(o.status)}.` };
  }
}

export interface Overlay {
  kind: "alert" | "incident";
  key: string;
  id: number;
  startMs: number;
  /** An incident's close (null while open); an alert is a moment. */
  endMs: number | null;
  label: string;
  severity: string;
  blockId: string | null;
}

/** Alerts and incidents about the IE as marks on the time axis, oldest first. */
export function overlaysOf(alerts: readonly Alert[], incidents: readonly Incident[]): Overlay[] {
  const out: Overlay[] = [];
  for (const a of alerts) {
    if (!Number.isFinite(a.atMs)) continue;
    out.push({ kind: "alert", key: `a${a.id}`, id: a.id, startMs: a.atMs, endMs: null, label: a.rule, severity: a.severity, blockId: a.blockId });
  }
  for (const i of incidents) {
    if (!Number.isFinite(i.openedAtMs)) continue;
    out.push({
      kind: "incident",
      key: `i${i.id}`,
      id: i.id,
      startMs: i.openedAtMs,
      endMs: i.closedAtMs,
      label: i.title,
      severity: i.severity,
      blockId: i.closedBy,
    });
  }
  return out.sort((a, b) => a.startMs - b.startMs);
}

export interface Tick {
  at: number;
  label: string;
}

export interface Scale {
  t0: number;
  t1: number;
  lo: number;
  hi: number;
  x: (ms: number) => number;
  y: (score: number) => number;
  xTicks: Tick[];
  yTicks: number[];
}

const MIN = 60_000;
const STEPS = [MIN, 2 * MIN, 5 * MIN, 10 * MIN, 15 * MIN, 30 * MIN, 60 * MIN, 2 * 60 * MIN, 3 * 60 * MIN, 6 * 60 * MIN, 12 * 60 * MIN, 24 * 60 * MIN, 2 * 24 * 60 * MIN, 7 * 24 * 60 * MIN];

function tickLabel(ms: number, step: number): string {
  const iso = new Date(ms).toISOString();
  return step >= 24 * 60 * MIN ? iso.slice(5, 10) : iso.slice(11, 16);
}

/**
 * Maps time and score into the plot box (`left`…`right`, `top`…`bottom`). The
 * time axis spans the series, the score axis 0 to 1 unless a score or Orion's
 * value lies outside it.
 */
export function makeScale(
  points: readonly SeriesPoint[],
  box: { left: number; right: number; top: number; bottom: number },
  extra: { values?: readonly (number | null)[]; times?: readonly number[] } = {},
  maxTicks = 6,
): Scale {
  const times = points.map((p) => p.atMs).concat(points.length ? [] : (extra.times ?? []));
  let t0 = times.length ? Math.min(...times) : Date.now() - 60 * MIN;
  let t1 = times.length ? Math.max(...times) : Date.now();
  if (t1 - t0 < 2 * MIN) {
    t0 -= MIN;
    t1 += MIN;
  }
  const values = [...points.map((p) => p.score), ...(extra.values ?? []).filter((v): v is number => typeof v === "number" && Number.isFinite(v))];
  const lo = Math.min(0, ...values);
  const hi = Math.max(1, ...values);
  const x = (ms: number) => box.left + ((ms - t0) / (t1 - t0)) * (box.right - box.left);
  const y = (s: number) => box.bottom - ((s - lo) / (hi - lo)) * (box.bottom - box.top);
  const step = STEPS.find((s) => (t1 - t0) / s <= maxTicks) ?? STEPS[STEPS.length - 1]!;
  const xTicks: Tick[] = [];
  for (let at = Math.ceil(t0 / step) * step; at <= t1; at += step) xTicks.push({ at, label: tickLabel(at, step) });
  const yTicks = [0, 0.25, 0.5, 0.75, 1].map((f) => lo + f * (hi - lo));
  return { t0, t1, lo, hi, x, y, xTicks, yTicks };
}

/** The point nearest in time to `ms` (for hover and click on the chart). */
export function nearest(points: readonly SeriesPoint[], ms: number): SeriesPoint | null {
  let best: SeriesPoint | null = null;
  for (const p of points) if (!best || Math.abs(p.atMs - ms) < Math.abs(best.atMs - ms)) best = p;
  return best;
}
