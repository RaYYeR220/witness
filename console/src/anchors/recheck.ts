/**
 * "The browser re-checks a checkpoint": read the checkpoint's record straight
 * from the pinned IOTA Rebased RPC (the same reader as step 5 of Verify) and
 * hold it, field by field, against what the explorer shows.
 *
 * The record is read from the trail pinned into this console, never from one
 * the explorer names, and its checkpoint hash is recomputed from the on-chain
 * data by the reader. Nothing here trusts the explorer's answer: it is what
 * gets checked.
 */

import { checkpointHash, fetchRecord, isDict, RebasedError, toHex } from "@witness/verify";

import type { AnchorCheckpoint } from "@/api/client";
import type { PinnedConfig } from "@/verify/pinned";

export type Agreement = "same" | "differs" | "unknown";

export interface RecheckRow {
  what: string;
  explorer: string | null;
  chain: string | null;
  c: Agreement;
}

/** The checkpoint as the record on the chain holds it, read by the browser. */
export interface ChainCheckpoint {
  fromMilestone: number | null;
  toMilestone: number | null;
  msRoot: string | null;
  msgCount: number | null;
  checkpointHash: string;
  addedBy: string | null;
}

export interface Recheck {
  /** The checkpoint (the very object the explorer listed) this result is about. */
  for: AnchorCheckpoint;
  /**
   * true: hash, window, root and message count are all the same and nothing differs or
   * went unanswered; false: something differs, or the record is missing; null: the chain
   * could not be read, or not every field could be compared ("not fully checked").
   */
  verdict: boolean | null;
  rows: RecheckRow[];
  /** What the record on the chain holds, once read. */
  chain: ChainCheckpoint | null;
  /** Why the chain could not be read, or why the explorer's own document is off. */
  problem: string | null;
  record: number | null;
  ms: number;
}

/** The rows that must all agree before a checkpoint counts as checked. */
export const REQUIRED_ROWS = ["Checkpoint hash", "Milestones", "Milestone root", "Messages committed"] as const;

type Pins = Pick<PinnedConfig, "rebasedRpc" | "trailId" | "auditTrailPackage" | "anchorWriter">;

const lowerHex = (v: unknown): string | null => (typeof v === "string" ? v.toLowerCase() : null);

function field(cp: unknown, ...path: string[]): unknown {
  let cur = cp;
  for (const k of path) {
    if (!isDict(cur)) return undefined;
    cur = (cur as Record<string, unknown>)[k];
  }
  return cur;
}

const text = (v: unknown): string | null => (v === undefined || v === null ? null : typeof v === "string" ? v : JSON.stringify(v));

function row(what: string, explorer: unknown, chain: unknown, norm: (v: unknown) => string | null = text): RecheckRow {
  const a = norm(explorer);
  const b = norm(chain);
  return { what, explorer: a, chain: b, c: a === null || b === null ? "unknown" : a === b ? "same" : "differs" };
}

/** Whether the explorer's checkpoint document hashes to the hash it states (computed here, no network). */
export function selfConsistent(a: AnchorCheckpoint): boolean | null {
  if (!isDict(a.checkpoint) || typeof a.checkpointHash !== "string") return null;
  try {
    return toHex(checkpointHash(a.checkpoint)) === a.checkpointHash.toLowerCase();
  } catch {
    return false;
  }
}

export async function recheckAnchor(a: AnchorCheckpoint, pins: Pins, options: { fetch?: typeof fetch; now?: () => number } = {}): Promise<Recheck> {
  const now = options.now ?? (() => performance.now());
  const t0 = now();
  const done = (r: Omit<Recheck, "ms" | "record" | "for" | "chain">, chain: ChainCheckpoint | null = null): Recheck => ({
    ...r,
    for: a,
    chain,
    record: a.record,
    ms: Math.round(now() - t0),
  });
  if (!pins.rebasedRpc || !pins.trailId || !pins.auditTrailPackage) {
    return done({ verdict: null, rows: [], problem: "This console pins no Rebased RPC, Audit Trail or package, so it cannot read the chain." });
  }
  if (typeof a.record !== "number" || !Number.isSafeInteger(a.record) || a.record < 0) {
    return done({ verdict: null, rows: [], problem: "The explorer names no record on the trail for this checkpoint." });
  }
  let rec;
  try {
    rec = await fetchRecord(pins.rebasedRpc, pins.trailId, a.record, { packageId: pins.auditTrailPackage, fetch: options.fetch });
  } catch (e) {
    const why = e instanceof RebasedError ? e.message : e instanceof Error ? e.name : String(e);
    return done({ verdict: null, rows: [], problem: `The record could not be read from IOTA Rebased (${why}).` });
  }
  if (rec === null) {
    return done({ verdict: false, rows: [], problem: `The pinned trail holds no record ${a.record}: nothing on the chain backs this checkpoint.` });
  }
  const cp = rec.checkpoint;
  const shown = a.checkpoint;
  const window = (from: unknown, to: unknown) => (typeof from === "number" && typeof to === "number" ? `${from}–${to}` : null);
  const rows: RecheckRow[] = [
    row("Checkpoint hash", a.checkpointHash, rec.checkpointHash, lowerHex),
    row("Milestones", window(a.fromMilestone, a.toMilestone), window(field(cp, "from", "index"), field(cp, "to", "index"))),
    row("Milestone root", a.msRoot, field(cp, "msRoot"), lowerHex),
    row("Messages committed", field(shown, "msgCount"), field(cp, "msgCount")),
    row("Writer policy hash", field(shown, "policyHash"), field(cp, "policyHash"), lowerHex),
    row("Previous checkpoint", field(shown, "prev") ?? "none", field(cp, "prev") ?? "none", lowerHex),
  ];
  // the expected writer comes from this console's pins, not from the explorer
  if (pins.anchorWriter) rows.push(row("Writer, as pinned here", pins.anchorWriter, rec.addedBy, lowerHex));
  const required = rows.filter((r) => (REQUIRED_ROWS as readonly string[]).includes(r.what));
  const verdict = rows.some((r) => r.c === "differs")
    ? false
    : required.length === REQUIRED_ROWS.length && rows.every((r) => r.c === "same")
      ? true
      : null;
  const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : null);
  const chain: ChainCheckpoint = {
    fromMilestone: num(field(cp, "from", "index")),
    toMilestone: num(field(cp, "to", "index")),
    msRoot: lowerHex(field(cp, "msRoot")),
    msgCount: num(field(cp, "msgCount")),
    checkpointHash: rec.checkpointHash,
    addedBy: lowerHex(rec.addedBy),
  };
  const problem =
    verdict === null ? `Not fully checked: ${rows.filter((r) => r.c === "unknown").map((r) => r.what.toLowerCase()).join(", ")} could not be compared.` : null;
  return done({ verdict, rows, problem }, chain);
}
