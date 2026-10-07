/**
 * Integrity in words: how much each incident event can be trusted, why an
 * incident opened and how it closed, and the one-line reason an alert gives.
 * Everything read from `detail` and `evidence` is untrusted JSON: only known
 * values are interpreted, the rest is shown as text.
 */

import { isDict } from "@witness/verify";

import type { Alert, Incident, IncidentEvent } from "@/api/client";
import { score2, utc } from "@/console/format";

export type TrustLevel = "proven" | "relayed" | "untrusted" | "revoked" | "unknown";

/**
 * The correlation engine's trust levels, in its words: none of them is a check
 * this browser made, so none is shown as one (no green).
 */
export const TRUST: Record<TrustLevel, { label: string; gloss: string }> = {
  proven: {
    label: "Proven, per the engine",
    gloss: "The engine found it producer-signed by a writer the policy allows for the tag, with no UNSIGNED or SHADOW alert on it. Only proven events shape an incident. Open the block in Verify to check it yourself.",
  },
  relayed: {
    label: "Relayed, per the engine",
    gloss: "Attested by the relay, or unsigned but received through the Messages API on a tag that allows it. It may open an incident, never shape or close one.",
  },
  untrusted: {
    label: "Untrusted, per the engine",
    gloss: "Forged, replayed, written around the relay, unsigned where a signature is required. Its content is never evidence; only the alert about it counts.",
  },
  revoked: {
    label: "Revoked",
    gloss: "The engine took this event back after the fact (a SHADOW alert found later, say): its block is evidence only and no longer shapes, remediates or closes the incident.",
  },
  unknown: { label: "Not rated", gloss: "The correlation engine recorded no trust level for this event." },
};

const detailOf = (e: Pick<IncidentEvent, "detail">) => (isDict(e.detail) ? (e.detail as Record<string, unknown>) : {});
const word = (v: unknown) => (typeof v === "string" && /^[A-Za-z0-9 _.:-]{1,40}$/.test(v) ? v : null);

/** The trust level the correlation engine recorded on an event (`detail.trust`; `detail.revoked` overrides it). */
export function trustOf(e: Pick<IncidentEvent, "detail">): TrustLevel {
  const d = detailOf(e);
  if (word(d.revoked)) return "revoked";
  const t = d.trust;
  return t === "proven" || t === "relayed" || t === "untrusted" ? t : "unknown";
}

/** How a level reads on one event: a revoked one says why and what it was. */
export function trustLine(e: Pick<IncidentEvent, "detail">): string {
  const level = trustOf(e);
  if (level !== "revoked") return TRUST[level].label;
  const d = detailOf(e);
  const was = word(d.was) ?? word(d.as);
  return `Revoked (${word(d.revoked)}): evidence only${was ? `, was ${was}` : ""}`;
}

export const ROLES: Record<string, string> = {
  trigger: "Opened it",
  "trust-drop": "Trust drop",
  security: "Security event",
  deployment: "Deployment",
  remediation: "Remediation",
  alert: "Alert",
};

export const roleLabel = (r: string) => (Object.hasOwn(ROLES, r) ? ROLES[r]! : r);

const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const str = (v: unknown): string | null => (typeof v === "string" && v ? v : null);

/** One line on what an event was, from the fields the engine writes (`as`, `rule`, `score`, `previousScore`). */
export function eventSummary(e: IncidentEvent): string {
  const d = isDict(e.detail) ? (e.detail as Record<string, unknown>) : {};
  const as = str(d.as);
  const rule = str(d.rule);
  const score = num(d.score);
  const prev = num(d.previousScore);
  if ((as === "trust-drop" || e.role === "trust-drop") && score !== null) {
    return prev !== null ? `Trust score fell from ${score2(prev)} to ${score2(score)}` : `Trust score ${score2(score)}`;
  }
  if (rule) return `${rule} alert`;
  if (score !== null) return `Trust score ${score2(score)}`;
  return e.tag ? `${e.tag} message` : "Block";
}

/** How the incident stands, in one sentence. */
export function statusLine(i: Incident): { tone: "open" | "closed" | "other"; label: string; text: string } {
  if (i.status === "open") {
    return {
      tone: "open",
      label: "Open",
      text: `Open since ${utc(i.openedAtMs)}${i.lastEventMs ? `; the last event was at ${utc(i.lastEventMs)}` : ""}.`,
    };
  }
  if (i.status === "closed:recovered") {
    const target = i.baselineScore !== null ? ` (${score2(i.baselineScore)})` : "";
    return {
      tone: "closed",
      label: "Closed, recovered",
      text: `Closed at ${utc(i.closedAtMs)}: a proven trust score came back to where the first drop fell from${target}.`,
    };
  }
  if (i.status === "closed:quiet") {
    return { tone: "closed", label: "Closed, quiet", text: `Closed at ${utc(i.closedAtMs)}: no event for 30 minutes.` };
  }
  return { tone: "other", label: i.status, text: `Status ${i.status}.` };
}

/** What the incident correlates on, in words (`ie:…`, `sc:…`, `iss:…`, `ledger`). */
export function keyLabel(k: string): string {
  if (k === "ledger") return "the ledger itself";
  const [kind, ...rest] = k.split(":");
  const v = rest.join(":");
  if (kind === "ie") return `IE ${v}`;
  if (kind === "sc") return `service component ${v}`;
  if (kind === "iss") return `issuer ${v}`;
  return k;
}

/** The reason an alert's evidence states, if it states one as text. */
export function alertReason(a: Pick<Alert, "evidence">, max = 220): string | null {
  const r = isDict(a.evidence) ? (a.evidence as Record<string, unknown>).reason : undefined;
  if (typeof r !== "string" || !r.trim()) return null;
  return r.length > max ? `${r.slice(0, max)}…` : r;
}
