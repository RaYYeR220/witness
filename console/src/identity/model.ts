/**
 * The component identities as the anchor service publishes them (through
 * `GET /identity`, passed through unchecked), read defensively, and the
 * status of each key as the trusted DID resolver reports it.
 */

import { isDict, snapshotKeys } from "@witness/verify";

import type { PolicySummary } from "@/api/client";

export interface IdentityKey {
  kid: string;
  type: string;
  relationships: string[];
  publicKeyHex: string | null;
}

export type Controller = { kind: "address"; address: string } | { kind: "identity"; did: string } | null;

export interface ComponentIdentity {
  name: string;
  did: string;
  objectId: string | null;
  controller: Controller;
  keys: IdentityKey[];
  createdTx: string | null;
  createdAt: string | null;
  retiredAt: string | null;
  reason: string | null;
}

const DID = /^did:[a-z0-9]+:[A-Za-z0-9:._%-]{1,200}$/;
const str = (v: unknown, max = 512): string | null => (typeof v === "string" && v.length > 0 && v.length <= max ? v : null);

/** One published identity, or null when it is not shaped like one. */
export function readIdentity(x: unknown): ComponentIdentity | null {
  if (!isDict(x)) return null;
  const o = x as Record<string, unknown>;
  const did = str(o.did);
  if (!did || !DID.test(did)) return null;
  const c = isDict(o.controller) ? (o.controller as Record<string, unknown>) : null;
  let controller: Controller = null;
  if (c?.kind === "address" && str(c.address)) controller = { kind: "address", address: c.address as string };
  else if (c?.kind === "identity" && str(c.did) && DID.test(c.did as string)) controller = { kind: "identity", did: c.did as string };
  const keys: IdentityKey[] = [];
  for (const k of Array.isArray(o.keys) ? o.keys : []) {
    if (!isDict(k)) continue;
    const r = k as Record<string, unknown>;
    const kid = str(r.kid);
    if (!kid) continue;
    keys.push({
      kid,
      type: str(r.type, 32) ?? "unknown",
      relationships: Array.isArray(r.relationships) ? r.relationships.filter((s): s is string => typeof s === "string").slice(0, 8) : [],
      publicKeyHex: str(r.publicKeyHex, 256),
    });
  }
  return {
    name: str(o.name, 64) ?? "unnamed",
    did,
    objectId: str(o.objectId, 80),
    controller,
    keys,
    createdTx: str(o.createdTx, 80),
    createdAt: str(o.createdAt, 40),
    retiredAt: str(o.retiredAt, 40),
    reason: str(o.reason, 300),
  };
}

export const readIdentities = (xs: unknown[]): ComponentIdentity[] => xs.map(readIdentity).filter((i): i is ComponentIdentity => i !== null);

/** `#sig-1` for `did:…#sig-1`. */
export const fragment = (kid: string) => (kid.includes("#") ? `#${kid.split("#").pop()}` : kid);

/** The tags a DID may write under the policy (a `*` default counts as every other tag). */
export function tagsFor(did: string, policy: PolicySummary | null): string[] {
  if (!policy) return [];
  return Object.entries(policy.tags)
    .filter(([, rule]) => rule.allowed.includes(did) || rule.allowed.includes("*"))
    .map(([tag]) => tag)
    .sort();
}

export type KeyState = { kind: "active" } | { kind: "revoked"; atMs: number } | { kind: "absent" };

export interface KeyStatus {
  /** Per kid of the resolver's answer: in force, or revoked at a time. */
  byKid: Map<string, KeyState>;
  /** Keys the resolver knows that the published list does not name (revoked ones, typically). */
  others: { kid: string; state: KeyState }[];
  /** False when the resolver could not read the whole key history: revocation times may be early bounds. */
  historyComplete: boolean | null;
}

/**
 * Key status from the resolver's answer (`{doc, keys: [{kid, revokedAtMs}], historyComplete}`),
 * read with the verifier's own snapshot reader. A kid with an entry in force is active; one whose
 * entries are all revoked is revoked at the latest time.
 */
export function keyStatus(resolved: unknown, published: readonly IdentityKey[]): KeyStatus {
  const table = snapshotKeys(resolved);
  const state = (kid: string): KeyState => {
    const entries = table.get(kid);
    if (!entries?.length) return { kind: "absent" };
    if (entries.some((e) => e.revokedAtMs === null)) return { kind: "active" };
    return { kind: "revoked", atMs: Math.max(...entries.map((e) => Number(e.revokedAtMs))) };
  };
  const byKid = new Map<string, KeyState>();
  for (const k of published) byKid.set(k.kid, state(k.kid));
  const others = [...table.keys()].filter((kid) => !byKid.has(kid)).map((kid) => ({ kid, state: state(kid) }));
  const hc = isDict(resolved) ? (resolved as Record<string, unknown>).historyComplete : undefined;
  return { byKid, others, historyComplete: typeof hc === "boolean" ? hc : null };
}
