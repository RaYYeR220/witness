/** Small formatting helpers shared by the console screens. */

export const shortHex = (h: string | null | undefined, head = 6, tail = 4): string => {
  if (!h) return "";
  return h.length > head + tail + 2 ? `${h.slice(0, head)}…${h.slice(-tail)}` : h;
};

/** `did:iota:testnet:0x6b9a…f7a2`: method and network kept, the object id shortened. */
export function shortDid(did: string | null | undefined): string {
  if (!did) return "";
  const m = /^(did:[a-z0-9]+:(?:[a-z0-9]+:)?)(0x[0-9a-fA-F]+)(#.*)?$/.exec(did);
  if (!m) return did.length > 32 ? `${did.slice(0, 22)}…${did.slice(-6)}` : did;
  return `${m[1]}${shortHex(m[2], 6, 4)}${m[3] ?? ""}`;
}

/** `2026-10-06 14:32:05 UTC`. */
export function utc(ms: number | null | undefined, withSeconds = true): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return "";
  const iso = new Date(ms).toISOString();
  return `${iso.slice(0, 10)} ${iso.slice(11, withSeconds ? 19 : 16)} UTC`;
}

/** `14:32:05` in UTC, for dense rows. */
export function clock(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return "";
  return new Date(ms).toISOString().slice(11, 19);
}

/** "just now", "12 s ago", "4 min ago", "3 h ago", else the UTC date. */
export function ago(ms: number | null | undefined, now = Date.now()): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return "";
  const s = Math.round((now - ms) / 1000);
  if (s < 5) return "just now";
  if (s < 60) return `${s} s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86_400) return `${Math.floor(s / 3600)} h ago`;
  return utc(ms, false);
}

export type VerdictFamily = "signed" | "unsigned" | "rejected" | "unknown";

const VERDICT_INFO: Record<string, { label: string; family: VerdictFamily; gloss: string }> = {
  PRODUCER_SIGNED: { label: "Producer signed", family: "signed", gloss: "Signed by the component that produced it, with a key its DID lists." },
  RELAY_ATTESTED: { label: "Relay attested", family: "signed", gloss: "Signed by the relay on the producer's behalf." },
  UNSIGNED_LEGACY: { label: "Unsigned legacy", family: "unsigned", gloss: "No signature: a message in the old, unsigned format." },
  FORGED: { label: "Forged", family: "rejected", gloss: "The signature does not check out against the issuer's key." },
  REPLAY: { label: "Replay", family: "rejected", gloss: "A copy of a message already on the ledger, or a reused sequence number." },
  REVOKED_KEY: { label: "Revoked key", family: "rejected", gloss: "Signed with a key revoked before the message was confirmed." },
  UNAUTHORIZED_WRITER: { label: "Unauthorized writer", family: "rejected", gloss: "Correctly signed, but by an identity the writer policy does not allow for this tag." },
  MALFORMED: { label: "Malformed", family: "rejected", gloss: "Claims to be a signed envelope but does not follow its format." },
};

export function verdictInfo(v: string | null | undefined): { label: string; family: VerdictFamily; gloss: string } {
  if (!v) return { label: "No verdict", family: "unknown", gloss: "The indexer has not judged this message yet." };
  return VERDICT_INFO[v] ?? { label: v, family: "unknown", gloss: "" };
}

/** Lifecycle statuses in the order the API walks them. */
export const LIFECYCLE = ["RECEIVED", "SUBMITTED", "SOLID", "CONFIRMED", "CONTENT_VERIFIED"] as const;
export const LIFECYCLE_BAD = new Set(["CONTENT_MISMATCH", "NOT_FOUND", "ORPHANED", "REJECTED"]);

export function statusLabel(s: string | null | undefined): string {
  if (!s) return "";
  return s
    .toLowerCase()
    .split("_")
    .map((w, i) => (i === 0 ? w[0]!.toUpperCase() + w.slice(1) : w))
    .join(" ");
}

/** Trust score from a message's decoded JSON (`body.score` of an envelope, or a top-level `score`). */
export function scoreOf(json: unknown): number | null {
  if (typeof json !== "object" || json === null) return null;
  const j = json as Record<string, unknown>;
  const body = (typeof j.body === "object" && j.body !== null ? j.body : j) as Record<string, unknown>;
  const s = body.score;
  return typeof s === "number" && Number.isFinite(s) ? s : null;
}
