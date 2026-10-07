/** Alert, incident and finding severities, most severe first. */
export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];

/** Sort key: 0 for critical … 4 for info, 5 for anything the console does not know. */
export function severityRank(s: string | null | undefined): number {
  const i = SEVERITIES.indexOf(s as Severity);
  return i < 0 ? SEVERITIES.length : i;
}

export function severityLabel(s: string | null | undefined): string {
  if (!s) return "Unrated";
  return s[0]!.toUpperCase() + s.slice(1);
}

/** Alert rules the indexer raises, with what each one means, for filters and tooltips. */
export const RULES: Record<string, string> = {
  FORGED: "The signature does not check out against the issuer's key.",
  UNAUTHORIZED_WRITER: "Correctly signed, by an identity the writer policy does not allow for the tag.",
  REPLAY: "A copy of a message already on the ledger, or a reused sequence number.",
  REVOKED_KEY: "Signed with a key revoked before the message was confirmed.",
  MALFORMED: "Claims to be a signed envelope but does not follow its format.",
  UNSIGNED: "An unsigned message on a tag whose writer policy requires signatures.",
  UNKNOWN_IE: "A message about an Infrastructure Element Orion does not know.",
  ANOMALY: "A trust score jump with no trustworthy security event for the IE shortly before it.",
  CLOCK_SKEW: "The signer's issue time is far from the milestone's.",
  CHAIN_GAP: "The envelope's prev is not the issuer's last seen block.",
  CHAIN_FORK: "Two messages of one issuer continue from the same prev.",
  DRIFT: "Orion's trustScore differs from the ledger's latest score, or cannot be read, for too long.",
  STALE: "No trust score on the ledger for an IE for longer than expected.",
  ANCHOR_MISMATCH: "The milestones of an anchored window no longer hash to the root recorded on IOTA Rebased.",
  ANCHOR_UNVERIFIABLE: "An anchored window could not be checked against IOTA Rebased for too long.",
  SHADOW: "Confirmed on the Tangle but never received through the Messages API: written around the relay.",
  MISSING_IN_DB: "A confirmed block on the Tangle is missing from the explorer's database.",
  ORPHANED: "A submitted block never confirmed.",
  CONTENT_MISMATCH: "The Tangle holds other bytes than the Messages API received.",
  NOT_FOUND: "A submitted block is not on the Tangle.",
  DB_TAMPER: "A stored record no longer matches the Tangle.",
};
