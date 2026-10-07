/** Envelope verdicts (Python `verdicts`). Alert severities belong to the explorer's rules. */

export const PRODUCER_SIGNED = "PRODUCER_SIGNED";
export const RELAY_ATTESTED = "RELAY_ATTESTED";
export const UNSIGNED_LEGACY = "UNSIGNED_LEGACY";
export const FORGED = "FORGED";
export const UNAUTHORIZED_WRITER = "UNAUTHORIZED_WRITER";
export const REPLAY = "REPLAY";
export const REVOKED_KEY = "REVOKED_KEY";
export const MALFORMED = "MALFORMED";

export type Verdict =
  | typeof PRODUCER_SIGNED
  | typeof RELAY_ATTESTED
  | typeof UNSIGNED_LEGACY
  | typeof FORGED
  | typeof UNAUTHORIZED_WRITER
  | typeof REPLAY
  | typeof REVOKED_KEY
  | typeof MALFORMED;
