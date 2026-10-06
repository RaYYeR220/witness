// Pure helpers for did:iota documents as they are stored on IOTA Rebased. No network access here.

import { PY_JSON_MAX_DEPTH, textTooDeep } from "@witness/verify";

export class InvalidDidError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidDidError";
  }
}

export class DidDecodeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DidDecodeError";
  }
}

export interface ParsedDid {
  did: string;
  /** Network segment, or null when the DID omits it (IOTA mainnet). */
  network: string | null;
  objectId: string;
}

// Network names are at most 8 characters: an alias ("testnet") or a chain id ("2304aa97").
const DID_RE = /^did:iota:(?:([a-z0-9]{1,8}):)?(0x[0-9a-fA-F]{64})$/;

export function parseDid(input: string): ParsedDid {
  const m = DID_RE.exec(input);
  if (!m) throw new InvalidDidError("not a did:iota DID");
  const network = m[1] ?? null;
  const objectId = m[2]!.toLowerCase();
  return { did: `did:iota:${network ? `${network}:` : ""}${objectId}`, network, objectId };
}

/** Placeholder DID that the Identity package stores in place of the real one. */
export const DID_PLACEHOLDER = "did:0:0";

/**
 * Decodes the `controlled_value` bytes of an on-chain Identity:
 * `"DID"` | version u8 (1) | encoding u8 (0 = JSON) | length u16 LE | JSON `{doc, meta}`.
 * Returns null for an empty value (a deleted or never-set document).
 */
export function decodeStateMetadata(bytes: Uint8Array | readonly number[] | null | undefined): { doc: unknown; meta: unknown } | null {
  if (bytes == null || bytes.length === 0) return null;
  const b = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  if (b.length < 7 || b[0] !== 0x44 || b[1] !== 0x49 || b[2] !== 0x44) throw new DidDecodeError("missing DID marker");
  if (b[3] !== 1) throw new DidDecodeError(`unsupported document version ${b[3]}`);
  if (b[4] !== 0) throw new DidDecodeError(`unsupported document encoding ${b[4]}`);
  const len = b[5]! | (b[6]! << 8);
  if (7 + len > b.length) throw new DidDecodeError("document length exceeds the stored bytes");
  let text: string;
  let parsed: unknown;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(b.subarray(7, 7 + len));
  } catch {
    throw new DidDecodeError("document is not valid UTF-8 JSON");
  }
  // Untrusted on-chain bytes: the nesting cap every other entry point applies, before
  // JSON.parse and the recursive walks that follow it (withRealDid).
  if (textTooDeep(text)) throw new DidDecodeError(`document is JSON nested deeper than ${PY_JSON_MAX_DEPTH} levels`);
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new DidDecodeError("document is not valid UTF-8 JSON");
  }
  if (typeof parsed !== "object" || parsed === null || !("doc" in parsed)) throw new DidDecodeError("document has no doc field");
  const { doc, meta } = parsed as { doc: unknown; meta?: unknown };
  return { doc, meta: meta ?? {} };
}

/** Replaces the placeholder DID (also inside DID URLs) with the real one, everywhere in a JSON value. */
export function withRealDid<T>(value: T, did: string): T {
  const swap = (s: string): string =>
    s === DID_PLACEHOLDER || s.startsWith(`${DID_PLACEHOLDER}#`) || s.startsWith(`${DID_PLACEHOLDER}?`) || s.startsWith(`${DID_PLACEHOLDER}/`)
      ? did + s.slice(DID_PLACEHOLDER.length)
      : s;
  const walk = (v: unknown): unknown => {
    if (typeof v === "string") return swap(v);
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, walk(x)]));
    return v;
  };
  return walk(value) as T;
}

export interface PublicJwk {
  kty: string;
  crv?: string;
  x?: string;
  [k: string]: unknown;
}

export interface MethodJson {
  id: string;
  type?: string;
  controller?: string;
  publicKeyJwk?: PublicJwk;
  publicKeyMultibase?: string;
  [k: string]: unknown;
}

export interface DidDocumentJson {
  id: string;
  verificationMethod?: MethodJson[];
  [k: string]: unknown;
}

export const RELATIONSHIPS = [
  "authentication",
  "assertionMethod",
  "keyAgreement",
  "capabilityInvocation",
  "capabilityDelegation",
] as const;

function isMethod(v: unknown): v is MethodJson {
  return typeof v === "object" && v !== null && typeof (v as { id?: unknown }).id === "string";
}

/** Every method a document defines, keyed by its full DID URL: top-level and embedded in relationships. */
export function collectMethods(doc: unknown): Map<string, MethodJson> {
  const out = new Map<string, MethodJson>();
  if (typeof doc !== "object" || doc === null) return out;
  const d = doc as Record<string, unknown>;
  const lists = [d.verificationMethod, ...RELATIONSHIPS.map((r) => d[r])];
  for (const list of lists) {
    if (!Array.isArray(list)) continue;
    for (const entry of list) if (isMethod(entry) && !out.has(entry.id)) out.set(entry.id, entry);
  }
  return out;
}

/**
 * Identity of a method for history comparison: its id plus its public key material. A key
 * replaced in place under the same id counts as a different method, so the old key is revoked.
 */
export function methodIdentity(kid: string, method: MethodJson): string {
  const jwk = method.publicKeyJwk;
  const material = jwk
    ? ["jwk", jwk.kty, jwk.crv, jwk.x, jwk.y, jwk.n, jwk.e].map((v) => (typeof v === "string" ? v : "")).join(":")
    : typeof method.publicKeyMultibase === "string"
      ? `multibase:${method.publicKeyMultibase}`
      : `type:${method.type ?? ""}`;
  return `${kid}\n${material}`;
}

export type KeyType = "Ed25519" | "X25519";

/** Extracts a raw OKP public key from a JWK-based method. Other key formats yield null. */
export function methodPublicKey(method: MethodJson): { type: KeyType; publicKeyHex: string } | null {
  const jwk = method.publicKeyJwk;
  if (!jwk || jwk.kty !== "OKP" || typeof jwk.x !== "string") return null;
  if (jwk.crv !== "Ed25519" && jwk.crv !== "X25519") return null;
  if (!/^[A-Za-z0-9_-]+$/.test(jwk.x)) return null;
  const raw = Buffer.from(jwk.x, "base64url");
  if (raw.length !== 32) return null;
  return { type: jwk.crv, publicKeyHex: raw.toString("hex") };
}
