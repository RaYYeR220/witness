/**
 * Signed `witness/v1` envelopes carried in IOTA tagged-data payloads.
 *
 * The signature is Ed25519 over the JCS form of the envelope without `sig`.
 * `verifyEnvelope` is signature-level only; policy, replay and revocation
 * checks belong to callers.
 */

import { b64urlDecode, b64urlEncode, isBytes } from "./bytes.js";
import { ed25519Sign, ed25519Verify, isWeakPublicKey } from "./ed25519.js";
import { CanonicalizationError, jcsBytes } from "./jcs.js";
import { get, has, isDict, isUint, type Json, type JsonObject } from "./json.js";
import { FORGED, MALFORMED, PRODUCER_SIGNED, RELAY_ATTESTED, type Verdict } from "./verdicts.js";

export interface KeyInfo {
  kid: string;
  ed25519Public: Uint8Array | null;
  x25519Public: Uint8Array | null;
  revokedAtMs: number | null;
}

export type KeyResolver = (kid: string) => KeyInfo | null | undefined;

export interface EnvelopeCheck {
  verdict: Verdict;
  iss: string | null;
  kid: string | null;
  seq: number | null;
  iat: number | null;
  reason: string | null;
  prev: string | null;
  corr: string | null;
}

export type Envelope = JsonObject;

const SIG_RE = /^[A-Za-z0-9_-]{86}$/;
const NONCE_RE = /^[A-Za-z0-9_-]{22}$/;
const PREV_RE = /^0x[0-9a-f]{64}$/;
const KEYS = new Set(["w", "tag", "iss", "kid", "seq", "iat", "nonce", "att", "body", "enc", "bix", "cmt", "prev", "corr", "sig"]);

/** Decode strict unpadded base64url; null unless `s` is the canonical encoding. */
function canonicalB64(s: unknown, pattern: RegExp): Uint8Array | null {
  if (typeof s !== "string" || !pattern.test(s)) return null;
  const raw = b64urlDecode(s);
  return raw !== null && b64urlEncode(raw) === s ? raw : null;
}

function signingInput(env: JsonObject): Uint8Array {
  const unsigned: JsonObject = {};
  for (const key of Object.keys(env)) {
    if (key !== "sig") Object.defineProperty(unsigned, key, { value: env[key], enumerable: true, writable: true, configurable: true });
  }
  return jcsBytes(unsigned);
}

/** A JSON object with `w: 1` (an int, not `1.0`) and a string `sig`. */
export function isEnvelope(obj: unknown): obj is Envelope {
  return isDict(obj) && get(obj, "w") === 1 && typeof get(obj, "sig") === "string";
}

function malformed(reason: string): EnvelopeCheck {
  return { verdict: MALFORMED, iss: null, kid: null, seq: null, iat: null, reason, prev: null, corr: null };
}

/** Describe the first structural problem, or null. */
function shapeError(env: unknown): string | null {
  if (!isEnvelope(env)) return "not a witness/v1 envelope";
  if (Object.keys(env).some((k) => !KEYS.has(k))) return "unknown top-level field";
  for (const name of ["tag", "iss", "kid"]) {
    if (typeof get(env, name) !== "string") return `missing or invalid field: ${name}`;
  }
  if (!isUint(get(env, "seq")) || !isUint(get(env, "iat"))) return "missing or invalid field: seq/iat";
  if (canonicalB64(get(env, "nonce"), NONCE_RE) === null) return "invalid nonce encoding";
  if (canonicalB64(env.sig, SIG_RE) === null) return "invalid sig encoding";
  const att = get(env, "att");
  const mode = isDict(att) ? get(att, "mode") : undefined;
  if (!isDict(att) || (mode !== "producer" && mode !== "relay")) return "missing or invalid field: att";
  const sub = get(att, "sub");
  if (mode === "relay" && !(typeof sub === "string" && sub)) return "relay attestation requires att.sub";
  if (has(att, "sub") && typeof sub !== "string") return "invalid field: att.sub";
  if (has(env, "body") === has(env, "enc")) return "exactly one of body or enc is required";
  if (has(env, "body") && env.body !== null && !isDict(env.body)) return "invalid field: body";
  if (has(env, "enc") && !isDict(env.enc)) return "invalid field: enc";
  if (has(env, "bix") && !(Array.isArray(env.bix) && env.bix.every((x) => typeof x === "string"))) {
    return "invalid field: bix";
  }
  if (has(env, "cmt") && !(isDict(env.cmt) && Object.values(env.cmt).every((v) => typeof v === "string"))) {
    return "invalid field: cmt";
  }
  if (has(env, "prev") && !(typeof env.prev === "string" && PREV_RE.test(env.prev))) return "invalid field: prev";
  if (has(env, "corr") && typeof env.corr !== "string") return "invalid field: corr";
  return null;
}

/** Check structure, tag binding, key resolution and signature. */
export function verifyEnvelope(env: unknown, blockTag: string, resolve: KeyResolver): EnvelopeCheck {
  const problem = shapeError(env);
  if (problem !== null) return malformed(problem);
  const e = env as Envelope;
  let input: Uint8Array;
  try {
    input = signingInput(e);
  } catch (err) {
    if (err instanceof CanonicalizationError) return malformed(`not canonicalizable: ${err.message}`);
    throw err;
  }

  const iss = e.iss as string;
  const kid = e.kid as string;
  const result = (verdict: Verdict, reason: string | null = null): EnvelopeCheck => ({
    verdict,
    iss,
    kid,
    seq: e.seq as number,
    iat: e.iat as number,
    reason,
    prev: has(e, "prev") ? (e.prev as string) : null,
    corr: has(e, "corr") ? (e.corr as string) : null,
  });

  if (e.tag !== blockTag) return result(FORGED, "envelope tag does not match block tag");
  if (kid.split("#")[0] !== iss) return result(FORGED, "kid does not belong to iss");
  const info = resolve(kid);
  if (!info || !isBytes(info.ed25519Public)) return result(FORGED, "signing key not resolvable");
  if (isWeakPublicKey(info.ed25519Public)) return result(FORGED, "weak public key");
  if (!ed25519Verify(info.ed25519Public, canonicalB64(e.sig, SIG_RE)!, input)) {
    return result(FORGED, "signature invalid");
  }
  return result(get(e.att as JsonObject, "mode") === "producer" ? PRODUCER_SIGNED : RELAY_ATTESTED);
}

// ---------------------------------------------------------------- sealing

/** OKP Ed25519 private JWK, as the anchor service stores signing keys. */
export interface Ed25519PrivateJwk {
  kty: string;
  crv: string;
  d: string;
  x?: string;
}

export interface SealOptions {
  iss: string;
  kid: string;
  /** 32-byte Ed25519 seed or an OKP Ed25519 private JWK. */
  signKey: Uint8Array | Ed25519PrivateJwk;
  seq: number;
  attMode: "producer" | "relay";
  attSub?: string | null;
  enc?: JsonObject | null;
  bix?: string[] | null;
  cmt?: Record<string, string> | null;
  nowMs?: number | null;
  nonce?: Uint8Array | null;
  prev?: string | null;
  corr?: string | null;
}

function seedOf(key: Uint8Array | Ed25519PrivateJwk): Uint8Array {
  if (isBytes(key)) {
    if (key.length !== 32) throw new TypeError("signKey must be a 32-byte Ed25519 seed");
    return key;
  }
  if (!isDict(key) || key.kty !== "OKP" || key.crv !== "Ed25519" || typeof key.d !== "string") {
    throw new TypeError("signKey must be a 32-byte seed or an OKP Ed25519 private JWK");
  }
  const seed = b64urlDecode(key.d);
  if (seed === null || seed.length !== 32) throw new TypeError("signKey JWK has an invalid d");
  return seed;
}

function randomNonce(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(16));
}

const present = <T>(v: T | null | undefined): v is T => v !== null && v !== undefined;

/** Build and sign an envelope for `tag` (Python `envelope.seal`). */
export function sealEnvelope(tag: string, body: JsonObject | null, opts: SealOptions): Envelope {
  const att: JsonObject = { mode: opts.attMode };
  if (present(opts.attSub)) att.sub = opts.attSub;
  if (present(opts.enc) && body !== null) throw new RangeError("envelope carries either body or enc, not both");
  if (!isUint(opts.seq)) throw new RangeError("seq must be an integer in [0, 2^53-1]");
  const iat = present(opts.nowMs) ? opts.nowMs : Date.now();
  if (!isUint(iat)) throw new RangeError("iat must be an integer in [0, 2^53-1]");
  if (present(opts.nonce) && opts.nonce.length !== 16) throw new RangeError("nonce must be 16 bytes");
  const seed = seedOf(opts.signKey);
  const env: JsonObject = {
    w: 1,
    tag,
    iss: opts.iss,
    kid: opts.kid,
    seq: opts.seq,
    iat,
    nonce: b64urlEncode(present(opts.nonce) ? opts.nonce : randomNonce()),
    att,
  };
  if (!present(opts.enc)) env.body = body as Json;
  if (present(opts.enc)) env.enc = opts.enc;
  if (present(opts.bix)) env.bix = opts.bix;
  if (present(opts.cmt)) env.cmt = opts.cmt;
  if (present(opts.prev)) env.prev = opts.prev;
  if (present(opts.corr)) env.corr = opts.corr;
  env.sig = b64urlEncode(ed25519Sign(seed, signingInput(env)));
  return env;
}
