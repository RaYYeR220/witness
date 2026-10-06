/**
 * Per-recipient encrypted payloads (JWE General JSON) and keyed blind-index
 * tokens. Only the suite the Python `encrypt_body` produces is accepted:
 * protected header exactly `{"enc":"A256GCM"}`, recipient `alg`
 * ECDH-ES+A256KW over X25519, no shared unprotected headers.
 */

import { x25519 } from "@noble/curves/ed25519";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import { flattenedDecrypt, importJWK } from "jose";
import type { FlattenedJWE } from "jose";

import { b64urlDecode, b64urlEncode, isBytes, isWellFormed, utf8Encode } from "./bytes.js";
import { get, has, isDict, parseJson, pyTruthy, type Json, type JsonObject } from "./json.js";

/** The JWE has no recipient entry for the given kid. */
export class NotARecipient extends Error {
  override name = "NotARecipient";

  constructor(readonly kid: string) {
    super(kid);
  }
}

/** The payload could not be decrypted or is not a JSON object. */
export class DecryptError extends Error {
  override name = "DecryptError";
}

/** OKP X25519 private JWK; `x` is optional and never trusted (derived from `d`). */
export interface X25519PrivateJwk {
  kty: string;
  crv: string;
  d: string;
  x?: string;
}

const ALG = "ECDH-ES+A256KW";
const ENC = "A256GCM";
const RECIPIENT_HEADER_KEYS = new Set(["alg", "kid", "epk"]);

function privateJwk(jwk: X25519PrivateJwk): { kty: "OKP"; crv: "X25519"; x: string; d: string } {
  const d = isDict(jwk) && jwk.kty === "OKP" && jwk.crv === "X25519" && typeof jwk.d === "string" ? b64urlDecode(jwk.d) : null;
  if (d === null || d.length !== 32) throw new TypeError("x25519PrivateJwk must be an OKP X25519 private JWK");
  return { kty: "OKP", crv: "X25519", x: b64urlEncode(x25519.getPublicKey(d)), d: b64urlEncode(d) };
}

function decodeUtf32(bytes: Uint8Array, littleEndian: boolean): string {
  if (bytes.length % 4) throw new TypeError("truncated UTF-32");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let out = "";
  for (let i = 0; i < bytes.length; i += 4) out += String.fromCodePoint(view.getUint32(i, littleEndian));
  return out;
}

/** `json.loads(bytes)`: Python sniffs UTF-8/16/32 (with or without BOM) before parsing. */
function loadsBytes(b: Uint8Array): Json {
  const starts = (...sig: number[]) => sig.every((v, i) => b[i] === v);
  const dec = (label: string, skip = 0) => new TextDecoder(label, { fatal: true, ignoreBOM: true }).decode(b.subarray(skip));
  let text: string;
  if (starts(0x00, 0x00, 0xfe, 0xff)) text = decodeUtf32(b.subarray(4), false);
  else if (starts(0xff, 0xfe, 0x00, 0x00)) text = decodeUtf32(b.subarray(4), true);
  else if (starts(0xfe, 0xff)) text = dec("utf-16be", 2);
  else if (starts(0xff, 0xfe)) text = dec("utf-16le", 2);
  else if (starts(0xef, 0xbb, 0xbf)) text = dec("utf-8", 3);
  else if (b.length >= 4 && !b[0]) text = b[1] ? dec("utf-16be") : decodeUtf32(b, false);
  else if (b.length >= 4 && !b[1]) text = b[2] || b[3] ? dec("utf-16le") : decodeUtf32(b, true);
  else if (b.length === 2 && !b[0]) text = dec("utf-16be");
  else if (b.length === 2 && !b[1]) text = dec("utf-16le");
  else text = dec("utf-8");
  return parseJson(text, { constants: true });
}

/** Only the one algorithm suite `encrypt_body` produces is accepted. */
function checkPinned(jwe: JsonObject, header: JsonObject): void {
  let protectedHeader: Json;
  try {
    const encoded = get(jwe, "protected");
    if (typeof encoded !== "string") throw new TypeError("protected is not a string");
    const raw = b64urlDecode(encoded);
    if (raw === null) throw new TypeError("protected is not base64url");
    protectedHeader = loadsBytes(raw);
  } catch {
    throw new DecryptError("invalid protected header");
  }
  const keys = isDict(protectedHeader) ? Object.keys(protectedHeader) : [];
  if (!(keys.length === 1 && keys[0] === "enc" && get(protectedHeader as JsonObject, "enc") === ENC)) {
    throw new DecryptError("unsupported protected header");
  }
  if (pyTruthy(get(jwe, "unprotected")) || pyTruthy(get(jwe, "header"))) throw new DecryptError("unexpected shared header");
  if (get(header, "alg") !== ALG || Object.keys(header).some((k) => !RECIPIENT_HEADER_KEYS.has(k))) {
    throw new DecryptError("unsupported recipient header");
  }
}

/**
 * Decrypt the body addressed to `kid` (Python `sealed.decrypt_body`).
 * Rejects with `NotARecipient` or `DecryptError`; a malformed key is a TypeError.
 */
export async function decryptBody(jwe: unknown, kid: string, x25519PrivateJwk: X25519PrivateJwk): Promise<JsonObject> {
  const keyJwk = privateJwk(x25519PrivateJwk);
  if (!isDict(jwe)) throw new DecryptError("not a general JWE");
  const entries = get(jwe, "recipients");
  if (!Array.isArray(entries)) throw new DecryptError("not a general JWE");
  const mine = entries.filter(
    (r): r is JsonObject => isDict(r) && isDict(get(r, "header")) && get(get(r, "header") as JsonObject, "kid") === kid,
  );
  const entry = mine[0];
  if (entry === undefined) throw new NotARecipient(kid);
  const header = entry.header as JsonObject;
  checkPinned(jwe, header);
  let body: Json;
  try {
    // A falsy shared header got past the pin. The reference merges it into the
    // header dict, which works for an empty object, list or string and fails for
    // null, 0 or false; it carries nothing either way, so it is not passed on.
    if (has(jwe, "unprotected")) {
      const u = jwe.unprotected;
      const empty = u === "" || (Array.isArray(u) && u.length === 0) || (isDict(u) && Object.keys(u).length === 0);
      if (!empty) throw new DecryptError("unusable shared header");
    }
    // Only this recipient's entry, so other recipients' entries cannot interfere.
    const single: Record<string, unknown> = { header };
    for (const k of ["protected", "iv", "ciphertext", "tag", "aad"]) {
      if (has(jwe, k)) single[k] = jwe[k];
    }
    if (has(entry, "encrypted_key")) single.encrypted_key = entry.encrypted_key;
    const key = await importJWK(keyJwk, ALG);
    const { plaintext } = await flattenedDecrypt(single as unknown as FlattenedJWE, key, {
      keyManagementAlgorithms: [ALG],
      contentEncryptionAlgorithms: [ENC],
    });
    body = loadsBytes(plaintext);
  } catch {
    throw new DecryptError("decryption failed");
  }
  if (!isDict(body)) throw new DecryptError("payload is not a JSON object");
  return body;
}

/** Keyed blind-index token: base64url(HMAC-SHA256(key, "<kind>:<value>")). */
export function blindToken(searchKey: Uint8Array, kind: "ie" | "tag", value: string): string {
  if (kind !== "ie" && kind !== "tag") throw new RangeError("kind must be 'ie' or 'tag'");
  if (!isBytes(searchKey) || searchKey.length === 0) throw new RangeError("search_key must not be empty");
  const message = `${kind}:${value}`;
  if (!isWellFormed(message)) throw new TypeError("value is not encodable as UTF-8");
  return b64urlEncode(hmac(sha256, searchKey, utf8Encode(message)));
}
