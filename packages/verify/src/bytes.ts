/** Byte helpers: hex, base64url, UTF-8. Plain Uint8Array only, so they run in any JS runtime. */

const HEX_DIGITS = "0123456789abcdef";

/** `0x`-prefixed lowercase hex, as the Python reference's `to_hex`. */
export function toHex(bytes: Uint8Array): string {
  let out = "0x";
  for (const b of bytes) out += HEX_DIGITS[b >> 4]! + HEX_DIGITS[b & 15]!;
  return out;
}

/**
 * Lenient hex decode matching Python `ids.from_hex`: optional `0x`/`0X`
 * prefix, either case, even length. Throws on anything else.
 */
export function fromHex(s: string): Uint8Array {
  const body = s.startsWith("0x") || s.startsWith("0X") ? s.slice(2) : s;
  if (!/^[0-9a-fA-F]*$/.test(body)) throw new TypeError(`invalid hex string: ${JSON.stringify(s)}`);
  if (body.length % 2) throw new TypeError(`odd-length hex string: ${JSON.stringify(s)}`);
  const out = new Uint8Array(body.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(body.slice(2 * i, 2 * i + 2), 16);
  return out;
}

const CANON_HEX = /^0x(?:[0-9a-f]{2})*$/;

/** True for the exact form `toHex` emits: `0x` + lowercase pairs. */
export function isCanonicalHex(s: string): boolean {
  return CANON_HEX.test(s);
}

const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B64URL_INDEX = new Map([...B64URL].map((c, i) => [c, i] as const));

/** Unpadded base64url. */
export function b64urlEncode(bytes: Uint8Array): string {
  let out = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out += B64URL[n >> 18]! + B64URL[(n >> 12) & 63]! + B64URL[(n >> 6) & 63]! + B64URL[n & 63]!;
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i]! << 16;
    out += B64URL[n >> 18]! + B64URL[(n >> 12) & 63]!;
  } else if (rest === 2) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8);
    out += B64URL[n >> 18]! + B64URL[(n >> 12) & 63]! + B64URL[(n >> 6) & 63]!;
  }
  return out;
}

/**
 * Decode unpadded base64url (up to two trailing `=` tolerated). Returns null
 * on characters outside the alphabet or an impossible length. Leftover bits are
 * ignored, so callers that need the canonical form re-encode and compare.
 */
export function b64urlDecode(s: string): Uint8Array | null {
  const body = s.replace(/={1,2}$/, "");
  if (body.length % 4 === 1) return null;
  const out = new Uint8Array(Math.floor((body.length * 3) / 4));
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (const c of body) {
    const v = B64URL_INDEX.get(c);
    if (v === undefined) return null;
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  return out;
}

export function utf8Encode(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

/** Strict UTF-8 decode (throws on invalid input, keeps a leading BOM). */
export function utf8DecodeStrict(bytes: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
}

/** True unless the string holds a lone surrogate (Python cannot UTF-8-encode those). */
export function isWellFormed(s: string): boolean {
  return !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(s);
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** Length-checked comparison that does not short-circuit on content. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/**
 * Uint8Array check that also accepts arrays from another realm (iframes,
 * jsdom's TextEncoder), where `instanceof` alone gives false negatives.
 */
export function isBytes(v: unknown, length?: number): v is Uint8Array {
  const ok = v instanceof Uint8Array || (ArrayBuffer.isView(v) && v.constructor?.name === "Uint8Array");
  return ok && (length === undefined || (v as Uint8Array).length === length);
}
