/** RFC 8785 (JCS) canonicalization with the domain rules of the Python `rfc8785` package. */

import canonicalizeImport from "canonicalize";

import { blake2b256 } from "./blake2b.js";
import { isWellFormed, utf8Encode } from "./bytes.js";
import { isDict, JsonNumber, MAX_UINT, RecursionError } from "./json.js";

type Serialize = (input: unknown) => string | undefined;
// `canonicalize` is CommonJS; depending on the loader the default import is the
// function itself or a namespace wrapping it.
const imported = canonicalizeImport as unknown as Serialize | { default: Serialize };
const serialize: Serialize = typeof imported === "function" ? imported : imported.default;

/** The value cannot be canonicalized (NaN/Infinity, unsafe integer, lone surrogate, non-JSON type). */
export class CanonicalizationError extends Error {
  override name = "CanonicalizationError";
}

/**
 * Deepest value `jcs` accepts (the top value is at depth 0), shared with the
 * Python reference (`witness_core.nesting.MAX_JCS_DEPTH`). The reference
 * serializer (`rfc8785`) recurses one Python frame per level under CPython's
 * 1000-frame limit, so on its own it would give up at a depth that depends on
 * its caller's stack; both sides check this fixed cap first instead. Deeper
 * values raise `RecursionError`.
 */
export const JCS_MAX_DEPTH = 500;

/** True when any value inside `value` sits deeper than `limit` (Python `nesting.value_too_deep`). */
function valueTooDeep(value: unknown, limit: number): boolean {
  const stack: [unknown, number][] = [[value, 0]];
  while (stack.length > 0) {
    const [v, depth] = stack.pop()!;
    if (depth > limit) return true;
    if (Array.isArray(v)) for (const x of v) stack.push([x, depth + 1]);
    else if (isDict(v)) for (const key of Object.keys(v)) stack.push([v[key], depth + 1]);
  }
  return false;
}

function floatName(f: number): string {
  return Number.isNaN(f) ? "nan" : f > 0 ? "inf" : "-inf";
}

/**
 * Validate against the I-JSON domain and rebuild as plain data. Integral numbers
 * beyond ±(2^53 - 1) are integers to Python and rejected; parse with
 * `parseJson` to keep float literals such as `1e300` serializable.
 */
function prepare(v: unknown, depth = 0): unknown {
  if (depth > JCS_MAX_DEPTH) throw new RecursionError("maximum recursion depth exceeded while canonicalizing");
  if (v === null || typeof v === "boolean") return v;
  if (typeof v === "string") {
    if (!isWellFormed(v)) throw new CanonicalizationError("input contains non-UTF-8 codepoints");
    return v;
  }
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new CanonicalizationError(`${floatName(v)} is not representable in JCS`);
    if (Number.isInteger(v) && Math.abs(v) > MAX_UINT) {
      throw new CanonicalizationError(`${BigInt(v)} exceeds safe integer domain for JSON floats`);
    }
    return v;
  }
  if (v instanceof JsonNumber) {
    if (v.kind === "int") throw new CanonicalizationError(`${v.literal} exceeds safe integer domain for JSON floats`);
    if (!Number.isFinite(v.value)) throw new CanonicalizationError(`${floatName(v.value)} is not representable in JCS`);
    return v.value;
  }
  if (Array.isArray(v)) return v.map((x) => prepare(x, depth + 1));
  if (isDict(v)) {
    const out: Record<string, unknown> = Object.create(null);
    for (const key of Object.keys(v)) {
      if (!isWellFormed(key)) throw new CanonicalizationError("input contains non-UTF-8 codepoints");
      out[key] = prepare(v[key], depth + 1);
    }
    return out;
  }
  throw new CanonicalizationError(`unsupported type: ${v === undefined ? "undefined" : typeof v}`);
}

/** Canonical JSON text of `value` (RFC 8785). Throws `CanonicalizationError`, or `RecursionError` when nested too deep. */
export function jcs(value: unknown): string {
  // Depth first, as the reference does, so the error does not depend on key order.
  if (valueTooDeep(value, JCS_MAX_DEPTH)) throw new RecursionError("maximum recursion depth exceeded while canonicalizing");
  return serialize(prepare(value))!;
}

/** UTF-8 bytes of `jcs(value)`: what signatures and hashes cover. */
export function jcsBytes(value: unknown): Uint8Array {
  return utf8Encode(jcs(value));
}

/** BLAKE2b-256 of the canonical form (Python `canon.canon_hash`). */
export function canonHash(value: unknown): Uint8Array {
  return blake2b256(jcsBytes(value));
}
