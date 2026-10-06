/**
 * Ed25519 with the exact acceptance rules of the Python reference, which
 * verifies through OpenSSL: cofactorless equation, S < L, public key decoded
 * leniently (non-canonical y accepted, small-order keys not refused), R compared
 * by encoding. `@noble/curves`' own `verify` follows ZIP-215 or strict RFC 8032,
 * both of which disagree with OpenSSL on crafted inputs, so the check is
 * assembled here from its point arithmetic.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { sha512 } from "@noble/hashes/sha2";

import { bytesEqual, concatBytes, isBytes } from "./bytes.js";

/** Order of the prime-order subgroup. */
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

function numberLE(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]!);
  return n;
}

export function ed25519Verify(publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array): boolean {
  if (!isBytes(publicKey, 32) || !isBytes(signature, 64) || !isBytes(message)) return false;
  const r = signature.subarray(0, 32);
  const s = numberLE(signature.subarray(32));
  if (s >= L) return false;
  let A;
  try {
    A = ed25519.Point.fromBytes(publicKey, true);
  } catch {
    return false;
  }
  const k = numberLE(sha512(concatBytes(r, publicKey, message))) % L;
  const R = ed25519.Point.BASE.multiplyUnsafe(s).subtract(A.multiplyUnsafe(k));
  return bytesEqual(R.toBytes(), r);
}

/** Deterministic RFC 8032 signature (identical to OpenSSL's for the same seed). */
export function ed25519Sign(seed: Uint8Array, message: Uint8Array): Uint8Array {
  return ed25519.sign(message, seed);
}

export function ed25519PublicKey(seed: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(seed);
}
