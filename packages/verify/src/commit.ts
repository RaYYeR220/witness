/** Salted commitments to sub-score values (Python `commit`). */

import { blake2b256 } from "./blake2b.js";
import { b64urlEncode, bytesEqual, concatBytes, isBytes, utf8Encode } from "./bytes.js";
import { jcsBytes } from "./jcs.js";

export const SALT_LEN = 16;

export function newSalt(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(SALT_LEN));
}

/** base64url(BLAKE2b-256(salt || JCS(value))). Throws on a wrong salt length. */
export function commit(value: unknown, salt: Uint8Array): string {
  if (!isBytes(salt, SALT_LEN)) throw new RangeError(`salt must be ${SALT_LEN} bytes`);
  return b64urlEncode(blake2b256(concatBytes(salt, jcsBytes(value))));
}

/** False on a wrong salt length or a non-string commitment; JCS errors propagate as in Python. */
export function verifyCommitment(commitment: unknown, value: unknown, salt: Uint8Array): boolean {
  if (typeof commitment !== "string" || !isBytes(salt, SALT_LEN)) return false;
  return bytesEqual(utf8Encode(commitment), utf8Encode(commit(value, salt)));
}
