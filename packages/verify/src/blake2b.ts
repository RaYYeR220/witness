import { blake2b } from "@noble/hashes/blake2b";

/** BLAKE2b with a 32-byte digest: block ids, milestone ids, Merkle nodes. */
export function blake2b256(data: Uint8Array): Uint8Array {
  return blake2b(data, { dkLen: 32 });
}
