import { ED25519_TORSION_SUBGROUP, ed25519 } from "@noble/curves/ed25519";
import { sha512 } from "@noble/hashes/sha2";
import { describe, expect, it } from "vitest";

import { concatBytes } from "../src/bytes.js";
import { ed25519Verify, isWeakPublicKey } from "../src/index.js";

// The Python reference verifies through OpenSSL (cofactorless equation, S < L)
// after refusing weak keys. These cases were cross-checked against
// cryptography 50 / OpenSSL 4 and pin that behaviour here.
const P = ed25519.Point;
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const p = 2n ** 255n - 19n;
const le = (n: bigint) => Uint8Array.from({ length: 32 }, (_, i) => Number((n >> BigInt(8 * i)) & 0xffn));
const num = (b: Uint8Array) => b.reduceRight((n, x) => (n << 8n) | BigInt(x), 0n);
const utf8 = (s: string) => new TextEncoder().encode(s);
const IDENTITY = le(1n);

describe("ed25519Verify follows OpenSSL", () => {
  it("accepts honest signatures and rejects tampering", () => {
    const seed = new Uint8Array(32).fill(9);
    const msg = utf8("honest");
    const sig = ed25519.sign(msg, seed);
    const pk = ed25519.getPublicKey(seed);
    expect(ed25519Verify(pk, sig, msg)).toBe(true);
    expect(ed25519Verify(pk, sig, utf8("other"))).toBe(false);
    expect(ed25519Verify(pk, concatBytes(sig.slice(0, 32), le(num(sig.slice(32)) + L)), msg)).toBe(false);
    const mixedR = P.fromHex(sig.slice(0, 32)).add(P.fromHex(ED25519_TORSION_SUBGROUP[1]!)).toBytes();
    expect(ed25519Verify(pk, concatBytes(mixedR, sig.slice(32)), msg)).toBe(false);
    expect(ed25519Verify(pk.slice(0, 31), sig, msg)).toBe(false);
    expect(ed25519Verify(pk, sig.slice(0, 63), msg)).toBe(false);
  });

  it("uses the cofactorless equation for keys with a torsion component", () => {
    const a = 123456789n;
    let accepted = 0;
    let rejected = 0;
    ED25519_TORSION_SUBGROUP.forEach((th, ti) => {
      const T = P.fromHex(th);
      const pk = P.BASE.multiply(a).add(T).toBytes();
      for (let m = 0; m < 6; m++) {
        const msg = utf8(`torsion ${ti} msg ${m}`);
        const R = P.BASE.multiply(1000n + BigInt(m)).toBytes();
        const k = num(sha512(concatBytes(R, pk, msg))) % L;
        const sig = concatBytes(R, le((1000n + BigInt(m) + k * a) % L));
        // Valid under [S]B = R + [k]A' only when [k]T vanishes.
        const expected = T.multiplyUnsafe(k).equals(P.ZERO);
        expect(ed25519Verify(pk, sig, utf8(`torsion ${ti} msg ${m}`))).toBe(expected);
        if (expected) accepted++;
        else rejected++;
      }
    });
    expect(accepted).toBeGreaterThan(0);
    expect(rejected).toBeGreaterThan(0);
  });

  it("refuses weak keys: small order, or not strictly encoded (OpenSSL alone accepts them)", () => {
    const anything = utf8("anything");
    const zeroSig = concatBytes(IDENTITY, le(0n));
    const torsion = ED25519_TORSION_SUBGROUP.map((h) => P.fromHex(h).toBytes());
    // Non-canonical encodings of small-order points: y >= p, and x = 0 with the sign bit set.
    const aliases = [le(p + 1n), le(1n | (1n << 255n)), le(p), le(p - 1n | (1n << 255n))];
    for (const pk of [...torsion, ...aliases]) {
      expect(isWeakPublicKey(pk)).toBe(true);
      expect(ed25519Verify(pk, zeroSig, anything)).toBe(false);
    }
    expect(torsion).toHaveLength(8);
    expect(isWeakPublicKey(le(2n))).toBe(true); // y = 2 is not on the curve
    expect(isWeakPublicKey(le(3n))).toBe(false); // y = 3 is, with large order...
    expect(isWeakPublicKey(le(p + 3n))).toBe(true); // ...but y = p + 3 does not decode strictly
    expect(isWeakPublicKey(new Uint8Array(31))).toBe(true);
    const pk = ed25519.getPublicKey(new Uint8Array(32).fill(9));
    expect(isWeakPublicKey(pk)).toBe(false);
    // A key with a torsion component is not of small order: it stays usable.
    const mixed = P.fromHex(pk).add(P.fromHex(ED25519_TORSION_SUBGROUP[1]!)).toBytes();
    expect(isWeakPublicKey(mixed)).toBe(false);
  });
});
