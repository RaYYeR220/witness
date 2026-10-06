import { describe, expect, it } from "vitest";

import { fromHex, toHex } from "../src/bytes.js";
import { auditPath, blake2b256, leafHash, merkleRoot, nodeHash, verifyPath } from "../src/index.js";
import type { PathStep } from "../src/index.js";
import { cones, milestones } from "./vectors.js";

const synth = (n: number) => Array.from({ length: n }, (_, i) => blake2b256(Uint8Array.of(i % 256, i >> 8)));
const flip = (b: Uint8Array) => Uint8Array.of(b[0]! ^ 1, ...b.slice(1));

describe("cones.json parity", () => {
  it.each(cones.map((c) => [c.index, c] as const))("milestone %i inclusion root", (index, cone) => {
    const values = cone.blockIdsWhiteFlagOrder.map(fromHex);
    const m = milestones.find((x) => x.index === index);
    expect(toHex(merkleRoot(values))).toBe(m.inclusionMerkleRoot);
    const root = merkleRoot(values);
    values.forEach((v: Uint8Array, i: number) => expect(verifyPath(v, auditPath(values, i), root)).toBe(true));
  });
});

describe("tree shape (Python reference values)", () => {
  it("roots", () => {
    expect(toHex(merkleRoot(synth(7)))).toBe("0x5b97035c7eecdbcfc19ed57019df949355b03f0a285a6957573815f1c8369cd9");
    expect(toHex(merkleRoot([]))).toBe("0x0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8");
    expect(toHex(merkleRoot(synth(1)))).toBe("0x35ae2c72e36672f319c4612bfc2061f1f867cbe6a1f9705d93b645ffdee45d75");
  });

  it("hand-computed shapes", () => {
    const v = synth(7);
    const l = v.map(leafHash);
    const N = nodeHash;
    expect(merkleRoot(v.slice(0, 3))).toEqual(N(N(l[0]!, l[1]!), l[2]!));
    expect(merkleRoot(v.slice(0, 5))).toEqual(N(N(N(l[0]!, l[1]!), N(l[2]!, l[3]!)), l[4]!));
    expect(merkleRoot(v)).toEqual(N(N(N(l[0]!, l[1]!), N(l[2]!, l[3]!)), N(N(l[4]!, l[5]!), l[6]!)));
    expect(auditPath(v.slice(0, 3), 0)).toEqual([
      { side: "R", hash: l[1] },
      { side: "R", hash: l[2] },
    ]);
    expect(auditPath(v, 4).map((s) => [s.side, toHex(s.hash).slice(0, 10)])).toEqual([
      ["R", "0xaad31645"],
      ["R", "0x65397900"],
      ["L", "0x1d45b338"],
    ]);
  });

  it("every leaf of many sizes verifies", () => {
    for (const n of [1, 2, 3, 5, 8, 13, 33]) {
      const v = synth(n);
      const r = merkleRoot(v);
      for (let i = 0; i < n; i++) expect(verifyPath(v[i], auditPath(v, i), r)).toBe(true);
    }
  });

  it("auditPath rejects out-of-range indexes", () => {
    expect(() => auditPath(synth(3), 3)).toThrow(RangeError);
    expect(() => auditPath([], 0)).toThrow(RangeError);
    expect(() => auditPath(synth(3), -1)).toThrow(RangeError);
  });
});

describe("verifyPath negatives", () => {
  const v = synth(7);
  const r = merkleRoot(v);
  const path = auditPath(v, 4);

  it("flipped or swapped steps fail", () => {
    path.forEach((step, j) => {
      const bad = path.map((s, k): PathStep => (k === j ? { side: s.side, hash: flip(s.hash) } : s));
      expect(verifyPath(v[4], bad, r)).toBe(false);
      const swapped = path.map((s, k): PathStep => (k === j ? { side: s.side === "L" ? "R" : "L", hash: s.hash } : s));
      expect(verifyPath(v[4], swapped, r)).toBe(false);
    });
    expect(verifyPath(flip(v[4]!), path, r)).toBe(false);
  });

  it("never throws on junk", () => {
    const junk: unknown[] = [null, undefined, 5, "x", {}, [], [null], [{ side: "X", hash: v[0] }], [{ side: "L" }]];
    for (const j of junk) {
      expect(verifyPath(v[4], j, r)).toBe(false);
      expect(verifyPath(j, path, r)).toBe(false);
      expect(verifyPath(v[4], path, j)).toBe(false);
    }
    expect(verifyPath(v[4]!.slice(0, 31), path, r)).toBe(false);
  });
});
