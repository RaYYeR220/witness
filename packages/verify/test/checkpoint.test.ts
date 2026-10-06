import { describe, expect, it } from "vitest";

import { fromHex, toHex } from "../src/bytes.js";
import {
  blake2b256,
  buildCheckpoint,
  canonHash,
  checkpointHash,
  checkpointShapeError,
  JsonNumber,
  membershipPath,
  merkleRoot,
  verifyPath,
} from "../src/index.js";
import type { BuildCheckpointInput } from "../src/index.js";
import { milestones } from "./vectors.js";

const ids = milestones.map((m) => fromHex(m.milestoneId));
const fill = (b: number) => new Uint8Array(32).fill(b);

function input(over: Partial<BuildCheckpointInput> = {}): BuildCheckpointInput {
  return {
    network: "private_tangle1",
    domain: "MyDomain",
    from: { index: 370, id: ids[0]! },
    to: { index: 373, id: ids[3]! },
    milestoneIds: ids,
    msgCount: 11,
    policyHash: new Uint8Array(32),
    prevHash: null,
    ...over,
  };
}

describe("buildCheckpoint / checkpointHash (Python reference values)", () => {
  it("builds the same checkpoint and hash as checkpoint.build", () => {
    const cp = buildCheckpoint(input());
    expect(cp).toEqual({
      v: 1,
      kind: "witness.checkpoint",
      network: "private_tangle1",
      domain: "MyDomain",
      from: { index: 370, id: "0x1f67cff6cf5b3978edd0188960acc4b1ef34c8349fe7b3da5d57dac9ec5d7745" },
      to: { index: 373, id: "0x62080b3856ac88aefba69a8534dcc1191132b7589338138bb222934b7d8701ac" },
      msRoot: "0xbdd5ad67fdf2010c667060fd02ef81beb8ce4c26ce40d0cec66d872c75920ff6",
      msgCount: 11,
      policyHash: `0x${"00".repeat(32)}`,
      prev: null,
    });
    expect(toHex(checkpointHash(cp))).toBe("0x53f0efec694b315320d93f5a1ea8a32adbf11fb442d31b533d91d401e1074590");
    const linked = buildCheckpoint(input({ policyHash: fill(1), prevHash: fill(2) }));
    expect(toHex(checkpointHash(linked))).toBe("0x75be77fd36497b92005fff68ff1d633e466964769aa6adf9e0630a0f45a83001");
    expect(checkpointShapeError(cp)).toBeNull();
  });

  it("msRoot matches an independent oracle and the hash is key-order free", () => {
    const leaves = ids.map((i) => blake2b256(Uint8Array.of(0, ...i)));
    const node = (l: Uint8Array, r: Uint8Array) => blake2b256(Uint8Array.of(1, ...l, ...r));
    const cp = buildCheckpoint(input());
    expect(cp.msRoot).toBe(toHex(node(node(leaves[0]!, leaves[1]!), node(leaves[2]!, leaves[3]!))));
    const reversed = Object.fromEntries(Object.entries(cp).reverse());
    expect(checkpointHash(reversed)).toEqual(checkpointHash(cp));
    expect(checkpointHash(cp)).toEqual(canonHash(cp));
    for (const [field, value] of [["msgCount", 12], ["domain", "Other"], ["network", "x"], ["prev", `0x${"33".repeat(32)}`]] as const) {
      expect(checkpointHash({ ...cp, [field]: value })).not.toEqual(checkpointHash(cp));
    }
  });

  it("membership paths prove each milestone of the window", () => {
    const all = [...ids, blake2b256(new TextEncoder().encode("extra"))];
    const root = merkleRoot(all);
    all.forEach((mid, i) => {
      const path = membershipPath(all, i);
      expect(verifyPath(mid, path, root)).toBe(true);
      expect(verifyPath(all[(i + 1) % all.length], path, root)).toBe(false);
    });
    expect(() => membershipPath([new Uint8Array(32)], 1)).toThrow(RangeError);
  });

  it("rejects an inconsistent window", () => {
    const policy = fill(0x11);
    const bad: Partial<BuildCheckpointInput>[] = [
      { to: { index: 374, id: ids[3]! } },
      { from: { index: 370, id: ids[1]! } },
      { to: { index: 373, id: ids[2]! } },
      { to: { index: 370, id: ids[0]! }, milestoneIds: [] },
      { from: { index: 370, id: Uint8Array.of(1) }, to: { index: 370, id: Uint8Array.of(1) }, milestoneIds: [Uint8Array.of(1)] },
      { to: { index: 370, id: ids[0]! }, milestoneIds: ids.slice(0, 1), policyHash: Uint8Array.of(0) },
      { to: { index: 370, id: ids[0]! }, milestoneIds: ids.slice(0, 1), msgCount: -1 },
    ];
    for (const over of bad) expect(() => buildCheckpoint(input({ policyHash: policy, ...over }))).toThrow();
  });
});

describe("checkpointShapeError", () => {
  const cp = buildCheckpoint(input({ msgCount: 12, policyHash: fill(0x11) }));

  it("accepts well-formed checkpoints", () => {
    expect(checkpointShapeError(cp)).toBeNull();
    expect(checkpointShapeError({ ...cp, prev: `0x${"ab".repeat(32)}` })).toBeNull();
  });

  it("names the first structural problem", () => {
    const { msRoot: _drop, ...noRoot } = cp;
    const bad: unknown[] = [
      null, [], { ...cp, kind: "other" }, { ...cp, v: 2 }, { ...cp, v: true }, { ...cp, extra: 1 }, noRoot,
      { ...cp, msRoot: "0x12" }, { ...cp, msRoot: cp.msRoot.toUpperCase() }, { ...cp, msgCount: -1 },
      { ...cp, msgCount: new JsonNumber("float", 1, "1.0") }, { ...cp, from: { index: 374, id: cp.from.id } },
      { ...cp, to: { index: "373", id: cp.to.id } }, { ...cp, to: { index: 373 } }, { ...cp, network: 5 },
      { ...cp, prev: "nope" },
    ];
    for (const b of bad) expect(typeof checkpointShapeError(b)).toBe("string");
    expect(checkpointShapeError({ ...cp, from: { index: 374, id: cp.from.id } })).toBe("from.index is after to.index");
    expect(checkpointShapeError({ ...cp, to: { index: 373 } })).toBe("to must be {index, id}");
  });
});
