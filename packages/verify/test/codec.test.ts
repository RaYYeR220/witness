import { describe, expect, it } from "vitest";

import { concatBytes, fromHex, toHex } from "../src/bytes.js";
import {
  blockId,
  DecodeError,
  milestoneId,
  parseBlock,
  parseMilestoneEssence,
  parseMilestonePayload,
} from "../src/index.js";
import { blocks, milestones } from "./vectors.js";

const le = (n: number, size: number) => {
  const out = new Uint8Array(size);
  for (let i = 0; i < size; i++) out[i] = Math.floor(n / 256 ** i) % 256;
  return out;
};
const fill = (byte: number, n: number) => new Uint8Array(n).fill(byte);
const utf8 = (s: string) => new TextEncoder().encode(s);

function decodeError(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(DecodeError);
    return (e as Error).message;
  }
  throw new Error("expected a DecodeError");
}

/** Signed milestone payload (type word + essence + signatures) from a vector entry. */
function milestonePayload(m: any, essence: Uint8Array = fromHex(m.essence)): Uint8Array {
  const sigs = m.signatures.map((s: any) => concatBytes(Uint8Array.of(0), fromHex(s.pk), fromHex(s.sig)));
  return concatBytes(le(7, 4), essence, Uint8Array.of(m.signatures.length), ...sigs);
}

describe("blocks.json parity", () => {
  it.each(blocks.map((b) => [b.blockId, b] as const))("%s", (_id, v) => {
    const raw = fromHex(v.raw);
    expect(toHex(blockId(raw))).toBe(v.blockId);
    const block = parseBlock(raw);
    if (v.kind === "tagged") {
      expect(block.payload?.kind).toBe("tagged_data");
      if (block.payload?.kind !== "tagged_data") return;
      expect(new TextDecoder().decode(block.payload.tag)).toBe(v.tag);
      expect(toHex(block.payload.data)).toBe(v.data);
    } else {
      expect(v.kind).toBe("milestone");
      expect(block.payload?.kind).toBe("milestone");
      if (block.payload?.kind !== "milestone") return;
      const { essence, essenceBytes, signatures } = block.payload;
      const m = milestones.find((x) => x.index === essence.index);
      if (m) {
        expect(toHex(essence.inclusionMerkleRoot)).toBe(m.inclusionMerkleRoot);
        expect(signatures).toHaveLength(m.signatures.length);
        expect(toHex(milestoneId(essenceBytes))).toBe(m.milestoneId);
      }
    }
  });

  it("covers both payload kinds and links milestone blocks to milestones.json", () => {
    expect(new Set(blocks.map((b) => b.kind))).toEqual(new Set(["tagged", "milestone"]));
    const linked = blocks.filter((b) => {
      const p = parseBlock(fromHex(b.raw)).payload;
      return p?.kind === "milestone" && milestones.some((m) => m.index === p.essence.index);
    });
    expect(linked.length).toBeGreaterThanOrEqual(1);
  });
});

describe("milestones.json parity", () => {
  it.each(milestones.map((m) => [m.index, m] as const))("milestone %i", (_i, m) => {
    const essence = fromHex(m.essence);
    const p = parseMilestonePayload(milestonePayload(m));
    expect(p.essence.index).toBe(m.index);
    expect(p.essence.timestamp).toBe(m.timestamp);
    expect(toHex(p.essence.previousMilestoneId)).toBe(m.previousMilestoneId);
    expect(toHex(p.essence.inclusionMerkleRoot)).toBe(m.inclusionMerkleRoot);
    expect(toHex(p.essenceBytes)).toBe(m.essence);
    expect(toHex(milestoneId(essence))).toBe(m.milestoneId);
    expect(p.signatures.map((s) => toHex(s.publicKey))).toEqual(m.signatures.map((s: any) => s.pk));
    expect(p.signatures.map((s) => toHex(s.signature))).toEqual(m.signatures.map((s: any) => s.sig));
    expect(parseMilestoneEssence(essence)).toEqual(p.essence);
  });
});

describe("decode errors (messages identical to the Python reference)", () => {
  const raw0 = fromHex(blocks[0].raw);
  const msRaw = fromHex(blocks.find((b) => b.kind === "milestone").raw);

  it("truncation and trailing bytes", () => {
    expect(decodeError(() => parseBlock(raw0.slice(0, -1)))).toBe(
      "block: truncated reading nonce (need 8 bytes at offset 199, have 7)",
    );
    expect(decodeError(() => parseBlock(concatBytes(raw0, Uint8Array.of(0))))).toBe(
      "block: 1 trailing bytes after offset 207",
    );
    expect(decodeError(() => parseBlock(raw0.slice(0, 40)))).toBe(
      "block: truncated reading parent[1] (need 32 bytes at offset 34, have 6)",
    );
    expect(decodeError(() => parseBlock(msRaw.slice(0, 150)))).toBe(
      "block: truncated reading payload (need 372 bytes at offset 70, have 80)",
    );
    expect(decodeError(() => parseMilestonePayload(le(5, 4)))).toBe("milestone payload: expected type 7, got 5");
  });

  it("every strict prefix of a milestone block fails to decode", () => {
    for (let n = 0; n < msRaw.length; n++) decodeError(() => parseBlock(msRaw.slice(0, n)));
  });

  it("trailing bytes inside a payload are rejected", () => {
    const block = (payload: Uint8Array) =>
      concatBytes(Uint8Array.of(2, 1), fill(0x22, 32), le(payload.length, 4), payload, new Uint8Array(8));
    const tagged = concatBytes(le(5, 4), Uint8Array.of(1), utf8("t"), le(2, 4), utf8("{}"));
    expect(parseBlock(block(tagged)).payload?.kind).toBe("tagged_data");
    decodeError(() => parseBlock(block(concatBytes(tagged, Uint8Array.of(0)))));
    decodeError(() => parseBlock(block(concatBytes(le(5, 4), Uint8Array.of(200), utf8("ab")))));
    decodeError(() => parseBlock(block(concatBytes(le(5, 4), Uint8Array.of(1), utf8("t"), le(50, 4), utf8("xy")))));
  });

  it("block without payload and unknown payload types", () => {
    const empty = concatBytes(Uint8Array.of(2, 1), fill(0x22, 32), le(0, 4), new Uint8Array(8));
    expect(parseBlock(empty).payload).toBeNull();
    const other = concatBytes(le(6, 4), utf8("abc"));
    const blk = parseBlock(concatBytes(Uint8Array.of(2, 1), fill(0x22, 32), le(other.length, 4), other, le(2 ** 40, 8)));
    expect(blk.payload).toEqual({ kind: "other", type: 6, raw: other });
    expect(blk.nonce).toBe(2n ** 40n);
  });
});

describe("milestone options", () => {
  const PARAMS_OPT = concatBytes(Uint8Array.of(1), le(400, 4), Uint8Array.of(2), le(3, 2), utf8("abc"));
  const RECEIPT_OPT = concatBytes(
    Uint8Array.of(0),
    le(1234, 4),
    Uint8Array.of(1),
    le(2, 2),
    ...[5, 6].map((k) => concatBytes(fill(k, 49), Uint8Array.of(0), fill(k + 1, 32), le(1000 + k, 8))),
    le(4, 4),
    Uint8Array.of(1),
    fill(0x33, 32),
    Uint8Array.of(2),
    le(999, 8),
  );

  function withOptions(count: number, options: Uint8Array) {
    const base = fromHex(milestones[0].essence);
    expect(base[base.length - 1]).toBe(0);
    const essence = concatBytes(base.slice(0, -1), Uint8Array.of(count), options);
    return { payload: milestonePayload(milestones[0], essence), essence };
  }

  it.each([
    ["protocol params", 1, PARAMS_OPT],
    ["receipt", 1, RECEIPT_OPT],
    ["receipt + params", 2, concatBytes(RECEIPT_OPT, PARAMS_OPT)],
  ] as const)("%s", (_name, count, options) => {
    const { payload, essence } = withOptions(count, options);
    const p = parseMilestonePayload(payload);
    expect(p.essence.options).toEqual(options);
    expect(p.essenceBytes).toEqual(essence);
    for (let n = 0; n < payload.length; n++) decodeError(() => parseMilestonePayload(payload.slice(0, n)));
  });

  it("rejects an unknown option type", () => {
    const { payload } = withOptions(1, Uint8Array.of(7, 0, 0));
    expect(decodeError(() => parseMilestonePayload(payload))).toBe("milestone option[0]: unsupported option type 7");
  });
});
