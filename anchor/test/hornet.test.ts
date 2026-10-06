import { readFileSync } from "node:fs";
import { fromHex, parseMilestonePayload, toHex, type MilestonePayload } from "@witness/verify";
import { describe, expect, it } from "vitest";
import { HornetClient, HornetError, HornetWindowVerifier, MilestoneMismatch } from "../src/hornet.js";

// Real milestones 370..373 of the local private Tangle and its coordinator keys (core/tests/vectors).
const vectors = (name: string) => JSON.parse(readFileSync(new URL(`../../core/tests/vectors/${name}.json`, import.meta.url), "utf8"));
const MILESTONES: { index: number; milestoneId: string; essence: string; previousMilestoneId: string; signatures: { pk: string; sig: string }[] }[] =
  vectors("milestones");
const KEYS: string[] = vectors("coordinator_keys").publicKeys;

/** Raw milestone payload bytes as HORNET serves them (type word, essence, signatures). */
function raw(m: (typeof MILESTONES)[number], sigs = m.signatures): Uint8Array {
  const parts: Uint8Array[] = [new Uint8Array([7, 0, 0, 0]), fromHex(m.essence), new Uint8Array([sigs.length])];
  for (const s of sigs) parts.push(new Uint8Array([0]), fromHex(s.pk), fromHex(s.sig));
  return Buffer.concat(parts);
}

function node(overrides: Record<number, Uint8Array | null> = {}) {
  const asked: number[] = [];
  return {
    asked,
    async milestone(index: number): Promise<MilestonePayload | null> {
      asked.push(index);
      if (index in overrides) return overrides[index] === null ? null : parseMilestonePayload(overrides[index]!);
      const m = MILESTONES.find((x) => x.index === index);
      return m ? parseMilestonePayload(raw(m)) : null;
    },
  };
}

const WINDOW = { from: 370, to: 373 };
const IDS = MILESTONES.map((m) => fromHex(m.milestoneId));
const PREV = fromHex(MILESTONES[0]!.previousMilestoneId);
const pinned = (keys = KEYS, threshold = 2) => ({ keys: new Set(keys), threshold });

describe("HornetWindowVerifier", () => {
  it("accepts a window whose ids, signatures and links all check out on the node", async () => {
    const n = node();
    await new HornetWindowVerifier(n, pinned()).verifyWindow(WINDOW, IDS, PREV);
    expect(n.asked.sort()).toEqual([370, 371, 372, 373]);
    await new HornetWindowVerifier(node(), pinned()).verifyWindow(WINDOW, IDS, null);
  });

  it("refuses ids that are not the node's", async () => {
    const ids = [...IDS];
    ids[2] = new Uint8Array(32).fill(1);
    await expect(new HornetWindowVerifier(node(), pinned()).verifyWindow(WINDOW, ids, PREV)).rejects.toThrow(MilestoneMismatch);
    await expect(new HornetWindowVerifier(node(), pinned()).verifyWindow(WINDOW, IDS.slice(1), PREV)).rejects.toThrow(MilestoneMismatch);
  });

  it("refuses milestones without enough valid pinned signatures", async () => {
    const other = "0x" + "11".repeat(32);
    await expect(new HornetWindowVerifier(node(), pinned([KEYS[0]!, other], 2)).verifyWindow(WINDOW, IDS, PREV)).rejects.toThrow(/1 valid/);
    const m = MILESTONES[1]!;
    const forged = m.signatures.map((s, i) => (i === 0 ? { ...s, sig: "0x" + "00".repeat(64) } : s));
    const n = node({ 371: raw(m, forged) });
    await expect(new HornetWindowVerifier(n, pinned()).verifyWindow(WINDOW, IDS, PREV)).rejects.toThrow(/milestone 371 has 1 valid/);
    // One valid pinned signature is enough when that is the pinned threshold.
    await new HornetWindowVerifier(node({ 371: raw(m, forged) }), pinned(KEYS, 1)).verifyWindow(WINDOW, IDS, PREV);
  });

  it("refuses a broken previous-milestone link and a node answering for another index", async () => {
    await expect(new HornetWindowVerifier(node(), pinned()).verifyWindow(WINDOW, IDS, new Uint8Array(32))).rejects.toThrow(/follows/);
    const n = node({ 372: raw(MILESTONES[3]!) });
    await expect(new HornetWindowVerifier(n, pinned()).verifyWindow(WINDOW, IDS, PREV)).rejects.toThrow(/returned milestone 373/);
  });

  it("cannot decide when the node lacks a milestone", async () => {
    const err = await new HornetWindowVerifier(node({ 373: null }), pinned()).verifyWindow(WINDOW, IDS, PREV).catch((e) => e);
    expect(err).toBeInstanceOf(HornetError);
    expect(err).not.toBeInstanceOf(MilestoneMismatch);
  });

  it("needs a sane threshold", () => {
    expect(() => new HornetWindowVerifier(node(), pinned(KEYS, 3))).toThrow(RangeError);
    expect(() => new HornetWindowVerifier(node(), pinned([], 1))).toThrow(RangeError);
  });
});

describe("HornetClient", () => {
  const m = MILESTONES[0]!;
  const fetchFrom = (routes: Record<string, () => Response>) => {
    const seen: { url: string; accept: string | null }[] = [];
    const impl = (async (url: string, init?: RequestInit) => {
      seen.push({ url, accept: new Headers(init?.headers).get("accept") });
      const route = Object.keys(routes).find((r) => url.endsWith(r));
      if (!route) return new Response("{}", { status: 404 });
      return routes[route]!();
    }) as unknown as typeof fetch;
    return { impl, seen };
  };

  it("reads raw milestones with the binary serializer", async () => {
    const { impl, seen } = fetchFrom({ "/milestones/by-index/370": () => new Response(raw(m)) });
    const c = new HornetClient("http://hornet:14265/", 1000, impl);
    const got = await c.milestone(370);
    expect(got!.essence.index).toBe(370);
    expect(seen[0]).toEqual({ url: "http://hornet:14265/api/core/v2/milestones/by-index/370", accept: "application/vnd.iota.serializer-v1" });
    expect(await c.milestone(999)).toBeNull();
  });

  it("reads tagged-data blocks and reports node trouble as HornetError", async () => {
    const block = { payload: { type: 5, tag: toHex(Buffer.from("witness.anchor")), data: toHex(Buffer.from('{"a":1}')) } };
    const { impl } = fetchFrom({
      "/blocks/0xab": () => new Response(JSON.stringify(block)),
      "/blocks/0xcd": () => new Response("{}", { status: 500 }),
      "/blocks/0xef": () => new Response(JSON.stringify({ payload: { type: 7 } })),
    });
    const c = new HornetClient("http://hornet", 1000, impl);
    expect(await c.taggedData("0xab")).toEqual({ tag: "witness.anchor", data: new Uint8Array(Buffer.from('{"a":1}')) });
    await expect(c.taggedData("0xcd")).rejects.toThrow(HornetError);
    expect(await c.taggedData("0xef")).toBeNull();
    expect(await c.taggedData("0x00")).toBeNull();
    const down = new HornetClient("http://hornet", 1000, (async () => {
      throw new TypeError("fetch failed");
    }) as unknown as typeof fetch);
    await expect(down.milestone(1)).rejects.toThrow(HornetError);
  });
});
