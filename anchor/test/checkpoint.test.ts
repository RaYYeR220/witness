import { readFileSync } from "node:fs";
import { blake2b256, fromHex, jcs, merkleRoot, toHex } from "@witness/verify";
import { describe, expect, it } from "vitest";
import {
  ApiMilestoneSource,
  RecordMismatchError,
  SourceError,
  buildCheckpoint,
  buildNextCheckpoint,
  checkpointHashHex,
  checkpointRecordData,
  checkpointRecordMetadata,
  decodeCheckpointRecord,
  nextWindow,
  normalizePolicy,
  parseMilestonesReply,
  policyHash,
  type MilestoneSource,
} from "../src/checkpoint.js";

// Written by test/vectors/make_checkpoint_vectors.py from the Python reference (witness_core).
const VECTORS = JSON.parse(readFileSync(new URL("./vectors/checkpoint.json", import.meta.url), "utf8"));

const mid = (i: number) => blake2b256(new TextEncoder().encode(`ms-${i}`));
const POLICY = fromHex("0x" + "ab".repeat(32));
const PARAMS = { network: "private_tangle1", domain: "MyDomain", policyHash: POLICY };

/** Milestone source over an in-memory Tangle that has indexed milestones 1..`latest`. */
function tangle(latest: number, msgCount: number | null = 4) {
  const asked: [number, number][] = [];
  const source: MilestoneSource & { latest: number } = {
    latest,
    async milestones(from, to) {
      asked.push([from, to]);
      const complete = to <= source.latest;
      const ids = [];
      for (let i = from; i <= Math.min(to, source.latest); i++) ids.push(mid(i));
      return { complete, ids: complete ? ids : [], msgCount };
    },
  };
  return { source, asked };
}

describe("Python parity", () => {
  it("normalizes and hashes the writer policy like witness_core.policy", () => {
    expect(normalizePolicy(VECTORS.policy.input)).toEqual(VECTORS.policy.normalized);
    expect(toHex(policyHash(VECTORS.policy.input))).toBe(VECTORS.policy.hash);
  });

  it("builds byte-identical checkpoints with identical hashes", () => {
    expect(VECTORS.checkpoints.length).toBeGreaterThanOrEqual(3);
    for (const v of VECTORS.checkpoints) {
      const ids = (v.input.milestoneIds as string[]).map((h) => fromHex(h));
      const cp = buildCheckpoint({
        network: v.input.network,
        domain: v.input.domain,
        from: { index: v.input.first, id: ids[0]! },
        to: { index: v.input.first + ids.length - 1, id: ids.at(-1)! },
        milestoneIds: ids,
        msgCount: v.input.msgCount,
        policyHash: fromHex(v.input.policyHash),
        prevHash: v.input.prevHash === null ? null : fromHex(v.input.prevHash),
      });
      expect(cp).toEqual(v.checkpoint);
      expect(jcs(cp)).toBe(v.jcs);
      expect(checkpointRecordData(cp)).toBe(v.jcs);
      expect(checkpointHashHex(cp)).toBe(v.hash);
    }
    // The second vector chains onto the first.
    expect(VECTORS.checkpoints[1].checkpoint.prev).toBe(VECTORS.checkpoints[0].hash);
  });
});

describe("policy normalization", () => {
  it("rejects malformed policies", () => {
    expect(() => normalizePolicy([])).toThrow(/object/);
    expect(() => normalizePolicy({ version: "x" })).toThrow(/version/);
    expect(() => normalizePolicy({ version: 1, tags: { a: { allowed: "did" } } })).toThrow(/allowed/);
    expect(normalizePolicy({ version: "2" })).toEqual({
      version: 2,
      tags: {},
      default: { allowed: [], require_signature: false, legacy_grace: true },
    });
  });
});

describe("window selection", () => {
  it("starts at the start index, then continues right after the previous window", () => {
    expect(nextWindow(null, 1, 60)).toEqual({ from: 1, to: 60 });
    expect(nextWindow(null, 3601, 12)).toEqual({ from: 3601, to: 3612 });
    expect(nextWindow({ to: { index: 3612, id: "0x" } }, 1, 12)).toEqual({ from: 3613, to: 3624 });
    expect(() => nextWindow(null, 1, 0)).toThrow();
  });

  it("builds only complete windows", async () => {
    const { source } = tangle(10);
    const r = await buildNextCheckpoint(source, PARAMS, null, 1, 12);
    expect(r).toEqual({ status: "waiting", window: { from: 1, to: 12 }, reason: expect.stringMatching(/1\.\.12/) });
    source.latest = 12;
    const ready = await buildNextCheckpoint(source, PARAMS, null, 1, 12);
    if (ready.status !== "ready") throw new Error("expected a checkpoint");
    const ids = Array.from({ length: 12 }, (_, i) => mid(i + 1));
    expect(ready.checkpoint).toMatchObject({
      from: { index: 1, id: toHex(mid(1)) },
      to: { index: 12, id: toHex(mid(12)) },
      msRoot: toHex(merkleRoot(ids)),
      msgCount: 4,
      policyHash: toHex(POLICY),
      prev: null,
      network: "private_tangle1",
      domain: "MyDomain",
    });
    expect(ready.checkpointHash).toBe(checkpointHashHex(ready.checkpoint));
  });

  it("chains each checkpoint to the previous one, contiguously", async () => {
    const { source, asked } = tangle(100, null);
    const first = await buildNextCheckpoint(source, PARAMS, null, 5, 12);
    if (first.status !== "ready") throw new Error("expected a checkpoint");
    const second = await buildNextCheckpoint(source, PARAMS, first, 5, 12);
    if (second.status !== "ready") throw new Error("expected a checkpoint");
    expect(asked).toEqual([
      [5, 16],
      [17, 28],
    ]);
    expect(second.checkpoint.from.index).toBe(first.checkpoint.to.index + 1);
    expect(second.checkpoint.prev).toBe(first.checkpointHash);
    expect(second.checkpoint.msgCount).toBe(0);
  });
});

describe("parseMilestonesReply", () => {
  const w = { from: 10, to: 12 };
  const ids = [10, 11, 12].map((i) => toHex(mid(i)));

  it("accepts a complete window and an optional msgCount", () => {
    const r = parseMilestonesReply({ from: 10, to: 12, ids, complete: true, msgCount: 9 }, w);
    expect(r.complete).toBe(true);
    expect(r.ids.map(toHex)).toEqual(ids);
    expect(r.msgCount).toBe(9);
    expect(parseMilestonesReply({ from: 10, to: 12, ids, complete: true }, w).msgCount).toBeNull();
  });

  it("treats complete=false as not ready, whatever ids came with it", () => {
    expect(parseMilestonesReply({ from: 10, to: 12, ids: ids.slice(0, 2), complete: false }, w)).toEqual({ complete: false, ids: [], msgCount: null });
    expect(parseMilestonesReply({ from: 10, to: 12, ids, complete: false }, w).complete).toBe(false);
  });

  it("refuses replies that cannot be trusted", () => {
    expect(() => parseMilestonesReply({ from: 11, to: 12, ids, complete: true }, w)).toThrow(SourceError);
    expect(() => parseMilestonesReply({ from: 10, to: 12, ids: ids.slice(0, 2), complete: true }, w)).toThrow(/2 of 3/);
    expect(() => parseMilestonesReply({ from: 10, to: 12, ids: [ids[0], ids[0], ids[2]], complete: true }, w)).toThrow(/repeats/);
    expect(() => parseMilestonesReply({ from: 10, to: 12, ids: [ids[0], ids[1], "0xABC"], complete: true }, w)).toThrow(/hex/);
    expect(() => parseMilestonesReply({ from: 10, to: 12, ids, complete: "yes" }, w)).toThrow(/complete/);
    expect(() => parseMilestonesReply({ from: 10, to: 12, ids, complete: true, msgCount: -1 }, w)).toThrow(/msgCount/);
    expect(() => parseMilestonesReply(null, w)).toThrow(SourceError);
  });
});

describe("ApiMilestoneSource", () => {
  it("asks GET {api}/milestones?from=&to= and validates the reply", async () => {
    const urls: string[] = [];
    const fetchImpl = (async (url: string) => {
      urls.push(url);
      return new Response(JSON.stringify({ from: 1, to: 2, ids: [toHex(mid(1)), toHex(mid(2))], complete: true }), { status: 200 });
    }) as unknown as typeof fetch;
    const r = await new ApiMilestoneSource("http://api.local/", 1000, fetchImpl).milestones(1, 2);
    expect(urls).toEqual(["http://api.local/milestones?from=1&to=2"]);
    expect(r.complete).toBe(true);
  });

  it("reports HTTP errors and unreachable APIs as SourceError", async () => {
    const http422 = (async () => new Response("{}", { status: 422 })) as unknown as typeof fetch;
    await expect(new ApiMilestoneSource("http://api.local", 1000, http422).milestones(1, 2)).rejects.toThrow(/HTTP 422/);
    const down = (async () => {
      throw new TypeError("fetch failed");
    }) as unknown as typeof fetch;
    await expect(new ApiMilestoneSource("http://api.local", 1000, down).milestones(1, 2)).rejects.toThrow(SourceError);
  });
});

describe("trail record encoding", () => {
  const cp = VECTORS.checkpoints[0].checkpoint;
  const hash = VECTORS.checkpoints[0].hash;

  it("round-trips: data is the JCS text, metadata names seq and hash", () => {
    const meta = checkpointRecordMetadata(7, hash);
    expect(JSON.parse(meta)).toEqual({ kind: "witness.checkpoint", seq: 7, checkpointHash: hash });
    expect(decodeCheckpointRecord(checkpointRecordData(cp), meta, 7)).toEqual({ checkpoint: cp, checkpointHash: hash });
    expect(decodeCheckpointRecord(new TextEncoder().encode(checkpointRecordData(cp)), meta, 7).checkpointHash).toBe(hash);
  });

  it("refuses a record that is not checkpoint seq", () => {
    const data = checkpointRecordData(cp);
    expect(() => decodeCheckpointRecord(data, checkpointRecordMetadata(8, hash), 7)).toThrow(/checkpoint 8, not 7/);
    expect(() => decodeCheckpointRecord(data, checkpointRecordMetadata(7, "0x" + "00".repeat(32)), 7)).toThrow(RecordMismatchError);
    expect(() => decodeCheckpointRecord(data, "sha256:00", 7)).toThrow(/metadata/);
    expect(() => decodeCheckpointRecord("{}", checkpointRecordMetadata(7, hash), 7)).toThrow(/not a checkpoint/);
    expect(() => decodeCheckpointRecord("nope", null, 7)).toThrow(/not JSON/);
  });
});
