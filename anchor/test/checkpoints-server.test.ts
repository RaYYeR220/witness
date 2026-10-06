import type http from "node:http";
import type { AddressInfo } from "node:net";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CheckpointReader } from "../src/checkpoint-api.js";
import { AnchorLoop } from "../src/loop.js";
import { bearerMatches, createAnchorServer, type ServerDeps } from "../src/server.js";
import { StateStore } from "../src/state.js";
import { FakeRelay, FakeTangle, FakeTrail, POLICY_HASH, TRAIL, WRITER, cleanupDirs, makeSigner, tmpDir } from "./helpers.js";

const TOKEN = "an-admin-token-of-some-length";
let server: http.Server | null = null;

afterEach(async () => {
  await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
  server = null;
  cleanupDirs();
});

async function start(opts: { latest?: number; adminToken?: string | null; withLoop?: boolean } = {}) {
  const trail = new FakeTrail();
  const tangle = new FakeTangle(opts.latest ?? 12);
  const { signer, keyInfo } = makeSigner();
  const relay = new FakeRelay([keyInfo]);
  const store = new StateStore(path.join(tmpDir(), "anchor-state.json"));
  const loop = new AnchorLoop({
    network: "testnet",
    writer: WRITER,
    trail,
    source: tangle,
    relay,
    signer,
    store,
    params: { network: "private_tangle1", domain: "MyDomain", policyHash: POLICY_HASH },
    every: 12,
    startIndex: 1,
    pollMs: 60_000,
  });
  const deps: ServerDeps = {
    network: "testnet",
    resolve: async () => {
      throw new Error("unused");
    },
    identities: () => null,
    cacheTtlMs: 0,
    checkpoints: new CheckpointReader(store, trail, "testnet", () => TRAIL),
    loop: opts.withLoop === false ? null : loop,
    adminToken: opts.adminToken === undefined ? TOKEN : opts.adminToken,
  };
  server = createAnchorServer(deps);
  await new Promise<void>((r) => server!.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const call = async (p: string, init?: RequestInit) => {
    const res = await fetch(base + p, init);
    return { status: res.status, body: (await res.json()) as any };
  };
  const run = (token: string | null = TOKEN) =>
    call("/checkpoints/run", { method: "POST", headers: token ? { authorization: `Bearer ${token}` } : {} });
  return { trail, tangle, relay, store, loop, call, run };
}

describe("POST /checkpoints/run", () => {
  it("needs the admin token", async () => {
    const s = await start();
    expect((await s.run(null)).status).toBe(401);
    expect((await s.run("wrong-token-wrong-token")).status).toBe(401);
    expect(s.trail.appends).toBe(0);
    const ok = await s.run();
    expect(ok.status).toBe(200);
    expect(ok.body).toMatchObject({ status: "anchored", seq: 1, window: { from: 1, to: 12 } });
    expect((await s.call("/checkpoints/run")).status).toBe(405);
  });

  it("is disabled without a configured token, and refused where no loop runs", async () => {
    const off = await start({ adminToken: null });
    expect((await off.run()).status).toBe(403);
    expect(off.trail.appends).toBe(0);
    await new Promise<void>((r) => server!.close(() => r()));
    const ro = await start({ withLoop: false });
    expect((await ro.run()).status).toBe(409);
  });

  it("answers 502 when the tick fails", async () => {
    const s = await start();
    s.trail.ensureTrail = async () => {
      throw new Error("rpc down");
    };
    const r = await s.run();
    expect(r.status).toBe(502);
    expect(r.body).toMatchObject({ status: "error", stage: "trail" });
  });
});

describe("GET /checkpoints/:seq", () => {
  it("returns the checkpoint read from the chain in the shape R11 and the console use", async () => {
    const s = await start();
    await s.run();
    const entry = s.store.load()!.checkpoints[0]!;
    const r = await s.call("/checkpoints/1");
    expect(r.status).toBe(200);
    expect(r.body).toEqual({
      seq: 1,
      checkpoint: entry.checkpoint,
      checkpointHash: entry.checkpointHash,
      tx: "Tx1",
      record: 1,
      network: "testnet",
      trail: TRAIL,
      source: "chain",
      addedBy: WRITER,
      timestampMs: expect.any(Number),
      links: { tx: "https://explorer.test/txblock/Tx1", trail: `https://explorer.test/object/${TRAIL}` },
    });
  });

  it("answers 502 when the chain cannot be read, never a stored copy", async () => {
    const s = await start();
    await s.run();
    s.trail.failReads = true;
    const r = await s.call("/checkpoints/1");
    expect(r.status).toBe(502);
    expect(r.body).toEqual({ error: expect.stringMatching(/rpc down/), source: "chain" });
    expect(r.body.checkpoint).toBeUndefined();
  });

  it("answers 502 when the record on chain is not that checkpoint", async () => {
    const s = await start();
    await s.run();
    s.trail.records[1]!.metadata = JSON.stringify({ kind: "witness.checkpoint", seq: 9, checkpointHash: "0x" });
    expect((await s.call("/checkpoints/1")).status).toBe(502);
    s.trail.records.pop();
    const gone = await s.call("/checkpoints/1");
    expect(gone.status).toBe(502);
    expect(gone.body.error).toMatch(/not on chain/);
  });

  it("answers 404 for unknown and 400 for malformed seqs", async () => {
    const s = await start();
    expect((await s.call("/checkpoints/1")).status).toBe(404);
    for (const bad of ["0", "-1", "abc", "1.5", "01", "9".repeat(20)]) expect((await s.call(`/checkpoints/${bad}`)).status).toBe(400);
  });
});

describe("GET /checkpoints", () => {
  it("lists checkpoints from the state with the trail head read from the chain", async () => {
    const s = await start({ latest: 24 });
    await s.run();
    await s.run();
    const r = await s.call("/checkpoints");
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({
      network: "testnet",
      trail: TRAIL,
      chain: { records: 3, tail: 2 },
      pending: null,
      mirror: { lastSeq: 2 },
      loop: { running: false, lastResult: { status: "anchored", seq: 2 } },
    });
    expect(r.body.checkpoints.map((c: any) => [c.seq, c.from.index, c.to.index, c.record, c.mirror.status])).toEqual([
      [2, 13, 24, 2, "posted"],
      [1, 1, 12, 1, "posted"],
    ]);
    expect((await s.call("/checkpoints?limit=1")).body.checkpoints).toHaveLength(1);
    expect((await s.call("/checkpoints?limit=0")).status).toBe(400);
  });

  it("still lists when the chain is unreachable, and says so", async () => {
    const s = await start();
    await s.run();
    s.trail.failReads = true;
    const r = await s.call("/checkpoints");
    expect(r.status).toBe(200);
    expect(r.body.chain).toBeNull();
    expect(r.body.chainError).toMatch(/rpc down/);
    expect(r.body.checkpoints).toHaveLength(1);
  });
});

describe("bearerMatches", () => {
  it("accepts only the exact bearer token", () => {
    expect(bearerMatches(`Bearer ${TOKEN}`, TOKEN)).toBe(true);
    expect(bearerMatches(`bearer ${TOKEN}`, TOKEN)).toBe(true);
    expect(bearerMatches(TOKEN, TOKEN)).toBe(false);
    expect(bearerMatches(`Bearer ${TOKEN}x`, TOKEN)).toBe(false);
    expect(bearerMatches(undefined, TOKEN)).toBe(false);
  });
});
