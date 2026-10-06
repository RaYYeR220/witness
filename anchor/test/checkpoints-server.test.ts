import type http from "node:http";
import type { AddressInfo } from "node:net";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CheckpointReader } from "../src/checkpoint-api.js";
import { AnchorLoop } from "../src/loop.js";
import { bearerMatches, createAnchorServer, type ServerDeps } from "../src/server.js";
import { StateStore } from "../src/state.js";
import { MilestoneMismatch } from "../src/hornet.js";
import { FakeRelay, FakeTangle, FakeTrail, FakeVerifier, POLICY_HASH, TRAIL, WRITER, cleanupDirs, makeSigner, tmpDir } from "./helpers.js";

const TOKEN = "an-admin-token-of-some-length";
let server: http.Server | null = null;

afterEach(async () => {
  await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
  server = null;
  cleanupDirs();
});

async function start(opts: { latest?: number; adminToken?: string | null; withLoop?: boolean; ttlMs?: number; trailId?: string } = {}) {
  let clock = 1_000_000;
  const trail = new FakeTrail();
  const tangle = new FakeTangle(opts.latest ?? 12);
  const { signer, keyInfo } = makeSigner();
  const relay = new FakeRelay([keyInfo]);
  const store = new StateStore(path.join(tmpDir(), "anchor-state.json"));
  const verifier = new FakeVerifier();
  const loop = new AnchorLoop({
    network: "testnet",
    writer: WRITER,
    trail,
    source: tangle,
    verifier,
    blocks: relay,
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
    checkpoints: new CheckpointReader(store, trail, "testnet", {
      writer: WRITER,
      trailId: () => opts.trailId ?? TRAIL,
      ttlMs: opts.ttlMs ?? 0,
      now: () => clock,
    }),
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
  const advance = (ms: number) => {
    clock += ms;
  };
  return { trail, tangle, relay, store, loop, verifier, call, run, advance };
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
    // The stage is reported; the node's own error text stays in the log.
    expect(r.body).toEqual({ status: "error", stage: "trail" });
    const list = await s.call("/checkpoints");
    expect(list.body.loop.lastResult).toEqual({ status: "error", stage: "trail" });
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
      txVerified: true,
      record: 1,
      network: "testnet",
      trail: TRAIL,
      source: "chain",
      readAtMs: 1_000_000,
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
    expect(r.body).toEqual({ error: "the trail could not be read from IOTA Rebased", source: "chain" });
    expect(JSON.stringify(r.body)).not.toMatch(/rpc down/);
  });

  it("answers 502 for a record by another writer, on another trail, or with another transaction", async () => {
    const s = await start();
    await s.run();
    s.trail.records[1]!.addedBy = "0x" + "ee".repeat(32);
    const foreign = await s.call("/checkpoints/1");
    expect(foreign.status).toBe(502);
    expect(foreign.body.error).toMatch(/not by the anchor's writer/);
    s.trail.records[1]!.addedBy = WRITER;
    s.trail.records[1]!.tx = "TxSomethingElse";
    expect((await s.call("/checkpoints/1")).body.error).toMatch(/another transaction/);
    await new Promise<void>((r) => server!.close(() => r()));
    const other = await start({ trailId: "0x" + "9".repeat(64) });
    await other.run();
    expect((await other.call("/checkpoints/1")).body.error).toMatch(/not the configured trail/);
  });

  it("serves a read again for a few seconds, shares concurrent reads and checks the transaction once", async () => {
    const s = await start({ ttlMs: 5_000 });
    await s.run();
    const reads = s.trail.reads;
    const [a, b] = await Promise.all([s.call("/checkpoints/1"), s.call("/checkpoints/1")]);
    expect(a.body).toEqual(b.body);
    expect(s.trail.reads).toBe(reads + 1);
    s.advance(4_000);
    expect((await s.call("/checkpoints/1")).body.readAtMs).toBe(1_000_000);
    expect(s.trail.reads).toBe(reads + 1);
    s.advance(2_000);
    const fresh = await s.call("/checkpoints/1");
    expect(fresh.body.readAtMs).toBe(1_006_000);
    expect(s.trail.reads).toBe(reads + 2);
    expect(s.trail.txLookups).toBe(1);
    // A failed read is not cached.
    s.advance(6_000);
    s.trail.failReads = true;
    expect((await s.call("/checkpoints/1")).status).toBe(502);
    s.trail.failReads = false;
    expect((await s.call("/checkpoints/1")).status).toBe(200);
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
    expect(r.body.chainError).toBe("the trail could not be read from IOTA Rebased");
    expect(r.body.checkpoints).toHaveLength(1);
  });
});

describe("GET /healthz", () => {
  it("turns degraded (503) when the loop refused a window the node disagrees with", async () => {
    const s = await start();
    expect(await s.call("/healthz")).toEqual({ status: 200, body: { status: "ok", network: "testnet" } });
    s.verifier.fail = new MilestoneMismatch("ids differ");
    await s.run();
    const h = await s.call("/healthz");
    expect(h.status).toBe(503);
    expect(h.body).toMatchObject({ status: "degraded", reason: expect.stringMatching(/verification/) });
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
