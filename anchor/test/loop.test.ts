import path from "node:path";
import { checkpointShapeError, merkleRoot, toHex } from "@witness/verify";
import { afterEach, describe, expect, it } from "vitest";
import { buildNextCheckpoint, checkpointHashHex } from "../src/checkpoint.js";
import { AnchorLoop, type LoopDeps } from "../src/loop.js";
import { ANCHOR_TAG, mirrorBody } from "../src/mirror.js";
import { StateStore, type AnchorState } from "../src/state.js";
import { HornetError, MilestoneMismatch } from "../src/hornet.js";
import { ANCHOR_DID, FakeRelay, FakeTangle, FakeTrail, FakeVerifier, POLICY_HASH, TRAIL, WRITER, cleanupDirs, makeSigner, mid, tmpDir } from "./helpers.js";

afterEach(cleanupDirs);

const PARAMS = { network: "private_tangle1", domain: "MyDomain", policyHash: POLICY_HASH };

function setup(over: Partial<LoopDeps> = {}, latest = 24) {
  const trail = new FakeTrail();
  const tangle = new FakeTangle(latest);
  const { signer, keyInfo } = makeSigner();
  const relay = new FakeRelay([keyInfo]);
  const store = new StateStore(path.join(tmpDir(), "data", "anchor-state.json"));
  const verifier = new FakeVerifier();
  const deps: LoopDeps = {
    network: "testnet",
    writer: WRITER,
    trail,
    source: tangle,
    verifier,
    blocks: relay,
    relay,
    signer,
    store,
    params: PARAMS,
    every: 12,
    startIndex: 1,
    pollMs: 60_000,
    ...over,
  };
  return { deps, trail, tangle, relay, store, verifier, signer, loop: new AnchorLoop(deps), restart: () => new AnchorLoop(deps) };
}

describe("AnchorLoop", () => {
  it("anchors a complete window, saves it, then mirrors it as a producer-signed witness.anchor", async () => {
    const { loop, trail, relay, store } = setup();
    const r = await loop.runOnce();
    expect(r).toMatchObject({ status: "anchored", seq: 1, window: { from: 1, to: 12 }, record: 1, tx: "Tx1", mirrored: true });

    const state = store.load()!;
    const [cp] = state.checkpoints;
    expect(cp).toMatchObject({ seq: 1, record: 1, tx: "Tx1", trail: TRAIL, addedBy: WRITER, mirror: { status: "posted", envelopeSeq: 1 } });
    expect(cp!.checkpoint.msRoot).toBe(toHex(merkleRoot(Array.from({ length: 12 }, (_, i) => mid(i + 1)))));
    expect(cp!.checkpoint.prev).toBeNull();
    expect(state.pending).toBeNull();

    // The trail record holds the checkpoint's JCS text; metadata names seq and hash.
    expect(JSON.parse(trail.records[1]!.data)).toEqual(cp!.checkpoint);
    expect(JSON.parse(trail.records[1]!.metadata!)).toEqual({ kind: "witness.checkpoint", seq: 1, checkpointHash: cp!.checkpointHash });

    expect(relay.posted).toHaveLength(1);
    const { env, blockId } = relay.posted[0]!;
    expect(env).toMatchObject({ tag: ANCHOR_TAG, iss: ANCHOR_DID, kid: `${ANCHOR_DID}#sig-1`, seq: 1, att: { mode: "producer" } });
    expect(env.prev).toBeUndefined();
    const body = env.body as any;
    // The shape witness_core.schema checks for witness.anchor.
    expect(checkpointShapeError(body.checkpoint)).toBeNull();
    expect(body.checkpointHash).toBe(checkpointHashHex(body.checkpoint));
    expect(body).toEqual({ seq: 1, checkpoint: cp!.checkpoint, checkpointHash: cp!.checkpointHash, rebased: { network: "testnet", trail: TRAIL, record: 1, tx: "Tx1" } });
    expect(state.mirror).toEqual({ lastSeq: 1, lastBlockId: blockId });
  });

  it("waits while the next window is incomplete and never anchors a partial one", async () => {
    const { loop, trail, tangle } = setup({}, 11);
    expect(await loop.runOnce()).toEqual({ status: "waiting", window: { from: 1, to: 12 }, reason: expect.any(String), cause: "incomplete" });
    expect(trail.appends).toBe(0);
    tangle.latest = 12;
    expect((await loop.runOnce()).status).toBe("anchored");
    expect(await loop.runOnce()).toMatchObject({ status: "waiting", window: { from: 13, to: 24 } });
    expect(trail.appends).toBe(1);
  });

  it("does not anchor a window whose message count the API does not report", async () => {
    const { loop, trail, tangle } = setup({}, 12);
    tangle.msgCount = false;
    expect(await loop.runOnce()).toMatchObject({ status: "waiting", cause: "no-msgcount" });
    expect(trail.appends).toBe(0);
    const dev = setup({ allowMissingMsgCount: true }, 12);
    dev.tangle.msgCount = false;
    expect(await dev.loop.runOnce()).toMatchObject({ status: "anchored" });
    expect(dev.store.load()!.checkpoints[0]!.checkpoint.msgCount).toBe(0);
  });

  it("chains windows: contiguous indexes, prev hash, mirror seq and prev block", async () => {
    const { loop, store, relay } = setup({ startIndex: 101 }, 200);
    await loop.runOnce();
    await loop.runOnce();
    const [a, b] = store.load()!.checkpoints;
    expect(a!.checkpoint.from.index).toBe(101);
    expect(b!.checkpoint.from.index).toBe(a!.checkpoint.to.index + 1);
    expect(b!.checkpoint.to.index).toBe(124);
    expect(b!.checkpoint.prev).toBe(a!.checkpointHash);
    expect(b!.seq).toBe(2);
    expect(relay.posted.map((p) => p.env.seq)).toEqual([1, 2]);
    expect(relay.posted[1]!.env.prev).toBe(relay.posted[0]!.blockId);
  });

  it("checks every window against the node before anchoring, chained to the previous checkpoint", async () => {
    const { loop, verifier, store } = setup({}, 24);
    await loop.runOnce();
    await loop.runOnce();
    const [a] = store.load()!.checkpoints;
    expect(verifier.calls).toEqual([
      { window: { from: 1, to: 12 }, ids: 12, prevId: null },
      { window: { from: 13, to: 24 }, ids: 12, prevId: a!.checkpoint.to.id },
    ]);
  });

  it("refuses to anchor and reports degraded health when the node disagrees", async () => {
    const { loop, verifier, trail } = setup({}, 24);
    verifier.fail = new MilestoneMismatch("milestone 3 is 0xaa on the node, the milestone source says 0xbb");
    expect(await loop.runOnce()).toMatchObject({ status: "error", stage: "verify" });
    expect(trail.appends).toBe(0);
    expect(loop.health()).toEqual({ status: "degraded", reason: expect.stringMatching(/1\.\.12 failed verification/) });
    verifier.fail = null;
    expect(await loop.runOnce()).toMatchObject({ status: "anchored", seq: 1 });
    expect(loop.health()).toEqual({ status: "ok", reason: null });
  });

  it("does not anchor while the node cannot be asked, without raising the alarm", async () => {
    const { loop, verifier, trail } = setup({}, 12);
    verifier.fail = new HornetError("HORNET unreachable: ECONNREFUSED");
    expect(await loop.runOnce()).toMatchObject({ status: "error", stage: "verify" });
    expect(trail.appends).toBe(0);
    expect(loop.health().status).toBe("ok");
  });

  it("reports a stall after too many ticks without a checkpoint, and recovers", async () => {
    const { loop, tangle } = setup({ stallTicks: 3 }, 11);
    await loop.runOnce();
    await loop.runOnce();
    expect(loop.health().status).toBe("ok");
    await loop.runOnce();
    expect(loop.health()).toEqual({ status: "degraded", reason: "no checkpoint for 3 ticks: waiting for milestones 1..12 (incomplete)" });
    tangle.latest = 12;
    await loop.runOnce();
    expect(loop.health()).toEqual({ status: "ok", reason: null });
  });

  it("reports repeated failures sooner than a quiet stall", async () => {
    const { loop, trail } = setup({ stallTicks: 60 }, 12);
    trail.ensureTrail = async () => {
      throw new Error("rpc down");
    };
    for (let i = 0; i < 4; i++) await loop.runOnce();
    expect(loop.health().status).toBe("ok");
    await loop.runOnce();
    expect(loop.health()).toEqual({ status: "degraded", reason: "5 failed ticks in a row (stage trail)" });
  });

  it("joins a running tick instead of starting a second one", async () => {
    const { loop, trail } = setup();
    const [x, y] = await Promise.all([loop.runOnce(), loop.runOnce()]);
    expect(x).toBe(y);
    expect(trail.appends).toBe(1);
  });
});

describe("restarts", () => {
  it("mirrors an appended-but-unmirrored checkpoint after a restart without appending again", async () => {
    const { loop, trail, relay, store, restart } = setup({}, 12);
    relay.down = true;
    const r = await loop.runOnce();
    expect(r).toMatchObject({ status: "anchored", seq: 1, mirrored: false, mirrorError: expect.stringMatching(/unreachable/) });
    expect(store.load()!.checkpoints[0]!.mirror).toBeNull();

    relay.down = false;
    const again = await restart().runOnce();
    expect(again).toMatchObject({ status: "waiting", window: { from: 13, to: 24 } });
    expect(trail.appends).toBe(1);
    expect(relay.posted).toHaveLength(1);
    const entry = store.load()!.checkpoints[0]!;
    expect(entry.mirror).toMatchObject({ status: "posted", envelopeSeq: 1 });
    expect(entry.mirrorError).toBeNull();
  });

  it("finishes an append that was persisted before a crash instead of anchoring the window twice", async () => {
    const { loop, trail, store, relay, restart } = setup({}, 24);
    trail.crashNext = true;
    trail.landOnCrash = false; // signed and saved, not yet on chain
    expect(await loop.runOnce()).toMatchObject({ status: "error", stage: "append" });
    const saved = store.load()!;
    expect(saved.pending).toMatchObject({ seq: 1, append: { digest: "Tx1" } });
    expect(saved.checkpoints).toHaveLength(0);

    const r = await restart().runOnce();
    expect(trail.resumeCalls).toEqual(["Tx1"]);
    // The pending checkpoint 1 is settled with its original transaction, then window 2 is anchored.
    expect(r).toMatchObject({ status: "anchored", seq: 2, window: { from: 13, to: 24 } });
    const state = store.load()!;
    expect(state.pending).toBeNull();
    expect(state.checkpoints.map((c) => [c.seq, c.tx, c.record])).toEqual([
      [1, "Tx1", 1],
      [2, "Tx2", 2],
    ]);
    expect(trail.appends).toBe(2);
    expect(trail.records.filter((x) => x.metadata?.includes('"seq":1')).length).toBe(1);
    expect(relay.posted.map((p) => (p.env.body as any).seq)).toEqual([1, 2]);
  });

  it("adopts an append that reached the chain although the process died", async () => {
    const { loop, trail, store, restart } = setup({}, 12);
    trail.crashNext = true;
    trail.landOnCrash = true;
    await loop.runOnce();
    expect(trail.appends).toBe(1);
    expect(await restart().runOnce()).toMatchObject({ status: "waiting" });
    expect(trail.appends).toBe(1);
    expect(store.load()!.checkpoints.map((c) => c.tx)).toEqual(["Tx1"]);
  });

  it("rebuilds the same window when the persisted transaction never executed", async () => {
    const { loop, trail, store, restart } = setup({}, 12);
    trail.crashNext = true;
    trail.landOnCrash = false;
    await loop.runOnce();
    const first = store.load()!.pending!;
    // Simulate a transaction that can never execute (its gas coin was spent elsewhere).
    trail.resumeAppend = async () => ({ status: "dropped", reason: "gas coin version consumed" });
    const r = await restart().runOnce();
    expect(r).toMatchObject({ status: "anchored", seq: 1, tx: "Tx2" });
    expect(store.load()!.checkpoints[0]!.checkpointHash).toBe(first.checkpointHash);
    expect(trail.appends).toBe(1);
  });

  it("does nothing new while a pending append cannot be settled", async () => {
    const { loop, trail, restart } = setup({}, 24);
    trail.crashNext = true;
    trail.landOnCrash = false;
    await loop.runOnce();
    trail.resumeError = new Error("rpc timeout");
    expect(await restart().runOnce()).toMatchObject({ status: "error", stage: "pending" });
    expect(trail.appends).toBe(0);
  });

  it("recovers a mirror whose reply was lost from the relay receipt", async () => {
    const { loop, relay, store, restart } = setup({}, 12);
    relay.loseReply = true;
    expect(await loop.runOnce()).toMatchObject({ mirrored: false });
    await restart().runOnce();
    expect(relay.posted).toHaveLength(1);
    expect(store.load()!.checkpoints[0]!.mirror).toMatchObject({ status: "posted", envelopeSeq: 1, recovered: true, blockId: relay.posted[0]!.blockId });
  });

  it("moves past a seq the relay claimed without a receipt", async () => {
    const { loop, relay, store, restart } = setup({}, 12);
    relay.claimWithoutReceipt.add(1);
    await loop.runOnce(); // seq 1 claimed, connection reset
    await restart().runOnce(); // REPLAY, no receipt: seq 1 is burnt
    expect(store.load()!.mirror.lastSeq).toBe(1);
    await restart().runOnce();
    const entry = store.load()!.checkpoints[0]!;
    expect(entry.mirror).toMatchObject({ status: "posted", envelopeSeq: 2 });
    expect((relay.posted[0]!.env.body as any).seq).toBe(1);
  });

  it("rebuilds a lost state file from the trail and continues the chain", async () => {
    const { deps, trail, tangle, store, relay } = setup({}, 36);
    // Two checkpoints written by an earlier run whose state file is gone.
    const one = await buildNextCheckpoint(tangle, PARAMS, null, 1, 12);
    if (one.status !== "ready") throw new Error("expected a checkpoint");
    const two = await buildNextCheckpoint(tangle, PARAMS, one, 1, 12);
    if (two.status !== "ready") throw new Error("expected a checkpoint");
    trail.seed(1, one.checkpoint, one.checkpointHash);
    trail.records.push({ data: "noise", metadata: "sha256:00", addedBy: WRITER, addedAtMs: 2, tx: "TxNoise" });
    trail.seed(2, two.checkpoint, two.checkpointHash);

    const r = await new AnchorLoop(deps).runOnce();
    expect(r).toMatchObject({ status: "anchored", seq: 3, window: { from: 25, to: 36 } });
    const state = store.load()!;
    expect(state.checkpoints.map((c) => [c.seq, c.record, c.tx, c.mirror?.status])).toEqual([
      [1, 1, "TxSeed1", "posted"],
      [2, 3, "TxSeed2", "posted"],
      [3, 4, "Tx1", "posted"],
    ]);
    expect(state.checkpoints[2]!.checkpoint.prev).toBe(two.checkpointHash);
    // The relay holds no mirror of ours, so the rebuilt checkpoints are mirrored again, in order.
    expect(relay.posted.map((p) => [(p.env.body as any).seq, p.env.seq])).toEqual([
      [1, 1],
      [2, 2],
      [3, 3],
    ]);
  });

  it("seeds the mirror chain from the relay receipts that carry the rebuilt checkpoints", async () => {
    const { deps, trail, tangle, store, relay, signer } = setup({}, 36);
    const one = await buildNextCheckpoint(tangle, PARAMS, null, 1, 12);
    const two = one.status === "ready" ? await buildNextCheckpoint(tangle, PARAMS, one, 1, 12) : one;
    if (one.status !== "ready" || two.status !== "ready") throw new Error("expected checkpoints");
    trail.seed(1, one.checkpoint, one.checkpointHash);
    trail.seed(2, two.checkpoint, two.checkpointHash);
    // An earlier run mirrored checkpoint 1 (envelope seq 1) and then posted seq 5 for checkpoint 2.
    const entry = (seq: number, w: typeof one, record: number) => ({
      seq, checkpoint: w.checkpoint, checkpointHash: w.checkpointHash, trail: TRAIL, record, tx: `TxSeed${seq}`,
      timestampMs: 0, addedBy: WRITER, anchoredAt: "", mirror: null,
    });
    const b1 = relay.seedPosted(ANCHOR_TAG, signer.seal(ANCHOR_TAG, mirrorBody(entry(1, one, 1), "testnet"), 1, null));
    const b2 = relay.seedPosted(ANCHOR_TAG, signer.seal(ANCHOR_TAG, mirrorBody(entry(2, two, 2), "testnet"), 5, b1));

    expect(await new AnchorLoop(deps).runOnce()).toMatchObject({ status: "anchored", seq: 3 });
    const state = store.load()!;
    expect(state.checkpoints.map((c) => c.mirror)).toEqual([
      expect.objectContaining({ status: "posted", blockId: b1, envelopeSeq: 1, recovered: true }),
      expect.objectContaining({ status: "posted", blockId: b2, envelopeSeq: 5, recovered: true }),
      expect.objectContaining({ status: "posted", envelopeSeq: 6 }),
    ]);
    const third = relay.posted.at(-1)!.env;
    expect([third.seq, third.prev]).toEqual([6, b2]);
  });

  it("does not adopt a receipt whose block mirrors another checkpoint", async () => {
    const { loop, relay, store, restart, signer } = setup({}, 12);
    relay.down = true;
    await loop.runOnce(); // checkpoint 1 anchored, mirror pending
    relay.down = false;
    const entry = store.load()!.checkpoints[0]!;
    // Something else already went out under seq 1 for this issuer.
    relay.seedPosted(ANCHOR_TAG, signer.seal(ANCHOR_TAG, mirrorBody({ ...entry, checkpointHash: "0x" + "00".repeat(32) }, "testnet"), 1, null));
    await restart().runOnce();
    expect(store.load()!.checkpoints[0]!.mirror).toBeNull();
    expect(store.load()!.mirror.lastSeq).toBe(1);
    await restart().runOnce();
    expect(store.load()!.checkpoints[0]!.mirror).toMatchObject({ status: "posted", envelopeSeq: 2 });
    expect(store.load()!.checkpoints[0]!.mirror).not.toHaveProperty("recovered");
  });

  it("refuses to rebuild a chain made for another policy, domain or Tangle", async () => {
    const { deps, trail, tangle, store } = setup({}, 24);
    const one = await buildNextCheckpoint(tangle, PARAMS, null, 1, 12);
    if (one.status !== "ready") throw new Error("expected a checkpoint");
    trail.seed(1, one.checkpoint, one.checkpointHash);
    const otherPolicy = new AnchorLoop({ ...deps, params: { ...PARAMS, policyHash: new Uint8Array(32) } });
    expect(await otherPolicy.runOnce()).toMatchObject({ status: "error", stage: "state", error: expect.stringMatching(/policyHash/) });
    const otherDomain = new AnchorLoop({ ...deps, params: { ...PARAMS, domain: "Elsewhere" } });
    expect(await otherDomain.runOnce()).toMatchObject({ status: "error", stage: "state", error: expect.stringMatching(/domain/) });
    expect(store.load()).toBeNull();
    expect(trail.appends).toBe(0);
  });

  it("will not continue a chain under another network or domain", async () => {
    const { deps, loop, trail } = setup({}, 24);
    await loop.runOnce();
    const moved = new AnchorLoop({ ...deps, params: { ...PARAMS, network: "private_tangle2" } });
    expect(await moved.runOnce()).toMatchObject({ status: "error", stage: "state", error: expect.stringMatching(/private_tangle2/) });
    expect(trail.appends).toBe(1);
  });

  it("ignores checkpoint records added by another address when rebuilding", async () => {
    const { deps, trail, tangle, store } = setup({}, 12);
    const one = await buildNextCheckpoint(tangle, PARAMS, null, 1, 12);
    if (one.status !== "ready") throw new Error("expected a checkpoint");
    trail.seed(1, one.checkpoint, one.checkpointHash, "0x" + "ee".repeat(32));
    expect(await new AnchorLoop(deps).runOnce()).toMatchObject({ status: "anchored", seq: 1, record: 2 });
    expect(store.load()!.checkpoints).toHaveLength(1);
  });

  it("refuses a state file that belongs to another trail", async () => {
    const { loop, store, trail } = setup();
    const foreign: AnchorState = { v: 1, network: "testnet", trail: "0x" + "9".repeat(64), checkpoints: [], pending: null, mirror: { lastSeq: 0, lastBlockId: null } };
    store.save(foreign);
    expect(await loop.runOnce()).toMatchObject({ status: "error", stage: "trail", error: expect.stringMatching(/move it aside/) });
    expect(trail.appends).toBe(0);
  });

  it("refuses a tampered state file", async () => {
    const { loop, store, trail } = setup({}, 24);
    await loop.runOnce();
    const s = store.load()!;
    s.checkpoints[0]!.checkpoint.msRoot = "0x" + "00".repeat(32);
    store.save(s);
    expect(await loop.runOnce()).toMatchObject({ status: "error", stage: "state", error: expect.stringMatching(/hash/) });
    expect(trail.appends).toBe(1);
  });
});
