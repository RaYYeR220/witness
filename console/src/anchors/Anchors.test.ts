// @vitest-environment jsdom
/**
 * The anchors re-check against a mocked IOTA Rebased RPC that answers with
 * the recorded testnet responses of core/tests/vectors/rebased_record.json
 * (record 4 of an Audit Trail), so the reader runs on real chain data.
 */
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { LiveAdapter, type AnchorCheckpoint, type WitnessData } from "@/api/client";
import { mountScreen, until } from "@/test/mount";
import { rebasedRecord as V } from "@/test/vectors";
import AnchorsView from "@/views/AnchorsView.vue";

import { recheckAnchor, selfConsistent } from "./recheck";

const PKG = "0x51368931f28620c7f65b4ae2c5167b42390e69729357a6347be378755b46e7df";
const WRITER = "0xd40892daf5c81e3d67ffe9806575970b973ecf6625eb8a88562afae0d8c940c8";

vi.mock("@/verify/pinned", () => {
  const PINNED = Object.freeze({
    network: "private_tangle1",
    trustedCoordinatorKeys: [],
    threshold: 2,
    rebasedNetwork: "testnet",
    trailId: "0xacb73c8f648cdb335e6644af7e52746c6a8d166e4ffced17826c7861ffbf3540",
    rebasedRpc: "https://api.testnet.iota.cafe",
    auditTrailPackage: "0x51368931f28620c7f65b4ae2c5167b42390e69729357a6347be378755b46e7df",
    anchorWriter: "0xd40892daf5c81e3d67ffe9806575970b973ecf6625eb8a88562afae0d8c940c8",
  });
  return { PINNED, pinnedConfig: () => ({ ...PINNED }), anchorPinned: () => true, anchorFetcher: () => null };
});

const PINS = { rebasedRpc: V.rpc as string, trailId: V.trail as string, auditTrailPackage: PKG, anchorWriter: WRITER };
const FIELDS = V.record.result.data.content.fields.value.fields.value.fields;
const CP = JSON.parse(FIELDS.data.fields.pos0);
const HASH: string = JSON.parse(FIELDS.metadata).checkpointHash;

/** The explorer's row for record 4, as GET /anchors would list it. */
function row(edit: Partial<AnchorCheckpoint> = {}): AnchorCheckpoint {
  return {
    seq: 1,
    fromMilestone: CP.from.index,
    toMilestone: CP.to.index,
    msRoot: CP.msRoot,
    checkpoint: structuredClone(CP),
    checkpointHash: HASH,
    network: "testnet",
    tx: "8L3KZB5SN8Dd7UTorJ6sUqC3DFyuatJ6WPvuSQZummtu",
    record: V.index,
    status: "anchored",
    createdAtMs: 1791315600518,
    ...edit,
  };
}

/** A JSON-RPC endpoint answering from the vector; `missing` answers as if the trail had no such record. */
function rpc({ missing = false, status = 200 } = {}) {
  const calls: string[] = [];
  const f = vi.fn(async (url: string, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body));
    calls.push(`${url} ${body.method}`);
    if (status !== 200) return new Response("down", { status });
    if (body.method === "iota_getObject") return Response.json(V.trailObject);
    if (missing) return Response.json({ jsonrpc: "2.0", id: 1, result: { error: { code: "dynamicFieldNotFound" } } });
    return Response.json(V.record);
  });
  return { f: f as unknown as typeof fetch, calls };
}

afterEach(() => {
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

describe("recheckAnchor", () => {
  it("reads the record from the pinned trail and finds every field the same", async () => {
    const { f, calls } = rpc();
    const r = await recheckAnchor(row(), PINS, { fetch: f });
    expect(r.verdict).toBe(true);
    expect(r.rows.map((x) => [x.what, x.c])).toEqual([
      ["Checkpoint hash", "same"],
      ["Milestones", "same"],
      ["Milestone root", "same"],
      ["Messages committed", "same"],
      ["Writer policy hash", "same"],
      ["Previous checkpoint", "same"],
      ["Writer, as pinned here", "same"],
    ]);
    expect(calls).toEqual([`${V.rpc} iota_getObject`, `${V.rpc} iotax_getDynamicFieldObject`]);
  });

  it("catches an explorer that shows another root or window than the chain holds", async () => {
    const r = await recheckAnchor(row({ msRoot: "0x" + "ee".repeat(32), toMilestone: CP.to.index + 1 }), PINS, { fetch: rpc().f });
    expect(r.verdict).toBe(false);
    expect(r.rows.filter((x) => x.c === "differs").map((x) => x.what)).toEqual(["Milestones", "Milestone root"]);
  });

  it("asks the pinned trail, never one the explorer could name, and checks who wrote the record", async () => {
    const r = await recheckAnchor(row(), { ...PINS, anchorWriter: "0x" + "99".repeat(32) }, { fetch: rpc().f });
    expect(r.verdict).toBe(false);
    expect(r.rows.find((x) => x.what === "Writer, as pinned here")!.c).toBe("differs");
  });

  it("says a missing record is missing, and an unreadable chain unread", async () => {
    const missing = await recheckAnchor(row(), PINS, { fetch: rpc({ missing: true }).f });
    expect(missing.verdict).toBe(false);
    expect(missing.problem).toContain("holds no record 4");
    const down = await recheckAnchor(row(), PINS, { fetch: rpc({ status: 503 }).f });
    expect(down.verdict).toBeNull();
    expect(down.problem).toContain("HTTP 503");
    expect(down.rows).toEqual([]);
    const unpinned = await recheckAnchor(row(), { ...PINS, trailId: null }, { fetch: rpc().f });
    expect(unpinned.verdict).toBeNull();
  });

  it("checks in the browser that the explorer's checkpoint document hashes to its stated hash", () => {
    expect(selfConsistent(row())).toBe(true);
    expect(selfConsistent(row({ checkpoint: { ...CP, msgCount: CP.msgCount + 1 } }))).toBe(false);
  });
});

describe("Anchors screen", () => {
  function data(items: AnchorCheckpoint[]): WitnessData {
    return Object.assign(Object.create(new LiveAdapter("/api")), {
      health: async () => ({ mode: "live", ok: true, network: "private_tangle1", version: "test", note: null }),
      anchors: async () => items,
    }) as WitnessData;
  }

  it("re-checks a checkpoint from the browser and shows the comparison", async () => {
    const { f, calls } = rpc();
    vi.stubGlobal("fetch", f);
    const { w } = await mountScreen(AnchorsView, { path: "/anchors", data: data([row()]) });
    await until(() => w.find(".cp").exists());
    expect(w.find(".cp").text()).toContain(`Milestones ${CP.from.index}–${CP.to.index}`);
    const tx = w.find('.cp a[target="_blank"]');
    expect(tx.attributes("href")).toBe("https://explorer.iota.org/txblock/8L3KZB5SN8Dd7UTorJ6sUqC3DFyuatJ6WPvuSQZummtu?network=testnet");
    await w.find(".re .btn").trigger("click");
    await until(() => w.find(".res .verdict").exists());
    expect(w.find(".res .verdict").attributes("data-v")).toBe("true");
    expect(w.find(".res .verdict").text()).toContain("The chain agrees");
    expect(w.findAll(".res tbody tr").every((r) => r.attributes("data-c") === "same")).toBe(true);
    expect(calls.every((c) => c.startsWith(V.rpc))).toBe(true);
    const res = await axe.run(document.body, { rules: { "color-contrast": { enabled: false } } });
    const bad = res.violations.filter((v) => v.impact === "critical" || v.impact === "serious");
    expect(bad.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`)).toEqual([]);
    w.unmount();
  });

  it("links each checkpoint to the one before it, and flags a broken link", async () => {
    vi.stubGlobal("fetch", rpc().f);
    const older = row({ seq: 1, record: 1, checkpointHash: "0x" + "11".repeat(32), checkpoint: { ...CP, prev: null } });
    const good = row({ seq: 2, record: 2, checkpoint: { ...CP, prev: "0x" + "11".repeat(32) } });
    const { w } = await mountScreen(AnchorsView, { path: "/anchors", data: data([good, older]) });
    await until(() => w.findAll(".cp").length === 2);
    expect(w.findAll(".cp")[0]!.find(".chain").text()).toContain("follows checkpoint 1");
    expect(w.findAll(".cp")[1]!.text()).toContain("the first checkpoint");
    w.unmount();
    const bad = row({ seq: 2, record: 2, checkpoint: { ...CP, prev: "0x" + "22".repeat(32) } });
    const { w: w2 } = await mountScreen(AnchorsView, { path: "/anchors", data: data([bad, older]) });
    await until(() => w2.findAll(".cp").length === 2);
    const first = w2.findAll(".cp")[0]!;
    expect(first.find('.chain .x-cmp[data-c="differs"]').text()).toContain("not checkpoint 1");
    // its document was edited, so it no longer hashes to the hash shown: the browser says so without asking anyone
    expect(first.text()).toContain("the explorer's own document does not hash to it");
    w2.unmount();
  });
});
