import { describe, expect, it } from "vitest";

import { keepEvents, lastAnchored, namedIn, pickMessages, REPORT_CSP, withCsp } from "./record-replay.mjs";

const id = (n: number) => `0x${n.toString(16).padStart(64, "0")}`;

describe("record-replay", () => {
  it("puts the API's report CSP into a recorded report page, first thing in <head>", () => {
    const page = '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>r</title></head><body>x</body></html>';
    const out = withCsp(page);
    expect(out).toContain(`<head><meta http-equiv="Content-Security-Policy" content="${REPORT_CSP}"><meta charset="utf-8">`);
    expect(REPORT_CSP).toContain("default-src 'none'");
    expect(withCsp("<p>no head</p>").startsWith("<!doctype html><head><meta http-equiv")).toBe(true);
  });

  it("reads the block ids and blind tokens a trials file names", () => {
    const text = [
      JSON.stringify({ class: "A01", blockId: "0x" + id(1).slice(2).toUpperCase(), alertRows: [{ blockId: id(1) }] }),
      JSON.stringify({ class: "A13", blockId: id(2), detail: { firstBlockId: id(3) } }),
      JSON.stringify({ class: "A11", blockId: id(4), detail: { blindToken: "o8iiZamgGYx_8EXjUxpm2mbNqotARutsGQmXrYuQBHc" } }),
      JSON.stringify({ class: "A18", blockId: null, detail: { subId: "x" } }),
    ].join("\n");
    const { ids, tokens } = namedIn(text);
    expect(ids.sort()).toEqual([id(1), id(2), id(3), id(4)]);
    expect(tokens).toEqual(["o8iiZamgGYx_8EXjUxpm2mbNqotARutsGQmXrYuQBHc"]);
  });

  it("cuts at the last anchored checkpoint, never a pending one", () => {
    expect(
      lastAnchored([
        { status: "pending", toMilestone: 2160, createdAtMs: 3 },
        { status: "anchored", toMilestone: 1440, createdAtMs: 2 },
        { status: "anchored", toMilestone: 720, createdAtMs: 1 },
      ]),
    ).toEqual({ milestone: 1440, atMs: 2 });
    expect(lastAnchored([{ status: "failed", toMilestone: 720 }])).toBeNull();
  });

  it("lists the newest, the named and a sample of each kind, in the API's order", () => {
    const m = (n: number, tag: string, verdict: string, encrypted = false) => ({ blockId: id(n), tag, verdict, encrypted });
    const scan = [
      m(9, "trust.score", "PRODUCER_SIGNED"),
      m(8, "trust.score", "PRODUCER_SIGNED"),
      m(7, "trust.score", "PRODUCER_SIGNED"),
      m(6, "LLO-K8s", "RELAY_ATTESTED"),
      m(5, "LLO-K8s", "RELAY_ATTESTED"),
      m(4, "trust.score", "FORGED"),
      m(3, "audit.report", "RELAY_ATTESTED", true),
      m(2, "audit.report", "RELAY_ATTESTED", true),
      m(1, "trust.score", "PRODUCER_SIGNED"),
    ];
    expect(pickMessages(scan, { limit: 2 }).map((x) => x.blockId)).toEqual([id(9), id(8)]);
    expect(pickMessages(scan, { limit: 1, include: [id(1), id(42)] }).map((x) => x.blockId)).toEqual([id(9), id(1)]);
    expect(pickMessages(scan, { limit: 1, sample: 1 }).map((x) => x.blockId)).toEqual([id(9), id(6), id(4), id(3)]);
    // an excluded block is never listed, however it would have been picked
    expect(pickMessages(scan, { limit: 2, include: [id(4)], sample: 1, exclude: [id(9), id(4), id(3)] }).map((x) => x.blockId)).toEqual([
      id(8),
      id(7),
      id(6),
      id(2),
    ]);
  });

  it("plays back only what the snapshot holds, up to the cut", () => {
    const recorded = new Set([id(1), id(2)]);
    const ev = (n: number, type: string, payload: Record<string, unknown>, atMs = n) => ({ id: n, type, atMs, payload });
    const events = [
      ev(1, "message", { blockId: id(1), msIndex: 10 }),
      ev(2, "lifecycle", { blockId: id(1), status: "CONFIRMED" }),
      ev(3, "message", { blockId: id(9), msIndex: 11 }), // not recorded
      ev(4, "milestone", { index: 20 }),
      ev(5, "milestone", { index: 21 }), // past the cut
      ev(6, "anchor", { from: 1, to: 20 }),
      ev(7, "message", { blockId: id(2), msIndex: 21 }), // recorded, but past the cut
      ev(8, "alert", { rule: "SHADOW" }, 1000),
      ev(9, "alert", { rule: "STALE" }, 1000 + 60_001), // more than a minute after the checkpoint
    ];
    const kept = keepEvents(events, { keep: 10, cut: 20, untilMs: 1000, recorded });
    expect(kept.map((e) => e.id)).toEqual([1, 2, 4, 6, 8]);
    expect(keepEvents(events, { keep: 2, cut: 20, untilMs: 1000, recorded }).map((e) => e.id)).toEqual([6, 8]);
    expect(keepEvents(events, { keep: 10, recorded }).map((e) => e.id)).toEqual([1, 2, 4, 5, 6, 7, 8, 9]);
  });
});
