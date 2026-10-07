import { describe, expect, it } from "vitest";

import { placeByTime, type FeedRow } from "./feed";

const row = (key: string, atMs: number | null): FeedRow => ({ kind: "milestone", key, index: 1, blocks: 1, messages: 0, atMs });
const keys = (list: FeedRow[]) => list.map((r) => r.key);

describe("placeByTime", () => {
  it("keeps the feed newest first, wherever a row arrives from", () => {
    let list: FeedRow[] = [];
    for (const r of [row("b", 200), row("d", 400), row("a", 100), row("c", 300)]) list = placeByTime(list, r);
    expect(keys(list)).toEqual(["d", "c", "b", "a"]);
  });

  it("puts the newest arrival first among equal times, and timeless rows on top", () => {
    let list = [row("x", 100)];
    list = placeByTime(list, row("y", 100));
    list = placeByTime(list, row("n", null));
    expect(keys(list)).toEqual(["n", "y", "x"]);
  });

  it("replaces an earlier copy of the same row and caps the length", () => {
    let list = [row("a", 300), row("b", 200)];
    list = placeByTime(list, row("b", 400));
    expect(keys(list)).toEqual(["b", "a"]);
    expect(keys(placeByTime(list, row("c", 100), 2))).toEqual(["b", "a"]);
  });
});

describe("lifecycleSteps", () => {
  it("marks reported steps, implies earlier ones and appends a bad outcome", async () => {
    const { lifecycleSteps } = await import("./feed");
    const s = lifecycleSteps(new Map([["CONFIRMED", 5]]));
    expect(s.map((x) => [x.status, x.reached, x.atMs])).toEqual([
      ["RECEIVED", true, null],
      ["SUBMITTED", true, null],
      ["SOLID", true, null],
      ["CONFIRMED", true, 5],
      ["CONTENT_VERIFIED", false, null],
    ]);
    const bad = lifecycleSteps(new Map([["SUBMITTED", 1], ["ORPHANED", 9]]));
    expect(bad.map((x) => [x.status, x.bad])).toEqual([
      ["RECEIVED", false],
      ["SUBMITTED", false],
      ["ORPHANED", true],
    ]);
  });
});
