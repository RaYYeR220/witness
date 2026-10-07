// @vitest-environment jsdom
import { flushPromises, mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";

import { DataError, type RecheckResult, type WitnessData } from "@/api/client";

import { DATA_KEY } from "./data";
import NodeChecks from "./NodeChecks.vue";

const A = "0x" + "aa".repeat(32);
const B = "0x" + "bb".repeat(32);
const checks = { solid: { check: "c", via: "", ok: true, referencedByMilestoneIndex: 7 }, content: { check: "d", via: "", ok: true, result: "MATCH" } };

function mountWith(recheck: (id: string) => Promise<RecheckResult>) {
  const data = { mode: "live", recheck } as unknown as WitnessData;
  return mount(NodeChecks, {
    props: { blockId: A, lifecycle: null, lifecycleError: null },
    global: { provide: { [DATA_KEY as symbol]: data } },
  });
}

describe("NodeChecks", () => {
  it("says when the node's answer is the stored, cached one", async () => {
    const w = mountWith(async (id) => ({ blockId: id, status: "CONTENT_VERIFIED", concluded: true, cached: true, timedOut: false, startedAtMs: 0, finishedAtMs: 1, checks, calls: [] }) as unknown as RecheckResult);
    await w.find("button").trigger("click");
    await flushPromises();
    expect(w.find(".note").text()).toContain("cached");
  });

  it("counts down a 429 and forgets it all when the block changes", async () => {
    const w = mountWith(async () => {
      throw new DataError("busy", 429, 9);
    });
    await w.find("button").trigger("click");
    await flushPromises();
    expect(w.find(".note").text()).toContain("Try again in 9 s");
    expect(w.find("button").attributes("disabled")).toBeDefined();
    await w.setProps({ blockId: B });
    expect(w.find(".note").exists()).toBe(false);
    expect(w.find("button").attributes("disabled")).toBeUndefined();
    w.unmount();
  });
});
