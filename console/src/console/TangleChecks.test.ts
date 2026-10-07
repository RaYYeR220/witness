// @vitest-environment jsdom
import { flushPromises, mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";

import { DataError, type Checks, type RecheckResult, type WitnessData } from "@/api/client";

import { DATA_KEY } from "./data";
import TangleChecks from "./TangleChecks.vue";

const A = "0x" + "aa".repeat(32);
const B = "0x" + "bb".repeat(32);
const checks = { solid: { check: "c", via: "", ok: true, referencedByMilestoneIndex: 7 }, content: { check: "d", via: "", ok: true, result: "MATCH" } };

function mountWith(recheck: (id: string) => Promise<RecheckResult>) {
  const data = { mode: "live", recheck } as unknown as WitnessData;
  return mount(TangleChecks, {
    props: { blockId: A, recorded: null, recordedError: null },
    global: { provide: { [DATA_KEY as symbol]: data } },
  });
}

describe("TangleChecks", () => {
  it("shows the brief's (c) and (d) with the explorer's recorded results and when it checked", () => {
    const at = 1791331070000;
    const recorded = {
      solid: { check: "c", via: "GET /api/core/v2/blocks/{blockId}/metadata", ok: true, referencedByMilestoneIndex: 1433, ledgerInclusionState: "noTransaction", checkedAtMs: at },
      content: { check: "d", via: "GET /api/core/v2/blocks/{blockId}", ok: true, result: "MATCH", checkedAtMs: at + 1000 },
    } as Checks;
    const w = mount(TangleChecks, {
      props: { blockId: A, recorded, recordedError: null },
      global: { provide: { [DATA_KEY as symbol]: { mode: "live" } as unknown as WitnessData } },
    });
    const [c, d] = w.findAll(".tc li");
    expect(c!.find(".name").text()).toBe("(c) Solid on the Tangle");
    expect(c!.find(".via").text()).toBe("via HORNET GET /api/core/v2/blocks/{blockId}/metadata");
    expect(c!.find(".res").text()).toBe("Yes, solid, referenced by milestone 1433, noTransaction.");
    expect(c!.find(".when").text()).toBe("checked by the explorer at 2026-10-06 23:57:50 UTC");
    expect(d!.find(".name").text()).toBe("(d) Same content as on the Tangle");
    expect(d!.find(".via").text()).toBe("via HORNET GET /api/core/v2/blocks/{blockId}");
    expect(d!.find(".res").text()).toContain("Match");
    // a mismatch is red; nothing here is green (it is the explorer's word)
    const bad = mount(TangleChecks, {
      props: { blockId: A, recorded: { ...recorded, content: { ...recorded.content, ok: false, result: "MISMATCH" } } as Checks, recordedError: null },
      global: { provide: { [DATA_KEY as symbol]: { mode: "live" } as unknown as WitnessData } },
    });
    expect(bad.findAll(".tc li")[1]!.attributes("data-tone")).toBe("no");
    expect(w.text()).toContain("not a check made in your browser");
  });

  it("says when the explorer has not checked yet, and never shows a route it does not know", () => {
    const w = mount(TangleChecks, {
      props: { blockId: A, recorded: { solid: { check: "c", via: "javascript:alert(1)", ok: null }, content: { check: "d", via: "", ok: null } }, recordedError: null },
      global: { provide: { [DATA_KEY as symbol]: { mode: "live" } as unknown as WitnessData } },
    } as never);
    expect(w.findAll(".tc .res").map((r) => r.text())).toEqual(["Not checked yet.", "Not checked yet."]);
    expect(w.find(".tc .via").text()).toBe("via HORNET GET /api/core/v2/blocks/{blockId}/metadata");
    expect(w.findAll(".tc .when").map((r) => r.text())).toEqual(["not checked by the explorer yet", "not checked by the explorer yet"]);
  });

  it("says when the node's answer is the stored, cached one", async () => {
    const w = mountWith(async (id) => ({ blockId: id, status: "CONTENT_VERIFIED", concluded: true, cached: true, timedOut: false, startedAtMs: 0, finishedAtMs: 1, checks, calls: [] }) as unknown as RecheckResult);
    await w.find("button").trigger("click");
    await flushPromises();
    expect(w.find(".note").text()).toContain("cached");
    expect(w.emitted("rechecked")).toHaveLength(1);
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
