// @vitest-environment jsdom
import { mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";
import { nextTick } from "vue";

import { wired } from "@/test/vectors";
import { createLadder, runLadder } from "@/verify/ladder";

import LadderPanel from "./LadderPanel.vue";

const NAMES = ["block_hash", "inclusion", "milestone_signatures", "envelope", "anchor"];

/** Runs a vector case through the ladder with the panel mounted, recording what the DOM shows after each step. */
async function climb(name: string) {
  const state = createLadder();
  const w = mount(LadderPanel, { props: { state, anchorPinned: true } });
  const frames: string[][] = [];
  const marks = () => w.findAll("li.step").map((li) => li.attributes("data-s")!);
  const { text, config, lookups } = wired(name);
  const ladder = await runLadder(state, text, {
    config,
    ...lookups,
    onStep: async () => {
      await nextTick();
      frames.push(marks());
    },
  });
  await nextTick();
  return { w, frames, ladder, marks };
}

describe("LadderPanel", () => {
  it("climbs a valid bundle: five green steps, in ladder order", async () => {
    const { w, frames, ladder, marks } = await climb("valid_anchored");
    expect(ladder?.overall).toBe("VALID");
    expect(w.findAll("li.step").map((li) => li.attributes("data-step"))).toEqual(NAMES);
    // after step k is decided, steps 1..k are green, k+1 is running, the rest are waiting
    expect(frames).toEqual([
      ["pass", "running", "waiting", "waiting", "waiting"],
      ["pass", "pass", "running", "waiting", "waiting"],
      ["pass", "pass", "pass", "running", "waiting"],
      ["pass", "pass", "pass", "pass", "running"],
      ["pass", "pass", "pass", "pass", "pass"],
    ]);
    expect(marks()).toEqual(["pass", "pass", "pass", "pass", "pass"]);
    expect(w.find(".overall").attributes("data-o")).toBe("VALID");
    expect(w.find(".overall").text()).toContain("All five checks passed in your browser");
    // each step shows the library's own detail
    expect(w.find('[data-step="block_hash"] .detail').text()).toMatch(/^BLAKE2b-256\(raw\) = 0x[0-9a-f]{64}$/);
  });

  it.each([
    ["raw_byte_flipped", 1, "block_hash"],
    ["path_hash_corrupted", 2, "inclusion"],
    ["signature_corrupted", 3, "milestone_signatures"],
    ["envelope_forged", 4, "envelope"],
    ["anchor_mismatch", 5, "anchor"],
  ])("turns the negative twin %s red at step %i", async (name, n, step) => {
    const { w, ladder } = await climb(name);
    expect(ladder?.overall).toBe("INVALID");
    const failed = w.findAll("li.step").filter((li) => li.attributes("data-s") === "fail");
    expect(failed[0]!.attributes("data-step")).toBe(step);
    expect(w.find(".overall").attributes("data-o")).toBe("INVALID");
    expect(w.find(".overall").text()).toContain(`Check ${n}`);
    expect(w.find(`[data-step="${step}"] .detail`).text().length).toBeGreaterThan(0);
  });

  it("says partial when a check cannot be evaluated, never valid", async () => {
    const { w, ladder } = await climb("anchor_unreachable");
    expect(ladder?.overall).toBe("PARTIAL");
    expect(w.find('[data-step="anchor"]').attributes("data-s")).toBe("unknown");
    expect(w.find(".overall").text()).toContain("Partial is not a pass");
  });
});
