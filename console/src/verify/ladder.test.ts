import { describe, expect, it } from "vitest";

import { createLadder, resetLadder, runLadder, stepValue, type StepView } from "./ladder";
import { bundleText, rawBytes, scoreDigitIndex, blockFields, trustedLookups, verifierConfig, type Which } from "./sample";

function run(which: Which, raw?: Uint8Array) {
  const state = createLadder();
  const seen: { name: string; status: string; at: string[] }[] = [];
  const promise = runLadder(state, bundleText(which, raw), verifierConfig(which), {
    ...trustedLookups(which),
    onStep: (step: StepView, s) => seen.push({ name: step.name, status: step.status, at: s.steps.map((x) => x.status) }),
  });
  return { state, seen, promise };
}

describe("runLadder over the landing sample", () => {
  it("lights five passed steps, in ladder order, from the library's onStep", async () => {
    const { state, seen, promise } = run("sample");
    expect(state.running).toBe(true);
    expect(state.steps[0]!.status).toBe("running");
    const ladder = await promise;

    expect(ladder?.overall).toBe("VALID");
    expect(seen.map((s) => s.name)).toEqual(["block_hash", "inclusion", "milestone_signatures", "envelope", "anchor"]);
    expect(seen.every((s) => s.status === "pass")).toBe(true);
    // when step k is reported, the steps after it have not been decided yet
    seen.forEach((s, k) => {
      expect(s.at.slice(0, k + 1).every((x) => x === "pass")).toBe(true);
      if (k < 4) expect(s.at[k + 1]).toBe("running");
      expect(s.at.slice(k + 2).every((x) => x === "waiting")).toBe(true);
    });
    expect(state.overall).toBe("VALID");
    expect(state.failedAt).toBeNull();
    expect(state.running).toBe(false);
    expect(state.computeMs).toBeGreaterThanOrEqual(0);
    expect(state.steps.map((s) => s.detail.length > 0)).toEqual([true, true, true, true, true]);
  });

  it("stops the forged twin at step 4, the sender signature", async () => {
    const { state, promise } = run("forged");
    const ladder = await promise;
    expect(ladder?.overall).toBe("INVALID");
    expect(state.steps.map((s) => s.status)).toEqual(["pass", "pass", "pass", "fail", "pass"]);
    expect(state.failedAt).toBe(4);
    expect(state.steps[3]!.detail).toMatch(/^FORGED/);
    expect(stepValue(state.steps[3]!)).toBe("signature rejected");
  });

  it("turns step 1 red when one byte of the block is flipped", async () => {
    const raw = rawBytes("sample");
    const i = scoreDigitIndex(raw, blockFields(raw));
    raw[i]! ^= 1;
    const { state, promise } = run("sample", raw);
    const ladder = await promise;
    expect(ladder?.overall).toBe("INVALID");
    expect(state.failedAt).toBe(1);
    expect(state.steps[0]!.status).toBe("fail");
    // the flipped byte sits in the signed envelope, so the sender signature breaks too
    expect(state.steps[3]!.status).toBe("fail");
    // the Merkle path and the milestone are checked against the claimed id: still fine
    expect(state.steps[1]!.status).toBe("pass");
    expect(state.steps[2]!.status).toBe("pass");
  });

  it("flips the hundredths digit of the score", () => {
    const raw = rawBytes("sample");
    const i = scoreDigitIndex(raw, blockFields(raw));
    expect(String.fromCharCode(raw[i]!)).toBe("2"); // "score":0.82
  });

  it("drops a run that a newer run superseded", async () => {
    const state = createLadder();
    const first = runLadder(state, bundleText("forged"), verifierConfig("forged"), { ...trustedLookups("forged"), pace: 5 });
    const second = runLadder(state, bundleText("sample"), verifierConfig("sample"), trustedLookups("sample"));
    expect(await first).toBeNull();
    expect((await second)?.overall).toBe("VALID");
    expect(state.steps.every((s) => s.status === "pass")).toBe(true);
  });

  it("can be reset mid-run", async () => {
    const state = createLadder();
    const p = runLadder(state, bundleText("sample"), verifierConfig("sample"), { ...trustedLookups("sample"), pace: 5 });
    resetLadder(state);
    expect(await p).toBeNull();
    expect(state.steps.every((s) => s.status === "waiting")).toBe(true);
  });

  it("leaves steps 4 and 5 unevaluated without trusted lookups", async () => {
    const state = createLadder();
    const ladder = await runLadder(state, bundleText("sample"), verifierConfig("sample"));
    expect(ladder?.overall).toBe("PARTIAL");
    expect(state.steps.map((s) => s.status)).toEqual(["pass", "pass", "pass", "unknown", "unknown"]);
  });

  it("fails all five steps on text that is not a bundle", async () => {
    const state = createLadder();
    await runLadder(state, "{not json", verifierConfig("sample"));
    expect(state.steps.map((s) => s.status)).toEqual(["fail", "fail", "fail", "fail", "fail"]);
    expect(state.failedAt).toBe(1);
  });
});
