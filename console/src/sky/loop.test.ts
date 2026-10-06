import { describe, expect, it } from "vitest";

import { needsFrame, traceAnimating, type LoopState, type TraceTiming } from "./loop";

const base: LoopState = { onScreen: true, hidden: false, still: false, p: 0, skyAlpha: 1, trace: null };
const trace = (t: Partial<TraceTiming>): TraceTiming => ({ hops: 2, elapsedHops: 0, toLadder: false, plumbFired: false, ...t });

describe("needsFrame", () => {
  it("animates the idle sky only while it is on screen and visible", () => {
    expect(needsFrame(base)).toBe(true);
    expect(needsFrame({ ...base, onScreen: false })).toBe(false);
    expect(needsFrame({ ...base, hidden: true })).toBe(false);
    expect(needsFrame({ ...base, p: 0.5, skyAlpha: 0 })).toBe(false);
    expect(needsFrame({ ...base, still: true })).toBe(false);
  });

  it("stops after a plain-block trace has finished drawing", () => {
    const s = { ...base, p: 0.5, skyAlpha: 0.5 };
    expect(needsFrame({ ...s, trace: trace({ elapsedHops: 1 }) })).toBe(true);
    expect(needsFrame({ ...s, trace: trace({ elapsedHops: 2 }) })).toBe(false);
    expect(needsFrame({ ...s, trace: trace({ elapsedHops: 1e6 }) })).toBe(false);
  });

  it("waits for the plumb line of a trust message, then stops", () => {
    const s = { ...base, p: 0.5, skyAlpha: 0.5 };
    expect(needsFrame({ ...s, trace: trace({ elapsedHops: 9, toLadder: true }) })).toBe(true);
    expect(needsFrame({ ...s, trace: trace({ elapsedHops: 9, toLadder: true, plumbFired: true }) })).toBe(false);
  });

  it("stops a trace that is no longer visible: past the sky, off screen, hidden", () => {
    const running = trace({ elapsedHops: 0.5, toLadder: true });
    expect(needsFrame({ ...base, p: 0.6, skyAlpha: 0, trace: running })).toBe(false);
    expect(needsFrame({ ...base, onScreen: false, trace: running })).toBe(false);
    expect(needsFrame({ ...base, hidden: true, trace: running })).toBe(false);
  });

  it("with reduced motion, runs only until the trace's plumb line has fired", () => {
    const still = { ...base, still: true };
    expect(needsFrame({ ...still, trace: trace({ elapsedHops: Infinity, toLadder: true }) })).toBe(true);
    expect(needsFrame({ ...still, trace: trace({ elapsedHops: Infinity, toLadder: true, plumbFired: true }) })).toBe(false);
    expect(needsFrame({ ...still, trace: trace({ elapsedHops: Infinity }) })).toBe(false);
    expect(needsFrame({ ...still, onScreen: false, trace: trace({ elapsedHops: Infinity, toLadder: true }) })).toBe(false);
  });

  it("treats a trace as animating only while its sky is visible", () => {
    expect(traceAnimating({ skyAlpha: 0.01, trace: trace({}) })).toBe(false);
    expect(traceAnimating({ skyAlpha: 0.5, trace: null })).toBe(false);
  });
});
