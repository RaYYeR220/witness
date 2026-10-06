// @vitest-environment jsdom
import axe from "axe-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { Lifecycle, Message, WitnessData } from "@/api/client";
import { mountScreen, until } from "@/test/mount";
import { bundleCase, wired } from "@/test/vectors";
import type { TrustedLookups } from "@/verify/lookups";

import VerifyView from "./VerifyView.vue";

// The screen verifies against the console's pins; here they are the vectors' pins.
vi.mock("@/verify/pinned", async () => {
  const { bundleCase: c } = await import("@/test/vectors");
  const cfg = c("valid_anchored").config;
  const PINNED = Object.freeze({ ...cfg, rebasedRpc: "https://rpc.example", auditTrailPackage: "0x" + "51".repeat(32), anchorWriter: null });
  return {
    PINNED,
    pinnedConfig: () => ({ ...PINNED, trustedCoordinatorKeys: [...PINNED.trustedCoordinatorKeys] }),
    anchorPinned: () => true,
    anchorFetcher: () => null,
  };
});

function fakeData(name: string, verdict: string): { data: WitnessData; lookups: TrustedLookups; blockId: string } {
  const c = bundleCase(name);
  const w = wired(name);
  const blockId: string = c.bundle.block.id;
  const message = {
    blockId,
    tag: "trust.score",
    kind: "trust.score",
    verdict,
    status: "CONTENT_VERIFIED",
    ieId: "MyDomain:fa163e5e25ef",
    iss: "did:iota:testnet:0x5e1f",
    kid: "did:iota:testnet:0x5e1f#sig-1",
    encrypted: false,
    msIndex: c.bundle.milestone.index,
    issuedAtMs: 1791283579000,
    dateMs: 1791283579000,
    json: { w: 1, tag: "trust.score", body: { id: "MyDomain:fa163e5e25ef", score: 0.82 }, sig: "x" },
    links: {},
    indexed: true,
    checks: { solid: { check: "c", via: "", ok: true }, content: { check: "d", via: "", ok: true, result: "MATCH" } },
  } as unknown as Message;
  const lifecycle = {
    blockId,
    status: "CONTENT_VERIFIED",
    transitions: ["RECEIVED", "SUBMITTED", "SOLID", "CONFIRMED", "CONTENT_VERIFIED"].map((status, i) => ({ status, atMs: 1791283579000 + i * 1000, at: "", subId: null, detail: null })),
    validations: [],
    contentChecks: [],
    checks: message.checks,
  } as Lifecycle;
  const data = {
    mode: "live",
    source: "test",
    message: async () => message,
    lifecycle: async () => lifecycle,
    bundle: async () => w.text,
    verifierConfig: async () => w.config,
    health: async () => ({ mode: "live", ok: true, network: "private_tangle1", version: "test", note: null }),
    recheck: async () => {
      throw new Error("not in this test");
    },
  } as unknown as WitnessData;
  const lookups: TrustedLookups = {
    resolveDid: w.lookups.resolveDid!,
    fetchAnchorRecord: w.lookups.fetchAnchorRecord,
    didSource: "recorded copies from the test vectors",
    anchorSource: "a recorded copy from the test vectors",
    recordedDids: true,
  };
  return { data, lookups, blockId };
}

beforeEach(() => {
  // reduced motion: the ladder runs without pauses
  vi.stubGlobal("matchMedia", (q: string) => ({ matches: q.includes("reduce"), media: q, addEventListener() {}, removeEventListener() {} }));
});
afterEach(() => {
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

describe("Verify", () => {
  it("shows the indexer's recorded verdict next to the browser's own, computed result", async () => {
    const { data, lookups, blockId } = fakeData("valid_anchored", "PRODUCER_SIGNED");
    const { w } = await mountScreen(VerifyView, { path: `/m/${blockId}`, data, lookups });
    await until(() => w.find(".overall").attributes("data-o") === "VALID");
    const [indexer, mine] = w.findAll(".vbox");
    expect(indexer!.text()).toContain("Recorded by the indexer");
    expect(indexer!.text()).toContain("Producer signed");
    expect(mine!.text()).toContain("Checked in your browser");
    expect(mine!.attributes("data-o")).toBe("VALID");
    expect(w.findAll("li.step").map((s) => s.attributes("data-s"))).toEqual(["pass", "pass", "pass", "pass", "pass"]);
    expect(w.find(".score").text()).toBe("0.82");
    expect(w.find(".hex").exists()).toBe(true);
    expect(w.find(".pins").text()).toContain("they are the same");
    w.unmount();
  });

  it("flags a disagreement: the indexer recorded a signature the browser rejects", async () => {
    const { data, lookups, blockId } = fakeData("envelope_forged", "PRODUCER_SIGNED");
    const { w } = await mountScreen(VerifyView, { path: `/m/${blockId}`, data, lookups });
    await until(() => w.find(".overall").attributes("data-o") === "INVALID");
    expect(w.find('[data-step="envelope"]').attributes("data-s")).toBe("fail");
    expect(w.find(".compare").text()).toContain("They disagree");
    w.unmount();
  });

  it("has no critical or serious axe violations", async () => {
    const { data, lookups, blockId } = fakeData("valid_anchored", "PRODUCER_SIGNED");
    const { w } = await mountScreen(VerifyView, { path: `/m/${blockId}`, data, lookups });
    await until(() => w.find(".overall").attributes("data-o") === "VALID");
    // jsdom does no layout, so colour contrast is left to the browser screenshots
    const result = await axe.run(document.body, { rules: { "color-contrast": { enabled: false } } });
    const bad = result.violations.filter((v) => v.impact === "critical" || v.impact === "serious");
    expect(bad.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`)).toEqual([]);
    w.unmount();
  });
});
