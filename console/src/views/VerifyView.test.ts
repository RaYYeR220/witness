// @vitest-environment jsdom
import axe from "axe-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ReplayAdapter, type Lifecycle, type Message, type WitnessData } from "@/api/client";
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

/** `served` swaps in another case's bundle, as a lying or confused API would. */
function fakeData(
  name: string,
  verdict: string,
  served = name,
  edit?: (bundle: Record<string, unknown>) => void,
): { data: WitnessData; lookups: TrustedLookups; blockId: string; message: Message; lifecycle: Lifecycle } {
  const c = bundleCase(name);
  const w = wired(name);
  let bundleText = wired(served).text;
  if (edit) {
    const b = JSON.parse(bundleText);
    edit(b);
    bundleText = JSON.stringify(b);
  }
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
    bundle: async () => bundleText,
    verifierConfig: async () => w.config,
    health: async () => ({ mode: "live", ok: true, network: "private_tangle1", version: "test", note: null }),
    lastAnchoredMilestone: async () => 373,
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
  return { data, lookups, blockId, message, lifecycle };
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

  it("refuses a proof of another block: banner, INVALID, no checks run on it", async () => {
    // asked for the forged twin's block, the API serves the valid sample's bundle instead
    const { data, lookups, blockId } = fakeData("envelope_forged", "PRODUCER_SIGNED", "valid_anchored");
    const { w } = await mountScreen(VerifyView, { path: `/m/${blockId}`, data, lookups });
    await until(() => w.find(".foreign").exists());
    await new Promise((r) => setTimeout(r, 50));
    expect(w.find(".foreign").text()).toContain("The explorer served a proof for another block");
    expect(w.find(".vbox.mine").attributes("data-o")).toBe("INVALID");
    expect(w.find(".vbox.mine").text()).not.toContain("VALID ");
    expect(w.find(".overall-chip").text()).toBe("INVALID");
    expect(w.find("li.step").exists()).toBe(false); // the ladder never ran on the foreign bundle
    expect(w.find(".hex").exists()).toBe(false); // nor are its bytes shown as this block's
    expect(w.text()).not.toContain("All five checks passed");
    w.unmount();
  });

  it("applies the same binding to a replay snapshot whose bundle file is swapped", async () => {
    const asked = fakeData("envelope_forged", "PRODUCER_SIGNED");
    const swapped = wired("valid_anchored").text;
    const files: Record<string, string> = {
      [`/replay/messages/${asked.blockId}.json`]: JSON.stringify(asked.message),
      [`/replay/lifecycle/${asked.blockId}.json`]: JSON.stringify(asked.lifecycle),
      [`/replay/bundles/${asked.blockId}.json`]: swapped,
      "/replay/manifest.json": JSON.stringify({ about: "test", recordedAtMs: 1791283579000, source: "test" }),
      "/replay/verifier-config.json": JSON.stringify(bundleCase("valid_anchored").config),
    };
    vi.stubGlobal("fetch", async (input: string) => {
      const body = files[String(input)];
      return body === undefined ? new Response("{}", { status: 404 }) : new Response(body, { status: 200 });
    });
    const { w } = await mountScreen(VerifyView, { path: `/m/${asked.blockId}`, data: new ReplayAdapter("/replay/"), lookups: asked.lookups });
    await until(() => w.find(".foreign").exists());
    expect(w.find(".overall-chip").text()).toBe("INVALID");
    expect(w.find("li.step").exists()).toBe(false);
    w.unmount();
  });

  it("names what the explorer's record says when it differs from the bytes", async () => {
    const f = fakeData("valid_anchored", "PRODUCER_SIGNED");
    (f.message as { ieId: string }).ieId = "OtherDomain:000000000000";
    const { w } = await mountScreen(VerifyView, { path: `/m/${f.blockId}`, data: f.data, lookups: f.lookups });
    await until(() => w.find(".overall").attributes("data-o") === "VALID");
    // the headline takes the IE from the bytes; the record's other IE is named as such
    expect(w.find(".title").text()).toContain("MyDomain:fa163e5e25ef");
    expect(w.text()).toContain("The explorer's record names IE OtherDomain:000000000000 instead");
    w.unmount();
  });

  it("says a signed message is just not anchored yet, with the last checkpoint's milestone", async () => {
    // the valid sample without its anchor section: a block newer than the last checkpoint
    const f = fakeData("valid_anchored", "PRODUCER_SIGNED", "valid_anchored", (b) => delete b.anchor);
    const { w } = await mountScreen(VerifyView, { path: `/m/${f.blockId}`, data: f.data, lookups: f.lookups });
    await until(() => w.find(".pending").exists() && w.find(".pending").text().includes("373"));
    expect(w.find(".overall-chip").text()).toBe("PARTIAL");
    expect(w.find(".pending").text()).toContain("Not anchored yet: the last checkpoint covers up to milestone 373, this block is in milestone 374; checks 1–4 passed.");
    w.unmount();
  });
});
