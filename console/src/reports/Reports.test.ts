// @vitest-environment jsdom
import { blake2b256, toHex, verifyBundleText, type Ladder, type StepResult, type VerifierConfig } from "@witness/verify";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { LiveAdapter, type Posture, type ReportDoc, type ReportResult, type WitnessData } from "@/api/client";
import examples from "@/fixtures/api/examples.json";
import live from "@/fixtures/api/live.json";
import { mountScreen, until } from "@/test/mount";
import { bundleCase, wired } from "@/test/vectors";
import type { TrustedLookups } from "@/verify/lookups";
import PostureView from "@/views/PostureView.vue";
import ReportsView from "@/views/ReportsView.vue";

import { checkReport, pinsUsable, readAuditMessage, recomputeReportHash, reportTotals, type CheckDeps } from "./model";

// The ladder is the real one unless a test says otherwise for one call.
vi.mock("@witness/verify", async (orig) => {
  const m = await orig<typeof import("@witness/verify")>();
  return { ...m, verifyBundleText: vi.fn(m.verifyBundleText) };
});

/* eslint-disable @typescript-eslint/no-explicit-any */
const REPORT = examples.report as unknown as ReportResult;
const PINS: VerifierConfig = bundleCase("valid_anchored").config;

/** A TIP-24 block whose tagged data is `message` under `tag`: protocol 2, one parent, nonce 0. */
function block(message: unknown, tagText = "audit.report"): { id: string; raw: Uint8Array } {
  const data = new TextEncoder().encode(JSON.stringify(message));
  const tag = new TextEncoder().encode(tagText);
  const payload = new Uint8Array(4 + 1 + tag.length + 4 + data.length);
  const pv = new DataView(payload.buffer);
  pv.setUint32(0, 5, true);
  payload[4] = tag.length;
  payload.set(tag, 5);
  pv.setUint32(5 + tag.length, data.length, true);
  payload.set(data, 9 + tag.length);
  const raw = new Uint8Array(1 + 1 + 32 + 4 + payload.length + 8);
  raw[0] = 2;
  raw[1] = 1;
  raw.fill(7, 2, 34);
  new DataView(raw.buffer).setUint32(34, payload.length, true);
  raw.set(payload, 38);
  return { id: toHex(blake2b256(raw)), raw };
}

const envelope = (reportHash: string) => ({ w: 1, tag: "audit.report", iss: REPORT.iss, kid: `${REPORT.iss}#sig-1`, seq: 1, iat: 1, sig: "x", body: { reportHash, generatedAt: 1 } });
const bundleOf = (b: { id: string; raw: Uint8Array }) => JSON.stringify({ v: 1, block: { id: b.id, raw: toHex(b.raw) } });
const docOf = (result: ReportResult): ReportDoc => ({ result, text: JSON.stringify(result) });

/** A ladder as the library reports it, with the given step outcomes. */
function ladderOf(oks: (boolean | null)[]): Ladder {
  const names = ["block_hash", "inclusion", "milestone_signatures", "envelope", "anchor"] as const;
  const steps = names.map((name, i) => ({ name, ok: oks[i] ?? null, detail: oks[i] === false ? `${name} broken` : oks[i] === null ? "not evaluated" : "ok" })) as StepResult[];
  const overall = oks.includes(false) ? "INVALID" : oks.includes(null) ? "PARTIAL" : "VALID";
  return { steps, overall } as Ladder;
}

/** The report anchored in block `b`, checked with `verify` (default: the real ladder with the vectors' pins). */
function deps(b: { id: string; raw: Uint8Array } | string, verify?: CheckDeps["verify"], config: CheckDeps["config"] = PINS): CheckDeps {
  return {
    config,
    bundle: async (id) => {
      if (typeof b === "string") throw new Error(b);
      if (id !== b.id) throw new Error("asked for another block");
      return bundleOf(b);
    },
    verify: verify ?? ((text) => verifyBundleText(text, PINS, {})),
    reportSigner: REPORT.iss,
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

describe("report hash", () => {
  it("is computed in the browser from the JSON served, with the same canonical hash as the API", () => {
    const r = recomputeReportHash(JSON.stringify(REPORT));
    expect(r.hash).toBe(REPORT.reportHash);
    expect(r.problem).toBeNull();
    expect(r.report).toEqual(REPORT.report); // the parse that was hashed, for the screen to show
    // key order and spacing do not matter (canonical form); one changed number does
    const reordered = JSON.stringify({ report: Object.fromEntries(Object.entries(REPORT.report as object).reverse()) }, null, 3);
    expect(recomputeReportHash(reordered).hash).toBe(REPORT.reportHash);
    const edited = structuredClone(REPORT) as any;
    edited.report.messages.total += 1;
    expect(recomputeReportHash(JSON.stringify(edited)).hash).not.toBe(REPORT.reportHash);
    // the stated hash is never what gets computed
    expect(recomputeReportHash(JSON.stringify({ ...edited, reportHash: REPORT.reportHash })).hash).not.toBe(REPORT.reportHash);
    expect(recomputeReportHash("{").problem).toBe("the answer is not JSON");
    expect(recomputeReportHash("{}").problem).toBe("the answer carries no report");
  });

  it("reads the audit.report message from bytes bound to the block id", () => {
    const b = block(envelope(REPORT.reportHash));
    expect(readAuditMessage(bundleOf(b), b.id)).toEqual({ tag: "audit.report", hash: REPORT.reportHash, iss: REPORT.iss, problem: null });
    const other = block(envelope("0x" + "00".repeat(32)));
    expect(readAuditMessage(bundleOf(other), b.id).problem).toContain("another block");
  });

  it("totals only numbers from the report", () => {
    expect(reportTotals(REPORT.report).map((t) => t.label)).toEqual(["Messages", "Confirmed", "Alerts", "Checkpoints", "Proofs listed"]);
    expect(reportTotals({ messages: { total: "<b>9</b>" } })).toEqual([]);
  });
});

describe("checkReport", () => {
  const anchoredIn = (b: { id: string }, edit: (r: any) => void = () => {}) => {
    const r = structuredClone(REPORT) as any;
    r.blockId = b.id;
    edit(r);
    return docOf(r);
  };
  const PASS = async () => ladderOf([true, true, true, true, null]);

  it("is verified only when the block passes checks 1 to 4, every hash agrees and the pinned signer signed it", async () => {
    const b = block(envelope(REPORT.reportHash));
    const c = await checkReport(anchoredIn(b), deps(b, PASS));
    expect(c.state).toBe("verified");
    expect(c.signer).toBe(REPORT.iss);
    expect([c.browserHash, c.ledgerHash, c.explorerHash]).toEqual([REPORT.reportHash, REPORT.reportHash, REPORT.reportHash]);
    expect(c.rebased).toBeNull();
  });

  it("is a mismatch when the explorer's reportHash is not the hash of the report it served", async () => {
    const b = block(envelope(REPORT.reportHash));
    const c = await checkReport(
      anchoredIn(b, (r) => (r.report.alerts.total = 0)),
      deps(b, PASS),
    );
    expect(c.state).toBe("mismatch");
    expect(c.reasons[0]).toContain("does not hash to the reportHash it states");
    expect(c.browserHash).not.toBe(REPORT.reportHash);
  });

  it("is a mismatch when the audit.report body names another hash", async () => {
    const b = block(envelope("0x" + "99".repeat(32)));
    const c = await checkReport(anchoredIn(b), deps(b, PASS));
    expect(c.state).toBe("mismatch");
    expect(c.reasons).toEqual(["the audit.report on the ledger names another hash than the report served"]);
  });

  it("is a mismatch when someone else than the pinned report signer signed the audit.report", async () => {
    const other = "did:iota:testnet:0x" + "77".repeat(32);
    const b = block({ ...envelope(REPORT.reportHash), iss: other, kid: `${other}#sig-1` });
    const c = await checkReport(anchoredIn(b), deps(b, PASS));
    expect(c.state).toBe("mismatch");
    expect(c.reasons).toEqual([`the audit.report was signed by ${other}, not by the report signer pinned in this console`]);
    expect(c.signer).toBeNull();
  });

  it("is not checked when the console pins no report signer", async () => {
    const b = block(envelope(REPORT.reportHash));
    const c = await checkReport(anchoredIn(b), { ...deps(b, PASS), reportSigner: null });
    expect(c.state).toBe("unchecked");
    expect(c.reasons).toEqual(["this console pins no report signer, so it cannot tell whose audit.report counts"]);
  });

  it("is a mismatch when the explorer serves the proof of another block", async () => {
    const named = block(envelope(REPORT.reportHash));
    const served = block(envelope(REPORT.reportHash), "audit.report ");
    const verify = vi.fn(PASS);
    const c = await checkReport(anchoredIn(named), { config: PINS, bundle: async () => bundleOf(served), verify, reportSigner: REPORT.iss });
    expect(c.state).toBe("mismatch");
    expect(c.reasons[0]).toContain("the explorer served the proof of another block");
    expect(verify).not.toHaveBeenCalled();
  });

  it("is a mismatch when a check fails on the block, here with the real ladder", async () => {
    const b = block(envelope(REPORT.reportHash)); // bytes that are in no milestone
    const c = await checkReport(anchoredIn(b), deps(b));
    expect(c.state).toBe("mismatch");
    expect(c.reasons.some((r) => r.startsWith("check 1 failed") || r.startsWith("check 2 failed"))).toBe(true);
  });

  it("is a mismatch when a block that verifies is not an audit.report naming the hash", async () => {
    // a real, fully valid trust.score block from the vectors: the ladder passes, the content does not
    const w = wired("valid_anchored");
    const id = bundleCase("valid_anchored").bundle.block.id;
    const c = await checkReport(anchoredIn({ id }), {
      config: w.config,
      bundle: async () => w.text,
      verify: (text) => verifyBundleText(text, w.config, w.lookups),
      reportSigner: REPORT.iss,
    });
    expect(c.ladder?.overall).toBe("VALID");
    expect(c.state).toBe("mismatch");
    expect(c.reasons[0]).toContain('tagged "trust.score", not audit.report');
  });

  it("is never verified without usable pins, or without an answer for every one of checks 1 to 4", async () => {
    const b = block(envelope(REPORT.reportHash));
    const verify = vi.fn(PASS);
    const unpinned = await checkReport(anchoredIn(b), deps(b, verify, { ...PINS, trustedCoordinatorKeys: [] }));
    expect(unpinned.state).toBe("unchecked");
    expect(unpinned.reasons).toEqual(["this console pins no coordinator keys to check the block with"]);
    expect(verify).not.toHaveBeenCalled();
    expect(pinsUsable({ ...PINS, threshold: 3 })).toBe(false);
    const signer = await checkReport(anchoredIn(b), deps(b, async () => ladderOf([true, true, true, null, null])));
    expect(signer.state).toBe("unchecked");
    expect(signer.reasons[0]).toContain("check 4 could not be evaluated");
    const noProof = await checkReport(anchoredIn(b), deps("404 no proof yet", PASS));
    expect(noProof.state).toBe("unchecked");
    const noRun = await checkReport(anchoredIn(b), deps(b, async () => null));
    expect(noRun.state).toBe("unchecked");
  });

  it("says not anchored when the explorer says so, and a mismatch wins over it", async () => {
    const r = { ...structuredClone(REPORT), anchored: false, blockId: null };
    expect((await checkReport(docOf(r), deps("unused"))).state).toBe("not-anchored");
    const edited = structuredClone(r) as any;
    edited.report.messages.total = 1;
    expect((await checkReport(docOf(edited), deps("unused"))).state).toBe("mismatch");
  });
});

function screenData(over: Record<string, unknown>): WitnessData {
  return Object.assign(Object.create(new LiveAdapter("/api")), {
    health: async () => ({ mode: "live", ok: true, network: "private_tangle1", version: "test", note: null }),
    ...over,
  }) as WitnessData;
}

const LOOKUPS: TrustedLookups = {
  resolveDid: async () => null,
  fetchAnchorRecord: null,
  didSource: "nowhere (test)",
  anchorSource: "nowhere (test)",
  recordedDids: true,
};

async function axeClean() {
  const res = await axe.run(document.body, { rules: { "color-contrast": { enabled: false } } });
  return res.violations.filter((v) => v.impact === "critical" || v.impact === "serious").map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`);
}

describe("Reports screen", () => {
  function reportIn(b: { id: string }, edit: (r: any) => void = () => {}) {
    const r = structuredClone(REPORT) as any;
    r.blockId = b.id;
    edit(r);
    return r as ReportResult;
  }
  const list = (r: ReportResult) => async () => ({ items: [{ ...examples.reports.items[0], blockId: r.blockId, anchored: r.anchored }], nextCursor: null, limit: 50 });

  it("shows a report as anchored only once the browser checked its audit.report block", async () => {
    const b = block(envelope(REPORT.reportHash));
    const result = reportIn(b);
    // this one ladder run passes checks 1 to 4 (a valid audit.report bundle needs keys the tests do not hold)
    vi.mocked(verifyBundleText).mockImplementationOnce(async (_text, _cfg, opts) => {
      const l = ladderOf([true, true, true, true, null]);
      for (const s of l.steps) await opts?.onStep?.(s);
      return l;
    });
    const bundle = vi.fn(async () => bundleOf(b));
    const d = screenData({ reports: list(result), report: async () => docOf(result), bundle });
    const { w } = await mountScreen(ReportsView, { path: "/reports", data: d, lookups: LOOKUPS });
    await until(() => w.find('.detail .anch[data-a="verified"]').exists());
    expect(bundle).toHaveBeenCalledWith(b.id);
    expect(w.find(".detail .anch").text()).toBe("Anchored, checked in your browser");
    expect(w.findAll(".hashes .x-cmp").map((c) => c.attributes("data-c"))).toEqual(["same", "same"]);
    expect(w.find('.x-note[data-tone="ok"]').text()).toContain("The ledger vouches for this report");
    expect(w.find('.x-note[data-tone="ok"]').text()).toContain("the report signer pinned in this console (checked in your browser)");
    // the list only repeats the explorer's claim
    expect(w.find(".list .anch").text()).toBe("Anchored, per the explorer");
    // the HTML page is a rendering, opened on its own, never embedded
    const html = w.find('a[target="_blank"]');
    expect(html.text()).toBe("Open the HTML rendering");
    expect(html.attributes("href")).toBe(`/api/reports/${REPORT.reportHash}.html`);
    expect(html.attributes("rel")).toContain("noopener");
    expect(w.find(".render-note").text()).toContain("not what your browser checked");
    expect(document.querySelector("iframe")).toBeNull();
    // the JSON on screen is the browser's own parse, the one it hashed
    expect(w.find(".json summary").text()).toBe("The report JSON, as your browser parsed and hashed it");
    expect(w.find(".totals").text()).toContain("Messages");
    expect(await axeClean()).toEqual([]);
    w.unmount();
  });

  it("turns red, with nothing green, when the report served does not match", async () => {
    const b = block(envelope(REPORT.reportHash));
    const result = reportIn(b, (r) => (r.report.alerts.total = 0)); // edited, hash kept
    const d = screenData({ reports: list(result), report: async () => docOf(result), bundle: async () => bundleOf(b) });
    const { w } = await mountScreen(ReportsView, { path: "/reports", data: d, lookups: LOOKUPS });
    await until(() => w.find('.detail .anch[data-a="mismatch"]').exists());
    expect(w.find(".detail .anch").text()).toBe("Does not match");
    expect(w.find('.x-note[data-tone="bad"]').text()).toContain("does not hash to the reportHash it states");
    expect(w.find('[data-c="same"]').exists()).toBe(false);
    expect(w.find('[data-a="verified"]').exists()).toBe(false);
    expect(w.find('.x-note[data-tone="ok"]').exists()).toBe(false);
    w.unmount();
  });

  it("labels an anchor it could not check as the explorer's word", async () => {
    const b = block(envelope(REPORT.reportHash));
    const result = reportIn(b);
    const d = screenData({
      reports: list(result),
      report: async () => docOf(result),
      bundle: async () => {
        throw new Error("no proof yet");
      },
    });
    const { w } = await mountScreen(ReportsView, { path: "/reports", data: d, lookups: LOOKUPS });
    await until(() => w.find('.detail .anch[data-a="unchecked"]').exists());
    expect(w.find(".detail .anch").text()).toBe("Anchored per the explorer (not checked in your browser)");
    expect(w.find('[data-c="same"]').exists()).toBe(false);
    w.unmount();
  });

  it("says plainly when a report is not anchored, and when there is none", async () => {
    const unanchored = { ...structuredClone(REPORT), anchored: false, blockId: null, anchoredAtMs: null };
    const bundle = vi.fn();
    const d = screenData({ reports: list(unanchored), report: async () => docOf(unanchored), bundle });
    const { w } = await mountScreen(ReportsView, { path: "/reports", data: d, lookups: LOOKUPS });
    await until(() => w.find('.detail .anch[data-a="not-anchored"]').exists());
    expect(w.find(".list .anch").text()).toBe("NOT anchored");
    expect(w.text()).toContain("Nothing on the ledger vouches for this report");
    expect(bundle).not.toHaveBeenCalled();
    w.unmount();
    const { w: w2 } = await mountScreen(ReportsView, { path: "/reports", data: screenData({ reports: async () => live.reports }), lookups: LOOKUPS });
    await until(() => w2.text().includes("No report yet"));
    w2.unmount();
  });
});

describe("Posture screen", () => {
  it("shows the last scan's findings with evidence and fixes, and the explorer's components", async () => {
    const d = screenData({ posture: async () => examples.posture as unknown as Posture, stats: async () => live.stats });
    const { w } = await mountScreen(PostureView, { path: "/posture", data: d });
    await until(() => w.findAll(".find").length === 2 && w.find(".svcs").exists());
    expect(w.findAll(".find .f-title").map((t) => t.text())).toEqual(examples.posture.findings.map((f) => f.title));
    expect(w.find(".find .fix").text()).toBe(examples.posture.findings[0]!.fix);
    expect(w.find(".find .json").text()).toContain('"source": "protocol config"');
    expect(w.text()).toContain("Scans run server-side by the operator");
    expect(w.find("button").exists()).toBe(false); // nothing here can start a scan
    expect(w.findAll(".svcs li").length).toBe(Object.keys(live.stats.services).length);
    expect(await axeClean()).toEqual([]);
    w.unmount();
  });

  it("says when no scan has run yet", async () => {
    const d = screenData({ posture: async () => live.posture, stats: async () => ({ ...live.stats, services: undefined }) });
    const { w } = await mountScreen(PostureView, { path: "/posture", data: d });
    await until(() => w.text().includes("None yet") && w.text().includes("does not report component statuses"));
    expect(w.text()).toContain("Findings appear here once the operator has run a scan.");
    w.unmount();
  });
});
