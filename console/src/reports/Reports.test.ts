// @vitest-environment jsdom
import { blake2b256, toHex } from "@witness/verify";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { LiveAdapter, type Posture, type ReportResult, type WitnessData } from "@/api/client";
import examples from "@/fixtures/api/examples.json";
import live from "@/fixtures/api/live.json";
import { mountScreen, until } from "@/test/mount";
import PostureView from "@/views/PostureView.vue";
import ReportsView from "@/views/ReportsView.vue";

import { ledgerReportHash, recomputeReportHash, reportTotals } from "./model";

/* eslint-disable @typescript-eslint/no-explicit-any */
const REPORT = examples.report as unknown as ReportResult;

/** A TIP-24 block whose tagged data is `message`: protocol 2, one parent, nonce 0. */
function block(message: unknown): { id: string; raw: Uint8Array } {
  const data = new TextEncoder().encode(JSON.stringify(message));
  const tag = new TextEncoder().encode("audit.report");
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

afterEach(() => {
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

describe("report hash", () => {
  it("recomputes in the browser the hash the API computed in Python", () => {
    const r = recomputeReportHash(JSON.stringify(REPORT));
    expect(r).toEqual({ hash: REPORT.reportHash, problem: null });
    // key order and spacing do not matter (canonical form), one changed number does
    const reordered = JSON.stringify({ report: Object.fromEntries(Object.entries(REPORT.report as object).reverse()) }, null, 3);
    expect(recomputeReportHash(reordered).hash).toBe(REPORT.reportHash);
    const edited = structuredClone(REPORT) as any;
    edited.report.messages.total += 1;
    expect(recomputeReportHash(JSON.stringify(edited)).hash).not.toBe(REPORT.reportHash);
    expect(recomputeReportHash("{").problem).toBe("the answer is not JSON");
    expect(recomputeReportHash("{}").problem).toBe("the answer carries no report");
  });

  it("reads the hash an audit.report block names from its own bytes, bound to its id", () => {
    const b = block(envelope(REPORT.reportHash));
    expect(ledgerReportHash(bundleOf(b), b.id)).toEqual({ hash: REPORT.reportHash, iss: REPORT.iss, problem: null });
    // the explorer serving another block's bytes is caught
    const other = block(envelope("0x" + "00".repeat(32)));
    expect(ledgerReportHash(bundleOf(other), b.id).problem).toContain("another block");
    expect(ledgerReportHash(bundleOf(block({ hello: 1 })), block({ hello: 1 }).id).problem).toBe("the block's message names no report hash");
  });

  it("totals only numbers from the report", () => {
    expect(reportTotals(REPORT.report).map((t) => t.label)).toEqual(["Messages", "Confirmed", "Alerts", "Checkpoints", "Proofs listed"]);
    expect(reportTotals({ messages: { total: "<b>9</b>" } })).toEqual([]);
  });
});

function screenData(over: Record<string, unknown>): WitnessData {
  return Object.assign(Object.create(new LiveAdapter("/api")), {
    health: async () => ({ mode: "live", ok: true, network: "private_tangle1", version: "test", note: null }),
    ...over,
  }) as WitnessData;
}

describe("Reports screen", () => {
  it("shows the three hashes agreeing for an anchored report", async () => {
    const b = block(envelope(REPORT.reportHash));
    const result = { ...structuredClone(REPORT), blockId: b.id };
    const bundle = vi.fn(async () => bundleOf(b));
    const d = screenData({
      reports: async () => ({ items: [{ ...examples.reports.items[0], blockId: b.id }], nextCursor: null, limit: 50 }),
      report: async () => ({ result, text: JSON.stringify(result) }),
      bundle,
    });
    const { w } = await mountScreen(ReportsView, { path: "/reports", data: d });
    await until(() => w.findAll(".hashes .x-cmp").length === 2);
    expect(bundle).toHaveBeenCalledWith(b.id);
    expect(w.findAll(".hashes .x-cmp").map((c) => c.attributes("data-c"))).toEqual(["same", "same"]);
    expect(w.find('.x-note[data-tone="ok"]').text()).toContain("All three agree");
    const html = w.find('a[target="_blank"]');
    expect(html.attributes("href")).toBe(`/api/reports/${REPORT.reportHash}.html`);
    expect(html.attributes("rel")).toContain("noopener");
    expect(document.querySelector("iframe")).toBeNull();
    expect(w.find(`a[href="/m/${b.id}"]`).exists()).toBe(true);
    const res = await axe.run(document.body, { rules: { "color-contrast": { enabled: false } } });
    const bad = res.violations.filter((v) => v.impact === "critical" || v.impact === "serious");
    expect(bad.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`)).toEqual([]);
    w.unmount();
  });

  it("flags a served report that is not the one the ledger names", async () => {
    const b = block(envelope(REPORT.reportHash));
    const tampered = structuredClone(REPORT) as any;
    tampered.blockId = b.id;
    tampered.report.alerts.total = 0; // the explorer edits the report but keeps the hash
    const d = screenData({
      reports: async () => ({ items: [{ ...examples.reports.items[0], blockId: b.id }], nextCursor: null, limit: 50 }),
      report: async () => ({ result: tampered, text: JSON.stringify(tampered) }),
      bundle: async () => bundleOf(b),
    });
    const { w } = await mountScreen(ReportsView, { path: "/reports", data: d });
    await until(() => w.findAll(".hashes .x-cmp").length === 2);
    expect(w.findAll(".hashes .x-cmp").map((c) => c.attributes("data-c"))).toEqual(["differs", "differs"]);
    expect(w.find('.x-note[data-tone="bad"]').text()).toContain("do not agree");
    w.unmount();
  });

  it("says plainly when a report is not anchored, and when there is none", async () => {
    const unanchored = { ...structuredClone(REPORT), anchored: false, blockId: null, anchoredAtMs: null };
    const bundle = vi.fn();
    const d = screenData({
      reports: async () => ({ items: [{ ...examples.reports.items[0], anchored: false, blockId: null }], nextCursor: null, limit: 50 }),
      report: async () => ({ result: unanchored, text: JSON.stringify(unanchored) }),
      bundle,
    });
    const { w } = await mountScreen(ReportsView, { path: "/reports", data: d });
    await until(() => w.find(".detail .anch").exists());
    expect(w.find(".detail .anch").text()).toBe("NOT anchored");
    expect(w.find(".list .anch").text()).toBe("NOT anchored");
    expect(w.text()).toContain("Nothing on the ledger vouches for this report yet");
    expect(bundle).not.toHaveBeenCalled();
    w.unmount();
    const { w: w2 } = await mountScreen(ReportsView, { path: "/reports", data: screenData({ reports: async () => live.reports }) });
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
    const res = await axe.run(document.body, { rules: { "color-contrast": { enabled: false } } });
    const bad = res.violations.filter((v) => v.impact === "critical" || v.impact === "serious");
    expect(bad.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`)).toEqual([]);
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
