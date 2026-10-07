// @vitest-environment jsdom
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { DataError, LiveAdapter, ReplayAdapter, fileKey, type Alert, type Flow, type FlowItem, type WitnessData } from "@/api/client";
import live from "@/fixtures/api/live.json";
import { mountScreen, until } from "@/test/mount";
import FlowsView from "@/views/FlowsView.vue";

import { chainAlerts, claimsIssuer, linkStates } from "./model";

/* eslint-disable @typescript-eslint/no-explicit-any */
const L = live as unknown as Record<string, any>;
const FLOW = L.flowIssuer as Flow; // 6 newest messages of the trust manager's chain, recorded from the API

const id = (n: number) => "0x" + n.toString(16).padStart(2, "0").repeat(32);
const item = (n: number, prev: number | null): FlowItem =>
  ({ ...FLOW.items[0]!, blockId: id(n), prev: prev === null ? null : id(prev), seq: n }) as FlowItem;

const json = (v: unknown) => new Response(JSON.stringify(v), { status: 200, headers: { "content-type": "application/json" } });

afterEach(() => {
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

describe("flow chain", () => {
  it("reads how each message links to the one before it", () => {
    // 1 starts; 2 follows 1; 3 skips to 1 (a gap); 4 and 5 both claim 3 (a fork)
    const items = [item(1, null), item(2, 1), item(3, 1), item(4, 3), item(5, 3)];
    const flow = { items, total: 5, chain: { links: 2, gaps: [id(3), id(5)], forks: [id(3)] } };
    const s = linkStates(flow);
    expect(items.map((i) => s.get(i.blockId))).toEqual(["start", "linked", "gap", "fork", "fork"]);
    // a page that starts mid-chain: the first message shown follows one older than the page
    const page = { items: items.slice(1, 3), total: 5, chain: { links: 2, gaps: [id(3)], forks: [] } };
    expect(page.items.map((i) => linkStates(page).get(i.blockId))).toEqual(["earlier", "gap"]);
  });

  it("keeps messages that only claim the issuer out of the chain", () => {
    // 3 is a forgery naming the producer, continuing from 2 as the genuine 4 does
    const forged = (n: number, prev: number, mark?: boolean): FlowItem => ({ ...item(n, prev), verdict: "FORGED", ...(mark === undefined ? {} : { claimsIssuer: mark }) });
    // the explorer marks it, and its chain view counts proven messages only
    const marked = [item(1, null), item(2, 1), forged(3, 2, true), item(4, 2)].map((i, k) => (k === 2 ? i : { ...i, claimsIssuer: false }));
    const s = linkStates({ items: marked, total: 4, chain: { links: 2, gaps: [], forks: [] } });
    expect(marked.map((i) => s.get(i.blockId))).toEqual(["start", "linked", "claims", "linked"]);
    // an older answer without the mark, whose chain view still counted the forgery as a fork
    const old = [item(1, null), item(2, 1), forged(3, 2), item(4, 2)];
    const t = linkStates({ items: old, total: 4, chain: { links: 2, gaps: [id(4)], forks: [id(2)] } });
    expect(old.map((i) => t.get(i.blockId))).toEqual(["start", "linked", "claims", "linked"]);
    // a fork of two proven messages stays a fork, whatever else claims the same prev
    const both = [item(1, null), item(2, 1), forged(3, 2), item(4, 2), item(5, 2)];
    const u = linkStates({ items: both, total: 5, chain: { links: 2, gaps: [id(5)], forks: [id(2)] } });
    expect(both.map((i) => u.get(i.blockId))).toEqual(["start", "linked", "claims", "fork", "fork"]);
    expect(claimsIssuer({ verdict: "RELAY_ATTESTED" })).toBe(false);
    expect(claimsIssuer({ verdict: "REPLAY" })).toBe(true);
    expect(claimsIssuer({ verdict: "FORGED", claimsIssuer: false })).toBe(false);
  });

  it("agrees with the explorer's chain view on the recorded flow", () => {
    const s = linkStates(FLOW);
    const gaps = new Set(FLOW.chain!.gaps);
    for (const [i, m] of FLOW.items.entries()) {
      if (i === 0) continue;
      expect(s.get(m.blockId) === "gap").toBe(gaps.has(m.blockId));
    }
  });

  it("keeps only CHAIN_GAP and CHAIN_FORK alerts, by block", () => {
    const a = (rule: string, blockId: string | null) => ({ id: 1, rule, severity: "medium", blockId, ieId: null, evidence: {}, atMs: 1, dedupeKey: null }) as Alert;
    const m = chainAlerts([a("CHAIN_GAP", id(3).toUpperCase()), a("FORGED", id(3)), a("CHAIN_FORK", null)]);
    expect([...m.keys()]).toEqual([id(3)]);
  });
});

describe("flows data layer", () => {
  it("asks the API's flow routes, and never with a grouping it does not have", async () => {
    const asked: string[] = [];
    vi.stubGlobal("fetch", async (u: string) => {
      asked.push(String(u));
      return json(String(u).includes("/flows/") ? FLOW : L.flowsIssuer);
    });
    const d = new LiveAdapter("/api");
    expect((await d.flows("issuer")).map((f) => f.key)).toEqual(L.flowsIssuer.items.map((f: { key: string }) => f.key));
    expect((await d.flow("issuer", FLOW.key, { limit: 100 })).total).toBe(FLOW.total);
    expect(asked).toEqual(["/api/flows?by=issuer", `/api/flows/issuer/${encodeURIComponent(FLOW.key)}?limit=100`]);
    await expect(d.flows("evil" as never)).rejects.toBeInstanceOf(DataError);
    await expect(d.flow("issuer", "a/b")).rejects.toBeInstanceOf(DataError);
    expect(asked).toHaveLength(2);
  });

  it("serves flows from a snapshot, and refuses a file about another flow", async () => {
    vi.stubGlobal("fetch", async (u: string) => {
      const url = String(u);
      if (url === "/replay/flows-issuer.json") return json(L.flowsIssuer);
      if (url === `/replay/flows/issuer/${fileKey(FLOW.key)}.json`) return json(FLOW);
      if (url === `/replay/flows/ie/${fileKey(FLOW.key)}.json`) return json(FLOW);
      return new Response("{}", { status: 404 });
    });
    const d = new ReplayAdapter("/replay/");
    expect((await d.flows("issuer")).length).toBe(L.flowsIssuer.items.length);
    expect(await d.flows("corr")).toEqual([]);
    expect((await d.flow("issuer", FLOW.key, { limit: 2 })).items).toEqual(FLOW.items.slice(-2));
    await expect(d.flow("ie", FLOW.key)).rejects.toMatchObject({ status: 404 });
  });
});

describe("Flows screen", () => {
  function data(flow: Flow, alerts: Alert[] = []) {
    const flowFn = vi.fn(async () => structuredClone(flow));
    const d = Object.assign(Object.create(new LiveAdapter("/api")), {
      health: async () => ({ mode: "live", ok: true, network: "private_tangle1", version: "test", note: null }),
      flows: async () => L.flowsIssuer.items,
      flow: flowFn,
      alerts: async (q: { rule?: string }) => alerts.filter((a) => a.rule === q.rule),
    }) as WitnessData;
    return { d, flowFn };
  }

  it("shows the most active producer's chain, newest first, each message linked to Verify", async () => {
    const { d, flowFn } = data(FLOW);
    const { w } = await mountScreen(FlowsView, { path: "/flows", data: d });
    await until(() => w.findAll(".tl .msg").length === FLOW.items.length);
    expect(flowFn).toHaveBeenCalledWith("issuer", L.flowsIssuer.items[0].key, { limit: 100 });
    expect(w.find('.list .row[aria-current="true"]').attributes("title")).toBe(L.flowsIssuer.items[0].key);
    const chain = w.find(".chain").text();
    expect(chain).toContain(String(FLOW.chain!.links));
    expect(w.findAll(".tl .msg a.x-link")[0]!.attributes("href")).toBe(`/m/${FLOW.items[FLOW.items.length - 1]!.blockId}`);
    expect(w.find(".tl .msg .link").text()).toContain("follows the message before it");
    const res = await axe.run(document.body, { rules: { "color-contrast": { enabled: false } } });
    const bad = res.violations.filter((v) => v.impact === "critical" || v.impact === "serious");
    expect(bad.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`)).toEqual([]);
    w.unmount();
  });

  it("flags a gap and a fork, with the alerts raised on them", async () => {
    const items = [item(1, null), item(2, 1), item(3, 1), item(4, 3), item(5, 3)];
    const flow = { ...FLOW, key: "x", items, total: 5, chain: { links: 2, gaps: [id(3), id(5)], forks: [id(3)] } } as Flow;
    const gapAlert = { id: 9, rule: "CHAIN_GAP", severity: "medium", blockId: id(3), ieId: null, evidence: { reason: "prev names an older block of this issuer" }, atMs: 1, dedupeKey: null } as Alert;
    const { d } = data(flow, [gapAlert]);
    const { w } = await mountScreen(FlowsView, { path: "/flows?by=issuer&key=x", data: d });
    await until(() => w.findAll(".tl .msg").length === 5 && w.find(".alert").exists());
    const byId = (n: number) => w.findAll(".tl .msg").find((m) => m.find("a.x-link").attributes("href") === `/m/${id(n)}`)!;
    expect(byId(3).attributes("data-link")).toBe("gap");
    expect(byId(3).find(".alert").text()).toContain("prev names an older block of this issuer");
    expect(byId(4).attributes("data-link")).toBe("fork");
    expect(byId(2).attributes("data-link")).toBe("linked");
    expect(w.find('.chain div[data-bad="true"]').exists()).toBe(true);
    w.unmount();
  });

  it("marks a message that only claims the producer, outside the chain", async () => {
    const items = [item(1, null), item(2, 1), { ...item(3, 2), verdict: "FORGED", claimsIssuer: true }, item(4, 2)];
    const flow = { ...FLOW, key: "y", items, total: 4, chain: { links: 2, gaps: [], forks: [] } } as Flow;
    const { d } = data(flow);
    const { w } = await mountScreen(FlowsView, { path: "/flows?by=issuer&key=y", data: d });
    await until(() => w.findAll(".tl .msg").length === 4);
    const byId = (n: number) => w.findAll(".tl .msg").find((m) => m.find("a.x-link").attributes("href") === `/m/${id(n)}`)!;
    expect(byId(3).attributes("data-link")).toBe("claims");
    expect(byId(3).find(".link").text()).toContain("claims this issuer");
    expect(byId(4).attributes("data-link")).toBe("linked");
    expect(w.find('.chain div[data-bad="true"]').exists()).toBe(false);
    w.unmount();
  });

  it("groups by correlation id without a chain", async () => {
    const corrFlow = { ...FLOW, by: "corr", key: "incident-7", chain: null } as Flow;
    const { d, flowFn } = data(corrFlow);
    const { w } = await mountScreen(FlowsView, { path: "/flows?by=corr&key=incident-7", data: d });
    await until(() => w.findAll(".tl .msg").length === FLOW.items.length);
    expect(flowFn).toHaveBeenCalledWith("corr", "incident-7", { limit: 100 });
    expect(w.find(".chain").exists()).toBe(false);
    expect(w.find(".tl .link").exists()).toBe(false);
    expect(w.find('.groups .chip[aria-pressed="true"]').text()).toBe("Correlation id");
    w.unmount();
  });
});
