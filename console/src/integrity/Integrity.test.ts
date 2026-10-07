// @vitest-environment jsdom
import { mount } from "@vue/test-utils";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { LiveAdapter, pageIncident, type Alert, type IncidentDetail as Detail, type IncidentEvent, type Scorecard, type WitnessData } from "@/api/client";
import live from "@/fixtures/api/live.json";
import { mountScreen, until } from "@/test/mount";
import IntegrityView from "@/views/IntegrityView.vue";

import IncidentDetail from "./IncidentDetail.vue";
import { statusLine, trustLine, trustOf } from "./model";

/* eslint-disable @typescript-eslint/no-explicit-any */
const L = live as unknown as Record<string, any>;
/** Incident 3 as the API recorded it in two pages of two. */
const P1 = L.incidentPage1 as Detail;
const P2 = L.incidentPage2 as Detail;
const FULL: Detail = { ...P1, events: [...P1.events, ...P2.events], alerts: [...P1.alerts, ...P2.alerts], nextEventsCursor: null, nextAlertsAfter: null };

const json = (v: unknown) => new Response(JSON.stringify(v), { status: 200, headers: { "content-type": "application/json" } });

afterEach(() => {
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

/** A router for RouterLink inside a component mounted alone. */
async function withRouter() {
  const { createRouter, createMemoryHistory } = await import("vue-router");
  const { defineComponent, h } = await import("vue");
  const Stub = defineComponent({ render: () => h("div") });
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/", component: Stub },
      { path: "/m/:blockId", name: "verify", component: Stub },
      { path: "/ie/:id?", name: "lineage", component: Stub },
    ],
  });
  await router.push("/");
  return router;
}

describe("incident model", () => {
  it("reads the trust level the engine recorded, and nothing else", () => {
    expect(P1.events.map(trustOf)).toEqual(P1.events.map((e: IncidentEvent) => (e.detail as { trust: string }).trust));
    expect(trustOf({ detail: { trust: "PROVEN" } })).toBe("unknown");
    expect(trustOf({ detail: "proven" })).toBe("unknown");
    expect(trustOf({ detail: null })).toBe("unknown");
  });

  it("says a revoked event is evidence only, whatever level it had", () => {
    const shadowed = (L.incidentClosedOrNot as Detail).events[0]!; // recorded: trust proven, revoked "shadow", was "trigger"
    expect((shadowed.detail as { trust: string }).trust).toBe("proven");
    expect(trustOf(shadowed)).toBe("revoked");
    expect(trustLine(shadowed)).toBe("Revoked (shadow): evidence only, was trigger");
    expect(trustLine({ detail: { trust: "proven" } })).toBe("Proven, per the engine");
    expect(trustOf({ detail: { trust: "proven", revoked: "<b>x</b>" } })).toBe("proven"); // not a word: ignored
  });

  it("says why an incident closed", () => {
    const base = L.incidents.items[0];
    expect(statusLine({ ...base, status: "open" }).label).toBe("Open");
    expect(statusLine({ ...base, status: "closed:recovered", baselineScore: 0.9, closedAtMs: 1791332389000 }).text).toContain("came back to where the first drop fell from (0.90)");
    expect(statusLine({ ...base, status: "closed:quiet", closedAtMs: 1791332389000 }).text).toContain("no event for 30 minutes");
  });
});

describe("IncidentDetail", () => {
  it("pages events and alerts with the API's own cursors", async () => {
    const asked: string[] = [];
    vi.stubGlobal("fetch", async (u: string) => {
      const url = String(u);
      asked.push(url);
      if (url === "/api/incidents/3?limit=2") return json(P1);
      if (url === `/api/incidents/3?limit=2&eventsAfter=${encodeURIComponent(P1.nextEventsCursor!)}`) return json(P2);
      if (url === `/api/incidents/3?limit=2&alertsAfter=${P1.nextAlertsAfter}`) return json(P2);
      return new Response("{}", { status: 404 });
    });
    const router = await withRouter();
    const w = mount(IncidentDetail, { props: { id: 3, data: new LiveAdapter("/api"), pageSize: 2 }, global: { plugins: [router] }, attachTo: document.body });
    await until(() => w.findAll(".ev").length === 2);
    const [moreEvents, moreAlerts] = w.findAll("button.more");
    expect(moreEvents!.text()).toBe(`Show more events (2 of ${P1.eventsTotal})`);
    expect(moreAlerts!.text()).toBe(`Show more alerts (${P1.alerts.length} of ${P1.alertsTotal})`);
    await moreEvents!.trigger("click");
    await until(() => w.findAll(".ev").length === 4);
    expect(w.findAll(".ev").map((e) => e.attributes("data-trust"))).toEqual(FULL.events.map(trustOf));
    // the second page of alerts is asked separately and appended once
    await w.findAll("button.more").at(-1)!.trigger("click");
    await until(() => w.findAll(".al li").length === FULL.alerts.length);
    expect(w.findAll("button.more")).toHaveLength(0);
    // the engine's levels are its word: never green
    expect(w.find('.ev-trust[data-trust="proven"]').text()).toBe("Proven, per the engine");
    expect(w.find(".tl .vm[data-f='signed']").exists()).toBe(false);
    expect(asked).toEqual([
      "/api/incidents/3?limit=2",
      `/api/incidents/3?limit=2&eventsAfter=${encodeURIComponent(P1.nextEventsCursor!)}`,
      `/api/incidents/3?limit=2&alertsAfter=${P1.nextAlertsAfter}`,
    ]);
    // why it opened: the trigger event, with a link to verify it
    expect(w.find(".inc-facts").text()).toContain("CONTENT_MISMATCH alert (proven, per the engine)");
    expect(w.find(`.inc-facts a[href="/m/${P1.events[0]!.blockId}"]`).exists()).toBe(true);
    // a block the explorer has no message for is not a Verify link
    const orphan = FULL.events.find((e) => !e.indexed)!;
    expect(w.find(`.tl a[href="/m/${orphan.blockId}"]`).exists()).toBe(false);
    expect(w.find(".tl").text()).toContain("not in the explorer's records");
    w.unmount();
  });

  it("pages a replayed incident the same way", async () => {
    const calls: unknown[] = [];
    const data = { incident: async (_id: number, page?: object) => (calls.push(page), pageIncident(structuredClone(FULL), page)) };
    const router = await withRouter();
    const w = mount(IncidentDetail, { props: { id: 3, data, pageSize: 3 }, global: { plugins: [router] } });
    await until(() => w.findAll(".ev").length === 3);
    await w.find("button.more").trigger("click");
    await until(() => w.findAll(".ev").length === 4);
    expect(calls).toEqual([{ limit: 3 }, { limit: 3, eventsAfter: "3" }, ...calls.slice(2)]);
  });
});

describe("Integrity screen", () => {
  const HOSTILE: Alert = {
    id: 9001,
    rule: "FORGED",
    severity: "critical",
    blockId: "0x" + "ab".repeat(32),
    ieId: "MyDomain:fa163e5e25ef",
    evidence: { reason: '<img src=x onerror="window.__pwned=1">', note: "</pre><script>window.__pwned=2</script>" },
    atMs: 1791332389000,
    dedupeKey: null,
  };

  function data(card: Scorecard | null = null) {
    const alerts = vi.fn(async () => [HOSTILE, ...(L.alerts.items as Alert[])]);
    const d = Object.assign(Object.create(new LiveAdapter("/api")), {
      health: async () => ({ mode: "live", ok: true, network: "private_tangle1", version: "test", note: null }),
      scorecard: async () => card,
      incidents: async () => L.incidents.items,
      incident: async (id: number, page?: object) => pageIncident({ ...structuredClone(FULL), id }, page),
      alerts,
    }) as WitnessData;
    return { d, alerts };
  }

  it("shows a placeholder until a scorecard is published, never numbers of its own", async () => {
    const { d } = data();
    const { w } = await mountScreen(IntegrityView, { path: "/integrity", data: d });
    await until(() => w.find(".placeholder").exists());
    expect(w.find(".card").text()).toContain("The scorecard appears after the evaluation run.");
    expect(w.find(".card").text()).not.toMatch(/\d+%/);
    w.unmount();
  });

  it("renders a published scorecard as written", async () => {
    const card: Scorecard = {
      schema: "witness-chaos/scorecard/v1",
      headline: "detected 57/60 attacks, 0/512 false positives",
      detected: 57,
      attacks: 60,
      detection_rate: 0.95,
      latency_p50_ms: 4200,
      latency_p95_ms: 9800,
      unexpected_alerts: 0,
      classes: [{ id: "A01", name: "Forged signature", expected: "FORGED", trials: 20, detected: 20, rate: 1, latency_p50_ms: 3900, latency_p95_ms: 6100 }],
      traps: { messages: 512, duration_s: 1900, false_positives: 0, meets_profile: true },
      controls: null,
    };
    const { d } = data(card);
    const { w } = await mountScreen(IntegrityView, { path: "/integrity", data: d });
    await until(() => w.find(".headline").exists());
    expect(w.find(".headline").text()).toBe(card.headline);
    expect(w.find(".nums").text()).toContain("95%");
    expect(w.find(".nums").text()).toContain("57/60");
    w.unmount();
  });

  it("filters alerts by severity and rule through the URL and shows evidence only as text", async () => {
    const { d, alerts } = data();
    const { w, router } = await mountScreen(IntegrityView, { path: "/integrity", data: d });
    await until(() => w.findAll(".alert").length > 1);
    expect(alerts).toHaveBeenLastCalledWith({ severity: undefined, rule: undefined, limit: 50 });
    // hostile evidence stays text
    const ev = w.find(".alert .a-ev");
    expect(ev.text()).toContain("onerror");
    expect(document.querySelector(".alerts img, .alerts script")).toBeNull();
    expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined();
    // severity
    await w.findAll(".sev .chip").find((b) => b.text() === "High")!.trigger("click");
    await until(() => router.currentRoute.value.query.severity === "high");
    await until(() => alerts.mock.calls.length >= 2);
    expect(alerts).toHaveBeenLastCalledWith({ severity: "high", rule: undefined, limit: 50 });
    // rule
    await w.find(".rule select").setValue("SHADOW");
    await until(() => router.currentRoute.value.query.rule === "SHADOW");
    await until(() => alerts.mock.calls.length >= 3);
    expect(alerts).toHaveBeenLastCalledWith({ severity: "high", rule: "SHADOW", limit: 50 });
    w.unmount();
  });

  it("opens the incident in the URL and has no critical or serious axe violations", async () => {
    const { d } = data();
    const { w } = await mountScreen(IntegrityView, { path: "/integrity?incident=2", data: d });
    await until(() => w.find(".inc-title").exists() && w.findAll(".alert").length > 1);
    expect(w.find('.inc-row[aria-current="true"]').text()).toContain(L.incidents.items.find((i: { id: number }) => i.id === 2).title);
    const res = await axe.run(document.body, { rules: { "color-contrast": { enabled: false } } });
    const bad = res.violations.filter((v) => v.impact === "critical" || v.impact === "serious");
    expect(bad.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`)).toEqual([]);
    w.unmount();
  });
});
