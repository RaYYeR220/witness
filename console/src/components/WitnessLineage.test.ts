// @vitest-environment jsdom
import { mount } from "@vue/test-utils";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { DataError, LiveAdapter, type Alert, type Incident, type Lineage, type WitnessData } from "@/api/client";
import examples from "@/fixtures/api/examples.json";
import live from "@/fixtures/api/live.json";
import { RECORDED_NOTE } from "@/console/format";
import { orionView, seriesOf } from "@/lineage/model";
import { mountScreen, until } from "@/test/mount";
import LineageView from "@/views/LineageView.vue";

import WitnessLineage from "./WitnessLineage.vue";

const ok = examples.lineageOrionOk as unknown as Lineage;
const IE = ok.ieId;

function source(lin: Lineage | Error, alerts: Alert[] = [], incidents: Incident[] = []) {
  return {
    lineage: vi.fn(async () => {
      if (lin instanceof Error) throw lin;
      return structuredClone(lin);
    }),
    alerts: vi.fn(async () => alerts),
    incidents: vi.fn(async () => incidents),
  };
}

const unreachable = (): Lineage => ({ ...structuredClone(ok), orion: { status: "unreachable", value: null, entityId: ok.orion.entityId }, drift: null });

afterEach(() => {
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

describe("lineage model", () => {
  it("draws only scored, timed entries, in time order", () => {
    const entries = [...ok.entries].reverse();
    entries.push({ ...entries[0]!, blockId: "0x" + "ee".repeat(32), score: null });
    expect(seriesOf(entries).map((p) => p.score)).toEqual([0.82, 0.8, 0.41, 0.43]);
  });

  it("claims drift only when Orion answered with a value", () => {
    expect(orionView(ok)).toMatchObject({ kind: "ok", value: 0.82, showDrift: true, drift: true });
    expect(orionView({ ...ok, drift: false })).toMatchObject({ showDrift: true, drift: false });
    for (const status of ["unreachable", "unknown_entity", "no_score", "not_configured", "weird"]) {
      // even if a confused API sent drift: true along with it
      const v = orionView({ ...ok, orion: { status, value: null, entityId: "x" }, drift: true });
      expect(v.showDrift).toBe(false);
      expect(v.value).toBeNull();
    }
    expect(orionView(unreachable()).headline).toBe("Orion unreachable");
  });
});

describe("WitnessLineage", () => {
  it("renders the ledger series, Orion's marker and the drift badge", async () => {
    const src = source(ok);
    const w = mount(WitnessLineage, { props: { ieId: IE, data: src, verifyHref: (b: string) => `/m/${b}` }, attachTo: document.body });
    await until(() => w.find(".plot").exists());
    expect(w.findAll(".pt")).toHaveLength(ok.entries.length);
    expect(w.findAll('.pt[data-f="signed"]')).toHaveLength(4);
    expect(w.find(".latest").exists()).toBe(true); // the ledger's current score is ringed
    expect(w.find(".orion-mark").exists()).toBe(true);
    expect(w.find(".orion-mark").attributes("data-drift")).toBe("yes");
    const badge = w.find(".drift-badge");
    expect(badge.text()).toBe("Drift");
    expect(badge.attributes("data-drift")).toBe("yes");
    expect(w.find(".wl-now").text()).toContain("0.43"); // the ledger
    expect(w.find(".wl-now").text()).toContain("0.82"); // Orion
    // every score links to Verify
    const links = w.findAll(".wl-entries a").map((a) => a.attributes("href"));
    expect(links).toEqual([...ok.entries].reverse().map((e) => `/m/${e.blockId}`));
    expect(w.find(".wl-v").attributes("title")).toBe(RECORDED_NOTE);
    expect(w.find(".wl-v").text()).toContain("recorded");
    expect(src.lineage).toHaveBeenCalledWith(IE, { limit: 1000 });
    expect(src.alerts).toHaveBeenCalledWith({ ie: IE, limit: 200 });
    expect(src.incidents).toHaveBeenCalledWith({ ie: IE });
    w.unmount();
  });

  it("says Orion is unreachable and shows no drift badge and no marker", async () => {
    const w = mount(WitnessLineage, { props: { ieId: IE, data: source(unreachable()) }, attachTo: document.body });
    await until(() => w.find(".plot").exists());
    expect(w.find(".wl-orion").text()).toContain("Orion unreachable");
    expect(w.find(".drift-badge").exists()).toBe(false);
    expect(w.find(".orion-mark").exists()).toBe(false);
    expect(w.findAll(".pt")).toHaveLength(ok.entries.length);
    w.unmount();
  });

  it("draws alerts and incidents about the IE on the time axis", async () => {
    const t0 = ok.entries[0]!.atMs!;
    const alerts = [{ id: 7, rule: "ANOMALY", severity: "medium", blockId: ok.entries[2]!.blockId, ieId: IE, evidence: {}, atMs: t0 + 125_000, dedupeKey: null }];
    const incidents = [
      {
        id: 4,
        title: `Trust score of ${IE} dropped 0.80 -> 0.41`,
        severity: "high",
        status: "open",
        ieId: IE,
        keys: [`ie:${IE}`],
        openedAtMs: t0 + 120_000,
        lastEventMs: t0 + 120_000,
        closedAtMs: null,
        closedBy: null,
        baselineScore: 0.8,
        lowScore: 0.41,
      },
    ];
    const w = mount(WitnessLineage, {
      props: { ieId: IE, data: source(ok, alerts, incidents), verifyHref: (b: string) => `/m/${b}`, incidentHref: (n: number) => `/integrity?incident=${n}` },
      attachTo: document.body,
    });
    await until(() => w.find(".plot").exists());
    expect(w.findAll(".band")).toHaveLength(1);
    expect(w.findAll(".mark")).toHaveLength(1);
    const items = w.findAll(".wl-evlist li");
    expect(items.map((li) => li.attributes("data-kind"))).toEqual(["alert", "incident"]);
    expect(w.find('.wl-evlist a[href="/integrity?incident=4"]').exists()).toBe(true);
    w.unmount();
  });

  it("asks the API's lineage route when given only apiBase", async () => {
    const asked: string[] = [];
    vi.stubGlobal("fetch", async (u: string) => {
      asked.push(String(u));
      const body = String(u).includes("/lineage") ? live.lineage : { items: [] };
      return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
    });
    const w = mount(WitnessLineage, { props: { ieId: live.lineage.ieId, apiBase: "https://witness.example/api" }, attachTo: document.body });
    await until(() => w.find(".plot").exists());
    expect(asked).toContain(`https://witness.example/api/ie/${encodeURIComponent(live.lineage.ieId)}/lineage?limit=1000`);
    // the recorded IE: Orion holds no score for it, so no badge
    expect(w.find(".drift-badge").exists()).toBe(false);
    expect(w.find(".wl-orion").text()).toContain("Orion holds no trust score");
    // without verifyHref the scores are not links
    expect(w.findAll(".wl-entries a")).toHaveLength(0);
    w.unmount();
  });

  it("explains an IE the ledger has nothing about, and refuses another IE's lineage", async () => {
    const a = mount(WitnessLineage, { props: { ieId: IE, data: source(new DataError("no ledger messages", 404)) } });
    await until(() => a.find(".wl-err").exists());
    expect(a.find(".wl-err").text()).toBe(`The ledger holds no messages about ${IE}.`);
    const b = mount(WitnessLineage, { props: { ieId: "Other:000000000000", data: source(ok) } });
    await until(() => b.find(".wl-err").exists());
    expect(b.find(".wl-err").text()).toContain("another IE");
    expect(b.find(".plot").exists()).toBe(false);
  });
});

describe("Lineage screen", () => {
  function data(): WitnessData {
    const d = new LiveAdapter("/api");
    return Object.assign(Object.create(d), {
      ies: async () => live.ie.items,
      lineage: async (ie: string) => ({ ...structuredClone(ok), ieId: ie }),
      alerts: async () => [],
      incidents: async () => [],
      health: async () => ({ mode: "live", ok: true, network: "private_tangle1", version: "test", note: null }),
    }) as WitnessData;
  }

  it("opens the most recently active IE and links scores to Verify through the router", async () => {
    const { w, router } = await mountScreen(LineageView, { path: "/ie", data: data() });
    await until(() => router.currentRoute.value.params.id === live.ie.items[0]!.ieId);
    await until(() => w.find(".plot").exists());
    const first = w.find(".wl-entries a");
    expect(first.attributes("href")).toMatch(/^\/m\/0x/);
    await first.trigger("click");
    await until(() => router.currentRoute.value.name === "verify");
    w.unmount();
  });

  it("has no critical or serious axe violations", async () => {
    const { w } = await mountScreen(LineageView, { path: `/ie/${IE}`, data: data() });
    await until(() => w.find(".plot").exists());
    const res = await axe.run(document.body, { rules: { "color-contrast": { enabled: false } } });
    const bad = res.violations.filter((v) => v.impact === "critical" || v.impact === "serious");
    expect(bad.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`)).toEqual([]);
    w.unmount();
  });
});
