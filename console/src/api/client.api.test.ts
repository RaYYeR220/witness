/**
 * The data layer against the real witness-api.
 *
 * fixtures/api/shapes.json lists the JSON fields of the API's response models
 * (console/scripts/api-shapes.py reads them from the pydantic models).
 * fixtures/api/live.json holds answers of a running API (trimmed), and
 * fixtures/api/examples.json answers built through the models for states the
 * running stack had none of (a posture scan with findings, an anchored report,
 * Orion answering). Tests here hold three things together: the recorded
 * answers fit the models, every field the console's types name exists in the
 * model, and both adapters ask for the API's real paths and hand screens the
 * same values.
 */
import { afterEach, describe, expect, it, vi } from "vitest";

import examples from "@/fixtures/api/examples.json";
import live from "@/fixtures/api/live.json";
import shapes from "@/fixtures/api/shapes.json";

import {
  asScorecard,
  DataError,
  fileKey,
  LiveAdapter,
  pageIncident,
  ReplayAdapter,
  type Alert,
  type AnchorCheckpoint,
  type Finding,
  type IeSummary,
  type Incident,
  type IncidentDetail,
  type IncidentEvent,
  type LedgerScore,
  type Lineage,
  type LineageEntry,
  type OrionState,
  type PolicySummary,
  type Posture,
  type ReportResult,
  type ReportSummary,
  type Stats,
  type TagRule,
} from "./client";

type Shapes = Record<string, Record<string, boolean>>;
const MODELS = shapes.models as Shapes;

/** Problems with `value` as an instance of `model`: a required field missing, or a field the model does not have. */
function misfit(model: string, value: unknown, extra: readonly string[] = []): string[] {
  const fields = MODELS[model];
  if (!fields) return [`no model ${model}`];
  if (typeof value !== "object" || value === null) return [`${model}: not an object`];
  const keys = Object.keys(value);
  const out: string[] = [];
  for (const [f, required] of Object.entries(fields)) if (required && !keys.includes(f)) out.push(`${model}.${f} missing`);
  for (const k of keys) if (!(k in fields) && !extra.includes(k)) out.push(`${model}.${k} unknown`);
  return out;
}

const each = (model: string, items: unknown[], extra: readonly string[] = []) => items.flatMap((x) => misfit(model, x, extra));

// The console's types, key by key: `satisfies` makes TypeScript fail when a
// type gains or loses a field and this list is not updated, and the test below
// fails when a listed field is not in the API model.
const READS = {
  IeSummary: { ieId: 1, count: 1, firstAtMs: 1, lastAtMs: 1, lastMsIndex: 1, latestScore: 1 } satisfies Record<keyof IeSummary, 1>,
  Lineage: { ieId: 1, entries: 1, total: 1, ledger: 1, orion: 1, drift: 1, epsilon: 1 } satisfies Record<keyof Lineage, 1>,
  LineageEntry: { blockId: 1, prev: 1, seq: 1, kind: 1, verdict: 1, msIndex: 1, wfIndex: 1, atMs: 1, score: 1, links: 1 } satisfies Record<
    keyof LineageEntry,
    1
  >,
  LedgerScore: { score: 1, blockId: 1, verdict: 1, msIndex: 1, atMs: 1 } satisfies Record<keyof LedgerScore, 1>,
  OrionState: { status: 1, value: 1, entityId: 1 } satisfies Record<keyof OrionState, 1>,
  AlertOut: { id: 1, rule: 1, severity: 1, blockId: 1, ieId: 1, evidence: 1, atMs: 1, dedupeKey: 1 } satisfies Record<keyof Alert, 1>,
  Incident: {
    id: 1,
    title: 1,
    severity: 1,
    status: 1,
    ieId: 1,
    keys: 1,
    openedAtMs: 1,
    lastEventMs: 1,
    closedAtMs: 1,
    closedBy: 1,
    baselineScore: 1,
    lowScore: 1,
  } satisfies Record<keyof Incident, 1>,
  IncidentDetail: { events: 1, eventsTotal: 1, nextEventsCursor: 1, alerts: 1, alertsTotal: 1, nextAlertsAfter: 1 } satisfies Record<
    Exclude<keyof IncidentDetail, keyof Incident>,
    1
  >,
  IncidentEvent: {
    blockId: 1,
    role: 1,
    atMs: 1,
    tag: 1,
    kind: 1,
    verdict: 1,
    status: 1,
    msIndex: 1,
    dateMs: 1,
    indexed: 1,
    detail: 1,
    links: 1,
  } satisfies Record<keyof IncidentEvent, 1>,
  AnchorOut: {
    seq: 1,
    fromMilestone: 1,
    toMilestone: 1,
    msRoot: 1,
    checkpoint: 1,
    checkpointHash: 1,
    network: 1,
    tx: 1,
    record: 1,
    status: 1,
    createdAtMs: 1,
  } satisfies Record<keyof AnchorCheckpoint, 1>,
  PolicySummary: { version: 1, hash: 1, tags: 1, default: 1 } satisfies Record<keyof PolicySummary, 1>,
  TagRuleOut: { allowed: 1, requireSignature: 1, legacyGrace: 1 } satisfies Record<keyof TagRule, 1>,
  Posture: { scannedAtMs: 1, active: 1, summary: 1, findings: 1 } satisfies Record<keyof Posture, 1>,
  Finding: { id: 1, severity: 1, title: 1, evidence: 1, fix: 1 } satisfies Record<keyof Finding, 1>,
  Stats: { counts: 1, services: 1, validator: 1, nodeRoute: 1, streamSubscribers: 1 } satisfies Record<keyof Stats, 1>,
  ReportSummary: {
    reportHash: 1,
    anchored: 1,
    blockId: 1,
    ie: 1,
    msFrom: 1,
    msTo: 1,
    iss: 1,
    seq: 1,
    generatedAtMs: 1,
    anchoredAtMs: 1,
    links: 1,
  } satisfies Record<keyof ReportSummary, 1>,
  ReportResult: { report: 1 } satisfies Record<Exclude<keyof ReportResult, keyof ReportSummary>, 1>,
};

describe("API contract", () => {
  it("every field the console's types read exists in the API model", () => {
    const missing: string[] = [];
    for (const [model, keys] of Object.entries(READS)) {
      for (const k of Object.keys(keys)) {
        if (!(k in (MODELS[model] ?? {}))) missing.push(`${model}.${k}`);
      }
    }
    expect(missing).toEqual([]);
  });

  it("the recorded answers fit the models", () => {
    const L = live as unknown as Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
    const E = examples as unknown as Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
    const problems = [
      ...misfit("IeList", L.ie),
      ...each("IeSummary", L.ie.items),
      ...[L.lineage, L.lineageUnknownEntity, E.lineageOrionOk].flatMap((x) => [
        ...misfit("Lineage", x),
        ...each("LineageEntry", x.entries),
        ...misfit("OrionState", x.orion),
        ...(x.ledger ? misfit("LedgerScore", x.ledger) : []),
      ]),
      ...misfit("AlertList", L.alerts),
      ...each("AlertOut", L.alerts.items),
      ...misfit("IncidentList", L.incidents),
      ...each("Incident", L.incidents.items),
      ...[L.incidentPage1, L.incidentPage2, L.incidentClosedOrNot].flatMap((x) => [
        ...misfit("IncidentDetail", x),
        ...each("IncidentEvent", x.events),
        ...each("AlertOut", x.alerts),
      ]),
      ...misfit("AnchorList", L.anchors),
      ...each("AnchorOut", L.anchors.items),
      ...misfit("Identity", L.identity),
      ...misfit("AnchorIdentities", L.identity.anchor),
      ...misfit("PolicySummary", L.identity.policy),
      ...each("TagRuleOut", Object.values(L.identity.policy.tags)),
      ...[L.posture, E.posture].flatMap((x) => [...misfit("Posture", x), ...each("Finding", x.findings)]),
      ...[L.reports, E.reports].flatMap((x) => [...misfit("ReportList", x), ...each("ReportSummary", x.items)]),
      ...misfit("ReportResult", E.report),
      ...misfit("Stats", L.stats),
    ];
    expect(problems).toEqual([]);
  });
});

// ------------------------------------------------------------------ fetch fakes

const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status, headers: { "content-type": "application/json" } });
const text = (t: string, type = "application/json") => new Response(t, { status: 200, headers: { "content-type": type } });

/** Records every URL asked and answers from `table` (by exact URL), else 404. */
function fakeFetch(table: Record<string, () => Response>) {
  const asked: string[] = [];
  vi.stubGlobal("fetch", async (input: string) => {
    const url = String(input);
    asked.push(url);
    const hit = table[url];
    return hit ? hit() : json({ detail: "Not Found" }, 404);
  });
  return asked;
}

afterEach(() => vi.unstubAllGlobals());

const IE = "MyDomain:fa163e5e25ef";
const L = live as unknown as Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
const E = examples as unknown as Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

describe("LiveAdapter", () => {
  it("asks the API's real paths and unwraps the item lists", async () => {
    const reportHash: string = E.report.reportHash;
    const p1 = L.incidentPage1;
    const asked = fakeFetch({
      "/api/ie": () => json(L.ie),
      [`/api/ie/${encodeURIComponent(IE)}/lineage?limit=50`]: () => json(L.lineage),
      "/api/alerts?severity=high&rule=SHADOW": () => json(L.alerts),
      "/api/incidents?status=open": () => json(L.incidents),
      "/api/incidents/3?limit=2": () => json(p1),
      [`/api/incidents/3?limit=2&eventsAfter=${encodeURIComponent(p1.nextEventsCursor)}&alertsAfter=${p1.nextAlertsAfter}`]: () => json(L.incidentPage2),
      "/api/anchors?limit=100": () => json(L.anchors),
      "/api/identity": () => json(L.identity),
      "/api/posture": () => json(L.posture),
      "/api/stats": () => json(L.stats),
      "/api/reports?limit=10": () => json(E.reports),
      [`/api/reports/${reportHash}`]: () => text(JSON.stringify(E.report)),
    });
    const d = new LiveAdapter("/api/");
    expect((await d.ies()).map((i) => i.ieId)).toEqual(L.ie.items.map((i: IeSummary) => i.ieId));
    const lin = await d.lineage(IE, { limit: 50 });
    expect(lin.ieId).toBe(IE);
    expect(lin.orion.status).toBe(L.lineage.orion.status);
    expect(await d.alerts({ severity: "high", rule: "SHADOW" })).toEqual(L.alerts.items);
    expect(await d.incidents({ status: "open" })).toEqual(L.incidents.items);
    const first = await d.incident(3, { limit: 2 });
    expect(first.events).toHaveLength(2);
    const second = await d.incident(3, { limit: 2, eventsAfter: first.nextEventsCursor!, alertsAfter: first.nextAlertsAfter! });
    expect(second.nextEventsCursor).toBeNull();
    expect((await d.anchors()).map((a) => a.record)).toEqual(L.anchors.items.map((a: AnchorCheckpoint) => a.record));
    expect((await d.identity()).policy?.hash).toBe(L.identity.policy.hash);
    expect((await d.posture()).scannedAtMs).toBeNull();
    expect((await d.stats()).services?.orion).toBe("ok");
    expect((await d.reports({ limit: 10 })).items[0]!.reportHash).toBe(reportHash);
    const doc = await d.report(reportHash);
    expect(doc.result.anchored).toBe(true);
    expect(doc.text).toBe(JSON.stringify(E.report));
    expect(d.reportHtmlUrl(reportHash)).toBe(`/api/reports/${reportHash}.html`);
    expect(asked.every((u) => u.startsWith("/api/"))).toBe(true);
  });

  it("never asks for a malformed report hash or incident id", async () => {
    const asked = fakeFetch({});
    const d = new LiveAdapter("/api");
    await expect(d.report("0xABC")).rejects.toMatchObject({ status: 400 });
    await expect(d.report(`0x${"CD".repeat(32)}`)).rejects.toBeInstanceOf(DataError);
    await expect(d.report(`0x${"cd".repeat(32)}/../../stats`)).rejects.toBeInstanceOf(DataError);
    await expect(d.incident(0)).rejects.toMatchObject({ status: 404 });
    await expect(d.incident(1.5)).rejects.toMatchObject({ status: 404 });
    expect(d.reportHtmlUrl("javascript:alert(1)")).toBeNull();
    expect(asked).toEqual([]);
  });

  it("has no scorecard unless one is published, and refuses a file that is not one", async () => {
    fakeFetch({
      "/eval/scorecard.json": () => json({ schema: "something/else", detected: 1 }),
    });
    expect(await new LiveAdapter("/api").scorecard()).toBeNull();
    expect(await new LiveAdapter("/api", { scorecardUrl: "/eval/missing.json" }).scorecard()).toBeNull();
    await expect(new LiveAdapter("/api", { scorecardUrl: "/eval/scorecard.json" }).scorecard()).rejects.toBeInstanceOf(DataError);
  });

  it("reads a static host's index page as a missing file, not as data", async () => {
    fakeFetch({ "/api/posture": () => text("<!doctype html><title>Witness</title>", "text/html") });
    await expect(new LiveAdapter("/api").posture()).rejects.toMatchObject({ status: 404 });
  });
});

describe("ReplayAdapter", () => {
  /** A snapshot as scripts/record-replay.mjs writes it, from the same recorded answers. */
  function snapshot(extra: Record<string, () => Response> = {}) {
    const full = { ...L.incidentPage1, events: [...L.incidentPage1.events, ...L.incidentPage2.events], alerts: [...L.incidentPage1.alerts, ...L.incidentPage2.alerts] };
    return fakeFetch({
      "/replay/ie.json": () => json(L.ie),
      [`/replay/lineage/${fileKey(IE)}.json`]: () => json(L.lineage),
      "/replay/alerts.json": () => json(L.alerts),
      "/replay/incidents.json": () => json(L.incidents),
      "/replay/incidents/3.json": () => json({ ...full, nextEventsCursor: null, nextAlertsAfter: null }),
      "/replay/anchors.json": () => json(L.anchors),
      "/replay/identity.json": () => json(L.identity),
      "/replay/stats.json": () => json(L.stats),
      "/replay/reports.json": () => json(E.reports),
      [`/replay/reports/${E.report.reportHash}.json`]: () => text(JSON.stringify(E.report)),
      ...extra,
    });
  }

  it("serves the same screens from static files", async () => {
    const asked = snapshot();
    const d = new ReplayAdapter("/replay/");
    expect((await d.ies()).length).toBe(L.ie.items.length);
    expect((await d.lineage(IE)).entries).toEqual(L.lineage.entries);
    expect((await d.lineage(IE, { limit: 3 })).entries).toEqual(L.lineage.entries.slice(-3));
    expect((await d.alerts({ rule: "SHADOW" })).map((a) => a.rule)).toEqual(["SHADOW"]);
    expect((await d.alerts({ severity: "critical" })).every((a: Alert) => a.severity === "critical")).toBe(true);
    expect((await d.incidents({ ie: "ChaosDomain:79c67275e6b0" })).map((i) => i.id)).toEqual([2]);
    expect((await d.anchors(1)).map((a) => a.seq)).toEqual([L.anchors.items[0].seq]);
    expect((await d.identity()).anchor.status).toBe("ok");
    expect((await d.stats()).counts.anchors).toBe(L.stats.counts.anchors);
    expect((await d.reports()).items).toHaveLength(1);
    expect((await d.report(E.report.reportHash)).result.reportHash).toBe(E.report.reportHash);
    expect(d.reportHtmlUrl(E.report.reportHash)).toBe(`/replay/reports/${E.report.reportHash}.html`);
    // what a snapshot does not hold is empty, not an error
    expect(await d.posture()).toEqual({ scannedAtMs: null, active: false, summary: {}, findings: [] });
    expect(await d.scorecard()).toBeNull();
    expect(asked.every((u) => u.startsWith("/replay/"))).toBe(true);
  });

  it("pages a recorded incident like the API does: events by cursor, alerts after an id", async () => {
    snapshot();
    const d = new ReplayAdapter("/replay/");
    const p1 = await d.incident(3, { limit: 2 });
    expect(p1.events.map((e) => e.blockId)).toEqual(L.incidentPage1.events.map((e: IncidentEvent) => e.blockId));
    expect(p1.nextEventsCursor).not.toBeNull();
    expect(p1.alerts.map((a) => a.id)).toEqual(L.incidentPage1.alerts.map((a: Alert) => a.id));
    const p2 = await d.incident(3, { limit: 2, eventsAfter: p1.nextEventsCursor!, alertsAfter: p1.nextAlertsAfter! });
    expect(p2.events.map((e) => e.blockId)).toEqual(L.incidentPage2.events.map((e: IncidentEvent) => e.blockId));
    expect(p2.alerts.map((a) => a.id)).toEqual(L.incidentPage2.alerts.map((a: Alert) => a.id));
    expect(p2.nextEventsCursor).toBeNull();
    expect(p2.nextAlertsAfter).toBeNull();
    expect(p2.eventsTotal).toBe(L.incidentPage1.eventsTotal);
  });

  it("refuses a recorded file that names another IE or incident", async () => {
    snapshot({
      [`/replay/lineage/${fileKey("MyDomain:fa163e000000")}.json`]: () => json(L.lineage),
      "/replay/incidents/2.json": () => json(L.incidentPage1),
    });
    const d = new ReplayAdapter("/replay/");
    await expect(d.lineage("MyDomain:fa163e000000")).rejects.toMatchObject({ status: 404 });
    await expect(d.incident(2)).rejects.toMatchObject({ status: 404 });
  });

  it("shows a recorded scorecard only when it is one", async () => {
    const card = {
      schema: "witness-chaos/scorecard/v1",
      headline: "detected 9/10 attacks",
      detected: 9,
      attacks: 10,
      detection_rate: 0.9,
      latency_p50_ms: 4200,
      latency_p95_ms: 9100,
      unexpected_alerts: 0,
      classes: [{ id: "A01", name: "Forged signature", expected: "FORGED", trials: 10, detected: 9, rate: 0.9, latency_p50_ms: 4200, latency_p95_ms: 9100 }],
      traps: null,
      controls: { trials: 5, passed: 5 },
    };
    snapshot({ "/replay/scorecard.json": () => json(card) });
    expect(await new ReplayAdapter("/replay/").scorecard()).toEqual(card);
    expect(asScorecard({ ...card, classes: [{ id: "A01" }] })).toBeNull();
    expect(asScorecard({ ...card, detected: "9" })).toBeNull();
  });
});

describe("pageIncident", () => {
  it("cuts a whole recorded incident into pages", () => {
    const events = Array.from({ length: 5 }, (_, i) => ({ blockId: `e${i}` })) as unknown as IncidentEvent[];
    const alerts = [3, 7, 9].map((id) => ({ id })) as unknown as Alert[];
    const full = { id: 1, events, alerts, eventsTotal: 5, alertsTotal: 3 } as unknown as IncidentDetail;
    const a = pageIncident(full, { limit: 2 });
    expect([a.events.length, a.nextEventsCursor, a.alerts.map((x) => x.id), a.nextAlertsAfter]).toEqual([2, "2", [3, 7], 7]);
    const b = pageIncident(full, { limit: 2, eventsAfter: "4", alertsAfter: 7 });
    expect([b.events.map((e) => e.blockId), b.nextEventsCursor, b.alerts.map((x) => x.id), b.nextAlertsAfter]).toEqual([["e4"], null, [9], null]);
  });
});
