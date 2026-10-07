/**
 * The replay build: the console served as static files with a recorded
 * snapshot and no API behind it. Every screen must render from the snapshot,
 * and Verify must still compute the five checks in the browser (step 5 reads
 * IOTA Rebased live, so it needs the network; without it the run is PARTIAL
 * and says so).
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { expect, test, type Page } from "@playwright/test";

import { axeCheck, ladderResult, noSideScroll, SCREENS } from "./helpers";

const SNAPSHOT = join(dirname(fileURLToPath(import.meta.url)), ".snapshot");
const has = existsSync(join(SNAPSHOT, "manifest.json"));
const read = (name: string) => JSON.parse(readFileSync(join(SNAPSHOT, name), "utf8"));

test.skip(!has, "no replay snapshot: run once with the stack up (e2e/prepare-replay.mjs records one)");

/** An anchored, producer-signed trust score of the snapshot with its proof recorded (any recorded message, not only the list). */
function anchoredMessage(): string {
  const last = Math.max(0, ...read("anchors.json").items.filter((a: { status: string }) => a.status === "anchored").map((a: { toMilestone: number }) => a.toMilestone));
  const ids = readdirSync(join(SNAPSHOT, "messages")).map((f) => f.replace(/\.json$/, ""));
  for (const id of ids) {
    if (!existsSync(join(SNAPSHOT, "bundles", `${id}.json`))) continue;
    const x = read(`messages/${id}.json`);
    // a did:key writer (the chaos runs) has no DID document to resolve
    if (x.tag === "trust.score" && x.verdict === "PRODUCER_SIGNED" && x.iss?.startsWith("did:iota:") && x.msIndex !== null && x.msIndex <= last) return id;
  }
  test.skip(true, "the snapshot holds no anchored message with a proof");
  return "";
}

/** Any message of the snapshot with its proof recorded, or null. */
function anyMessage(): string | null {
  const m = read("messages.json").items.find((x: { blockId: string }) => existsSync(join(SNAPSHOT, "bundles", `${x.blockId}.json`)));
  return m?.blockId ?? null;
}

/** Records every request that would need an API. */
function watchApi(page: Page): string[] {
  const hits: string[] = [];
  page.on("request", (r) => {
    const u = new URL(r.url());
    if (u.pathname.startsWith("/api/") || u.port === "7200" || u.pathname.startsWith("/anchor/")) hits.push(r.url());
  });
  return hits;
}

test("serves Live from the snapshot with no API", async ({ page }) => {
  const hits = watchApi(page);
  await page.goto("/live");
  await expect(page.locator(".status .lbl")).toHaveText("Replay");
  await expect(page.locator(".rows .msg").first()).toBeVisible({ timeout: 15_000 });
  expect(hits).toEqual([]);
});

test("Verify computes the five checks in the browser from a recorded proof", async ({ page }) => {
  const hits = watchApi(page);
  const id = anchoredMessage();
  await page.goto(`/m/${id}`);
  const { overall, steps } = await ladderResult(page);
  expect(steps.slice(0, 4)).toEqual(["pass", "pass", "pass", "pass"]);
  if (overall !== "VALID") {
    // only an unreachable Rebased RPC may hold step 5 back, never a failure
    expect(overall).toBe("PARTIAL");
    expect(steps[4]).toBe("unknown");
    test.info().annotations.push({ type: "note", description: "IOTA Rebased was not reachable: step 5 not checked" });
  }
  expect(hits).toEqual([]);
});

test("every explorer screen renders from the snapshot, with no critical axe violation and no sideways scroll at 390 px", async ({ page }) => {
  const hits = watchApi(page);
  const ie = read("ie.json").items[0]?.ieId ?? "MyDomain:fa163e5e25ef";
  const id = anyMessage();
  test.skip(!id, "the snapshot holds no message with a proof");
  const screens = SCREENS(ie, id!);
  for (const s of screens) {
    await page.goto(s.path);
    await expect(page.locator(s.ready).first(), `${s.name} renders`).toBeVisible({ timeout: 30_000 });
    const { critical, serious } = await axeCheck(page);
    expect(critical, `${s.name}: critical axe violations`).toEqual([]);
    if (serious.length) test.info().annotations.push({ type: `axe serious on ${s.name}`, description: serious.join("; ") });
  }
  await page.setViewportSize({ width: 390, height: 844 });
  for (const s of screens) {
    await page.goto(s.path);
    await expect(page.locator(s.ready).first(), `${s.name} renders at 390 px`).toBeVisible({ timeout: 30_000 });
    await noSideScroll(page, s.name);
  }
  expect(hits).toEqual([]);
});

test("Reports renders the snapshot's reports, and never embeds a report page", async ({ page }) => {
  const hits = watchApi(page);
  const reports = read("reports.json").items;
  await page.goto("/reports");
  if (!reports.length) {
    await expect(page.locator(".empty")).toContainText("No report yet");
  } else {
    await expect(page.locator(".list li")).toHaveCount(reports.length);
    await expect(page.locator(".detail .anch")).not.toHaveAttribute("data-a", "checking", { timeout: 60_000 });
    const html = page.locator('a[target="_blank"]', { hasText: "HTML rendering" });
    await expect(html).toHaveAttribute("href", /\/replay\/reports\/0x[0-9a-f]{64}\.html$/);
  }
  await expect(page.locator("iframe")).toHaveCount(0);
  expect(hits).toEqual([]);
});

test("Flows: the snapshot's producer chains", async ({ page }) => {
  const hits = watchApi(page);
  const flows = existsSync(join(SNAPSHOT, "flows-issuer.json")) ? read("flows-issuer.json").items : [];
  test.skip(!flows.length, "the snapshot holds no flows");
  await page.goto("/flows");
  await expect(page.locator(".tl .msg").first()).toBeVisible();
  await expect(page.locator(".chain")).toBeVisible();
  expect(hits).toEqual([]);
});

test("Lineage, Integrity and Anchors show the snapshot's data", async ({ page }) => {
  const ie = read("ie.json").items[0].ieId;
  await page.goto(`/ie/${encodeURIComponent(ie)}`);
  await expect(page.locator(".plot")).toBeVisible();
  await expect(page.locator(".wl-entries tbody tr").first()).toBeVisible();
  await page.goto("/integrity");
  const incidents = read("incidents.json").items;
  if (incidents.length) await expect(page.locator(".inc-row")).toHaveCount(incidents.length);
  await expect(page.locator(".card")).toContainText(/scorecard/i);
  await page.goto("/anchors");
  await expect(page.locator(".cp")).toHaveCount(read("anchors.json").items.length);
  await expect(page.locator(".cp .st").first()).toHaveText(/per the explorer|Pending|Failed|Mismatch/);
});
