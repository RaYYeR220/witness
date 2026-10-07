/**
 * The replay build: the console served as static files with a recorded
 * snapshot and no API behind it. Every screen must render from the snapshot,
 * and Verify must still compute the five checks in the browser (step 5 reads
 * IOTA Rebased live, so it needs the network; without it the run is PARTIAL
 * and says so).
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { expect, test, type Page } from "@playwright/test";

import { axeCheck, ladderResult, SCREENS } from "./helpers";

const SNAPSHOT = join(dirname(fileURLToPath(import.meta.url)), ".snapshot");
const has = existsSync(join(SNAPSHOT, "manifest.json"));
const read = (name: string) => JSON.parse(readFileSync(join(SNAPSHOT, name), "utf8"));

test.skip(!has, "no replay snapshot: run once with the stack up (e2e/prepare-replay.mjs records one)");

/** An anchored message of the snapshot that has its proof recorded. */
function anchoredMessage(): string {
  const last = Math.max(0, ...read("anchors.json").items.filter((a: { status: string }) => a.status === "anchored").map((a: { toMilestone: number }) => a.toMilestone));
  const m = read("messages.json").items.find(
    (x: { msIndex: number | null; blockId: string; tag: string; verdict: string; iss: string | null }) =>
      x.tag === "trust.score" &&
      x.verdict === "PRODUCER_SIGNED" &&
      x.iss?.startsWith("did:iota:") && // a did:key writer (the chaos runs) has no DID document to resolve
      x.msIndex !== null &&
      x.msIndex <= last &&
      existsSync(join(SNAPSHOT, "bundles", `${x.blockId}.json`)),
  );
  if (!m) test.skip(true, "the snapshot holds no anchored message with a proof");
  return m.blockId;
}

function anyMessage(): string {
  const m = read("messages.json").items.find((x: { blockId: string }) => existsSync(join(SNAPSHOT, "bundles", `${x.blockId}.json`)));
  return m.blockId;
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

test("every explorer screen renders from the snapshot, with no critical axe violation", async ({ page }) => {
  const hits = watchApi(page);
  const ie = read("ie.json").items[0]?.ieId ?? "MyDomain:fa163e5e25ef";
  for (const s of SCREENS(ie, anyMessage())) {
    await page.goto(s.path);
    await expect(page.locator(s.ready).first(), `${s.name} renders`).toBeVisible({ timeout: 30_000 });
    const { critical, serious } = await axeCheck(page);
    expect(critical, `${s.name}: critical axe violations`).toEqual([]);
    if (serious.length) test.info().annotations.push({ type: `axe serious on ${s.name}`, description: serious.join("; ") });
  }
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
