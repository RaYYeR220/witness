/**
 * The console against a running stack. Skips cleanly when the API does not
 * answer. By default it runs this build (vite preview, which proxies /api to
 * the stack); WITNESS_E2E_URL points it at a deployed console instead (the
 * compose stack serves one at http://127.0.0.1:8080), where the explorer
 * screens are checked only if that build has them.
 */
import { expect, test } from "@playwright/test";

import { axeCheck, ladderResult, noSideScroll, SCREENS } from "./helpers";

const API = process.env.WITNESS_E2E_API ?? "http://127.0.0.1:7200";

async function api(path: string): Promise<any> {
  const r = await fetch(`${API}${path}`, { signal: AbortSignal.timeout(10_000) });
  if (!r.ok) throw new Error(`${path} answered ${r.status}`);
  return r.json();
}

let up = false;
test.beforeAll(async () => {
  try {
    up = (await api("/healthz")).status === "ok";
  } catch {
    up = false;
  }
});
test.beforeEach(() => test.skip(!up, `no witness-api answering at ${API}`));

/** Whether the console under test has the explorer screens (a deployed build may predate them). */
async function hasExplorer(page: import("@playwright/test").Page): Promise<boolean> {
  await page.goto("/live");
  return (await page.locator('nav[aria-label="Console"] a', { hasText: "Lineage" }).count()) > 0;
}

/** A trust.score message in a milestone the newest anchored checkpoint covers. */
async function anchoredMessage(): Promise<string | null> {
  const anchors = (await api("/anchors?limit=20")).items.filter((a: { status: string }) => a.status === "anchored");
  for (const a of anchors) {
    const page = await api(`/messages?tag=trust.score&ms_from=${a.fromMilestone}&ms_to=${a.toMilestone}&verdict=PRODUCER_SIGNED&limit=20`);
    // a did:key writer (the chaos runs) has no DID document to resolve
    const m = page.items.find((x: { iss: string | null }) => x.iss?.startsWith("did:iota:"));
    if (m) return m.blockId;
  }
  return null;
}

test("Live shows trust scores within 10 s, then a new one as it lands, which opens in Verify with checks 1 to 4 green", async ({ page }) => {
  test.setTimeout(180_000);
  await page.goto("/live");
  const rows = page.locator(".rows .msg");
  await expect(rows.filter({ hasText: "trust.score" }).first()).toBeVisible({ timeout: 10_000 });
  // a row newer than everything on the page at load: one the stream brought in
  const newestAtLoad = await rows.evaluateAll((els) => Math.max(0, ...els.map((e) => Date.parse(e.querySelector("time")?.getAttribute("datetime") ?? "") || 0)));
  const started = Date.now();
  const handle = await page.waitForFunction(
    (after) =>
      [...document.querySelectorAll(".rows .msg")].find(
        (e) =>
          (e.textContent ?? "").includes("trust.score") &&
          (e.textContent ?? "").includes("did:iota:") &&
          (Date.parse(e.querySelector("time")?.getAttribute("datetime") ?? "") || 0) > after,
      ) ?? null,
    newestAtLoad,
    { timeout: 150_000, polling: 500 },
  );
  test.info().annotations.push({ type: "new row after", description: `${Math.round((Date.now() - started) / 1000)} s (trust scores land about once a minute)` });
  const href = await handle.evaluate((e) => (e as HTMLAnchorElement).getAttribute("href"));
  // the stream carries its lifecycle transitions: they show on the row
  await page.waitForFunction((h) => document.querySelector(`.rows a.msg[href="${h}"] .lc`) !== null, href, { timeout: 20_000 });
  await (handle.asElement() as import("@playwright/test").ElementHandle<HTMLElement>).click();
  await expect(page).toHaveURL(new RegExp(`${href}$`));
  await expect(page).toHaveURL(/\/m\/0x[0-9a-f]{64}$/);
  const { overall, steps } = await ladderResult(page);
  expect(steps.slice(0, 4)).toEqual(["pass", "pass", "pass", "pass"]);
  // the newest messages are usually newer than the last checkpoint: PARTIAL, and the screen says why
  if (overall !== "VALID") {
    expect(overall).toBe("PARTIAL");
    await expect(page.locator(".compare.pending")).toContainText("Not anchored yet");
  }
});

test("an anchored message verifies with all five checks green", async ({ page }) => {
  const id = await anchoredMessage();
  test.skip(!id, "no anchored trust.score message yet");
  await page.goto(`/m/${id}`);
  const { overall, steps } = await ladderResult(page);
  expect(steps).toEqual(["pass", "pass", "pass", "pass", "pass"]);
  expect(overall).toBe("VALID");
});

test("Verify shows the brief's (c) and (d) above the ladder, with the explorer's recorded results", async ({ page }) => {
  test.skip(!(await hasExplorer(page)), "this console build has no explorer screens");
  const id = await anchoredMessage();
  test.skip(!id, "no anchored trust.score message yet");
  await page.goto(`/m/${id}`);
  const tangle = page.locator(".tangle");
  await expect(tangle.locator('li[data-check="c"] .name')).toHaveText("(c) Solid on the Tangle");
  await expect(tangle.locator('li[data-check="c"] .via')).toContainText("via HORNET GET /api/core/v2/blocks/{blockId}/metadata");
  await expect(tangle.locator('li[data-check="d"] .name')).toHaveText("(d) Same content as on the Tangle");
  await expect(tangle.locator('li[data-check="c"] .when')).toContainText("checked by the explorer at");
  const above = await page.evaluate(() => {
    const t = document.querySelector(".tangle");
    const c = document.querySelector("section.checks");
    return !!t && !!c && (t.compareDocumentPosition(c) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0;
  });
  expect(above).toBe(true);
});

test("Flows: a producer's chain, each message opening in Verify", async ({ page }) => {
  test.skip(!(await hasExplorer(page)), "this console build has no explorer screens");
  const top = (await api("/flows?by=issuer")).items[0];
  test.skip(!top, "no flow yet");
  await page.goto("/flows");
  await expect(page.locator('.list .row[aria-current="true"]')).toHaveAttribute("title", top.key);
  await expect(page.locator(".chain")).toBeVisible();
  const first = page.locator(".tl .msg a.x-link").first();
  await expect(first).toHaveAttribute("href", /^\/m\/0x[0-9a-f]{64}$/);
  await expect(page.locator(".tl .msg .link").first()).toBeVisible();
  await first.click();
  await expect(page).toHaveURL(/\/m\/0x[0-9a-f]{64}$/);
});

test("Anchors: the browser re-reads the newest checkpoint from IOTA Rebased and the chain agrees", async ({ page }) => {
  test.skip(!(await hasExplorer(page)), "this console build has no explorer screens");
  const anchored = (await api("/anchors?limit=5")).items.filter((a: { status: string }) => a.status === "anchored");
  test.skip(!anchored.length, "nothing anchored yet");
  await page.goto("/anchors");
  const first = page.locator(".cp").first();
  await expect(first.locator(".st")).toHaveText("Anchored, per the explorer");
  await first.locator(".re .btn").click();
  await expect(first.locator(".res .verdict")).toHaveAttribute("data-v", "true", { timeout: 45_000 });
  // the explorer's status keeps its own words; the browser's result is its own chip
  await expect(first.locator(".st")).toHaveText("Anchored, per the explorer");
  await expect(first.locator(".chk")).toHaveText("Checked on IOTA Rebased in your browser");
  await expect(first).toHaveAttribute("data-check", "agrees");
});

test("Reports: an anchored report is checked in the browser, signer included", async ({ page }) => {
  test.skip(!(await hasExplorer(page)), "this console build has no explorer screens");
  const report = (await api("/reports?limit=1")).items[0];
  test.skip(!report, "no audit report on this stack yet");
  await page.goto(`/reports?report=${report.reportHash}`);
  const state = page.locator(".detail .anch");
  await expect(state).not.toHaveAttribute("data-a", "checking", { timeout: 60_000 });
  if (report.anchored) {
    await expect(state).toHaveAttribute("data-a", "verified");
    await expect(page.locator('.x-note[data-tone="ok"]')).toContainText("(checked in your browser)");
    await expect(page.locator(".hashes .x-cmp")).toHaveCount(2);
    for (const c of await page.locator(".hashes .x-cmp").all()) await expect(c).toHaveAttribute("data-c", "same");
  } else {
    await expect(state).toHaveAttribute("data-a", "not-anchored");
  }
  await expect(page.locator("iframe")).toHaveCount(0);
});

test("Lineage draws the ledger series and says what Orion answered", async ({ page }) => {
  test.skip(!(await hasExplorer(page)), "this console build has no explorer screens");
  const ie = (await api("/ie")).items[0]?.ieId;
  test.skip(!ie, "no IE on the ledger yet");
  const lin = await api(`/ie/${encodeURIComponent(ie)}/lineage?limit=1`);
  await page.goto(`/ie/${encodeURIComponent(ie)}`);
  await expect(page.locator(".plot")).toBeVisible();
  if (lin.orion.status === "ok") await expect(page.locator(".orion-mark")).toBeVisible();
  else await expect(page.locator(".drift-badge")).toHaveCount(0);
});

test("every screen has no critical axe violation, and none scrolls sideways at 390 px", async ({ page }) => {
  const explorer = await hasExplorer(page);
  const ie = (await api("/ie")).items[0]?.ieId ?? "MyDomain:fa163e5e25ef";
  const id = (await anchoredMessage()) ?? (await api("/messages?limit=1")).items[0].blockId;
  const screens = [{ name: "landing", path: "/", ready: "h1" }, ...SCREENS(ie, id).filter((s) => explorer || ["live", "search", "verify"].includes(s.name))];
  for (const s of screens) {
    await page.goto(s.path);
    await expect(page.locator(s.ready).first(), `${s.name} renders`).toBeVisible({ timeout: 60_000 });
    const { critical, serious } = await axeCheck(page);
    expect(critical, `${s.name}: critical axe violations`).toEqual([]);
    if (serious.length) test.info().annotations.push({ type: `axe serious on ${s.name}`, description: serious.join("; ") });
  }
  await page.setViewportSize({ width: 390, height: 844 });
  for (const s of screens) {
    await page.goto(s.path);
    await expect(page.locator(s.ready).first(), `${s.name} renders at 390 px`).toBeVisible({ timeout: 60_000 });
    await noSideScroll(page, s.name);
  }
});
