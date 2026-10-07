/** Shared steps of the e2e specs. */
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

import { expect, type Page } from "@playwright/test";

const require = createRequire(import.meta.url);
const AXE = readFileSync(require.resolve("axe-core/axe.min.js"), "utf8");

interface AxeViolation {
  id: string;
  impact: string | null;
  nodes: { target: string[] }[];
}

/** Runs axe on the page; returns the violations by impact. Contexts run with bypassCSP, so the script can be added. */
export async function axeCheck(page: Page): Promise<{ critical: string[]; serious: string[] }> {
  await page.addScriptTag({ content: AXE });
  const violations = (await page.evaluate(async () => {
    const axe = (window as unknown as { axe: { run: (ctx: Document, opts: object) => Promise<{ violations: unknown[] }> } }).axe;
    return (await axe.run(document, { resultTypes: ["violations"] })).violations;
  })) as AxeViolation[];
  const say = (v: AxeViolation) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).slice(0, 4).join(", ")}`;
  return {
    critical: violations.filter((v) => v.impact === "critical").map(say),
    serious: violations.filter((v) => v.impact === "serious").map(say),
  };
}

/** The steps of the Verify ladder once it has finished, and the overall verdict. */
export async function ladderResult(page: Page, timeout = 60_000): Promise<{ overall: string; steps: string[] }> {
  const overall = page.locator(".overall");
  await expect(overall).toHaveAttribute("data-o", /^(VALID|INVALID|PARTIAL|ERROR)$/, { timeout });
  const steps = await page.locator("li.step").evaluateAll((els) => els.map((e) => e.getAttribute("data-s") ?? ""));
  return { overall: (await overall.getAttribute("data-o")) ?? "", steps };
}

/** Asserts the page does not scroll sideways at a phone's width. */
export async function noSideScroll(page: Page, name: string, width = 390): Promise<void> {
  const sw = await page.evaluate(() => document.documentElement.scrollWidth);
  expect(sw, `${name} scrolls sideways at ${width} px`).toBeLessThanOrEqual(width);
}

/** The console's screens, with a selector that shows each one has rendered its data. */
export const SCREENS = (ie: string, blockId: string) => [
  { name: "live", path: "/live", ready: ".rows li" },
  { name: "search", path: "/search", ready: ".read" },
  { name: "verify", path: `/m/${blockId}`, ready: '.overall[data-o]:not([data-o="RUNNING"])' },
  { name: "lineage", path: `/ie/${encodeURIComponent(ie)}`, ready: ".plot, .wl-err" },
  { name: "flows", path: "/flows", ready: ".tl .msg, .x-quiet" },
  { name: "integrity", path: "/integrity", ready: ".card" },
  { name: "identity", path: "/identity", ready: ".x-sec" },
  { name: "anchors", path: "/anchors", ready: ".cp, .x-quiet" },
  { name: "posture", path: "/posture", ready: ".svcs, .x-sec .x-quiet" },
  { name: "reports", path: "/reports", ready: ".empty, .list" },
];
