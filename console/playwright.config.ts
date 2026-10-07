import { defineConfig, devices } from "@playwright/test";

/**
 * End-to-end specs (e2e/). Two projects, chosen with --project:
 *
 *   replay  builds the replay console (e2e/prepare-replay.mjs) and serves it
 *           with no API; needs a recorded snapshot (made from the stack once)
 *   live    this build against the running stack (vite preview proxies /api
 *           and /anchor/resolve/), or a deployed console at WITNESS_E2E_URL;
 *           skips when the API does not answer
 *
 * Only the server the chosen project needs is started. Browsers come from
 * Playwright's own cache.
 */
function chosenProject(argv: string[]): string {
  const i = argv.indexOf("--project");
  const arg = i >= 0 ? argv[i + 1] : argv.find((a) => a.startsWith("--project="))?.slice("--project=".length);
  return arg === "live" ? "live" : "replay";
}
const project = chosenProject(process.argv);
const liveUrl = process.env.WITNESS_E2E_URL;

export default defineConfig({
  testDir: "e2e",
  timeout: 120_000,
  workers: 1,
  reporter: [["list"]],
  use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 }, bypassCSP: true, trace: "off" },
  projects: [
    { name: "replay", testMatch: /replay\.spec\.ts/, use: { baseURL: "http://localhost:4184" } },
    { name: "live", testMatch: /live\.spec\.ts/, use: { baseURL: liveUrl ?? "http://localhost:4183" } },
  ],
  webServer:
    project === "replay"
      ? {
          command: "node e2e/prepare-replay.mjs && npx vite preview --outDir e2e/.dist-replay --port 4184 --strictPort",
          url: "http://localhost:4184/",
          timeout: 240_000,
          reuseExistingServer: false,
        }
      : liveUrl
        ? undefined
        : {
            command: "npx vite build --outDir e2e/.dist-live --emptyOutDir --logLevel warn && npx vite preview --outDir e2e/.dist-live --port 4183 --strictPort",
            url: "http://localhost:4183/",
            timeout: 240_000,
            reuseExistingServer: false,
          },
});
