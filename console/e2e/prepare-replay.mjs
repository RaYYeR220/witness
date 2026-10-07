#!/usr/bin/env node
/**
 * Builds the replay console for the e2e specs: e2e/.dist-replay with the
 * snapshot in e2e/.snapshot copied to its replay/ directory.
 *
 * The snapshot is recorded from a running stack with scripts/record-replay.mjs
 * the first time (or with --record). Without a snapshot and without a stack
 * the build still happens, empty, and the replay specs skip.
 */

import { spawnSync } from "node:child_process";
import { cpSync, existsSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const snapshot = join(here, ".snapshot");
const out = join(here, ".dist-replay");
const api = process.env.WITNESS_E2E_API ?? "http://127.0.0.1:7200";

const run = (cmd, args) => {
  const r = spawnSync(cmd, args, { cwd: root, stdio: "inherit", shell: process.platform === "win32" });
  if (r.status !== 0) process.exit(r.status ?? 1);
};

async function apiUp() {
  try {
    return (await fetch(`${api}/healthz`, { signal: AbortSignal.timeout(3000) })).ok;
  } catch {
    return false;
  }
}

if (process.argv.includes("--record") || !existsSync(join(snapshot, "manifest.json"))) {
  if (await apiUp()) run("node", ["scripts/record-replay.mjs", "--api", api, "--out", snapshot]);
  else console.warn(`no replay snapshot in ${snapshot} and no API at ${api}: the replay specs will skip`);
}

rmSync(out, { recursive: true, force: true });
run("npx", ["vite", "build", "--mode", "replay", "--outDir", out, "--emptyOutDir", "--logLevel", "warn"]);
if (existsSync(join(snapshot, "manifest.json"))) cpSync(snapshot, join(out, "replay"), { recursive: true });
