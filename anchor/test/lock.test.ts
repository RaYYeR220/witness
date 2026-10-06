import { spawn } from "node:child_process";
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { hostname } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { readJsonIfExists, writeJsonAtomic } from "../src/fsutil.js";
import { LockError, PROCESS_TOKEN, acquireLock, processAlive, type LockInfo } from "../src/lock.js";
import { cleanupDirs, tmpDir } from "./helpers.js";

afterEach(cleanupDirs);

const DEAD = 2_000_000_000;
const HOST = hostname();
const lockOf = (file: string): LockInfo => JSON.parse(readFileSync(file, "utf8"));
const seed = (file: string, info: Partial<LockInfo>) =>
  writeFileSync(file, JSON.stringify({ pid: DEAD, host: HOST, token: "dead-token", bootId: null, since: "earlier", ...info }));
/** Another process on this host, as far as the lock can tell. */
const other = (pid: number, token: string) => ({ pid, token, bootId: null, alive: (p: number) => p !== DEAD });

describe("acquireLock", () => {
  it("lets one holder in and refuses the next while it lives", () => {
    const file = path.join(tmpDir(), "state", "anchor-state.json.lock");
    const release = acquireLock(file);
    expect(lockOf(file)).toMatchObject({ pid: process.pid, host: HOST, token: PROCESS_TOKEN });
    expect(() => acquireLock(file)).toThrow(LockError);
    release();
    expect(existsSync(file)).toBe(false);
    acquireLock(file)();
  });

  it("takes over a lock left by a dead process on this host", () => {
    const file = path.join(tmpDir(), "a.lock");
    seed(file, {});
    const release = acquireLock(file, { alive: () => false });
    expect(lockOf(file).token).toBe(PROCESS_TOKEN);
    release();
    expect(readdirSync(path.dirname(file))).toEqual([]);
  });

  it("treats a lock with our pid but another token as a previous incarnation's (pid reuse)", () => {
    const file = path.join(tmpDir(), "pid1.lock");
    seed(file, { pid: 1, token: "before-the-restart" });
    const release = acquireLock(file, { pid: 1, token: "after-the-restart", alive: () => true });
    expect(lockOf(file)).toMatchObject({ pid: 1, token: "after-the-restart" });
    // The same incarnation asking twice is refused, not taken over.
    expect(() => acquireLock(file, { pid: 1, token: "after-the-restart", alive: () => true })).toThrow(/pid 1/);
    release();
  });

  it("treats a lock from before a reboot as stale, whatever its pid", () => {
    const file = path.join(tmpDir(), "boot.lock");
    seed(file, { pid: 4242, bootId: "boot-a" });
    acquireLock(file, { ...other(77, "t77"), bootId: "boot-b", alive: () => true })();
    seed(file, { pid: 4242, bootId: "boot-b" });
    expect(() => acquireLock(file, { ...other(77, "t77"), bootId: "boot-b", alive: () => true })).toThrow(/pid 4242/);
  });

  it("refuses a live holder, a lock from another host and an unreadable lock", () => {
    const file = path.join(tmpDir(), "b.lock");
    seed(file, { pid: 4242 });
    expect(() => acquireLock(file, { alive: () => true })).toThrow(/pid 4242/);
    seed(file, { host: "elsewhere" });
    expect(() => acquireLock(file, { alive: () => false })).toThrow(/elsewhere/);
    writeFileSync(file, "garbage");
    expect(() => acquireLock(file, { alive: () => false })).toThrow(/unreadable/);
  });

  it("lets exactly one of two contenders win a stale lock when the other takes it over first", () => {
    const file = path.join(tmpDir(), "race.lock");
    seed(file, {});
    // A judges the lock stale; before A moves it, B takes it over completely.
    let bWon = false;
    const a = () =>
      acquireLock(file, {
        ...other(101, "token-a"),
        beforeTakeover: () => {
          acquireLock(file, other(102, "token-b"));
          bWon = true;
        },
      });
    expect(a).toThrow(LockError);
    expect(bWon).toBe(true);
    // B's lock is back in place and nothing else is left behind.
    expect(lockOf(file)).toMatchObject({ pid: 102, token: "token-b" });
    expect(readdirSync(path.dirname(file))).toEqual(["race.lock"]);
  });

  it("does not remove a lock someone else holds by now", () => {
    const file = path.join(tmpDir(), "c.lock");
    const release = acquireLock(file);
    seed(file, { pid: 4242, token: "someone" });
    release();
    expect(existsSync(file)).toBe(true);
  });

  it("knows its own process is alive", () => {
    expect(processAlive(process.pid)).toBe(true);
    expect(processAlive(0)).toBe(false);
  });

  it("lets exactly one of several processes take a stale lock", async () => {
    const child = fileURLToPath(new URL("./fixtures/lock-child.ts", import.meta.url));
    const run = (file: string) =>
      new Promise<string>((resolve, reject) => {
        const p = spawn(process.execPath, ["--import", "tsx", child, file, "2500"], {
          cwd: path.resolve(path.dirname(child), "..", ".."),
          stdio: ["ignore", "pipe", "pipe"],
        });
        let out = "";
        let err = "";
        p.stdout.on("data", (d) => (out += d));
        p.stderr.on("data", (d) => (err += d));
        p.on("error", reject);
        p.on("exit", () => resolve(out.trim() || `no output: ${err.slice(0, 300)}`));
      });
    for (let round = 0; round < 2; round++) {
      const file = path.join(tmpDir(), "multi.lock");
      seed(file, {});
      const results = await Promise.all([run(file), run(file), run(file)]);
      expect(results.sort()).toEqual(["lost", "lost", "won"]);
      expect(readdirSync(path.dirname(file))).toEqual([]);
    }
  }, 60_000);
});

describe("writeJsonAtomic", () => {
  it("replaces the file in one step and leaves no temp files", () => {
    const dir = tmpDir();
    const file = path.join(dir, "s.json");
    writeJsonAtomic(file, { n: 1 });
    writeJsonAtomic(file, { n: 2 });
    expect(readJsonIfExists(file)).toEqual({ n: 2 });
    expect(readdirSync(dir)).toEqual(["s.json"]);
  });
});
