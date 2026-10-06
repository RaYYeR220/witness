import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { hostname } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { readJsonIfExists, writeJsonAtomic } from "../src/fsutil.js";
import { LockError, acquireLock, processAlive } from "../src/lock.js";
import { cleanupDirs, tmpDir } from "./helpers.js";

afterEach(cleanupDirs);

describe("acquireLock", () => {
  it("lets one holder in and refuses the next while it lives", () => {
    const file = path.join(tmpDir(), "state", "anchor-state.json.lock");
    const release = acquireLock(file);
    expect(JSON.parse(readFileSync(file, "utf8"))).toMatchObject({ pid: process.pid, host: hostname() });
    expect(() => acquireLock(file)).toThrow(LockError);
    release();
    expect(existsSync(file)).toBe(false);
    acquireLock(file)();
  });

  it("takes over a lock left by a dead process on this host", () => {
    const file = path.join(tmpDir(), "a.lock");
    writeFileSync(file, JSON.stringify({ pid: 999_999_999, host: hostname(), since: "earlier" }));
    const release = acquireLock(file, () => false);
    expect(JSON.parse(readFileSync(file, "utf8")).pid).toBe(process.pid);
    release();
  });

  it("refuses a live holder, a lock from another host and an unreadable lock", () => {
    const file = path.join(tmpDir(), "b.lock");
    writeFileSync(file, JSON.stringify({ pid: 4242, host: hostname(), since: "earlier" }));
    expect(() => acquireLock(file, () => true)).toThrow(/pid 4242/);
    writeFileSync(file, JSON.stringify({ pid: 4242, host: "elsewhere", since: "earlier" }));
    expect(() => acquireLock(file, () => false)).toThrow(/elsewhere/);
    writeFileSync(file, "garbage");
    expect(() => acquireLock(file, () => false)).toThrow(/unreadable/);
  });

  it("does not remove a lock someone else holds by now", () => {
    const file = path.join(tmpDir(), "c.lock");
    const release = acquireLock(file);
    writeFileSync(file, JSON.stringify({ pid: 4242, host: hostname(), since: "later" }));
    release();
    expect(existsSync(file)).toBe(true);
  });

  it("knows its own process is alive", () => {
    expect(processAlive(process.pid)).toBe(true);
    expect(processAlive(0)).toBe(false);
  });
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
