import { randomBytes } from "node:crypto";
import { closeSync, existsSync, linkSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, writeSync } from "node:fs";
import { hostname } from "node:os";
import path from "node:path";

export class LockError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LockError";
  }
}

export interface LockInfo {
  pid: number;
  host: string;
  /** Random per process start: a lock with our pid but another token is a previous incarnation's. */
  token: string;
  /** Kernel boot id where available: after a reboot every pid in an old lock is meaningless. */
  bootId: string | null;
  since: string;
}

/** This process start's token. Every acquire of this process uses it. */
export const PROCESS_TOKEN = randomBytes(16).toString("hex");

function readBootId(): string | null {
  try {
    const id = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
    return id || null;
  } catch {
    return null;
  }
}
const BOOT_ID = readBootId();

/** True while process `pid` exists on this host (EPERM: it exists, we may not signal it). */
export function processAlive(pid: number): boolean {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

function readLock(file: string): LockInfo | null {
  try {
    const info = JSON.parse(readFileSync(file, "utf8")) as LockInfo;
    return typeof info?.pid === "number" && typeof info.host === "string" ? info : null;
  } catch {
    return null;
  }
}

function pause(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

export interface LockOptions {
  alive?: (pid: number) => boolean;
  /** Identity of this acquirer; tests use them to play several processes. */
  pid?: number;
  token?: string;
  bootId?: string | null;
  host?: string;
  /** Test hook: runs after a stale lock was judged and before it is taken over. */
  beforeTakeover?: () => void;
}

/**
 * Takes `file` as an exclusive lock, so only one anchoring loop writes a state file and spends
 * from its wallet. Returns the release function.
 *
 * The lock is created with O_EXCL and holds our pid, host, a per-start token and the boot id.
 * A lock of this host is stale when the machine rebooted since (boot id), when its pid is ours but
 * its token is not (a previous incarnation with a reused pid, as in a restarted container), or
 * when its process is gone. A stale lock is taken over without a race: it is renamed to a unique
 * name (only one contender's rename can succeed), and only if the renamed file still is the stale
 * lock that was judged is it removed; a lock that turned out to be someone's fresh one is put back.
 * After creating our lock we read it again and give up unless it holds our token. A live holder,
 * or a lock of another host (which cannot be checked), is refused.
 */
export function acquireLock(file: string, opts: LockOptions = {}): () => void {
  const alive = opts.alive ?? processAlive;
  const me: LockInfo = {
    pid: opts.pid ?? process.pid,
    host: opts.host ?? hostname(),
    token: opts.token ?? PROCESS_TOKEN,
    bootId: opts.bootId === undefined ? BOOT_ID : opts.bootId,
    since: new Date().toISOString(),
  };
  const isStale = (held: LockInfo): boolean => {
    if (held.host !== me.host) return false;
    if (held.bootId && me.bootId && held.bootId !== me.bootId) return true;
    // Ours always carries our token; with our pid and anything else it is an earlier incarnation's.
    if (held.pid === me.pid) return held.token !== me.token;
    return !alive(held.pid);
  };
  const refuse = (held: LockInfo | null): never => {
    const who = held ? `pid ${held.pid} on ${held.host} since ${held.since}` : "an unreadable lock";
    throw new LockError(`${file} is held by ${who}; another anchoring loop runs on this state (delete the lock only if it does not)`);
  };
  const same = (a: LockInfo | null, b: LockInfo) => a !== null && a.token === b.token && a.pid === b.pid && a.since === b.since;

  mkdirSync(path.dirname(file), { recursive: true });
  for (let attempt = 0; attempt < 20; attempt++) {
    let fd: number;
    try {
      fd = openSync(file, "wx", 0o644);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      const held = readLock(file);
      if (held === null) {
        // Being written this very moment, or garbage: never taken over blindly.
        if (attempt < 3) {
          pause(20);
          continue;
        }
        return refuse(null);
      }
      if (!isStale(held)) return refuse(held);
      opts.beforeTakeover?.();
      const aside = `${file}.stale-${randomBytes(6).toString("hex")}`;
      try {
        renameSync(file, aside);
      } catch (e) {
        const code = (e as NodeJS.ErrnoException).code;
        if (code === "ENOENT" || code === "EPERM" || code === "EBUSY" || code === "EACCES") {
          pause(10); // someone else moved it first (or, on Windows, a reader holds it open)
          continue;
        }
        throw e;
      }
      const moved = readLock(aside);
      if (same(moved, held)) {
        rmSync(aside, { force: true });
        continue; // the stale lock is gone; now race for O_EXCL like everyone else
      }
      // We moved a lock taken after our read: put it back (never over another one) and stand aside.
      try {
        linkSync(aside, file);
        rmSync(aside, { force: true });
      } catch {
        // `file` exists again: leave the moved lock where it is rather than clobber anything.
      }
      return refuse(moved);
    }
    try {
      writeSync(fd, JSON.stringify(me));
    } finally {
      closeSync(fd);
    }
    if (!same(readLock(file), me)) {
      throw new LockError(`${file} changed hands while it was being taken; another anchoring loop is starting`);
    }
    let released = false;
    return () => {
      if (released) return;
      released = true;
      if (same(readLock(file), me)) rmSync(file, { force: true });
    };
  }
  if (existsSync(file)) return refuse(readLock(file));
  throw new LockError(`${file}: could not take the lock`);
}
