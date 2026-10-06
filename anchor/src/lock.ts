import { closeSync, mkdirSync, openSync, readFileSync, rmSync, writeSync } from "node:fs";
import { hostname } from "node:os";
import path from "node:path";

export class LockError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LockError";
  }
}

interface LockInfo {
  pid: number;
  host: string;
  since: string;
}

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
    return typeof info?.pid === "number" ? info : null;
  } catch {
    return null;
  }
}

/**
 * Takes `file` as an exclusive lock (O_EXCL create) holding our pid, so only one anchoring loop
 * writes a state file and spends from its wallet. A lock left by a process that no longer runs
 * on this host is stale and taken over; one held by a live process (or one on another host,
 * which cannot be checked) is refused. Returns the release function.
 */
export function acquireLock(file: string, alive: (pid: number) => boolean = processAlive): () => void {
  mkdirSync(path.dirname(file), { recursive: true });
  const me: LockInfo = { pid: process.pid, host: hostname(), since: new Date().toISOString() };
  for (let attempt = 0; attempt < 2; attempt++) {
    let fd: number;
    try {
      fd = openSync(file, "wx", 0o644);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      const held = readLock(file);
      const stale = held !== null && held.host === me.host && held.pid !== me.pid && !alive(held.pid);
      if (!stale) {
        const who = held ? `pid ${held.pid} on ${held.host} since ${held.since}` : "an unreadable lock";
        throw new LockError(`${file} is held by ${who}; another anchoring loop runs on this state (delete the lock only if it does not)`);
      }
      rmSync(file, { force: true });
      continue;
    }
    try {
      writeSync(fd, JSON.stringify(me));
    } finally {
      closeSync(fd);
    }
    let released = false;
    return () => {
      if (released) return;
      released = true;
      if (readLock(file)?.pid === me.pid) rmSync(file, { force: true });
    };
  }
  throw new LockError(`${file}: could not take over a stale lock`);
}
