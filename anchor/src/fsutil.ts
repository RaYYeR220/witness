import { randomBytes } from "node:crypto";
import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, writeSync } from "node:fs";
import path from "node:path";

/** fsync a directory so a rename in it survives a crash. Windows cannot do that; skipped there. */
export function syncDir(dir: string): void {
  let fd: number | null = null;
  try {
    fd = openSync(dir, "r");
    fsyncSync(fd);
  } catch {
    // EISDIR/EPERM on Windows: directory entries cannot be flushed from user space there.
  } finally {
    if (fd !== null) closeSync(fd);
  }
}

/**
 * Writes JSON through a temp file and a rename, so readers never see a half-written file. The
 * temp file is flushed to disk before the rename and the directory after it, so after a crash
 * the file holds either the old or the new content, never an empty or torn one.
 */
export function writeJsonAtomic(file: string, value: unknown, opts: { secret?: boolean } = {}): void {
  const dir = path.dirname(file);
  mkdirSync(dir, { recursive: true, mode: opts.secret ? 0o700 : 0o755 });
  const tmp = path.join(dir, `.${path.basename(file)}.${randomBytes(6).toString("hex")}.tmp`);
  try {
    const fd = openSync(tmp, "wx", opts.secret ? 0o600 : 0o644);
    try {
      writeSync(fd, `${JSON.stringify(value, null, 2)}\n`);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, file);
  } catch (err) {
    rmSync(tmp, { force: true });
    throw err;
  }
  syncDir(dir);
}

export function readJsonIfExists<T>(file: string): T | null {
  let text: string;
  try {
    text = readFileSync(file, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new Error(`${file} is not valid JSON`);
  }
}
