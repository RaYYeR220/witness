import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";

/** Writes JSON through a temp file and a rename, so readers never see a half-written file. */
export function writeJsonAtomic(file: string, value: unknown, opts: { secret?: boolean } = {}): void {
  const dir = path.dirname(file);
  mkdirSync(dir, { recursive: true, mode: opts.secret ? 0o700 : 0o755 });
  const tmp = path.join(dir, `.${path.basename(file)}.${randomBytes(6).toString("hex")}.tmp`);
  try {
    writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, { mode: opts.secret ? 0o600 : 0o644, flag: "wx" });
    renameSync(tmp, file);
  } catch (err) {
    rmSync(tmp, { force: true });
    throw err;
  }
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
