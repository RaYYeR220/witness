type Level = "debug" | "info" | "warn" | "error";

function emit(level: Level, msg: string, fields?: Record<string, unknown>): void {
  const line = JSON.stringify({ ts: new Date().toISOString(), level, msg, ...fields }, (_k, v) =>
    typeof v === "bigint" ? v.toString() : v instanceof Error ? { name: v.name, message: v.message } : v,
  );
  if (level === "error" || level === "warn") process.stderr.write(`${line}\n`);
  else process.stdout.write(`${line}\n`);
}

/** JSON-lines logger. Callers pass identifiers and digests only, never key material. */
export const log = {
  debug: (msg: string, fields?: Record<string, unknown>) => {
    if (process.env.ANCHOR_DEBUG) emit("debug", msg, fields);
  },
  info: (msg: string, fields?: Record<string, unknown>) => emit("info", msg, fields),
  warn: (msg: string, fields?: Record<string, unknown>) => emit("warn", msg, fields),
  error: (msg: string, fields?: Record<string, unknown>) => emit("error", msg, fields),
};
