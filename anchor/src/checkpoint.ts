import { readFileSync } from "node:fs";
import {
  buildCheckpoint,
  canonHash,
  checkpointHash,
  checkpointShapeError,
  fromHex,
  jcs,
  toHex,
  type Checkpoint,
} from "@witness/verify";

// The checkpoint format itself (fields, JCS bytes, BLAKE2b hash) lives in @witness/verify, the
// line-by-line port of witness_core.checkpoint; this module adds what the anchor needs around it:
// window selection, the milestone source, the policy hash and the trail record encoding.
export { buildCheckpoint, checkpointHash, checkpointShapeError, type Checkpoint };

export const RECORD_KIND = "witness.checkpoint";
const H32 = /^0x[0-9a-f]{64}$/;

export function checkpointHashHex(cp: Checkpoint): string {
  return toHex(checkpointHash(cp));
}

// ---------------------------------------------------------------- writer policy

/** Python's `bool(v)` for JSON values (empty containers, "" and 0 are false). */
function pyTruthy(v: unknown): boolean {
  if (Array.isArray(v)) return v.length > 0;
  if (v !== null && typeof v === "object") return Object.keys(v).length > 0;
  return Boolean(v);
}

const has = (o: Record<string, unknown>, k: string) => Object.prototype.hasOwnProperty.call(o, k);

/** `bool(d.get(key, fallback))`; an explicit null is refused rather than read as false. */
function flagOf(r: Record<string, unknown>, key: string, fallback: boolean, where: string): boolean {
  if (!has(r, key)) return fallback;
  if (r[key] === null) throw new Error(`${where}.${key} is null; write true or false`);
  return pyTruthy(r[key]);
}

function ruleDict(d: unknown, where: string): Record<string, unknown> {
  if (d === null || typeof d !== "object" || Array.isArray(d)) throw new Error(`${where} must be an object`);
  const r = d as Record<string, unknown>;
  const allowed = has(r, "allowed") ? r.allowed : [];
  if (!Array.isArray(allowed) || !allowed.every((x) => typeof x === "string")) throw new Error(`${where}.allowed must be a list of strings`);
  return {
    allowed: [...allowed],
    require_signature: flagOf(r, "require_signature", false, where),
    legacy_grace: flagOf(r, "legacy_grace", true, where),
  };
}

/**
 * Normal form of a writer policy, as `witness_core.policy.to_dict(policy.load(d))` builds it:
 * only `version`, `tags` and `default`, every rule with all three fields, flags read with
 * Python truthiness. Inputs Python would read differently or not at all (explicit nulls,
 * non-integer versions, non-string writers) are refused, so the hash can never silently differ.
 */
export function normalizePolicy(d: unknown): Record<string, unknown> {
  if (d === null || typeof d !== "object" || Array.isArray(d)) throw new Error("writer policy must be a JSON object");
  const p = d as Record<string, unknown>;
  const version = typeof p.version === "string" && /^\s*[+-]?\d+\s*$/.test(p.version) ? Number(p.version) : p.version;
  if (typeof version !== "number" || !Number.isSafeInteger(version)) throw new Error("writer policy version must be an integer");
  const tags = has(p, "tags") ? p.tags : {};
  if (tags === null || typeof tags !== "object" || Array.isArray(tags)) throw new Error("writer policy tags must be an object");
  const outTags: Record<string, unknown> = {};
  for (const [tag, rule] of Object.entries(tags)) outTags[tag] = ruleDict(rule, `tags[${JSON.stringify(tag)}]`);
  return { version, tags: outTags, default: ruleDict(has(p, "default") ? p.default : {}, "default") };
}

/** BLAKE2b-256 over the JCS form of the normalized policy (`witness_core.policy.policy_hash`). */
export function policyHash(policy: unknown): Uint8Array {
  return canonHash(normalizePolicy(policy));
}

export function loadPolicyHash(file: string): Uint8Array {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(file, "utf8"));
  } catch (err) {
    throw new Error(`writer policy ${file} is not readable JSON: ${(err as Error).message.slice(0, 120)}`);
  }
  return policyHash(parsed);
}

// ---------------------------------------------------------------- windows

export interface Window {
  from: number;
  to: number;
}

/**
 * The window after `last` (or the first one from `startIndex`): `every` milestones, starting right
 * after the previous checkpoint's `to`, so consecutive checkpoints cover the Tangle without gaps.
 */
export function nextWindow(last: Pick<Checkpoint, "to"> | null, startIndex: number, every: number): Window {
  if (!Number.isSafeInteger(every) || every < 1) throw new RangeError("every must be a positive integer");
  const from = last ? last.to.index + 1 : startIndex;
  return { from, to: from + every - 1 };
}

export interface MilestoneWindow {
  /** False when some milestone of the window is not indexed (yet). */
  complete: boolean;
  /** Milestone ids `from..to` in index order (only meaningful when complete). */
  ids: Uint8Array[];
  /** Messages referenced in the window, when the source reports it. */
  msgCount: number | null;
}

export interface MilestoneSource {
  milestones(from: number, to: number): Promise<MilestoneWindow>;
}

export class SourceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SourceError";
  }
}

const isUint = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;

/** Validates a witness-api `/milestones` reply for the window it was asked about. */
export function parseMilestonesReply(body: unknown, w: Window): MilestoneWindow {
  if (body === null || typeof body !== "object") throw new SourceError("milestones reply is not a JSON object");
  const b = body as Record<string, unknown>;
  if (b.from !== w.from || b.to !== w.to) throw new SourceError(`milestones reply is about ${String(b.from)}..${String(b.to)}, asked ${w.from}..${w.to}`);
  if (typeof b.complete !== "boolean") throw new SourceError("milestones reply has no complete flag");
  if (!Array.isArray(b.ids) || !b.ids.every((id) => typeof id === "string" && H32.test(id))) {
    throw new SourceError("milestones reply ids must be 32-byte lowercase hex strings");
  }
  const msgCount = b.msgCount === undefined || b.msgCount === null ? null : b.msgCount;
  if (msgCount !== null && !isUint(msgCount)) throw new SourceError("milestones reply msgCount must be an unsigned integer");
  const expected = w.to - w.from + 1;
  // `complete` alone is not trusted: a complete window has exactly one id per index.
  const complete = b.complete && b.ids.length === expected;
  if (b.complete && !complete) throw new SourceError(`milestones reply claims complete with ${b.ids.length} of ${expected} ids`);
  if (complete && new Set(b.ids).size !== expected) throw new SourceError("milestones reply repeats a milestone id");
  return { complete, ids: complete ? (b.ids as string[]).map((id) => fromHex(id)) : [], msgCount };
}

/** Milestone ids from the Witness Explorer API (`GET {api}/milestones?from=&to=`). */
export class ApiMilestoneSource implements MilestoneSource {
  readonly #base: string;
  readonly #timeoutMs: number;
  readonly #fetch: typeof fetch;

  constructor(baseUrl: string, timeoutMs = 10_000, fetchImpl: typeof fetch = fetch) {
    this.#base = baseUrl.replace(/\/+$/, "");
    this.#timeoutMs = timeoutMs;
    this.#fetch = fetchImpl;
  }

  async milestones(from: number, to: number): Promise<MilestoneWindow> {
    const url = `${this.#base}/milestones?from=${from}&to=${to}`;
    let res: Response;
    try {
      res = await this.#fetch(url, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(this.#timeoutMs) });
    } catch (err) {
      throw new SourceError(`witness-api unreachable: ${(err as Error).message}`);
    }
    if (!res.ok) throw new SourceError(`witness-api answered HTTP ${res.status} for milestones ${from}..${to}`);
    let body: unknown;
    try {
      body = await res.json();
    } catch {
      throw new SourceError("witness-api sent no JSON");
    }
    return parseMilestonesReply(body, { from, to });
  }
}

export interface CheckpointParams {
  network: string;
  domain: string;
  policyHash: Uint8Array;
}

export type WindowResult =
  | { status: "ready"; window: Window; checkpoint: Checkpoint; checkpointHash: string; milestoneIds: Uint8Array[] }
  /** `cause`: the window is not fully indexed yet, or the source cannot say how many messages it holds. */
  | { status: "waiting"; window: Window; reason: string; cause: "incomplete" | "no-msgcount" };

export interface BuildOptions {
  /**
   * Development only: commit `msgCount: 0` when the source does not report it (the HORNET stub).
   * Otherwise such a window is not anchored: a checkpoint never commits to a made-up count.
   */
  allowMissingMsgCount?: boolean;
}

/**
 * Builds the checkpoint of the next window when every milestone of it is available. Only
 * complete windows are ever anchored; an incomplete one is reported as `waiting`, and so is a
 * complete one whose message count the source does not report (unless explicitly allowed).
 */
export async function buildNextCheckpoint(
  source: MilestoneSource,
  params: CheckpointParams,
  last: { checkpoint: Checkpoint; checkpointHash: string } | null,
  startIndex: number,
  every: number,
  opts: BuildOptions = {},
): Promise<WindowResult> {
  const window = nextWindow(last?.checkpoint ?? null, startIndex, every);
  const got = await source.milestones(window.from, window.to);
  if (!got.complete) {
    return { status: "waiting", window, reason: `milestones ${window.from}..${window.to} are not all indexed yet`, cause: "incomplete" };
  }
  if (got.msgCount === null && !opts.allowMissingMsgCount) {
    return {
      status: "waiting",
      window,
      reason: `the milestone source reports no msgCount for ${window.from}..${window.to}; refusing to commit a made-up count`,
      cause: "no-msgcount",
    };
  }
  const checkpoint = buildCheckpoint({
    network: params.network,
    domain: params.domain,
    from: { index: window.from, id: got.ids[0]! },
    to: { index: window.to, id: got.ids[got.ids.length - 1]! },
    milestoneIds: got.ids,
    msgCount: got.msgCount ?? 0,
    policyHash: params.policyHash,
    prevHash: last ? fromHex(last.checkpointHash) : null,
  });
  return { status: "ready", window, checkpoint, checkpointHash: checkpointHashHex(checkpoint), milestoneIds: got.ids };
}

// ---------------------------------------------------------------- trail record encoding

/** Record data: the checkpoint's JCS text, exactly the bytes its hash is taken over. */
export function checkpointRecordData(cp: Checkpoint): string {
  return jcs(cp);
}

/** Record metadata: names the checkpoint seq and hash, so the chain alone maps seq to record. */
export function checkpointRecordMetadata(seq: number, hash: string): string {
  return jcs({ kind: RECORD_KIND, seq, checkpointHash: hash });
}

export class RecordMismatchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RecordMismatchError";
  }
}

/**
 * Decodes a trail record written by the anchor and checks it is checkpoint `seq`: well-formed
 * checkpoint data, metadata naming `seq`, and a metadata hash equal to the hash of the data.
 */
export function decodeCheckpointRecord(
  data: string | Uint8Array,
  metadata: string | null,
  seq: number,
): { checkpoint: Checkpoint; checkpointHash: string } {
  const text = typeof data === "string" ? data : Buffer.from(data).toString("utf8");
  let cp: unknown;
  try {
    cp = JSON.parse(text);
  } catch {
    throw new RecordMismatchError("record data is not JSON");
  }
  const problem = checkpointShapeError(cp);
  if (problem) throw new RecordMismatchError(`record data is not a checkpoint: ${problem}`);
  const hash = checkpointHashHex(cp as Checkpoint);
  let meta: unknown;
  try {
    meta = metadata === null ? null : JSON.parse(metadata);
  } catch {
    meta = null;
  }
  const m = meta as { kind?: unknown; seq?: unknown; checkpointHash?: unknown } | null;
  if (!m || m.kind !== RECORD_KIND) throw new RecordMismatchError("record metadata does not describe a witness checkpoint");
  if (m.seq !== seq) throw new RecordMismatchError(`record holds checkpoint ${String(m.seq)}, not ${seq}`);
  if (m.checkpointHash !== hash) throw new RecordMismatchError("record metadata hash differs from the hash of its data");
  return { checkpoint: cp as Checkpoint, checkpointHash: hash };
}
