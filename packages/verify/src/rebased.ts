/**
 * Reads the anchor's Audit Trail record straight from a pinned IOTA Rebased
 * JSON-RPC (Python `rebased`).
 *
 * Step 5 of the ladder needs the on-chain record of the checkpoint. This
 * module fetches it from a fullnode the verifier pins, never through the
 * anchor service or the explorer's API: the trail object must be of the pinned
 * Audit Trail package, the record is read from its records table, and the
 * checkpoint is taken from the record's own data (the metadata hash must agree
 * with it), so the hash is recomputed from on-chain bytes.
 *
 * Two read-only calls: `iota_getObject` on the pinned trail, then
 * `iotax_getDynamicFieldObject` on its records table with the record index.
 */

import { toHex, utf8DecodeStrict } from "./bytes.js";
import { CHECKPOINT_KIND, checkpointHash, checkpointShapeError } from "./checkpoint.js";
import { get, has, isDict, JsonNumber, JsonParseError, parseJson, pyRepr, pyTruthy, RecursionError, type Json } from "./json.js";

const NOT_FOUND = "dynamicFieldNotFound";
const MAX_INDEX = Number.MAX_SAFE_INTEGER;
const DEFAULT_TIMEOUT_MS = 15_000;
/** A trail object or one record is a few KiB; anything past this is not an answer to read. */
export const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

/** The chain could not be read, or what it returned is not the pinned trail's record. */
export class RebasedError extends Error {
  override name = "RebasedError";
}

/** What `fetchRecord` returns for a record the trail holds. */
export interface AnchorRecord {
  /** The checkpoint parsed from the record's on-chain data. */
  checkpoint: Json;
  /** Its hash, recomputed here; the record metadata must state the same. */
  checkpointHash: string;
  /** The address that added the record (for the pinned-writer check of step 5). */
  addedBy: unknown;
}

export interface RebasedReadOptions {
  /** The fetch to use (default: the global one). */
  fetch?: typeof fetch;
  /** Per call; default 15 s like the Python reference. */
  timeoutMs?: number;
  /** Accept a plain-http RPC (local tests only). */
  allowHttp?: boolean;
  /** Largest response body read, in bytes (default 2 MiB). */
  maxBytes?: number;
}

/** The pins a fetcher reads; the same names as `VerifierConfig`. */
export interface RebasedPins {
  trailId?: string | null;
  rebasedRpc?: string | null;
  auditTrailPackage?: string | null;
}

/** Python's `str()` of a JSON scalar, as an f-string prints it. */
function pyStr(v: unknown): string {
  return typeof v === "string" ? v : pyRepr(v);
}

/** `obj[k1][k2]...`, null as soon as a step is not an object (Python `_get`). */
function dig(obj: unknown, ...path: string[]): unknown {
  let cur = obj;
  for (const key of path) {
    if (!isDict(cur)) return null;
    cur = get(cur, key) ?? null;
  }
  return cur;
}

/** `urlsplit(url).scheme`: lowercase, empty when the URL has none. */
function scheme(url: string): string {
  const m = /^([A-Za-z][A-Za-z0-9+.-]*):/.exec(url);
  return m ? m[1]!.toLowerCase() : "";
}

function schemeOk(url: string, allowHttp: boolean): boolean {
  const s = scheme(url);
  return s === "https" || (allowHttp && s === "http");
}

/** `type(exc).__name__`: an Error's name, a DOMException's too (TimeoutError, AbortError). */
function errorName(e: unknown): string {
  const name = typeof e === "object" && e !== null ? (e as { name?: unknown }).name : undefined;
  return typeof name === "string" && name ? name : "Error";
}

type ReadOpts = Required<Omit<RebasedReadOptions, "allowHttp">>;

/** The body as text, refusing more than `max` bytes (by header, then while reading). */
async function readCapped(resp: Response, method: string, max: number): Promise<string> {
  const declared = Number(resp.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > max) {
    void resp.body?.cancel().catch(() => undefined);
    throw new RebasedError(`${method}: response over ${max} bytes`);
  }
  if (!resp.body) return resp.text();
  const reader = resp.body.getReader();
  const parts: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) {
      void reader.cancel().catch(() => undefined);
      throw new RebasedError(`${method}: response over ${max} bytes`);
    }
    parts.push(value);
  }
  const all = new Uint8Array(size);
  let at = 0;
  for (const p of parts) {
    all.set(p, at);
    at += p.byteLength;
  }
  return new TextDecoder().decode(all);
}

async function rpc(url: string, method: string, params: unknown[], opts: ReadOpts): Promise<unknown> {
  const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method, params });
  let resp: Response;
  let text: string;
  try {
    // Redirects are refused (the fetch rejects); like the reference, anything but a 200 is an error.
    resp = await opts.fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
      redirect: "error",
      signal: AbortSignal.timeout(opts.timeoutMs),
    });
    if (resp.status !== 200) {
      void resp.body?.cancel().catch(() => undefined);
      throw new RebasedError(`${method}: HTTP ${resp.status}`);
    }
    text = await readCapped(resp, method, opts.maxBytes);
  } catch (e) {
    if (e instanceof RebasedError) throw e;
    throw new RebasedError(`${method}: ${errorName(e)}`);
  }
  let doc: Json;
  try {
    doc = parseJson(text, { constants: true });
  } catch (e) {
    if (e instanceof JsonParseError || e instanceof RecursionError) throw new RebasedError(`${method}: response is not JSON`);
    throw e;
  }
  if (!isDict(doc)) throw new RebasedError(`${method}: unexpected response`);
  if (has(doc, "error")) {
    const err = doc.error;
    const code = isDict(err) ? (get(err, "code") ?? null) : null;
    throw new RebasedError(`${method}: RPC error ${pyStr(code)}`);
  }
  return get(doc, "result") ?? null;
}

async function recordsTable(url: string, trailId: string, packageId: string, opts: ReadOpts): Promise<string> {
  const result = await rpc(url, "iota_getObject", [trailId, { showContent: true, showType: true }], opts);
  const kind = dig(result, "data", "type");
  if (typeof kind !== "string" || !kind.startsWith(`${packageId}::main::AuditTrail<`)) {
    throw new RebasedError("the pinned trail object is not an Audit Trail of the pinned package");
  }
  const table = dig(result, "data", "content", "fields", "records", "fields", "id", "id");
  if (typeof table !== "string") throw new RebasedError("trail has no records table");
  return table;
}

/** The record's data as text: a `Text` variant, or UTF-8 `Bytes` given as a list of byte values. */
function recordText(fields: Record<string, unknown>): string {
  const data = get(fields, "data");
  const variant = isDict(data) ? (get(data, "variant") ?? null) : null;
  const pos0 = dig(data, "fields", "pos0");
  if (variant === "Text" && typeof pos0 === "string") return pos0;
  if (variant === "Bytes" && Array.isArray(pos0)) {
    // bytes(list): ints 0..255 (a bool counts as 0/1), anything else is a TypeError/ValueError.
    const raw = new Uint8Array(pos0.length);
    for (let i = 0; i < pos0.length; i++) {
      const b = pos0[i] === true ? 1 : pos0[i] === false ? 0 : pos0[i];
      if (typeof b !== "number" || !Number.isInteger(b) || b < 0 || b > 255) throw new RebasedError("record bytes are not UTF-8 text");
      raw[i] = b;
    }
    try {
      return utf8DecodeStrict(raw);
    } catch {
      throw new RebasedError("record bytes are not UTF-8 text");
    }
  }
  throw new RebasedError(`unknown record data variant ${pyRepr(variant)}`);
}

/** Python `int(x)` for a sequence number; null where Python raises TypeError/ValueError. */
function pyInt(v: unknown): bigint | null {
  if (v === true) return 1n;
  if (v === false) return 0n;
  if (typeof v === "number" && Number.isFinite(v)) return BigInt(Math.trunc(v));
  if (v instanceof JsonNumber) {
    if (v.kind === "int") return BigInt(v.literal);
    if (Number.isNaN(v.value)) return null;
    if (!Number.isFinite(v.value)) {
      const e = new Error("cannot convert float infinity to integer");
      e.name = "OverflowError"; // not caught by the reference either
      throw e;
    }
    return BigInt(Math.trunc(v.value));
  }
  if (typeof v === "string") {
    const m = /^\s*([+-]?)(\d+(?:_\d+)*)\s*$/.exec(v);
    if (!m) return null;
    const n = BigInt(m[2]!.replace(/_/g, ""));
    return m[1] === "-" ? -n : n;
  }
  return null;
}

/**
 * The checkpoint record `index` of the trail, or null when the trail has no
 * such record. The checkpoint is parsed from the on-chain record data and its
 * hash is recomputed; the record metadata's hash is accepted only if it equals
 * that. Anything else that is wrong rejects with `RebasedError`.
 */
export async function fetchRecord(
  rpcUrl: string,
  trailId: string,
  index: number,
  options: RebasedReadOptions & { packageId: string },
): Promise<AnchorRecord | null> {
  const { packageId, allowHttp = false } = options;
  if (typeof rpcUrl !== "string" || !schemeOk(rpcUrl, allowHttp)) throw new RebasedError("the Rebased RPC must be an https URL");
  if (typeof index !== "number" || !Number.isInteger(index) || index < 0 || index > MAX_INDEX) {
    throw new RebasedError("record index must be a non-negative integer");
  }
  const opts: ReadOpts = {
    fetch: options.fetch ?? globalThis.fetch.bind(globalThis),
    timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    maxBytes: options.maxBytes ?? MAX_RESPONSE_BYTES,
  };
  const table = await recordsTable(rpcUrl, trailId, packageId, opts);
  const result = await rpc(rpcUrl, "iotax_getDynamicFieldObject", [table, { type: "u64", value: String(index) }], opts);
  if (dig(result, "error", "code") === NOT_FOUND) return null;
  if (dig(result, "error") !== null) throw new RebasedError(`reading record ${index}: ${pyStr(dig(result, "error", "code"))}`);
  const fields = dig(result, "data", "content", "fields", "value", "fields", "value", "fields");
  if (!isDict(fields)) throw new RebasedError(`record ${index} has an unexpected shape`);
  const sequence = pyInt(get(fields, "sequence_number") ?? null);
  if (sequence === null) throw new RebasedError(`record ${index} has no sequence number`);
  if (sequence !== BigInt(index)) throw new RebasedError(`record ${index} reports sequence ${sequence}`);
  let cp: Json;
  let digest: string;
  let meta: Json;
  try {
    cp = parseJson(recordText(fields), { constants: true });
    const problem = checkpointShapeError(cp);
    if (problem !== null) throw new RebasedError(`record data is not a checkpoint: ${problem}`);
    digest = toHex(checkpointHash(cp));
    // `json.loads(fields.get("metadata") or "null")`: anything else than text is a TypeError.
    const metadata = get(fields, "metadata");
    const text = pyTruthy(metadata) ? metadata : "null";
    if (typeof text !== "string") throw new TypeError("metadata is not text");
    meta = parseJson(text, { constants: true });
  } catch (e) {
    if (e instanceof RebasedError) throw e;
    throw new RebasedError("record data or metadata is not valid JSON");
  }
  if (!isDict(meta) || get(meta, "kind") !== CHECKPOINT_KIND) {
    throw new RebasedError("record metadata does not describe a witness checkpoint");
  }
  if (get(meta, "checkpointHash") !== digest) throw new RebasedError("record metadata hash differs from the hash of its data");
  return { checkpoint: cp, checkpointHash: digest, addedBy: get(fields, "added_by") ?? null };
}

/**
 * The `fetchAnchorRecord` callback of `verifyBundle`, bound to the pinned
 * config (Python `make_fetcher`). The trail, package and RPC come from `cfg`
 * only; the bundle supplies just the record index. `rpcUrl` overrides the
 * pinned `cfg.rebasedRpc`.
 */
export function makeRebasedFetcher(
  cfg: RebasedPins,
  options: RebasedReadOptions & { rpcUrl?: string | null } = {},
): (anchor: unknown) => Promise<AnchorRecord | null> {
  return async (anchor: unknown) => {
    const url = options.rpcUrl || cfg.rebasedRpc;
    if (!url || !cfg.trailId || !cfg.auditTrailPackage) {
      throw new RebasedError("verifier config pins no Rebased RPC, trail or Audit Trail package");
    }
    const record = dig(anchor, "rebased", "record");
    return fetchRecord(url, cfg.trailId, record as number, { ...options, packageId: cfg.auditTrailPackage });
  };
}
