/**
 * The console's data layer: one interface, two adapters.
 *
 * LiveAdapter talks to a running witness-api; ReplayAdapter reads a recorded
 * snapshot of the same responses as static files, so the console works with
 * no backend at all. Screens depend on `WitnessData` only.
 *
 * Verification never goes through here. The console fetches a bundle and
 * checks it in the browser with @witness/verify against the pins built into
 * the console (verify/pinned.ts), so a lying API can at worst make a check
 * fail. The API's own `verifierConfig()` is for display and comparison only.
 */

import { canonHash, isDict, isEnvelope, parseJson, toHex, type VerifierConfig } from "@witness/verify";

import { openEventStream, type StreamStatus } from "./sse";

export type { StreamStatus } from "./sse";

export const VERDICTS = [
  "PRODUCER_SIGNED",
  "RELAY_ATTESTED",
  "UNSIGNED_LEGACY",
  "FORGED",
  "REPLAY",
  "REVOKED_KEY",
  "UNAUTHORIZED_WRITER",
  "MALFORMED",
] as const;

export type Verdict = (typeof VERDICTS)[number];

/** One stored message as `GET /messages` lists it (witness-api `Message`). */
export interface MessageSummary {
  blockId: string;
  tag: string | null;
  kind: string | null;
  /** The verdict the indexer recorded when it stored the message. */
  verdict: Verdict | string | null;
  status: string | null;
  ieId: string | null;
  iss: string | null;
  kid: string | null;
  seq: number | null;
  prev: string | null;
  corr: string | null;
  nonce: string | null;
  encrypted: boolean;
  msIndex: number | null;
  wfIndex: number | null;
  issuedAtMs: number | null;
  milestoneAtMs: number | null;
  receivedAtMs: number | null;
  confirmedAtMs: number | null;
  dateMs: number | null;
  date: string | null;
  canonHash: string | null;
  /** Decoded JSON of the tagged data (the envelope for signed messages). */
  json: unknown;
  links: Record<string, string>;
}

export interface NodeCheck {
  check: "c" | "d";
  via: string;
  ok: boolean | null;
  detail?: string | null;
  checkedAtMs?: number | null;
  isSolid?: boolean | null;
  referencedByMilestoneIndex?: number | null;
  ledgerInclusionState?: string | null;
  result?: "MATCH" | "MISMATCH" | "NOT_FOUND" | null;
  diff?: unknown;
}

export interface Checks {
  solid: NodeCheck;
  content: NodeCheck;
}

export interface Submission {
  subId: string;
  source: string;
  receivedAtMs: number;
  tag: string | null;
  message: unknown;
  dataHex: string | null;
  hornetStatus: number | null;
  relayVerdict: string | null;
  iss: string | null;
  seq: number | null;
}

/** `GET /messages/{id}`. */
export interface Message extends MessageSummary {
  indexed: boolean;
  dataHex: string | null;
  submission: Submission | null;
  checks: Checks;
}

export interface Transition {
  status: string;
  atMs: number;
  at: string;
  subId: string | null;
  detail: unknown;
}

/** `GET /messages/{id}/lifecycle`. */
export interface Lifecycle {
  blockId: string;
  status: string | null;
  transitions: Transition[];
  validations: { checkedAtMs: number; isSolid: boolean; referencedByMilestoneIndex: number | null; ledgerInclusionState: string | null }[];
  contentChecks: { checkedAtMs: number; result: string; diff: unknown }[];
  checks: Checks;
}

/** `POST /messages/{id}/verify`. */
export interface RecheckResult {
  blockId: string;
  status: string | null;
  concluded: boolean;
  cached: boolean;
  timedOut: boolean;
  startedAtMs: number;
  finishedAtMs: number;
  checks: Checks;
  calls: { request: string; outcome: "answered" | "not_found" | "unavailable"; httpStatus: number | null; error?: string | null; atMs: number; durationMs: number }[];
}

export interface Page<T> {
  items: T[];
  nextCursor: string | null;
  limit: number;
}

/** `GET /messages` parameters, named as the API names them. */
export interface MessageQuery {
  block_id?: string;
  tag?: string;
  date_from?: string;
  date_to?: string;
  iss?: string;
  verdict?: string;
  kind?: string;
  ie?: string;
  ms_from?: number;
  ms_to?: number;
  q?: string;
  jsonpath?: string;
  cursor?: string;
  limit?: number;
}

/** `POST /lookup`. */
export interface LookupResult {
  canonHash: string;
  bodyCanonHash: string | null;
  matches: MessageSummary[];
}

export interface BlindMatch {
  token: string;
  blockId: string;
  tag: string | null;
  kind: string | null;
  ieId: string | null;
  iss: string | null;
  verdict: string | null;
  msIndex: number | null;
  milestoneAtMs: number | null;
}

export interface LineagePoint {
  blockId: string;
  atMs: number;
  value: number;
  verdict: Verdict;
}

export interface Lineage {
  entityId: string;
  series: LineagePoint[];
  orion: { value: number | null; reachable: boolean; atMs: number | null };
}

export interface Alert {
  id: string;
  rule: string;
  severity: "info" | "warning" | "critical";
  blockId: string | null;
  openedAtMs: number;
  summary: string;
}

export interface AnchorCheckpoint {
  record: number;
  fromIndex: number;
  toIndex: number;
  msRoot: string;
  checkpointHash: string;
  tx: string | null;
  anchoredAtMs: number | null;
}

export interface IdentityRecord {
  did: string;
  version: string;
  keys: { kid: string; type: "Ed25519" | "X25519"; publicKeyHex: string; revokedAtMs: number | null }[];
}

export interface Posture {
  atMs: number;
  counts: Partial<Record<Verdict, number>>;
  lastMilestone: number | null;
  lastAnchorRecord: number | null;
}

export interface ReportSummary {
  id: string;
  title: string;
  createdAtMs: number;
}

export const STREAM_TYPES = ["message", "milestone", "alert", "anchor", "incident", "lifecycle", "submission", "posture"] as const;
export type StreamType = (typeof STREAM_TYPES)[number];

/** One event of `GET /stream` (the payload's shape depends on `type`). */
export interface StreamEvent {
  id: number;
  type: StreamType | string;
  atMs: number;
  at: string;
  payload: Record<string, unknown>;
}

export interface StreamOptions {
  types?: readonly StreamType[];
  onStatus?: (status: StreamStatus, info: { retryInMs?: number; reason?: string }) => void;
}

/** What the console knows about the data source, for the status line. */
export interface SourceHealth {
  mode: "live" | "replay";
  ok: boolean;
  /** Tangle network the source reports. */
  network: string | null;
  version: string | null;
  /** One short sentence when something is off, or what the snapshot is. */
  note: string | null;
}

/** Everything a console screen may ask for. */
export interface WitnessData {
  readonly mode: "live" | "replay";
  /** Where the data comes from, in words, for the screen to show. */
  readonly source: string;
  messages(query?: MessageQuery): Promise<Page<MessageSummary>>;
  message(blockId: string): Promise<Message>;
  lifecycle(blockId: string): Promise<Lifecycle>;
  /** Was this exact JSON stored? `doc` is sent as written; the server canonicalises it. */
  lookup(doc: string): Promise<LookupResult>;
  lookupBlind(tokens: string[]): Promise<BlindMatch[]>;
  /** Ask the API to re-run the node checks (c) and (d) now. */
  recheck(blockId: string): Promise<RecheckResult>;
  health(): Promise<SourceHealth>;
  /** The last milestone an anchored checkpoint covers (`GET /anchors`), or null when none is anchored. */
  lastAnchoredMilestone(): Promise<number | null>;
  lineage(entityId: string): Promise<Lineage>;
  alerts(): Promise<Alert[]>;
  anchors(): Promise<AnchorCheckpoint[]>;
  identity(did: string): Promise<IdentityRecord>;
  posture(): Promise<Posture>;
  reports(): Promise<ReportSummary[]>;
  /** Subscribes to the event stream; returns the unsubscribe function. */
  stream(onEvent: (event: StreamEvent) => void, options?: StreamOptions): () => void;
  /**
   * The pins the API says it verifies with. Informational only: the console
   * shows it next to its own pins and flags a difference, but never verifies
   * with it (see verify/pinned.ts).
   */
  verifierConfig(): Promise<VerifierConfig>;
  /** The proof bundle as raw text, for `verifyBundleText`. */
  bundle(blockId: string): Promise<string>;
}

interface AnchorRow {
  toMilestone?: unknown;
  status?: unknown;
}

/** The highest `toMilestone` among anchored checkpoints of a `GET /anchors` page. */
export function lastAnchoredOf(page: { items?: AnchorRow[] } | null | undefined): number | null {
  let best: number | null = null;
  for (const a of page?.items ?? []) {
    if (a.status !== "anchored" || typeof a.toMilestone !== "number") continue;
    best = best === null ? a.toMilestone : Math.max(best, a.toMilestone);
  }
  return best;
}

export class DataError extends Error {
  override name = "DataError";
  constructor(
    message: string,
    readonly status: number | null,
    /** Seconds the server asked to wait (429/503 Retry-After). */
    readonly retryAfterS: number | null = null,
  ) {
    super(message);
  }
}

async function errorFrom(url: string, res: Response): Promise<DataError> {
  let detail = "";
  try {
    const body = (await res.json()) as { detail?: unknown };
    if (typeof body?.detail === "string") detail = body.detail;
  } catch {
    /* no JSON body */
  }
  const ra = res.headers.get("retry-after");
  const retry = ra && /^\d+$/.test(ra.trim()) ? Number(ra) : null;
  return new DataError(detail || `${url} answered ${res.status}`, res.status, retry);
}

async function request(url: string, init: RequestInit = {}, as: "json" | "text" = "json"): Promise<unknown> {
  let res: Response;
  try {
    res = await fetch(url, { ...init, headers: { accept: as === "json" ? "application/json" : "*/*", ...(init.headers ?? {}) } });
  } catch (e) {
    throw new DataError(`${url} is unreachable (${e instanceof Error ? e.message : String(e)})`, null);
  }
  if (!res.ok) throw await errorFrom(url, res);
  return as === "json" ? res.json() : res.text();
}

const get = (url: string, as: "json" | "text" = "json") => request(url, {}, as);

const qs = (params: object) => {
  const s = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== "") s.set(k, String(v));
  const text = s.toString();
  return text ? `?${text}` : "";
};

const withLimit = (query: MessageQuery) => ({ limit: 50, ...query });

/** A running witness-api at `baseUrl`. */
export class LiveAdapter implements WitnessData {
  readonly mode = "live" as const;
  readonly source: string;
  private readonly base: string;

  constructor(baseUrl: string) {
    this.base = baseUrl.replace(/\/+$/, "");
    this.source = `witness-api at ${this.base}`;
  }

  messages(query: MessageQuery = {}) {
    return get(`${this.base}/messages${qs(withLimit(query))}`) as Promise<Page<MessageSummary>>;
  }
  message(blockId: string) {
    return get(`${this.base}/messages/${encodeURIComponent(blockId)}`) as Promise<Message>;
  }
  lifecycle(blockId: string) {
    return get(`${this.base}/messages/${encodeURIComponent(blockId)}/lifecycle`) as Promise<Lifecycle>;
  }
  lookup(doc: string) {
    return request(`${this.base}/lookup`, { method: "POST", headers: { "content-type": "application/json" }, body: doc }) as Promise<LookupResult>;
  }
  async lookupBlind(tokens: string[]) {
    const out = (await request(`${this.base}/lookup/blind`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ tokens }),
    })) as { matches: BlindMatch[] };
    return out.matches;
  }
  recheck(blockId: string) {
    return request(`${this.base}/messages/${encodeURIComponent(blockId)}/verify`, { method: "POST" }) as Promise<RecheckResult>;
  }
  async health(): Promise<SourceHealth> {
    try {
      const h = (await get(`${this.base}/healthz`)) as { status: string; db: string; network: string; version: string };
      return {
        mode: "live",
        ok: h.status === "ok",
        network: h.network ?? null,
        version: h.version ?? null,
        note: h.status === "ok" ? null : "the API cannot reach its database",
      };
    } catch (e) {
      const note = e instanceof DataError && e.status === 503 ? "the API cannot reach its database" : "the API does not answer";
      return { mode: "live", ok: false, network: null, version: null, note };
    }
  }
  async lastAnchoredMilestone() {
    return lastAnchoredOf((await get(`${this.base}/anchors?limit=20`)) as { items: AnchorRow[] });
  }
  lineage(entityId: string) {
    return get(`${this.base}/lineage/${encodeURIComponent(entityId)}`) as Promise<Lineage>;
  }
  alerts() {
    return get(`${this.base}/alerts`) as Promise<Alert[]>;
  }
  anchors() {
    return get(`${this.base}/checkpoints`) as Promise<AnchorCheckpoint[]>;
  }
  identity(did: string) {
    return get(`${this.base}/identity/${encodeURIComponent(did)}`) as Promise<IdentityRecord>;
  }
  posture() {
    return get(`${this.base}/posture`) as Promise<Posture>;
  }
  reports() {
    return get(`${this.base}/reports`) as Promise<ReportSummary[]>;
  }
  stream(onEvent: (event: StreamEvent) => void, options: StreamOptions = {}) {
    const url = `${this.base}/stream${qs({ types: options.types?.join(",") })}`;
    const handle = openEventStream(url, {
      onStatus: options.onStatus,
      onMessage: (msg) => {
        let event: unknown;
        try {
          event = JSON.parse(msg.data);
        } catch {
          return; // not an event this console understands
        }
        if (isDict(event) && typeof event.type === "string") onEvent(event as unknown as StreamEvent);
      },
    });
    return () => handle.close();
  }
  verifierConfig() {
    return get(`${this.base}/config/verifier`) as Promise<VerifierConfig>;
  }
  bundle(blockId: string) {
    return get(`${this.base}/proofs/${encodeURIComponent(blockId)}`, "text") as Promise<string>;
  }
}

// ---------------------------------------------------------------- replay

/** `manifest.json` of a replay snapshot. */
export interface ReplayManifest {
  about: string;
  recordedAtMs: number | null;
  source: string;
}

const lower = (s: unknown) => (typeof s === "string" ? s.toLowerCase() : "");

/** A date bound as the API reads it: ISO date/time or epoch ms; a bare date in `date_to` covers the day. */
export function dateBound(text: string | undefined, end: boolean): number | null {
  if (!text) return null;
  const t = text.trim();
  if (/^\d{11,16}$/.test(t)) return Number(t);
  if (/^\d{4}-\d{2}-\d{2}$/.test(t)) return Date.parse(`${t}T00:00:00Z`) + (end ? 86_400_000 - 1 : 0);
  const ms = Date.parse(/[zZ]|[+-]\d{2}:?\d{2}$/.test(t) ? t : `${t}Z`);
  return Number.isNaN(ms) ? null : ms;
}

function bodyOf(json: unknown): unknown {
  return isDict(json) && isEnvelope(json) ? json.body : json;
}

function atPath(json: unknown, path: string): unknown {
  let cur: unknown = bodyOf(json);
  for (const key of path.split(".")) {
    if (!isDict(cur)) return undefined;
    cur = (cur as Record<string, unknown>)[key];
  }
  return cur;
}

/** `GET /messages` filtering over a recorded list, for replay. */
export function filterMessages(items: MessageSummary[], query: MessageQuery): MessageSummary[] {
  const from = dateBound(query.date_from, false);
  const to = dateBound(query.date_to, true);
  return items.filter((m) => {
    if (query.block_id && lower(m.blockId) !== lower(query.block_id)) return false;
    if (query.tag && m.tag !== query.tag) return false;
    if (query.iss && m.iss !== query.iss) return false;
    if (query.verdict && m.verdict !== query.verdict) return false;
    if (query.kind && m.kind !== query.kind) return false;
    if (query.ie && m.ieId !== query.ie) return false;
    if (query.ms_from !== undefined && (m.msIndex === null || m.msIndex < query.ms_from)) return false;
    if (query.ms_to !== undefined && (m.msIndex === null || m.msIndex > query.ms_to)) return false;
    if (from !== null && (m.dateMs === null || m.dateMs < from)) return false;
    if (to !== null && (m.dateMs === null || m.dateMs > to)) return false;
    if (query.q && !JSON.stringify(m.json ?? null).toLowerCase().includes(query.q.toLowerCase())) return false;
    if (query.jsonpath) {
      const [path, ...rest] = query.jsonpath.split("=");
      const want = rest.join("=");
      const v = atPath(m.json, path ?? "");
      if (v === undefined || (typeof v === "string" ? v : JSON.stringify(v)) !== want) return false;
    }
    return true;
  });
}

/** BLAKE2b-256 of the JCS form, as the API's /lookup computes it; null when the text is not canonicalisable JSON. */
export function localCanonHash(text: string): { hash: string; bodyHash: string | null } | null {
  try {
    const doc = parseJson(text, { constants: true });
    const hash = toHex(canonHash(doc));
    const body = isDict(doc) && isEnvelope(doc) && isDict(doc.body) ? toHex(canonHash(doc.body)) : null;
    return { hash, bodyHash: body };
  } catch {
    return null;
  }
}

/** A recorded snapshot served as static files under `root` (default `/replay/`). */
export class ReplayAdapter implements WitnessData {
  readonly mode = "replay" as const;
  readonly source: string;
  private readonly root: string;
  private all: Promise<MessageSummary[]> | null = null;

  constructor(root = "/replay/") {
    this.root = root.endsWith("/") ? root : `${root}/`;
    this.source = `recorded snapshot at ${this.root}`;
  }

  private file(name: string, as: "json" | "text" = "json") {
    return get(`${this.root}${name}`, as);
  }
  private allMessages() {
    this.all ??= (this.file("messages.json") as Promise<Page<MessageSummary>>).then((p) => p.items);
    return this.all;
  }
  manifest() {
    return this.file("manifest.json") as Promise<ReplayManifest>;
  }
  async messages(query: MessageQuery = {}) {
    const items = filterMessages(await this.allMessages(), query);
    const limit = query.limit ?? 50;
    const start = query.cursor ? Number(query.cursor) || 0 : 0;
    const page = items.slice(start, start + limit);
    return { items: page, nextCursor: start + limit < items.length ? String(start + limit) : null, limit };
  }
  message(blockId: string) {
    return this.file(`messages/${encodeURIComponent(blockId)}.json`) as Promise<Message>;
  }
  lifecycle(blockId: string) {
    return this.file(`lifecycle/${encodeURIComponent(blockId)}.json`) as Promise<Lifecycle>;
  }
  async lookup(doc: string): Promise<LookupResult> {
    const local = localCanonHash(doc);
    if (!local) throw new DataError("JSON cannot be canonicalised", 400);
    const wanted = new Set([local.hash, local.bodyHash].filter((h): h is string => h !== null));
    const matches = (await this.allMessages()).filter((m) => m.canonHash !== null && wanted.has(m.canonHash));
    return { canonHash: local.hash, bodyCanonHash: local.bodyHash, matches };
  }
  async lookupBlind(tokens: string[]) {
    let index: Record<string, BlindMatch[]> = {};
    try {
      index = (await this.file("blind.json")) as Record<string, BlindMatch[]>;
    } catch {
      /* a snapshot without sealed messages has no blind index */
    }
    return tokens.flatMap((t) => index[t] ?? []);
  }
  async recheck(): Promise<RecheckResult> {
    throw new DataError("this is a recorded snapshot: there is no node to ask", 503);
  }
  async health(): Promise<SourceHealth> {
    try {
      const m = await this.manifest();
      const when = m.recordedAtMs ? new Date(m.recordedAtMs).toISOString().slice(0, 16).replace("T", " ") + " UTC" : null;
      return { mode: "replay", ok: true, network: null, version: null, note: when ? `recorded ${when}` : m.about };
    } catch {
      return { mode: "replay", ok: false, network: null, version: null, note: "the snapshot is missing" };
    }
  }
  async lastAnchoredMilestone() {
    try {
      return lastAnchoredOf((await this.file("anchors.json")) as { items: AnchorRow[] });
    } catch {
      return null; // a snapshot recorded before any checkpoint
    }
  }
  lineage(entityId: string) {
    return this.file(`lineage/${encodeURIComponent(entityId)}.json`) as Promise<Lineage>;
  }
  alerts() {
    return this.file("alerts.json") as Promise<Alert[]>;
  }
  anchors() {
    return this.file("checkpoints.json") as Promise<AnchorCheckpoint[]>;
  }
  identity(did: string) {
    return this.file(`identity/${encodeURIComponent(did)}.json`) as Promise<IdentityRecord>;
  }
  posture() {
    return this.file("posture.json") as Promise<Posture>;
  }
  reports() {
    return this.file("reports.json") as Promise<ReportSummary[]>;
  }
  /** Plays the recorded events back, keeping their spacing (at most 4 s apart). */
  stream(onEvent: (event: StreamEvent) => void, options: StreamOptions = {}) {
    let stopped = false;
    const timers: ReturnType<typeof setTimeout>[] = [];
    options.onStatus?.("connecting", {});
    void (this.file("stream.json") as Promise<StreamEvent[]>)
      .then((events) => {
        if (stopped) return;
        options.onStatus?.("open", {});
        const wanted = options.types ? new Set<string>(options.types) : null;
        let at = 0;
        let prev: number | null = null;
        for (const e of events) {
          if (wanted && !wanted.has(e.type)) continue;
          at += prev === null ? 600 : Math.min(4000, Math.max(250, e.atMs - prev));
          prev = e.atMs;
          timers.push(setTimeout(() => !stopped && onEvent(e), at));
        }
      })
      .catch(() => !stopped && options.onStatus?.("open", {})); // a snapshot without a recorded stream simply stays quiet
    return () => {
      stopped = true;
      timers.forEach(clearTimeout);
      options.onStatus?.("closed", {});
    };
  }
  verifierConfig() {
    return this.file("verifier-config.json") as Promise<VerifierConfig>;
  }
  bundle(blockId: string) {
    return this.file(`bundles/${encodeURIComponent(blockId)}.json`, "text") as Promise<string>;
  }
}

/** The adapter for this build: `VITE_MODE=replay` (or `vite build --mode replay`) serves the snapshot, otherwise `VITE_API_URL`. */
export function createData(env: Record<string, string | undefined> = import.meta.env): WitnessData {
  if (env.VITE_MODE === "replay" || env.MODE === "replay") return new ReplayAdapter(env.VITE_REPLAY_ROOT ?? `${import.meta.env.BASE_URL}replay/`);
  return new LiveAdapter(env.VITE_API_URL ?? "/api");
}
