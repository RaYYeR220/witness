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

import { isoOf } from "@/console/format";

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

// ------------------------------------------------- IEs and score lineage

/** One row of `GET /ie`. */
export interface IeSummary {
  ieId: string;
  count: number;
  firstAtMs: number | null;
  lastAtMs: number | null;
  lastMsIndex: number | null;
  latestScore: number | null;
}

/** One ledger message about an IE, in milestone order (`GET /ie/{id}/lineage`). */
export interface LineageEntry {
  blockId: string;
  prev: string | null;
  seq: number | null;
  kind: string | null;
  verdict: string | null;
  msIndex: number | null;
  wfIndex: number | null;
  atMs: number | null;
  /** The trust score this message carries; null for a message about the IE without one. */
  score: number | null;
  links: Record<string, string>;
}

/** The latest score the ledger vouches for (signed, or legacy where the policy allows it). */
export interface LedgerScore {
  score: number;
  blockId: string;
  verdict: string | null;
  msIndex: number | null;
  atMs: number | null;
}

export const ORION_STATUSES = ["ok", "unknown_entity", "no_score", "unreachable", "not_configured"] as const;
export type OrionStatus = (typeof ORION_STATUSES)[number];

/** What the aeriOS context broker answered for the IE's `trustScore`; `value` is set only with status ok. */
export interface OrionState {
  status: OrionStatus | string;
  value: number | null;
  entityId: string;
}

/** `GET /ie/{id}/lineage`. */
export interface Lineage {
  ieId: string;
  /** The newest `limit` entries, oldest first. */
  entries: LineageEntry[];
  total: number;
  ledger: LedgerScore | null;
  orion: OrionState;
  /** Orion differs from the ledger by more than `epsilon`; null when Orion could not be compared. */
  drift: boolean | null;
  epsilon: number;
}

// ------------------------------------------------------ alerts, incidents

/** One integrity alert (`GET /alerts`, and the alerts of an incident). */
export interface Alert {
  id: number;
  rule: string;
  severity: string;
  blockId: string | null;
  ieId: string | null;
  /** What the rule saw. Untrusted data: shown as text only. */
  evidence: unknown;
  atMs: number;
  dedupeKey: string | null;
}

/** `GET /alerts` parameters, named as the API names them. */
export interface AlertQuery {
  rule?: string;
  severity?: string;
  ie?: string;
  block_id?: string;
  since?: string;
  limit?: number;
}

/** One incident of `GET /incidents`. */
export interface Incident {
  id: number;
  title: string;
  severity: string;
  /** open, closed:recovered or closed:quiet. */
  status: string;
  ieId: string | null;
  keys: string[];
  openedAtMs: number;
  lastEventMs: number | null;
  closedAtMs: number | null;
  /** Block id of the trust score that closed it on recovery. */
  closedBy: string | null;
  baselineScore: number | null;
  lowScore: number | null;
}

export interface IncidentQuery {
  status?: string;
  severity?: string;
  ie?: string;
  since?: string;
  limit?: number;
}

/** One event on an incident's timeline. */
export interface IncidentEvent {
  blockId: string;
  /** trigger, trust-drop, security, deployment, remediation or alert. */
  role: string;
  atMs: number | null;
  tag: string | null;
  kind: string | null;
  verdict: string | null;
  status: string | null;
  msIndex: number | null;
  dateMs: number | null;
  indexed: boolean;
  /** What the correlation engine saw (`trust`: proven, relayed or untrusted). Untrusted data. */
  detail: unknown;
  links: Record<string, string>;
}

/** `GET /incidents/{id}`: one page of events and one of alerts, with cursors for the next. */
export interface IncidentDetail extends Incident {
  events: IncidentEvent[];
  eventsTotal: number;
  nextEventsCursor: string | null;
  alerts: Alert[];
  alertsTotal: number;
  nextAlertsAfter: number | null;
}

/** Paging of `GET /incidents/{id}`: the cursors are the previous page's `nextEventsCursor` and `nextAlertsAfter`. */
export interface IncidentPage {
  eventsAfter?: string;
  alertsAfter?: number;
  limit?: number;
}

// ---------------------------------------------------------------- anchors

/** One checkpoint of `GET /anchors` (newest first). */
export interface AnchorCheckpoint {
  seq: number;
  fromMilestone: number;
  toMilestone: number;
  msRoot: string | null;
  /** The checkpoint document as the explorer stored it. Untrusted until re-read from the chain. */
  checkpoint: unknown;
  checkpointHash: string | null;
  /** IOTA Rebased network the record was written to. */
  network: string | null;
  /** Rebased transaction digest. */
  tx: string | null;
  /** Record index in the Audit Trail. */
  record: number | null;
  /** pending, anchored, failed or mismatch. */
  status: string;
  createdAtMs: number;
}

// ---------------------------------------------------------------- identity

export interface TagRule {
  allowed: string[];
  requireSignature: boolean;
  legacyGrace: boolean;
}

/** The writer policy: who may write which tag, and the hash every checkpoint commits to. */
export interface PolicySummary {
  version: number;
  hash: string;
  tags: Record<string, TagRule>;
  default: TagRule;
}

/** `GET /identity`. `identities` and `previous` are what the anchor service publishes, passed through unchecked. */
export interface Identity {
  anchor: {
    status: "ok" | "unreachable" | "not_configured" | string;
    network: string | null;
    identities: unknown[];
    previous: unknown[];
  };
  policy: PolicySummary | null;
}

// ---------------------------------------------------------------- posture

export interface Finding {
  id: string;
  severity: "high" | "medium" | "low" | "info" | string;
  title: string;
  /** What the check observed. Untrusted data: shown as text only. */
  evidence: unknown;
  /** The remediation the scan proposes. */
  fix: string;
}

/** `GET /posture`: the last scan, or an empty one with `scannedAtMs: null`. */
export interface Posture {
  scannedAtMs: number | null;
  active: boolean;
  summary: Record<string, number>;
  findings: Finding[];
}

/** `GET /stats`. `services` (component statuses) is absent on APIs older than the deploy task. */
export interface Stats {
  counts: Record<string, number>;
  services?: Record<string, string>;
  validator: { configured: boolean; running: boolean; pending: number };
  nodeRoute: { enabled: boolean; route: string | null; registered: boolean; error: string | null };
  streamSubscribers: number;
}

// ---------------------------------------------------------------- reports

/** One audit report of `GET /reports`. */
export interface ReportSummary {
  reportHash: string;
  /** True once the relay accepted the audit.report message naming this hash. */
  anchored: boolean;
  blockId: string | null;
  ie: string | null;
  msFrom: number | null;
  msTo: number | null;
  iss: string | null;
  seq: number | null;
  generatedAtMs: number;
  anchoredAtMs: number | null;
  links: Record<string, string>;
}

/** `GET /reports/{hash}`. */
export interface ReportResult extends ReportSummary {
  /** The full report; its canonical form hashes to `reportHash`. */
  report: unknown;
}

/** A report as served: the parsed answer and the exact text, so the browser hashes what it was given. */
export interface ReportDoc {
  result: ReportResult;
  text: string;
}

// ---------------------------------------------------------------- evaluation

export interface ScorecardClass {
  id: string;
  name: string;
  expected: string;
  trials: number;
  detected: number;
  rate: number;
  latency_p50_ms: number | null;
  latency_p95_ms: number | null;
}

/** An evaluation scorecard (witness-chaos `scorecard.json`), when the deployment publishes one. */
export interface Scorecard {
  schema: typeof SCORECARD_SCHEMA;
  headline: string;
  detected: number;
  attacks: number;
  detection_rate: number;
  latency_p50_ms: number | null;
  latency_p95_ms: number | null;
  unexpected_alerts: number;
  classes: ScorecardClass[];
  traps: { messages: number; duration_s: number; false_positives: number; meets_profile: boolean } | null;
  controls: { trials: number; passed: number } | null;
}

export const SCORECARD_SCHEMA = "witness-chaos/scorecard/v1";

const isNum = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);
const isNumOrNull = (v: unknown) => v === null || v === undefined || isNum(v);

/** The scorecard if `doc` is one (schema and the fields the console shows), else null. Numbers are shown as written. */
export function asScorecard(doc: unknown): Scorecard | null {
  if (!isDict(doc) || doc.schema !== SCORECARD_SCHEMA) return null;
  const d = doc as Record<string, unknown>;
  if (!isNum(d.detected) || !isNum(d.attacks) || !isNum(d.detection_rate) || typeof d.headline !== "string") return null;
  if (!isNumOrNull(d.latency_p50_ms) || !isNumOrNull(d.latency_p95_ms) || !Array.isArray(d.classes)) return null;
  const classes: ScorecardClass[] = [];
  for (const c of d.classes) {
    if (!isDict(c)) return null;
    const r = c as Record<string, unknown>;
    if (typeof r.id !== "string" || typeof r.name !== "string" || !isNum(r.trials) || !isNum(r.detected) || !isNum(r.rate)) return null;
    classes.push({
      id: r.id,
      name: r.name,
      expected: typeof r.expected === "string" ? r.expected : "",
      trials: r.trials,
      detected: r.detected,
      rate: r.rate,
      latency_p50_ms: isNum(r.latency_p50_ms) ? r.latency_p50_ms : null,
      latency_p95_ms: isNum(r.latency_p95_ms) ? r.latency_p95_ms : null,
    });
  }
  const t = isDict(d.traps) ? (d.traps as Record<string, unknown>) : null;
  const k = isDict(d.controls) ? (d.controls as Record<string, unknown>) : null;
  return {
    schema: SCORECARD_SCHEMA,
    headline: d.headline,
    detected: d.detected,
    attacks: d.attacks,
    detection_rate: d.detection_rate,
    latency_p50_ms: isNum(d.latency_p50_ms) ? d.latency_p50_ms : null,
    latency_p95_ms: isNum(d.latency_p95_ms) ? d.latency_p95_ms : null,
    unexpected_alerts: isNum(d.unexpected_alerts) ? d.unexpected_alerts : 0,
    classes,
    traps:
      t && isNum(t.messages) && isNum(t.duration_s) && isNum(t.false_positives)
        ? { messages: t.messages, duration_s: t.duration_s, false_positives: t.false_positives, meets_profile: t.meets_profile === true }
        : null,
    controls: k && isNum(k.trials) && isNum(k.passed) ? { trials: k.trials, passed: k.passed } : null,
  };
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
  /** Infrastructure Elements with messages on the ledger, most recently active first (`GET /ie`). */
  ies(): Promise<IeSummary[]>;
  /** The IE's score lineage next to Orion's current value (`GET /ie/{id}/lineage`). */
  lineage(ieId: string, options?: { limit?: number }): Promise<Lineage>;
  /** Integrity alerts, newest first (`GET /alerts`). */
  alerts(query?: AlertQuery): Promise<Alert[]>;
  /** Incidents, newest first (`GET /incidents`). */
  incidents(query?: IncidentQuery): Promise<Incident[]>;
  /** One incident with a page of its timeline and of its alerts (`GET /incidents/{id}`). */
  incident(id: number, page?: IncidentPage): Promise<IncidentDetail>;
  /** Checkpoints, newest first (`GET /anchors`). */
  anchors(limit?: number): Promise<AnchorCheckpoint[]>;
  /** Component DIDs as the anchor service publishes them, and the writer policy (`GET /identity`). */
  identity(): Promise<Identity>;
  /** The last node posture scan (`GET /posture`). Scans are started by the operator, never from here. */
  posture(): Promise<Posture>;
  /** Row counts and component statuses (`GET /stats`). */
  stats(): Promise<Stats>;
  /** Audit reports, newest first (`GET /reports`). */
  reports(query?: { cursor?: string; limit?: number }): Promise<Page<ReportSummary>>;
  /** One report with its exact JSON text (`GET /reports/{hash}`). */
  report(reportHash: string): Promise<ReportDoc>;
  /** Where the report's self-contained HTML page is (`GET /reports/{hash}.html`), for a link; null for a malformed hash. */
  reportHtmlUrl(reportHash: string): string | null;
  /** The evaluation scorecard, when this deployment publishes one; null otherwise. */
  scorecard(): Promise<Scorecard | null>;
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
  // A static host answers a missing snapshot file with its index page: that is a 404, not data.
  if ((res.headers.get("content-type") ?? "").includes("text/html")) {
    void res.body?.cancel().catch(() => undefined);
    throw new DataError(`${url} was not found`, 404);
  }
  if (as === "text") return res.text();
  try {
    return await res.json();
  } catch {
    throw new DataError(`${url} did not answer JSON`, null);
  }
}

const get = (url: string, as: "json" | "text" = "json") => request(url, {}, as);

const qs = (params: object) => {
  const s = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== "") s.set(k, String(v));
  const text = s.toString();
  return text ? `?${text}` : "";
};

const withLimit = (query: MessageQuery) => ({ limit: 50, ...query });

const HASH32 = /^0x[0-9a-f]{64}$/;

/** A report hash as the API names reports: 0x and 64 lowercase hex digits. */
export const isReportHash = (h: unknown): h is string => typeof h === "string" && HASH32.test(h);

function reportDoc(text: string): ReportDoc {
  const result = JSON.parse(text) as ReportResult;
  return { result, text };
}

function checkIncidentId(id: number) {
  if (!Number.isSafeInteger(id) || id < 1) throw new DataError(`no incident ${String(id)}`, 404);
}

function checkReportHash(h: string) {
  if (!isReportHash(h)) throw new DataError("a report hash is 0x and 64 lowercase hex digits", 400);
}

/** A running witness-api at `baseUrl`. `scorecardUrl` is a published evaluation scorecard (static JSON), if any. */
export class LiveAdapter implements WitnessData {
  readonly mode = "live" as const;
  readonly source: string;
  private readonly base: string;
  private readonly scorecardUrl: string | null;

  constructor(baseUrl: string, options: { scorecardUrl?: string | null } = {}) {
    this.base = baseUrl.replace(/\/+$/, "");
    this.source = `witness-api at ${this.base}`;
    this.scorecardUrl = options.scorecardUrl || null;
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
  async ies() {
    return ((await get(`${this.base}/ie`)) as { items: IeSummary[] }).items;
  }
  lineage(ieId: string, options: { limit?: number } = {}) {
    return get(`${this.base}/ie/${encodeURIComponent(ieId)}/lineage${qs({ limit: options.limit })}`) as Promise<Lineage>;
  }
  async alerts(query: AlertQuery = {}) {
    return ((await get(`${this.base}/alerts${qs(query)}`)) as { items: Alert[] }).items;
  }
  async incidents(query: IncidentQuery = {}) {
    return ((await get(`${this.base}/incidents${qs(query)}`)) as { items: Incident[] }).items;
  }
  async incident(id: number, page: IncidentPage = {}) {
    checkIncidentId(id);
    return get(`${this.base}/incidents/${id}${qs({ limit: page.limit, eventsAfter: page.eventsAfter, alertsAfter: page.alertsAfter })}`) as Promise<IncidentDetail>;
  }
  async anchors(limit = 100) {
    return ((await get(`${this.base}/anchors${qs({ limit })}`)) as { items: AnchorCheckpoint[] }).items;
  }
  identity() {
    return get(`${this.base}/identity`) as Promise<Identity>;
  }
  posture() {
    return get(`${this.base}/posture`) as Promise<Posture>;
  }
  stats() {
    return get(`${this.base}/stats`) as Promise<Stats>;
  }
  reports(query: { cursor?: string; limit?: number } = {}) {
    return get(`${this.base}/reports${qs(query)}`) as Promise<Page<ReportSummary>>;
  }
  async report(reportHash: string) {
    checkReportHash(reportHash);
    return reportDoc((await get(`${this.base}/reports/${reportHash}`, "text")) as string);
  }
  reportHtmlUrl(reportHash: string) {
    return isReportHash(reportHash) ? `${this.base}/reports/${reportHash}.html` : null;
  }
  async scorecard() {
    if (!this.scorecardUrl) return null;
    let doc: unknown;
    try {
      doc = await get(this.scorecardUrl);
    } catch (e) {
      if (e instanceof DataError && e.status === 404) return null;
      throw e;
    }
    const card = asScorecard(doc);
    if (!card) throw new DataError(`${this.scorecardUrl} is not a ${SCORECARD_SCHEMA} scorecard`, null);
    return card;
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

/**
 * The file name an id is recorded under in a snapshot: anything but
 * [A-Za-z0-9._-] becomes "_" (scripts/record-replay.mjs writes the same).
 * Readers check the id inside the file, so two ids sharing a name never mix.
 */
export const fileKey = (id: string) => id.replace(/[^A-Za-z0-9._-]/g, "_");

/** `GET /alerts` filtering over a recorded list (newest first), for replay. */
export function filterAlerts(items: Alert[], query: AlertQuery): Alert[] {
  const since = dateBound(query.since, false);
  return items.filter(
    (a) =>
      (!query.rule || a.rule === query.rule) &&
      (!query.severity || a.severity === query.severity) &&
      (!query.ie || a.ieId === query.ie) &&
      (!query.block_id || lower(a.blockId) === lower(query.block_id)) &&
      (since === null || a.atMs >= since),
  );
}

/** `GET /incidents` filtering over a recorded list, for replay. */
export function filterIncidents(items: Incident[], query: IncidentQuery): Incident[] {
  const since = dateBound(query.since, false);
  return items.filter(
    (i) =>
      (!query.status || i.status === query.status) &&
      (!query.severity || i.severity === query.severity) &&
      (!query.ie || i.ieId === query.ie) &&
      (since === null || (i.lastEventMs ?? i.openedAtMs) >= since),
  );
}

/**
 * One page of a recorded incident, like `GET /incidents/{id}` cuts it: events
 * after an offset cursor (opaque to screens, as the API's is), alerts after an
 * alert id, `limit` of each.
 */
export function pageIncident(full: IncidentDetail, page: IncidentPage = {}): IncidentDetail {
  const limit = page.limit ?? 500;
  const start = page.eventsAfter && /^\d+$/.test(page.eventsAfter) ? Number(page.eventsAfter) : 0;
  const events = full.events.slice(start, start + limit);
  const after = page.alertsAfter ?? null;
  const rest = full.alerts.filter((a) => after === null || a.id > after);
  const alerts = rest.slice(0, limit);
  return {
    ...full,
    events,
    nextEventsCursor: start + limit < full.events.length ? String(start + limit) : null,
    alerts,
    nextAlertsAfter: rest.length > limit ? alerts[alerts.length - 1]!.id : null,
  };
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
      const iso = isoOf(m.recordedAtMs);
      const when = iso ? `${iso.slice(0, 16).replace("T", " ")} UTC` : null;
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
  /** A file the snapshot may not have: null on 404. */
  private async optional(name: string): Promise<unknown> {
    try {
      return await this.file(name);
    } catch (e) {
      if (e instanceof DataError && e.status === 404) return null;
      throw e;
    }
  }
  async ies() {
    return (((await this.optional("ie.json")) as { items: IeSummary[] } | null)?.items ?? []) as IeSummary[];
  }
  async lineage(ieId: string, options: { limit?: number } = {}) {
    const doc = (await this.optional(`lineage/${fileKey(ieId)}.json`)) as Lineage | null;
    if (!doc || doc.ieId !== ieId) throw new DataError(`this snapshot holds no lineage for ${ieId}`, 404);
    const limit = options.limit ?? 1000;
    return doc.entries.length > limit ? { ...doc, entries: doc.entries.slice(-limit) } : doc;
  }
  async alerts(query: AlertQuery = {}) {
    const all = (((await this.optional("alerts.json")) as { items: Alert[] } | null)?.items ?? []) as Alert[];
    return filterAlerts(all, query).slice(0, query.limit ?? 200);
  }
  async incidents(query: IncidentQuery = {}) {
    const all = (((await this.optional("incidents.json")) as { items: Incident[] } | null)?.items ?? []) as Incident[];
    return filterIncidents(all, query).slice(0, query.limit ?? 200);
  }
  async incident(id: number, page: IncidentPage = {}) {
    checkIncidentId(id);
    const doc = (await this.optional(`incidents/${id}.json`)) as IncidentDetail | null;
    if (!doc || doc.id !== id) throw new DataError(`this snapshot holds no incident ${id}`, 404);
    return pageIncident(doc, page);
  }
  async anchors(limit = 100) {
    return ((((await this.optional("anchors.json")) as { items: AnchorCheckpoint[] } | null)?.items ?? []) as AnchorCheckpoint[]).slice(0, limit);
  }
  identity() {
    return this.file("identity.json") as Promise<Identity>;
  }
  async posture() {
    return ((await this.optional("posture.json")) as Posture | null) ?? { scannedAtMs: null, active: false, summary: {}, findings: [] };
  }
  stats() {
    return this.file("stats.json") as Promise<Stats>;
  }
  async reports(query: { cursor?: string; limit?: number } = {}) {
    const all = (((await this.optional("reports.json")) as { items: ReportSummary[] } | null)?.items ?? []) as ReportSummary[];
    const limit = query.limit ?? 50;
    const start = query.cursor ? Number(query.cursor) || 0 : 0;
    return { items: all.slice(start, start + limit), nextCursor: start + limit < all.length ? String(start + limit) : null, limit };
  }
  async report(reportHash: string) {
    checkReportHash(reportHash);
    return reportDoc((await this.file(`reports/${reportHash}.json`, "text")) as string);
  }
  reportHtmlUrl(reportHash: string) {
    return isReportHash(reportHash) ? `${this.root}reports/${reportHash}.html` : null;
  }
  async scorecard() {
    const doc = await this.optional("scorecard.json");
    if (doc === null) return null;
    const card = asScorecard(doc);
    if (!card) throw new DataError(`the snapshot's scorecard.json is not a ${SCORECARD_SCHEMA} scorecard`, null);
    return card;
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
  return new LiveAdapter(env.VITE_API_URL ?? "/api", { scorecardUrl: env.VITE_SCORECARD_URL ?? null });
}
