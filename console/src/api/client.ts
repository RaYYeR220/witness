/**
 * The console's data layer: one interface, two adapters.
 *
 * LiveAdapter talks to a running witness-api; ReplayAdapter reads a recorded
 * snapshot of the same responses as static files, so the console works with
 * no backend at all. Screens depend on `WitnessData` only. Verification never
 * goes through here: the console fetches a bundle and checks it in the browser
 * with @witness/verify, so a lying API can at worst make a check fail.
 */

import type { VerifierConfig } from "@witness/verify";

export type Verdict =
  | "PRODUCER_SIGNED"
  | "RELAY_ATTESTED"
  | "UNSIGNED_LEGACY"
  | "FORGED"
  | "REPLAY"
  | "REVOKED_KEY"
  | "UNAUTHORIZED_WRITER"
  | "MALFORMED";

export interface MessageSummary {
  blockId: string;
  tag: string;
  domain: string | null;
  verdict: Verdict;
  milestoneIndex: number | null;
  receivedAtMs: number;
}

export interface Message extends MessageSummary {
  raw: string;
  envelope: unknown;
  issuer: string | null;
}

export interface Page<T> {
  items: T[];
  next: string | null;
}

export interface MessageQuery {
  tag?: string;
  domain?: string;
  verdict?: Verdict;
  cursor?: string;
  limit?: number;
}

export interface LookupHit {
  kind: "block" | "milestone" | "did" | "domain" | "entity";
  id: string;
  label: string;
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

export type StreamEvent = { type: "message"; message: MessageSummary } | { type: "alert"; alert: Alert };

/** Everything a console screen may ask for. */
export interface WitnessData {
  readonly mode: "live" | "replay";
  messages(query?: MessageQuery): Promise<Page<MessageSummary>>;
  message(blockId: string): Promise<Message>;
  lookup(q: string): Promise<LookupHit[]>;
  lineage(entityId: string): Promise<Lineage>;
  alerts(): Promise<Alert[]>;
  anchors(): Promise<AnchorCheckpoint[]>;
  identity(did: string): Promise<IdentityRecord>;
  posture(): Promise<Posture>;
  reports(): Promise<ReportSummary[]>;
  /** Subscribes to new messages and alerts; returns the unsubscribe function. */
  stream(onEvent: (event: StreamEvent) => void): () => void;
  verifierConfig(): Promise<VerifierConfig>;
  /** The proof bundle as raw text, for `verifyBundleText`. */
  bundle(blockId: string): Promise<string>;
}

export class DataError extends Error {
  override name = "DataError";
  constructor(
    message: string,
    readonly status: number | null,
  ) {
    super(message);
  }
}

async function get(url: string, as: "json" | "text" = "json"): Promise<unknown> {
  const res = await fetch(url, { headers: { accept: as === "json" ? "application/json" : "*/*" } });
  if (!res.ok) throw new DataError(`${url} answered ${res.status}`, res.status);
  return as === "json" ? res.json() : res.text();
}

const q = (params: Record<string, string | number | undefined>) => {
  const s = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined) s.set(k, String(v));
  const text = s.toString();
  return text ? `?${text}` : "";
};

/** A running witness-api at `baseUrl`. */
export class LiveAdapter implements WitnessData {
  readonly mode = "live" as const;
  private readonly base: string;

  constructor(baseUrl: string) {
    this.base = baseUrl.replace(/\/+$/, "");
  }

  messages(query: MessageQuery = {}) {
    return get(`${this.base}/messages${q({ ...query })}`) as Promise<Page<MessageSummary>>;
  }
  message(blockId: string) {
    return get(`${this.base}/messages/${encodeURIComponent(blockId)}`) as Promise<Message>;
  }
  lookup(text: string) {
    return get(`${this.base}/lookup${q({ q: text })}`) as Promise<LookupHit[]>;
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
  stream(onEvent: (event: StreamEvent) => void) {
    const source = new EventSource(`${this.base}/stream`);
    source.onmessage = (e) => onEvent(JSON.parse(e.data as string) as StreamEvent);
    return () => source.close();
  }
  verifierConfig() {
    return get(`${this.base}/verifier-config`) as Promise<VerifierConfig>;
  }
  bundle(blockId: string) {
    return get(`${this.base}/bundles/${encodeURIComponent(blockId)}`, "text") as Promise<string>;
  }
}

/** A recorded snapshot served as static files under `root` (default `/replay/`). */
export class ReplayAdapter implements WitnessData {
  readonly mode = "replay" as const;
  private readonly root: string;

  constructor(root = "/replay/") {
    this.root = root.endsWith("/") ? root : `${root}/`;
  }

  private file(name: string, as: "json" | "text" = "json") {
    return get(`${this.root}${name}`, as);
  }
  messages() {
    return this.file("messages.json") as Promise<Page<MessageSummary>>;
  }
  message(blockId: string) {
    return this.file(`messages/${blockId}.json`) as Promise<Message>;
  }
  async lookup(text: string) {
    const all = (await this.file("lookup.json")) as LookupHit[];
    const needle = text.trim().toLowerCase();
    return all.filter((h) => h.id.toLowerCase().includes(needle) || h.label.toLowerCase().includes(needle));
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
  stream(onEvent: (event: StreamEvent) => void) {
    let stopped = false;
    void (this.file("stream.json") as Promise<StreamEvent[]>)
      .then((events) => {
        if (!stopped) events.forEach(onEvent);
      })
      .catch(() => undefined); // a snapshot without a recorded stream simply stays quiet
    return () => {
      stopped = true;
    };
  }
  verifierConfig() {
    return this.file("verifier-config.json") as Promise<VerifierConfig>;
  }
  bundle(blockId: string) {
    return this.file(`bundles/${blockId}.json`, "text") as Promise<string>;
  }
}

/** The adapter for this build: `VITE_MODE=replay` serves the snapshot, otherwise `VITE_API_URL`. */
export function createData(env: Record<string, string | undefined> = import.meta.env): WitnessData {
  if (env.VITE_MODE === "replay") return new ReplayAdapter(env.VITE_REPLAY_ROOT ?? "/replay/");
  return new LiveAdapter(env.VITE_API_URL ?? "/api");
}
