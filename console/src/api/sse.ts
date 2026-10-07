/**
 * Server-Sent Events over fetch, with resume.
 *
 * `EventSource` cannot say why it failed (the API answers 503 with
 * Retry-After when its stream slots are taken) and gives up for good on any
 * non-200 answer. This client reads the stream with fetch, reconnects with an
 * exponential backoff, honours Retry-After and the server's `retry:` field,
 * and resumes from the last event it saw: with the `Last-Event-ID` header when
 * the stream is on this origin, or with `?after=<id>` (which the API treats the
 * same) when a header would need a CORS preflight.
 */

export type StreamStatus = "connecting" | "open" | "retrying" | "closed";

export interface SseMessage {
  id: string | null;
  event: string;
  data: string;
}

export interface SseOptions {
  /** Called for each complete event, in order. */
  onMessage: (msg: SseMessage) => void;
  /** Connection state changes; `retryInMs` is set while waiting to reconnect. */
  onStatus?: (status: StreamStatus, info: { retryInMs?: number; reason?: string }) => void;
  /** Resume after this event id on the first connection too. */
  lastEventId?: string | null;
  fetch?: typeof fetch;
  /** First retry delay, doubled per failed attempt up to `maxDelayMs`. */
  baseDelayMs?: number;
  maxDelayMs?: number;
  /** Send `Last-Event-ID` as a header (default: only when `url` is on this page's origin). */
  header?: boolean;
}

export interface SseHandle {
  close(): void;
  /** The id of the last event received, the resume point. */
  readonly lastEventId: string | null;
}

function sameOrigin(url: string): boolean {
  if (typeof location === "undefined") return true;
  try {
    return new URL(url, location.href).origin === location.origin;
  } catch {
    return false;
  }
}

function withAfter(url: string, id: string): string {
  const base = typeof location === "undefined" ? "http://localhost/" : location.href;
  const u = new URL(url, base);
  u.searchParams.set("after", id);
  return /^[a-z][a-z0-9+.-]*:/i.test(url) ? u.toString() : u.pathname + u.search;
}

/** Retry-After as milliseconds (seconds or an HTTP date); null when absent or unusable. */
export function retryAfterMs(value: string | null, now = Date.now()): number | null {
  if (!value) return null;
  if (/^\s*\d+\s*$/.test(value)) return Number(value) * 1000;
  const at = Date.parse(value);
  return Number.isNaN(at) ? null : Math.max(0, at - now);
}

/** Largest event (or unterminated line) the parser holds; bigger ones are dropped, never buffered. */
export const MAX_EVENT_CHARS = 1024 * 1024;

/** Splits an SSE byte stream into events (WHATWG HTML, "event stream interpretation"). */
export class SseParser {
  private buffer = "";
  private data: string[] = [];
  private dataSize = 0;
  /** The current event outgrew the cap: its data is dropped until the blank line that ends it. */
  private oversize = false;
  /** A line outgrew the cap before its line break: skip to the next break. */
  private skippingLine = false;
  private event = "";
  private id: string | null = null;
  /** Last id seen in the stream, including ids on events without data. */
  lastEventId: string | null;
  retryMs: number | null = null;
  /** How many oversize events were dropped. */
  dropped = 0;

  constructor(
    private readonly emit: (msg: SseMessage) => void,
    lastEventId: string | null = null,
    private readonly maxChars = MAX_EVENT_CHARS,
  ) {
    this.lastEventId = lastEventId;
  }

  push(chunk: string): void {
    this.buffer += chunk;
    let nl: number;
    while ((nl = this.buffer.search(/\r\n|\r|\n/)) >= 0) {
      const sep = this.buffer.startsWith("\r\n", nl) ? 2 : 1;
      // a lone \r at the very end may be the first half of \r\n: wait for more
      if (sep === 1 && this.buffer[nl] === "\r" && nl === this.buffer.length - 1) break;
      const line = this.buffer.slice(0, nl);
      this.buffer = this.buffer.slice(nl + sep);
      if (this.skippingLine) {
        this.skippingLine = false; // the rest of the oversize line ends here
        continue;
      }
      this.line(line);
    }
    if (this.buffer.length > this.maxChars) {
      // one line longer than any event may be: drop it, and the event it belongs to
      this.buffer = "";
      this.skippingLine = true;
      this.oversize = true;
    }
  }

  private line(line: string): void {
    if (line === "") return this.dispatch();
    if (line.startsWith(":")) return; // comment / heartbeat
    const colon = line.indexOf(":");
    const field = colon < 0 ? line : line.slice(0, colon);
    let value = colon < 0 ? "" : line.slice(colon + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    if (field === "data") {
      if (this.oversize) return;
      this.dataSize += value.length + 1;
      if (this.dataSize > this.maxChars) {
        this.oversize = true;
        this.data = [];
        return;
      }
      this.data.push(value);
    } else if (field === "event") this.event = value;
    else if (field === "id" && !value.includes("\0")) this.id = value;
    else if (field === "retry" && /^\d+$/.test(value)) this.retryMs = Number(value);
  }

  private dispatch(): void {
    // the id still counts for an oversize event, so a resume skips it instead of fetching it again
    if (this.id !== null) this.lastEventId = this.id;
    if (this.oversize) this.dropped += 1;
    else if (this.data.length) this.emit({ id: this.lastEventId, event: this.event || "message", data: this.data.join("\n") });
    this.data = [];
    this.dataSize = 0;
    this.oversize = false;
    this.event = "";
    this.id = null;
  }
}

/** Opens `url` as an event stream and keeps it open until `close()`. */
export function openEventStream(url: string, options: SseOptions): SseHandle {
  const doFetch = options.fetch ?? globalThis.fetch.bind(globalThis);
  const base = options.baseDelayMs ?? 1000;
  const max = options.maxDelayMs ?? 30_000;
  const header = options.header ?? sameOrigin(url);
  let lastEventId: string | null = options.lastEventId ?? null;
  let closed = false;
  let attempt = 0;
  let controller: AbortController | null = null;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let serverRetry: number | null = null;
  /** Consecutive 400 answers to a resume: the server does not take that event id. */
  let refusedResume = 0;

  const status = (s: StreamStatus, info: { retryInMs?: number; reason?: string } = {}) => {
    if (!closed || s === "closed") options.onStatus?.(s, info);
  };

  const schedule = (reason: string, retryAfter: number | null) => {
    if (closed) return;
    const backoff = Math.min(max, (serverRetry ?? base) * 2 ** attempt);
    // the server's Retry-After counts, up to the longest backoff we ever wait
    const wait = Math.min(max, Math.max(retryAfter ?? 0, backoff));
    attempt += 1;
    status("retrying", { retryInMs: wait, reason });
    timer = setTimeout(connect, wait);
  };

  async function connect() {
    timer = null;
    if (closed) return;
    controller = new AbortController();
    status("connecting");
    const headers: Record<string, string> = { accept: "text/event-stream" };
    let target = url;
    if (lastEventId !== null) {
      if (header) headers["Last-Event-ID"] = lastEventId;
      else target = withAfter(url, lastEventId);
    }
    let res: Response;
    try {
      res = await doFetch(target, { headers, signal: controller.signal, cache: "no-store" });
    } catch (e) {
      if (closed) return;
      return schedule(e instanceof Error ? e.message : "network error", null);
    }
    if (res.status !== 200 || !res.body) {
      void res.body?.cancel().catch(() => undefined);
      if (res.status === 400 && lastEventId !== null && ++refusedResume >= 2) {
        // the resume point is refused again and again: start over from the newest event
        lastEventId = null;
        refusedResume = 0;
        return schedule("the server refused the resume point; starting from the newest event", null);
      }
      const why = res.status === 503 ? "the server's stream slots are full" : `the server answered ${res.status}`;
      return schedule(why, retryAfterMs(res.headers.get("retry-after")));
    }
    attempt = 0;
    refusedResume = 0;
    status("open");
    const parser = new SseParser((msg) => {
      if (!closed) options.onMessage(msg);
    }, lastEventId);
    const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done || closed) break;
        parser.push(value);
        lastEventId = parser.lastEventId;
        serverRetry = parser.retryMs ?? serverRetry;
      }
    } catch {
      /* the connection dropped: reconnect below */
    }
    lastEventId = parser.lastEventId;
    if (!closed) schedule("the stream ended", null);
  }

  void connect();
  return {
    close() {
      if (closed) return;
      closed = true;
      if (timer) clearTimeout(timer);
      controller?.abort();
      status("closed");
    },
    get lastEventId() {
      return lastEventId;
    },
  };
}
