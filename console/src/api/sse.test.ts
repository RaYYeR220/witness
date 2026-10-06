import { describe, expect, it } from "vitest";

import { openEventStream, retryAfterMs, SseParser, type SseMessage, type StreamStatus } from "./sse";

const enc = new TextEncoder();

/** A 200 text/event-stream response whose body is `chunks`, then the end of the stream. */
function sse(chunks: string[]): Response {
  const body = new ReadableStream<Uint8Array>({
    start(c) {
      for (const ch of chunks) c.enqueue(enc.encode(ch));
      c.close();
    },
  });
  return new Response(body, { status: 200, headers: { "content-type": "text/event-stream" } });
}

/** A stream that stays open until the client aborts it. */
function open(signal: AbortSignal): Response {
  const body = new ReadableStream<Uint8Array>({
    start(c) {
      signal.addEventListener("abort", () => c.error(new DOMException("aborted", "AbortError")));
    },
  });
  return new Response(body, { status: 200 });
}

const event = (id: number, type: string, payload: object) =>
  `id: ${id}\nevent: ${type}\ndata: ${JSON.stringify({ id, type, atMs: 1, at: "x", payload })}\n\n`;

describe("SseParser", () => {
  it("splits events across chunk boundaries and line ending styles", () => {
    const got: SseMessage[] = [];
    const p = new SseParser((m) => got.push(m));
    p.push(": heartbeat\n\nid: 7\nevent: mess");
    p.push("age\ndata: {\"a\":\r\ndata: 1}\r\n\r");
    p.push("\nid: 8\ndata: two\n\n");
    expect(got).toEqual([
      { id: "7", event: "message", data: '{"a":\n1}' },
      { id: "8", event: "message", data: "two" },
    ]);
    expect(p.lastEventId).toBe("8");
  });

  it("keeps the last id for an event without data and reads retry", () => {
    const got: SseMessage[] = [];
    const p = new SseParser((m) => got.push(m), "3");
    p.push("id: 4\n\nretry: 2500\n\n");
    expect(got).toEqual([]);
    expect(p.lastEventId).toBe("4");
    expect(p.retryMs).toBe(2500);
  });
});

describe("retryAfterMs", () => {
  it("reads seconds and HTTP dates", () => {
    expect(retryAfterMs("5")).toBe(5000);
    expect(retryAfterMs(new Date(10_000).toUTCString(), 4000)).toBe(6000);
    expect(retryAfterMs(null)).toBeNull();
    expect(retryAfterMs("soon")).toBeNull();
  });
});

describe("openEventStream", () => {
  it("resumes after the last event with Last-Event-ID when the stream drops", async () => {
    const calls: { url: string; headers: Record<string, string> }[] = [];
    const statuses: [StreamStatus, number | undefined][] = [];
    const got: SseMessage[] = [];
    let done!: () => void;
    const finished = new Promise<void>((r) => (done = r));
    const fetchMock = (async (url: string, init: RequestInit) => {
      calls.push({ url, headers: { ...(init.headers as Record<string, string>) } });
      if (calls.length === 1) return sse([event(41, "message", { blockId: "0x01" }), event(42, "milestone", { index: 9 })]);
      if (calls.length === 2) return new Response("busy", { status: 503, headers: { "retry-after": "0" } });
      if (calls.length === 3) return sse([event(43, "message", { blockId: "0x02" })]);
      done();
      return open(init.signal!);
    }) as unknown as typeof fetch;

    const h = openEventStream("/api/stream?types=message", {
      fetch: fetchMock,
      baseDelayMs: 5,
      header: true,
      onMessage: (m) => got.push(m),
      onStatus: (s, info) => statuses.push([s, info.retryInMs]),
    });
    await finished;
    await new Promise((r) => setTimeout(r, 20));
    h.close();

    expect(calls[0]!.headers["Last-Event-ID"]).toBeUndefined();
    // the reconnects carry the id of the last event the client saw
    expect(calls[1]!.headers["Last-Event-ID"]).toBe("42");
    expect(calls[2]!.headers["Last-Event-ID"]).toBe("42");
    expect(calls[3]!.headers["Last-Event-ID"]).toBe("43");
    expect(got.map((m) => m.id)).toEqual(["41", "42", "43"]);
    expect(h.lastEventId).toBe("43");
    // drop -> retrying with backoff; the 503 is retried too, waiting longer
    const retries = statuses.filter(([s]) => s === "retrying").map(([, ms]) => ms!);
    expect(retries.length).toBeGreaterThanOrEqual(2);
    expect(retries[1]!).toBeGreaterThan(retries[0]!);
    expect(statuses.at(-1)![0]).toBe("closed");
  });

  it("uses ?after= instead of the header across origins", async () => {
    const urls: string[] = [];
    let done!: () => void;
    const finished = new Promise<void>((r) => (done = r));
    const fetchMock = (async (url: string, init: RequestInit) => {
      urls.push(url);
      expect((init.headers as Record<string, string>)["Last-Event-ID"]).toBeUndefined();
      if (urls.length === 1) return sse([event(7, "alert", { rule: "FORGED" })]);
      done();
      return sse([]);
    }) as unknown as typeof fetch;
    const h = openEventStream("https://api.example/stream", { fetch: fetchMock, baseDelayMs: 1, header: false, onMessage: () => undefined });
    await finished;
    h.close();
    expect(urls[1]).toBe("https://api.example/stream?after=7");
  });
});
