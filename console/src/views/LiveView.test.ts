// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";

import { LiveAdapter } from "@/api/client";
import { mountScreen, until } from "@/test/mount";

import LiveView from "./LiveView.vue";

const OLD = "0x" + "11".repeat(32);
const NEW = "0x" + "22".repeat(32);
const DID = "did:iota:testnet:0x6b9a693ebf2ac6fb771a75d25b1284ba75aeb0ae16618eaf5d41d24828a6f7a2";

const summary = (blockId: string, score: number, msIndex: number) => ({
  blockId,
  tag: "trust.score",
  kind: "trust.score",
  verdict: "PRODUCER_SIGNED",
  status: "CONFIRMED",
  ieId: "MyDomain:fa163e5e25ef",
  iss: DID,
  encrypted: false,
  msIndex,
  dateMs: 1791283579000,
  json: { w: 1, sig: "x", body: { id: "MyDomain:fa163e5e25ef", score } },
  links: {},
});

const enc = new TextEncoder();
function stream(text: string, signal?: AbortSignal): Response {
  const body = new ReadableStream<Uint8Array>({
    start(c) {
      if (text) c.enqueue(enc.encode(text));
      if (!signal) c.close();
      else signal.addEventListener("abort", () => c.error(new DOMException("aborted", "AbortError")));
    },
  });
  return new Response(body, { status: 200, headers: { "content-type": "text/event-stream" } });
}

const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status, headers: { "content-type": "application/json" } });

afterEach(() => {
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

describe("Live", () => {
  it("shows a streamed trust message and resumes the stream with Last-Event-ID", async () => {
    const streams: { url: string; lastEventId: string | undefined }[] = [];
    vi.stubGlobal("fetch", async (input: string, init: RequestInit = {}) => {
      const url = String(input);
      if (url.startsWith("/api/healthz")) return json({ status: "ok", db: "ok", network: "private_tangle1", version: "0.1.0" });
      if (url.startsWith("/api/stream")) {
        const headers = (init.headers ?? {}) as Record<string, string>;
        streams.push({ url, lastEventId: headers["Last-Event-ID"] });
        if (streams.length === 1) {
          const payload = { blockId: NEW, tag: "trust.score", kind: "trust.score", verdict: "PRODUCER_SIGNED", ieId: "MyDomain:fa163e5e25ef", iss: DID, msIndex: 1285, ts: 1791283600, encrypted: false };
          return stream(`id: 101\nevent: message\ndata: ${JSON.stringify({ id: 101, type: "message", atMs: 1791283600500, at: "", payload })}\n\n`);
        }
        return stream("", init.signal ?? undefined);
      }
      if (url.includes("block_id=")) return json({ items: [summary(NEW, 0.82, 1285)], nextCursor: null, limit: 1 });
      if (url.startsWith("/api/messages")) return json({ items: [summary(OLD, 0.74, 1284)], nextCursor: null, limit: 25 });
      return json({ detail: "not here" }, 404);
    });

    const { w } = await mountScreen(LiveView, { path: "/live", data: new LiveAdapter("/api") });

    // the streamed message lands on top of the listed one, with a link to Verify
    await until(() => w.findAll("a.msg").length === 2);
    const rows = w.findAll("a.msg");
    expect(rows[0]!.attributes("href")).toBe(`/m/${NEW}`);
    expect(rows[1]!.attributes("href")).toBe(`/m/${OLD}`);
    expect(rows[0]!.text()).toContain("Producer signed");
    expect(rows[0]!.text()).toContain("MyDomain:fa163e5e25ef");
    expect(rows[0]!.text()).toContain("ms 1285");
    // the score is not in the event: it is read from the stored message
    await until(() => rows[0]!.find(".score").exists());
    expect(rows[0]!.find(".score").text()).toBe("0.82");

    // the first stream ended: the client reconnects and resumes after event 101
    await until(() => streams.length >= 2, 4000);
    expect(streams[0]!.lastEventId).toBeUndefined();
    expect(streams[0]!.url).toContain("types=message%2Cmilestone%2Calert%2Canchor%2Cincident");
    expect(streams[1]!.lastEventId).toBe("101");
    w.unmount();
  });

  it("holds new events while paused and shows them on resume", async () => {
    let push!: (text: string) => void;
    vi.stubGlobal("fetch", async (input: string, init: RequestInit = {}) => {
      const url = String(input);
      if (url.startsWith("/api/healthz")) return json({ status: "ok", db: "ok", network: "private_tangle1", version: "0.1.0" });
      if (url.startsWith("/api/stream")) {
        const body = new ReadableStream<Uint8Array>({
          start(c) {
            push = (t) => c.enqueue(enc.encode(t));
            init.signal?.addEventListener("abort", () => c.error(new DOMException("aborted", "AbortError")));
          },
        });
        return new Response(body, { status: 200 });
      }
      if (url.includes("block_id=")) return json({ items: [], nextCursor: null, limit: 1 });
      return json({ items: [], nextCursor: null, limit: 25 });
    });
    const { w } = await mountScreen(LiveView, { path: "/live", data: new LiveAdapter("/api") });
    await until(() => typeof push === "function" && w.find(".conn").attributes("data-s") === "open");
    await w.find("button.btn").trigger("click"); // pause
    push(`id: 5\nevent: milestone\ndata: ${JSON.stringify({ id: 5, type: "milestone", atMs: 1, at: "", payload: { index: 77, ts: 1, blocks: 3, newMessages: 0 } })}\n\n`);
    await until(() => w.find("button.btn").text().includes("(1)"));
    expect(w.find(".ms-row").exists()).toBe(false);
    await w.find("button.btn").trigger("click"); // resume
    await until(() => w.find(".ms-row").exists());
    expect(w.find(".ms-row").text()).toContain("Milestone 77");
    w.unmount();
  });

  it("announces connection changes, not every event", async () => {
    vi.stubGlobal("fetch", async (input: string, init: RequestInit = {}) => {
      const url = String(input);
      if (url.startsWith("/api/healthz")) return json({ status: "ok", db: "ok", network: "private_tangle1", version: "0.1.0" });
      if (url.startsWith("/api/stream")) {
        const ev = `id: 9\nevent: milestone\ndata: ${JSON.stringify({ id: 9, type: "milestone", atMs: 1, at: "", payload: { index: 9, ts: 1, blocks: 1, newMessages: 0 } })}\n\n`;
        return stream(ev, init.signal ?? undefined);
      }
      return json({ items: [], nextCursor: null, limit: 25 });
    });
    const { w } = await mountScreen(LiveView, { path: "/live", data: new LiveAdapter("/api") });
    await until(() => w.find(".ms-row").exists());
    const live = w.find('.conn [aria-live="polite"]');
    expect(live.text()).toBe("Connected");
    expect(w.find(".conn").text()).toContain("resuming after event 9");
    w.unmount();
  });
});
