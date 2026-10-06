import { createHash, timingSafeEqual } from "node:crypto";
import http from "node:http";
import { ChainReadError, CheckpointNotFound, type CheckpointReader } from "./checkpoint-api.js";
import { DidNotFoundError, InvalidDidError, resolvedKeys, type PublicIdentity, type ResolvedDid, type ResolvedKey } from "./did.js";
import { parseDid, type DidDocumentJson } from "./didcodec.js";
import { log } from "./log.js";
import type { LoopHealth, LoopStatus, TickResult } from "./loop.js";
import { MAX_DOC_DEPTH, valueTooDeep } from "./untrusted.js";

export interface ServerDeps {
  network: string;
  resolve: (did: string) => Promise<ResolvedDid>;
  /** Contents of the public identity file; null when it has not been written yet. */
  identities: () => IdentitiesBody | null;
  /** How long a resolution (found or not found) is served from memory. */
  cacheTtlMs: number;
  now?: () => number;
  /** Checkpoint read API; `/checkpoints*` answers 503 without it. */
  checkpoints?: Pick<CheckpointReader, "get" | "list"> | null;
  /** The anchoring loop, when this instance writes checkpoints. */
  loop?: { runOnce(): Promise<TickResult>; status(): LoopStatus; health(): LoopHealth } | null;
  /** Bearer token for admin endpoints; null disables them. */
  adminToken?: string | null;
}

export interface IdentitiesBody {
  identities: PublicIdentity[];
  previous?: unknown[];
}

/** Body of `GET /resolve/:did`, consumed by the Python indexer's resolver client. */
export interface ResolveResponse {
  doc: DidDocumentJson;
  version: string;
  keys: ResolvedKey[];
  /** False when revocation times may be early bounds rather than exact (see resolveDid). */
  historyComplete: boolean;
}

export function toResolveResponse(r: ResolvedDid): ResolveResponse {
  return { doc: r.doc, version: r.version, keys: resolvedKeys(r), historyComplete: r.historyComplete };
}

interface Reply {
  status: number;
  body: unknown;
}

const MAX_CACHE_ENTRIES = 1024;
const MAX_DID_LENGTH = 128;
const SEQ = /^[1-9]\d{0,14}$/;

/** A tick result as clients may see it: failures keep their stage, their raw text stays in the log. */
export function publicTick(r: TickResult | null): unknown {
  return r && r.status === "error" ? { status: "error", stage: r.stage } : r;
}

function digest(s: string): Buffer {
  return createHash("sha256").update(s, "utf8").digest();
}

/** Constant-time check of `Authorization: Bearer <token>`. */
export function bearerMatches(header: string | undefined, token: string): boolean {
  const m = /^Bearer\s+(\S+)\s*$/i.exec(header ?? "");
  return m !== null && timingSafeEqual(digest(m[1]!), digest(token));
}

export function createAnchorServer(deps: ServerDeps): http.Server {
  const now = deps.now ?? Date.now;
  const cache = new Map<string, { expires: number; reply: Reply }>();
  const inflight = new Map<string, Promise<Reply>>();

  async function resolveReply(did: string): Promise<Reply> {
    const hit = cache.get(did);
    if (hit && hit.expires > now()) return hit.reply;
    if (hit) cache.delete(did);
    const pending = inflight.get(did);
    if (pending) return pending;

    const p = (async (): Promise<Reply> => {
      let reply: Reply;
      try {
        const body = toResolveResponse(await deps.resolve(did));
        // A hostile document must not be served for clients to walk: answered as unusable,
        // a definitive refusal clients cache like "no such DID".
        reply = valueTooDeep(body, MAX_DOC_DEPTH)
          ? { status: 422, body: { error: `DID document unusable: nested deeper than ${MAX_DOC_DEPTH} levels` } }
          : { status: 200, body };
      } catch (err) {
        if (err instanceof InvalidDidError) return { status: 400, body: { error: err.message } };
        if (err instanceof DidNotFoundError) reply = { status: 404, body: { error: err.message } };
        else {
          log.error("DID resolution failed", { did, error: err });
          return { status: 502, body: { error: "DID resolution failed upstream" } };
        }
      }
      if (deps.cacheTtlMs > 0) {
        if (cache.size >= MAX_CACHE_ENTRIES) cache.delete(cache.keys().next().value!);
        cache.set(did, { expires: now() + deps.cacheTtlMs, reply });
      }
      return reply;
    })().finally(() => inflight.delete(did));
    inflight.set(did, p);
    return p;
  }

  async function checkpointRoute(req: http.IncomingMessage, p: string, url: URL): Promise<Reply> {
    if (p === "/checkpoints/run") {
      if (req.method !== "POST") return { status: 405, body: { error: "use POST" } };
      if (!deps.adminToken) return { status: 403, body: { error: "admin endpoints are disabled (ANCHOR_ADMIN_TOKEN is not set)" } };
      if (!bearerMatches(req.headers.authorization, deps.adminToken)) return { status: 401, body: { error: "admin token required" } };
      if (!deps.loop) return { status: 409, body: { error: "this instance does not anchor (ANCHOR_LOOP is off)" } };
      const result = await deps.loop.runOnce();
      if (result.status === "error") log.warn("admin-triggered anchor tick failed", { stage: result.stage, error: result.error });
      return { status: result.status === "error" ? 502 : 200, body: publicTick(result) };
    }
    if (req.method !== "GET") return { status: 405, body: { error: "method not allowed" } };
    const cps = deps.checkpoints;
    if (!cps) return { status: 503, body: { error: "checkpoints are not configured" } };
    if (p === "/checkpoints") {
      const raw = url.searchParams.get("limit");
      const limit = raw === null ? 100 : Number(raw);
      if (!Number.isInteger(limit) || limit < 1 || limit > 1000) return { status: 400, body: { error: "limit must be 1..1000" } };
      const list = await cps.list(limit);
      const loop = deps.loop ? deps.loop.status() : null;
      return { status: 200, body: { ...list, loop: loop && { ...loop, lastResult: publicTick(loop.lastResult) } } };
    }
    const raw = p.slice("/checkpoints/".length);
    if (!SEQ.test(raw)) return { status: 400, body: { error: "checkpoint seq must be a positive integer" } };
    const seq = Number(raw);
    try {
      return { status: 200, body: await cps.get(seq) };
    } catch (err) {
      if (err instanceof CheckpointNotFound) return { status: 404, body: { error: err.message } };
      if (err instanceof ChainReadError) {
        log.warn("checkpoint read from chain failed", { seq, error: err.message, detail: err.detail });
        return { status: 502, body: { error: err.message, source: "chain" } };
      }
      log.error("checkpoint read failed", { seq, error: err });
      return { status: 502, body: { error: "checkpoint could not be read from the chain", source: "chain" } };
    }
  }

  async function route(req: http.IncomingMessage): Promise<Reply> {
    const url = new URL(req.url ?? "/", "http://anchor.local");
    const p = url.pathname;
    if (p === "/checkpoints" || p.startsWith("/checkpoints/")) return checkpointRoute(req, p, url);
    if (req.method !== "GET") return { status: 405, body: { error: "method not allowed" } };
    if (p === "/healthz") {
      const h = deps.loop?.health();
      if (h && h.status !== "ok") return { status: 503, body: { status: h.status, network: deps.network, reason: h.reason } };
      return { status: 200, body: { status: "ok", network: deps.network } };
    }
    if (p === "/identities") {
      const file = deps.identities();
      return { status: 200, body: { network: deps.network, identities: file?.identities ?? [], previous: file?.previous ?? [] } };
    }
    if (p.startsWith("/resolve/")) {
      let did: string;
      try {
        did = decodeURIComponent(p.slice("/resolve/".length));
      } catch {
        return { status: 400, body: { error: "malformed DID in path" } };
      }
      if (did.length > MAX_DID_LENGTH) return { status: 400, body: { error: "not a did:iota DID" } };
      try {
        // One cache entry per DID, however the hex is cased.
        return await resolveReply(parseDid(did).did);
      } catch (err) {
        if (err instanceof InvalidDidError) return { status: 400, body: { error: err.message } };
        throw err;
      }
    }
    return { status: 404, body: { error: "not found" } };
  }

  return http.createServer((req, res) => {
    const headers: Record<string, string> = {
      "access-control-allow-origin": "*",
      "x-content-type-options": "nosniff",
    };
    if (req.method === "OPTIONS") {
      res.writeHead(204, { ...headers, "access-control-allow-methods": "GET", "access-control-max-age": "600" }).end();
      return;
    }
    if (req.method !== "GET" && req.method !== "POST") {
      res.writeHead(405, { ...headers, allow: "GET", "content-type": "application/json" }).end(JSON.stringify({ error: "method not allowed" }));
      return;
    }
    // Admin requests carry no body we read; drain whatever was sent.
    req.resume();
    route(req)
      .catch((err: unknown): Reply => {
        log.error("request failed", { path: req.url, error: err });
        return { status: 500, body: { error: "internal error" } };
      })
      .then((reply) => {
        res.writeHead(reply.status, { ...headers, "content-type": "application/json", "cache-control": "no-store" });
        res.end(JSON.stringify(reply.body));
      });
  });
}
