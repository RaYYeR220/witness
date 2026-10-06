import http from "node:http";
import { DidNotFoundError, InvalidDidError, resolvedKeys, type PublicIdentity, type ResolvedDid, type ResolvedKey } from "./did.js";
import { parseDid, type DidDocumentJson } from "./didcodec.js";
import { log } from "./log.js";

export interface ServerDeps {
  network: string;
  resolve: (did: string) => Promise<ResolvedDid>;
  /** Contents of the public identity file; null when it has not been written yet. */
  identities: () => IdentitiesBody | null;
  /** How long a resolution (found or not found) is served from memory. */
  cacheTtlMs: number;
  now?: () => number;
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
        reply = { status: 200, body: toResolveResponse(await deps.resolve(did)) };
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

  async function route(req: http.IncomingMessage): Promise<Reply> {
    const url = new URL(req.url ?? "/", "http://anchor.local");
    const p = url.pathname;
    if (p === "/healthz") return { status: 200, body: { status: "ok", network: deps.network } };
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
    if (req.method !== "GET") {
      res.writeHead(405, { ...headers, allow: "GET", "content-type": "application/json" }).end(JSON.stringify({ error: "method not allowed" }));
      return;
    }
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
