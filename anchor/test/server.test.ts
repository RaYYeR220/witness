import type { AddressInfo } from "node:net";
import type http from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { DidNotFoundError, InvalidDidError, type PublicIdentity, type ResolvedDid } from "../src/did.js";
import { createAnchorServer, type ServerDeps } from "../src/server.js";

const DID = `did:iota:testnet:0x${"cd".repeat(32)}`;

const resolved: ResolvedDid = {
  did: DID,
  objectId: `0x${"cd".repeat(32)}`,
  doc: {
    id: DID,
    verificationMethod: [
      { id: `${DID}#sig-1`, controller: DID, type: "JsonWebKey2020", publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: Buffer.alloc(32, 7).toString("base64url") } },
    ],
    authentication: [`${DID}#sig-1`],
  },
  meta: { created: null, updated: null, deactivated: false },
  version: "1129706989",
  revokedMethods: [
    {
      kid: `${DID}#kex-1`,
      revokedAtMs: 1_791_282_482_045,
      tx: "GWDrDKNuawyYaAtyuuD5fYK1afzb6iUs5LyAMbvuyuDA",
      exact: true,
      method: { id: `${DID}#kex-1`, type: "JsonWebKey2020", publicKeyJwk: { kty: "OKP", crv: "X25519", x: Buffer.alloc(32, 9).toString("base64url") } },
    },
  ],
  historyComplete: true,
};

let server: http.Server | null = null;

async function start(overrides: Partial<ServerDeps> = {}) {
  let clock = 1_000_000;
  const calls: string[] = [];
  const deps: ServerDeps = {
    network: "testnet",
    resolve: async (did) => {
      calls.push(did);
      return resolved;
    },
    identities: () => null,
    cacheTtlMs: 60_000,
    now: () => clock,
    ...overrides,
  };
  server = createAnchorServer(deps);
  await new Promise<void>((r) => server!.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {
    calls,
    advance: (ms: number) => {
      clock += ms;
    },
    get: async (p: string, init?: RequestInit) => {
      const res = await fetch(base + p, init);
      const body: any = res.status === 204 ? null : await res.json();
      return { status: res.status, headers: res.headers, body };
    },
  };
}

afterEach(async () => {
  await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
  server = null;
});

describe("GET /resolve/:did", () => {
  it("returns {doc, version, keys, historyComplete} with the indexer's key shape", async () => {
    const s = await start();
    const { status, body, headers } = await s.get(`/resolve/${DID}`);
    expect(status).toBe(200);
    expect(headers.get("content-type")).toBe("application/json");
    expect(Object.keys(body).sort()).toEqual(["doc", "historyComplete", "keys", "version"]);
    expect(body.historyComplete).toBe(true);
    expect(body.doc).toEqual(resolved.doc);
    expect(body.version).toBe("1129706989");
    expect(body.keys).toEqual([
      { kid: `${DID}#sig-1`, type: "Ed25519", publicKeyHex: "07".repeat(32), revokedAtMs: null },
      { kid: `${DID}#kex-1`, type: "X25519", publicKeyHex: "09".repeat(32), revokedAtMs: 1_791_282_482_045 },
    ]);
    for (const k of body.keys) expect(Object.keys(k).sort()).toEqual(["kid", "publicKeyHex", "revokedAtMs", "type"]);
  });

  it("accepts a percent-encoded DID", async () => {
    const s = await start();
    expect((await s.get(`/resolve/${encodeURIComponent(DID)}`)).status).toBe(200);
    expect(s.calls).toEqual([DID]);
  });

  it("normalises the DID, so differently cased hex shares one cache entry", async () => {
    const s = await start();
    const upper = `did:iota:testnet:0x${"CD".repeat(32)}`;
    expect((await s.get(`/resolve/${upper}`)).status).toBe(200);
    expect((await s.get(`/resolve/${DID}`)).status).toBe(200);
    expect(s.calls).toEqual([DID]);
  });

  it("serves repeats from cache for the TTL, then resolves again", async () => {
    const s = await start();
    await s.get(`/resolve/${DID}`);
    await s.get(`/resolve/${DID}`);
    s.advance(59_000);
    await s.get(`/resolve/${DID}`);
    expect(s.calls).toHaveLength(1);
    s.advance(2_000);
    await s.get(`/resolve/${DID}`);
    expect(s.calls).toHaveLength(2);
  });

  it("collapses concurrent lookups of one DID into one resolution", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let count = 0;
    const s = await start({
      resolve: async () => {
        count++;
        await gate;
        return resolved;
      },
    });
    const pending = Promise.all([s.get(`/resolve/${DID}`), s.get(`/resolve/${DID}`), s.get(`/resolve/${DID}`)]);
    await new Promise((r) => setTimeout(r, 50));
    release();
    const replies = await pending;
    expect(replies.map((r) => r.status)).toEqual([200, 200, 200]);
    expect(count).toBe(1);
  });

  it("maps errors to 400, 404 and 502, and does not cache upstream failures", async () => {
    let mode: "invalid" | "missing" | "down" = "invalid";
    let count = 0;
    const s = await start({
      resolve: async () => {
        count++;
        if (mode === "invalid") throw new InvalidDidError("not a did:iota DID");
        if (mode === "missing") throw new DidNotFoundError("not found");
        throw new Error("ECONNRESET");
      },
    });
    // Not a did:iota DID at all: rejected before resolving.
    expect((await s.get("/resolve/did:web:example.com")).status).toBe(400);
    expect(count).toBe(0);
    // Well-formed but refused by the resolver (another network).
    expect((await s.get(`/resolve/did:iota:0x${"cd".repeat(32)}`)).status).toBe(400);
    expect(count).toBe(1);
    mode = "missing";
    expect((await s.get(`/resolve/${DID}`)).status).toBe(404);
    expect((await s.get(`/resolve/${DID}`)).status).toBe(404);
    expect(count).toBe(2);
    mode = "down";
    const other = DID.replace("cd", "ef");
    const down = await s.get(`/resolve/${other}`);
    expect(down.status).toBe(502);
    expect(JSON.stringify(down.body)).not.toContain("ECONNRESET");
    expect((await s.get(`/resolve/${other}`)).status).toBe(502);
    expect(count).toBe(4);
  });

  it("rejects malformed paths without resolving", async () => {
    const s = await start();
    expect((await s.get("/resolve/%E0%A4%A")).status).toBe(400);
    expect((await s.get(`/resolve/${"a".repeat(200)}`)).status).toBe(400);
    expect(s.calls).toHaveLength(0);
  });
});

describe("other routes", () => {
  it("answers health checks", async () => {
    const s = await start();
    expect(await s.get("/healthz")).toMatchObject({ status: 200, body: { status: "ok", network: "testnet" } });
  });

  it("lists the identities from the public identity file", async () => {
    const ident: PublicIdentity = {
      name: "relay",
      did: DID,
      objectId: resolved.objectId,
      controller: { kind: "identity", did: `did:iota:testnet:0x${"ab".repeat(32)}`, objectId: `0x${"ab".repeat(32)}` },
      keys: [],
      createdTx: "Tx",
      createdAt: "2026-10-06T00:00:00.000Z",
      links: { identity: "https://explorer.iota.org/object/x?network=testnet", createdTx: "https://explorer.iota.org/txblock/Tx?network=testnet" },
    };
    const retired = { ...ident, did: `did:iota:testnet:0x${"ee".repeat(32)}`, retiredAt: "2026-10-06T13:00:00.000Z" };
    const s = await start({ identities: () => ({ identities: [ident], previous: [retired] }) });
    expect((await s.get("/identities")).body).toEqual({ network: "testnet", identities: [ident], previous: [retired] });
  });

  it("lists nothing before identities are bootstrapped", async () => {
    const s = await start();
    expect((await s.get("/identities")).body).toEqual({ network: "testnet", identities: [], previous: [] });
  });

  it("returns 404 for unknown paths and 405 for writes", async () => {
    const s = await start();
    expect((await s.get("/nothing-here")).status).toBe(404);
    // Without a checkpoint reader the checkpoint routes exist but are unavailable.
    expect((await s.get("/checkpoints")).status).toBe(503);
    expect((await s.get(`/resolve/${DID}`, { method: "POST" })).status).toBe(405);
    const pre = await s.get(`/resolve/${DID}`, { method: "OPTIONS" });
    expect(pre.status).toBe(204);
    expect(pre.headers.get("access-control-allow-origin")).toBe("*");
  });
});
