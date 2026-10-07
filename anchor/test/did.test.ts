import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { NETWORKS } from "../src/config.js";
import {
  DidNotFoundError,
  InvalidDidError,
  loadIdentityRegistry,
  methodFragment,
  resolveDid,
  resolvedKeys,
  retireIdentities,
  revocationOf,
  type DidRpc,
} from "../src/did.js";

const PKG = NETWORKS.testnet.packages.identityOriginal;
const CFG = { didNetwork: "testnet", packages: NETWORKS.testnet.packages };
const OBJ = "0x47616703b4f0258638bca77f0cb8ea4e19f0350136f043f0da22f8892d2697b1";
const DID = `did:iota:testnet:${OBJ}`;

const SIG_X = Buffer.alloc(32, 1).toString("base64url");
const KEX_X = Buffer.alloc(32, 2).toString("base64url");
const KEX2_X = Buffer.alloc(32, 3).toString("base64url");

const sigMethod = { id: "did:0:0#sig-1", controller: "did:0:0", type: "JsonWebKey2020", publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: SIG_X, alg: "EdDSA" } };
const kexMethod = (x = KEX_X, frag = "kex-1") => ({ id: `did:0:0#${frag}`, controller: "did:0:0", type: "JsonWebKey2020", publicKeyJwk: { kty: "OKP", crv: "X25519", x } });

/** Packs a document the way the Identity package stores it: "DID" | 1 | 0 | u16 LE length | JSON. */
function pack(doc: Record<string, unknown> | null, meta: Record<string, unknown> = {}): number[] | null {
  if (doc === null) return null;
  const json = Buffer.from(JSON.stringify({ doc: { id: "did:0:0", ...doc }, meta: { created: "2026-10-06T10:27:58Z", ...meta } }));
  const len = Buffer.alloc(2);
  len.writeUInt16LE(json.length);
  return [...Buffer.concat([Buffer.from("DID"), Buffer.from([1, 0]), len, json])];
}

interface Version {
  version: string;
  tx: string;
  ts: number | null;
  doc: Record<string, unknown> | null;
  meta?: Record<string, unknown>;
  created?: boolean;
}

function identityObject(v: Version, updatedMs: number) {
  return {
    objectId: OBJ,
    version: v.version,
    digest: "d",
    type: `${PKG}::identity::Identity`,
    previousTransaction: v.tx,
    content: {
      dataType: "moveObject" as const,
      type: `${PKG}::identity::Identity`,
      hasPublicTransfer: false,
      fields: { created: "1000", updated: String(updatedMs), deleted: false, did_doc: { fields: { controlled_value: pack(v.doc, v.meta) } } },
    },
  };
}

/** A fake JSON-RPC node holding the history of one Identity object. */
function fakeRpc(
  versions: Version[],
  opts: { pageSize?: number; indexed?: number; pruned?: string[]; type?: string; missing?: boolean; current?: number } = {},
) {
  const calls = { getObject: 0, query: 0, past: 0 };
  const indexed = versions.slice(0, opts.indexed ?? versions.length);
  const pageSize = opts.pageSize ?? 50;
  const latest = versions[opts.current ?? versions.length - 1]!;
  const rpc = {
    async getObject() {
      calls.getObject++;
      if (opts.missing) return { error: { code: "notExists", object_id: OBJ } };
      const o = identityObject(latest, 5000);
      return { data: { ...o, type: opts.type ?? o.type } };
    },
    async queryTransactionBlocks(input: { cursor?: string | null; filter?: unknown; order?: string; limit?: number }) {
      calls.query++;
      expect(input.filter).toEqual({ ChangedObject: OBJ });
      expect(input.order).toBe("ascending");
      const size = Math.min(input.limit ?? pageSize, pageSize);
      const start = input.cursor ? Number(input.cursor) : 0;
      const slice = indexed.slice(start, start + size);
      const next = start + size;
      return {
        data: slice.map((v) => {
          const ref = { owner: { Shared: { initial_shared_version: 1 } }, reference: { objectId: OBJ, version: Number(v.version), digest: "x" } };
          return {
            digest: v.tx,
            timestampMs: v.ts === null ? null : String(v.ts),
            checkpoint: "1",
            effects: v.created ? { created: [ref], mutated: [] } : { mutated: [ref] },
          };
        }),
        hasNextPage: next < indexed.length,
        nextCursor: next < indexed.length ? String(next) : null,
      };
    },
    async tryGetPastObject(input: { id: string; version: number }) {
      calls.past++;
      expect(input.id).toBe(OBJ);
      const v = versions.find((x) => Number(x.version) === input.version);
      if (!v || opts.pruned?.includes(v.version)) return { status: "VersionNotFound", details: [OBJ, String(input.version)] };
      return { status: "VersionFound", details: identityObject(v, v.ts ?? 0) };
    },
  };
  return { rpc: rpc as unknown as DidRpc, calls };
}

const created: Version = { version: "100", tx: "TxCreate", ts: 1_000, doc: { verificationMethod: [sigMethod], keyAgreement: [kexMethod()] }, created: true };
const kexRemoved: Version = { version: "200", tx: "TxRevoke", ts: 2_000, doc: { verificationMethod: [sigMethod] } };

describe("resolveDid", () => {
  it("maps a removed method to the timestamp of the transaction that removed it", async () => {
    const { rpc } = fakeRpc([created, kexRemoved]);
    const r = await resolveDid(rpc, CFG, DID);

    expect(r.did).toBe(DID);
    expect(r.version).toBe("200");
    expect(r.historyComplete).toBe(true);
    expect(r.doc.id).toBe(DID);
    expect(r.doc.verificationMethod?.map((m) => m.id)).toEqual([`${DID}#sig-1`]);
    expect(r.doc.keyAgreement).toBeUndefined();
    expect(r.revokedMethods).toEqual([
      expect.objectContaining({ kid: `${DID}#kex-1`, revokedAtMs: 2_000, tx: "TxRevoke" }),
    ]);
    expect(r.revokedMethods[0]!.method.publicKeyJwk?.x).toBe(KEX_X);
    expect(r.meta.created).toBe(new Date(1000).toISOString());
    expect(r.meta.updated).toBe(new Date(5000).toISOString());
  });

  it("flattens current and revoked keys for the HTTP resolver", async () => {
    const { rpc } = fakeRpc([created, kexRemoved]);
    const keys = resolvedKeys(await resolveDid(rpc, CFG, DID));
    expect(keys).toEqual([
      { kid: `${DID}#sig-1`, type: "Ed25519", publicKeyHex: "01".repeat(32), revokedAtMs: null },
      { kid: `${DID}#kex-1`, type: "X25519", publicKeyHex: "02".repeat(32), revokedAtMs: 2_000 },
    ]);
  });

  it("walks every page of the transaction history", async () => {
    const versions: Version[] = [
      created,
      { version: "150", tx: "TxNoop", ts: 1_500, doc: created.doc },
      { version: "160", tx: "TxAddKex2", ts: 1_600, doc: { verificationMethod: [sigMethod], keyAgreement: [kexMethod(), kexMethod(KEX2_X, "kex-2")] } },
      { version: "200", tx: "TxRevoke", ts: 2_000, doc: { verificationMethod: [sigMethod], keyAgreement: [kexMethod(KEX2_X, "kex-2")] } },
    ];
    const { rpc, calls } = fakeRpc(versions, { pageSize: 1 });
    const r = await resolveDid(rpc, CFG, DID);
    expect(calls.query).toBe(4);
    expect(r.revokedMethods.map((m) => [m.kid, m.revokedAtMs, m.tx])).toEqual([[`${DID}#kex-1`, 2_000, "TxRevoke"]]);
  });

  it("treats a method that comes back as current again", async () => {
    const readded: Version = { version: "300", tx: "TxReadd", ts: 3_000, doc: created.doc };
    const { rpc } = fakeRpc([created, kexRemoved, readded]);
    const r = await resolveDid(rpc, CFG, DID);
    expect(r.revokedMethods).toEqual([]);
    expect(resolvedKeys(r).every((k) => k.revokedAtMs === null)).toBe(true);
  });

  it("revokes every method when the document is deleted", async () => {
    const gone: Version = { version: "300", tx: "TxDelete", ts: 3_000, doc: null };
    const { rpc } = fakeRpc([created, gone]);
    const r = await resolveDid(rpc, CFG, DID);
    expect(r.meta.deactivated).toBe(true);
    expect(r.revokedMethods.map((m) => m.kid).sort()).toEqual([`${DID}#kex-1`, `${DID}#sig-1`]);
    expect(r.revokedMethods.every((m) => m.revokedAtMs === 3_000)).toBe(true);
  });

  it("dates a change hidden by index lag just after the last transaction seen", async () => {
    const { rpc } = fakeRpc([created, kexRemoved], { indexed: 1 });
    const r = await resolveDid(rpc, CFG, DID);
    expect(r.historyComplete).toBe(false);
    expect(r.revokedMethods).toEqual([expect.objectContaining({ kid: `${DID}#kex-1`, revokedAtMs: 1_001, tx: "TxRevoke", exact: false })]);
  });

  it("dates a removal across an unreadable version at the earliest transaction of the gap", async () => {
    // v100 readable with kex-1, v200 pruned (kex-1 removed here), v300 readable without kex-1.
    const noop: Version = { version: "300", tx: "TxLater", ts: 3_000, doc: kexRemoved.doc };
    const { rpc } = fakeRpc([created, kexRemoved, noop], { pruned: ["200"] });
    const r = await resolveDid(rpc, CFG, DID);
    expect(r.historyComplete).toBe(false);
    expect(r.revokedMethods).toEqual([expect.objectContaining({ kid: `${DID}#kex-1`, revokedAtMs: 2_000, tx: "TxRevoke", exact: false })]);
    expect(resolvedKeys(r).find((k) => k.kid.endsWith("#kex-1"))?.revokedAtMs).toBe(2_000);
  });

  it("dates a removal behind the page cap at the first unread transaction", async () => {
    const noop: Version = { version: "300", tx: "TxLater", ts: 3_000, doc: kexRemoved.doc };
    const { rpc } = fakeRpc([created, kexRemoved, noop], { pageSize: 1 });
    const r = await resolveDid(rpc, CFG, DID, { maxPages: 1, pageSize: 1 });
    expect(r.historyComplete).toBe(false);
    expect(r.revokedMethods).toEqual([expect.objectContaining({ kid: `${DID}#kex-1`, revokedAtMs: 2_000, tx: "TxRevoke", exact: false })]);
  });

  it("revokes the old key when a method is replaced under the same id", async () => {
    const SIG2_X = Buffer.alloc(32, 4).toString("base64url");
    const rotated: Version = {
      version: "200",
      tx: "TxRotate",
      ts: 2_000,
      doc: { verificationMethod: [{ ...sigMethod, publicKeyJwk: { ...sigMethod.publicKeyJwk, x: SIG2_X } }], keyAgreement: [kexMethod()] },
    };
    const { rpc } = fakeRpc([created, rotated]);
    const keys = resolvedKeys(await resolveDid(rpc, CFG, DID));
    expect(keys).toEqual([
      { kid: `${DID}#sig-1`, type: "Ed25519", publicKeyHex: "04".repeat(32), revokedAtMs: null },
      { kid: `${DID}#kex-1`, type: "X25519", publicKeyHex: "02".repeat(32), revokedAtMs: null },
      { kid: `${DID}#sig-1`, type: "Ed25519", publicKeyHex: "01".repeat(32), revokedAtMs: 2_000 },
    ]);
  });

  it("revokes every key when the document is deactivated", async () => {
    const deactivated: Version = { version: "200", tx: "TxDeactivate", ts: 2_000, doc: created.doc, meta: { deactivated: true } };
    const { rpc } = fakeRpc([created, deactivated]);
    const r = await resolveDid(rpc, CFG, DID);
    expect(r.meta.deactivated).toBe(true);
    const keys = resolvedKeys(r);
    expect(keys).toHaveLength(2);
    expect(keys.every((k) => k.revokedAtMs === 2_000)).toBe(true);
  });

  it("ignores history newer than the document it read", async () => {
    const sigOnly: Version = { version: "100", tx: "TxCreate", ts: 1_000, doc: { verificationMethod: [sigMethod] }, created: true };
    const kexAdded: Version = { version: "200", tx: "TxAddKex", ts: 2_000, doc: created.doc };
    const { rpc } = fakeRpc([sigOnly, kexAdded], { current: 0 });
    const r = await resolveDid(rpc, CFG, DID);
    expect(r.version).toBe("100");
    expect(r.revokedMethods).toEqual([]);
  });

  it("flags an incomplete history when a past version is pruned", async () => {
    const { rpc } = fakeRpc([created, kexRemoved], { pruned: ["100"] });
    const r = await resolveDid(rpc, CFG, DID);
    expect(r.historyComplete).toBe(false);
    expect(r.revokedMethods).toEqual([]);
  });

  it("rejects DIDs of another network before touching the node", async () => {
    const { rpc, calls } = fakeRpc([created]);
    await expect(resolveDid(rpc, CFG, `did:iota:${OBJ}`)).rejects.toBeInstanceOf(InvalidDidError);
    await expect(resolveDid(rpc, CFG, "did:key:z6Mk")).rejects.toBeInstanceOf(InvalidDidError);
    expect(calls.getObject).toBe(0);
  });

  it("reports unknown objects and foreign object types as not found", async () => {
    await expect(resolveDid(fakeRpc([created], { missing: true }).rpc, CFG, DID)).rejects.toBeInstanceOf(DidNotFoundError);
    await expect(resolveDid(fakeRpc([created], { type: "0x2::coin::Coin<0x2::iota::IOTA>" }).rpc, CFG, DID)).rejects.toBeInstanceOf(
      DidNotFoundError,
    );
  });
});

describe("revocationOf", () => {
  const EXPLORER = { explorerUrl: "https://explorer.iota.org", network: "testnet" as const };
  const sigRemoved: Version = { version: "200", tx: "TxRevokeSig", ts: 2_000, doc: { keyAgreement: [kexMethod()] } };

  it("records the removal of a signing method with its transaction and time", async () => {
    const r = await resolveDid(fakeRpc([created, sigRemoved]).rpc, CFG, DID);
    expect(revocationOf(EXPLORER, r, `${DID}#sig-1`)).toEqual({
      kid: `${DID}#sig-1`,
      revokedAtMs: 2_000,
      revokedAt: new Date(2_000).toISOString(),
      tx: "TxRevokeSig",
      exact: true,
      link: "https://explorer.iota.org/txblock/TxRevokeSig?network=testnet",
    });
    // The resolver serves the same key with its revocation time.
    expect(resolvedKeys(r)).toContainEqual({ kid: `${DID}#sig-1`, type: "Ed25519", publicKeyHex: "01".repeat(32), revokedAtMs: 2_000 });
  });

  it("is null while the method is current or was never there", async () => {
    const r = await resolveDid(fakeRpc([created]).rpc, CFG, DID);
    expect(revocationOf(EXPLORER, r, `${DID}#sig-1`)).toBeNull();
    expect(revocationOf(EXPLORER, r, `${DID}#sig-9`)).toBeNull();
  });
});

describe("methodFragment", () => {
  it("accepts a full kid, #fragment or a bare fragment", () => {
    expect(methodFragment(DID, `${DID}#kex-1`)).toBe("kex-1");
    expect(methodFragment(DID, "#kex-1")).toBe("kex-1");
    expect(methodFragment(DID, "kex-1")).toBe("kex-1");
    expect(methodFragment(DID, `did:iota:testnet:${OBJ.toUpperCase().replace("0X", "0x")}#kex-1`)).toBe("kex-1");
  });

  it("refuses a kid of another DID and malformed fragments", () => {
    expect(() => methodFragment(DID, `did:iota:testnet:0x${"1".repeat(64)}#kex-1`)).toThrow(InvalidDidError);
    expect(() => methodFragment(DID, "#")).toThrow(/fragment/);
    expect(() => methodFragment(DID, "kex 1")).toThrow(/fragment/);
  });
});

describe("retireIdentities", () => {
  it("moves the registry and every component's keys aside without deleting them", () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "anchor-retire-"));
    try {
      const cfg = { secretsDir: dir, network: "testnet" as const };
      const entry = (name: string) => ({ name, did: `did:iota:testnet:0x${"1".repeat(64)}`, objectId: `0x${"1".repeat(64)}` });
      writeFileSync(path.join(dir, "identities.json"), JSON.stringify({ network: "testnet", identities: { domain: entry("domain"), relay: entry("relay") } }));
      for (const n of ["domain", "relay"]) {
        mkdirSync(path.join(dir, n));
        writeFileSync(path.join(dir, n, "sig-1.jwk.json"), "{}");
      }
      const retired = retireIdentities(cfg);
      expect(retired.map((e) => e.name)).toEqual(["domain", "relay"]);
      expect(existsSync(path.join(dir, "identities.json"))).toBe(false);
      expect(existsSync(path.join(dir, "relay"))).toBe(false);
      const [stale] = readdirSync(path.join(dir, ".stale"));
      expect(readdirSync(path.join(dir, ".stale", stale!)).sort()).toEqual(["domain", "identities.json", "relay"]);
      expect(loadIdentityRegistry(cfg).identities).toEqual({});
      expect(retireIdentities(cfg)).toEqual([]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
