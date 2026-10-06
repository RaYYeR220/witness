import { describe, expect, it } from "vitest";
import { NETWORKS } from "../src/config.js";
import { DidNotFoundError, InvalidDidError, resolveDid, resolvedKeys, type DidRpc } from "../src/did.js";

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
function pack(doc: Record<string, unknown> | null): number[] | null {
  if (doc === null) return null;
  const json = Buffer.from(JSON.stringify({ doc: { id: "did:0:0", ...doc }, meta: { created: "2026-10-06T10:27:58Z" } }));
  const len = Buffer.alloc(2);
  len.writeUInt16LE(json.length);
  return [...Buffer.concat([Buffer.from("DID"), Buffer.from([1, 0]), len, json])];
}

interface Version {
  version: string;
  tx: string;
  ts: number | null;
  doc: Record<string, unknown> | null;
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
      fields: { created: "1000", updated: String(updatedMs), deleted: false, did_doc: { fields: { controlled_value: pack(v.doc) } } },
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
    async queryTransactionBlocks(input: { cursor?: string | null; filter?: unknown; order?: string }) {
      calls.query++;
      expect(input.filter).toEqual({ ChangedObject: OBJ });
      expect(input.order).toBe("ascending");
      const start = input.cursor ? Number(input.cursor) : 0;
      const slice = indexed.slice(start, start + pageSize);
      const next = start + pageSize;
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

  it("uses the live object when the transaction index lags behind", async () => {
    const { rpc } = fakeRpc([created, kexRemoved], { indexed: 1 });
    const r = await resolveDid(rpc, CFG, DID);
    expect(r.revokedMethods).toEqual([expect.objectContaining({ kid: `${DID}#kex-1`, revokedAtMs: 5_000, tx: "TxRevoke" })]);
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
