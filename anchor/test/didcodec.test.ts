import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { buildComponentDocument } from "../src/did.js";
import {
  DidDecodeError,
  InvalidDidError,
  collectMethods,
  decodeStateMetadata,
  methodPublicKey,
  parseDid,
  withRealDid,
  type DidDocumentJson,
  type PublicJwk,
} from "../src/didcodec.js";

const OBJ = "0x" + "ab".repeat(32);

function publicJwk(curve: "ed25519" | "x25519"): PublicJwk {
  const jwk = generateKeyPairSync(curve as "ed25519").publicKey.export({ format: "jwk" });
  return { kty: "OKP", crv: String(jwk.crv), x: String(jwk.x) };
}

describe("parseDid", () => {
  it("parses testnet and mainnet DIDs", () => {
    expect(parseDid(`did:iota:testnet:${OBJ}`)).toEqual({ did: `did:iota:testnet:${OBJ}`, network: "testnet", objectId: OBJ });
    expect(parseDid(`did:iota:${OBJ}`)).toEqual({ did: `did:iota:${OBJ}`, network: null, objectId: OBJ });
    expect(parseDid(`did:iota:2304aa97:${OBJ.toUpperCase().replace("0X", "0x")}`).objectId).toBe(OBJ);
  });

  it("rejects anything else", () => {
    for (const bad of ["", "did:key:z6Mk", `did:iota:testnet:${OBJ}#sig-1`, `did:iota:toolongnet:${OBJ}`, "did:iota:testnet:0x12"]) {
      expect(() => parseDid(bad)).toThrow(InvalidDidError);
    }
  });
});

describe("decodeStateMetadata", () => {
  it("rejects malformed bytes", () => {
    expect(decodeStateMetadata(null)).toBeNull();
    expect(decodeStateMetadata([])).toBeNull();
    expect(() => decodeStateMetadata([1, 2, 3, 4, 5, 6, 7])).toThrow(DidDecodeError);
    const header = [...Buffer.from("DID"), 1, 0, 200, 0];
    expect(() => decodeStateMetadata([...header, ...Buffer.from("{}")])).toThrow(/length/);
    expect(() => decodeStateMetadata([...Buffer.from("DID"), 1, 1, 2, 0, ...Buffer.from("{}")])).toThrow(/encoding/);
  });

  it("decodes what the identity library packs", async () => {
    const sig = publicJwk("ed25519");
    const kex = publicJwk("x25519");
    const doc = await buildComponentDocument("testnet", { ...sig, alg: "EdDSA" }, kex);
    const decoded = decodeStateMetadata(doc.pack());
    expect(decoded).not.toBeNull();
    const did = `did:iota:testnet:${OBJ}`;
    const real = withRealDid(decoded!.doc, did) as DidDocumentJson;

    expect(real.id).toBe(did);
    expect(real.verificationMethod).toEqual([
      expect.objectContaining({ id: `${did}#sig-1`, controller: did, publicKeyJwk: expect.objectContaining({ crv: "Ed25519", x: sig.x }) }),
    ]);
    expect(real.authentication).toEqual([`${did}#sig-1`]);
    expect(real.assertionMethod).toEqual([`${did}#sig-1`]);
    expect(real.keyAgreement).toEqual([
      expect.objectContaining({ id: `${did}#kex-1`, publicKeyJwk: expect.objectContaining({ crv: "X25519", x: kex.x }) }),
    ]);

    const methods = collectMethods(real);
    expect([...methods.keys()]).toEqual([`${did}#sig-1`, `${did}#kex-1`]);
    expect(methodPublicKey(methods.get(`${did}#sig-1`)!)).toEqual({ type: "Ed25519", publicKeyHex: Buffer.from(sig.x!, "base64url").toString("hex") });
    expect(methodPublicKey(methods.get(`${did}#kex-1`)!)?.type).toBe("X25519");
  }, 120_000); // first use compiles the identity WASM module
});

describe("buildComponentDocument", () => {
  it("names the controlling DID in the document", async () => {
    const domain = `did:iota:testnet:0x${"d0".repeat(32)}`;
    const doc = await buildComponentDocument("testnet", { ...publicJwk("ed25519"), alg: "EdDSA" }, publicJwk("x25519"), domain);
    const real = withRealDid(decodeStateMetadata(doc.pack())!.doc, `did:iota:testnet:${OBJ}`) as DidDocumentJson;
    expect(real.controller).toBe(domain);
    expect(real.verificationMethod![0]!.controller).toBe(`did:iota:testnet:${OBJ}`);
  }, 120_000);
});

describe("withRealDid", () => {
  it("swaps only the placeholder DID and DID URLs built on it", () => {
    const out = withRealDid({ id: "did:0:0", a: ["did:0:0#k", "did:0:0x", "x did:0:0"], b: { c: "did:0:0?q=1" } }, "did:iota:testnet:0x1");
    expect(out).toEqual({ id: "did:iota:testnet:0x1", a: ["did:iota:testnet:0x1#k", "did:0:0x", "x did:0:0"], b: { c: "did:iota:testnet:0x1?q=1" } });
  });
});

describe("methodPublicKey", () => {
  it("ignores key types the resolver does not serve", () => {
    expect(methodPublicKey({ id: "k", publicKeyJwk: { kty: "EC", crv: "P-256", x: "AA" } })).toBeNull();
    expect(methodPublicKey({ id: "k", publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "short" } })).toBeNull();
    expect(methodPublicKey({ id: "k", publicKeyMultibase: "z6Mk" })).toBeNull();
  });
});
