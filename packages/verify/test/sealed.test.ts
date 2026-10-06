import { ed25519 } from "@noble/curves/ed25519";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import { describe, expect, it } from "vitest";

import { b64urlDecode, b64urlEncode, fromHex, utf8Encode } from "../src/bytes.js";
import {
  blindToken,
  commit,
  decryptBody,
  DecryptError,
  FORGED,
  NotARecipient,
  PRODUCER_SIGNED,
  SALT_LEN,
  sealEnvelope,
  verifyCommitment,
  verifyEnvelope,
} from "../src/index.js";
import { clone, sealed } from "./vectors.js";

const [A, B] = sealed.recipients as { kid: string; private_jwk: any }[];
const C = sealed.negative.find((n: any) => n.name === "non_recipient").private_jwk;
const flip = (s: string) => {
  const bytes = b64urlDecode(s)!;
  bytes[0]! ^= 1;
  return b64urlEncode(bytes);
};
const jwe = () => clone(sealed.jwe);

async function rejects(p: Promise<unknown>, cls: typeof DecryptError | typeof NotARecipient) {
  await expect(p).rejects.toBeInstanceOf(cls);
}

describe("sealed.json parity", () => {
  it("every recipient decrypts the body", async () => {
    for (const r of sealed.recipients) expect(await decryptBody(sealed.jwe, r.kid, r.private_jwk)).toEqual(sealed.body);
  });

  it.each(sealed.negative.map((n: any) => [n.name, n] as const))("negative: %s", async (_name, n: any) => {
    const cls = { NotARecipient, DecryptError }[n.error as "NotARecipient" | "DecryptError"];
    expect(cls).toBeDefined();
    await rejects(decryptBody(n.jwe, n.kid, n.private_jwk), cls);
  });

  it.each(sealed.blind_tokens.map((t: any) => [t.kind, t.value, t] as const))("blind token %s:%s", (_k, _v, t: any) => {
    expect(blindToken(fromHex(t.key_hex), t.kind, t.value)).toBe(t.token);
  });

  it.each(sealed.commitments.map((c: any) => [JSON.stringify(c.value), c] as const))("commitment %s", (_v, c: any) => {
    const salt = fromHex(c.salt_hex);
    expect(commit(c.value, salt)).toBe(c.commitment);
    expect(verifyCommitment(c.commitment, c.value, salt)).toBe(true);
  });

  it("salt length is pinned to the vectors' value", () => {
    expect(SALT_LEN).toBe(sealed.commitment_salt_len);
    const c = sealed.commitments[0];
    const salt = fromHex(c.salt_hex);
    for (const n of [0, 15, 17]) {
      expect(() => commit(c.value, new Uint8Array(n))).toThrow();
      expect(verifyCommitment(c.commitment, c.value, new Uint8Array(n))).toBe(false);
    }
    expect(verifyCommitment(c.commitment, 0.43, salt)).toBe(false);
    expect(verifyCommitment(c.commitment, c.value, new Uint8Array(16).fill(2))).toBe(false);
    expect(verifyCommitment(null, c.value, salt)).toBe(false);
  });
});

describe("decryptBody pins and failure modes (ported reference tests)", () => {
  it("wrong key for a listed kid", async () => {
    await rejects(decryptBody(sealed.jwe, "a#k", C), DecryptError);
  });

  it.each(["iv", "tag", "protected", "ciphertext"])("tampered %s", async (field) => {
    const j = jwe();
    j[field] = flip(j[field]);
    await rejects(decryptBody(j, "a#k", A!.private_jwk), DecryptError);
  });

  it("tampered encrypted_key only hurts its own recipient", async () => {
    const j = jwe();
    j.recipients[0].encrypted_key = flip(j.recipients[0].encrypted_key);
    await rejects(decryptBody(j, "a#k", A!.private_jwk), DecryptError);
    expect(await decryptBody(j, "b#k", B!.private_jwk)).toEqual(sealed.body);
  });

  it("recipient entry without header or kid is not ours; without alg it is refused", async () => {
    let j = jwe();
    delete j.recipients[0].header;
    await rejects(decryptBody(j, "a#k", A!.private_jwk), NotARecipient);
    j = jwe();
    delete j.recipients[0].header.kid;
    await rejects(decryptBody(j, "a#k", A!.private_jwk), NotARecipient);
    j = jwe();
    delete j.recipients[0].header.alg;
    await rejects(decryptBody(j, "a#k", A!.private_jwk), DecryptError);
  });

  it.each([null, [], "x", 5, {}, { recipients: "x" }])("not a general JWE: %j", async (bad) => {
    await rejects(decryptBody(bad, "a#k", A!.private_jwk), DecryptError);
  });

  it.each([{ enc: "A128GCM" }, { enc: "A256GCM", zip: "DEF" }, {}, { enc: "A256GCM", x: 1 }])(
    "protected header pinned: %j",
    async (header) => {
      const j = jwe();
      j.protected = b64urlEncode(utf8Encode(JSON.stringify(header)));
      await rejects(decryptBody(j, "a#k", A!.private_jwk), DecryptError);
    },
  );

  it.each(["ECDH-ES", "ECDH-ES+A128KW", "dir", "none"])("recipient alg pinned: %s", async (alg) => {
    const j = jwe();
    j.recipients[0].header.alg = alg;
    await rejects(decryptBody(j, "a#k", A!.private_jwk), DecryptError);
  });

  it("shared headers and extra recipient header fields are refused", async () => {
    let j = jwe();
    j.unprotected = { zip: "DEF" };
    await rejects(decryptBody(j, "a#k", A!.private_jwk), DecryptError);
    j = jwe();
    j.header = { x: 1 };
    await rejects(decryptBody(j, "a#k", A!.private_jwk), DecryptError);
    j = jwe();
    j.recipients[0].header.cty = "json";
    await rejects(decryptBody(j, "a#k", A!.private_jwk), DecryptError);
  });

  it("an empty shared header is tolerated exactly where the reference tolerates it", async () => {
    for (const empty of [{}, [], ""]) {
      const j = jwe();
      j.unprotected = empty;
      expect(await decryptBody(j, "a#k", A!.private_jwk)).toEqual(sealed.body);
    }
    for (const bad of [null, 0, false]) {
      const j = jwe();
      j.unprotected = bad;
      await rejects(decryptBody(j, "a#k", A!.private_jwk), DecryptError);
    }
    const j = jwe();
    j.header = null;
    expect(await decryptBody(j, "a#k", A!.private_jwk)).toEqual(sealed.body);
  });

  it("the public x in the JWK is not trusted (derived from d, like the reference)", async () => {
    const jwk = { ...A!.private_jwk, x: C.x };
    expect(await decryptBody(sealed.jwe, "a#k", jwk)).toEqual(sealed.body);
    await expect(decryptBody(sealed.jwe, "a#k", { kty: "OKP", crv: "Ed25519", d: A!.private_jwk.d })).rejects.toThrow(
      TypeError,
    );
  });

  it("a sealed envelope's signature covers the ciphertext", () => {
    const sk = new Uint8Array(32).fill(7);
    const kid = "did:iota:testnet:0xabc#sig-1";
    const info = { kid, ed25519Public: ed25519.getPublicKey(sk), x25519Public: null, revokedAtMs: null };
    const env = sealEnvelope("trust.score", null, {
      iss: "did:iota:testnet:0xabc", kid, signKey: sk, seq: 1, attMode: "producer",
      nowMs: 1_700_000_000_000, enc: jwe(), bix: ["x"],
    });
    expect("body" in env).toBe(false);
    expect(verifyEnvelope(env, "trust.score", () => info).verdict).toBe(PRODUCER_SIGNED);
    const bad = clone(env) as any;
    bad.enc.ciphertext = flip(bad.enc.ciphertext);
    expect(verifyEnvelope(bad, "trust.score", () => info).verdict).toBe(FORGED);
  });
});

describe("blindToken", () => {
  it("is HMAC-SHA256 over kind:value, keyed and kind-separated", () => {
    const k1 = new Uint8Array(32).fill(1);
    const k2 = new Uint8Array(32).fill(2);
    const t = blindToken(k1, "ie", "D:x");
    expect(t).toBe(b64urlEncode(hmac(sha256, k1, utf8Encode("ie:D:x"))));
    expect(t).not.toBe(blindToken(k2, "ie", "D:x"));
    expect(t).not.toBe(blindToken(k1, "tag", "D:x"));
  });

  it("rejects an unknown kind and an empty key", () => {
    expect(() => blindToken(new Uint8Array(32), "other" as "ie", "v")).toThrow();
    expect(() => blindToken(new Uint8Array(0), "ie", "v")).toThrow();
  });
});
