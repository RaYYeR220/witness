import { ed25519 } from "@noble/curves/ed25519";
import { describe, expect, it } from "vitest";

import { b64urlEncode, fromHex } from "../src/bytes.js";
import {
  FORGED,
  isEnvelope,
  jcs,
  JsonNumber,
  MALFORMED,
  parseJson,
  PRODUCER_SIGNED,
  RELAY_ATTESTED,
  sealEnvelope,
  verifyEnvelope,
} from "../src/index.js";
import type { KeyInfo, SealOptions } from "../src/index.js";
import { clone, envelopes, raw } from "./vectors.js";

const DID = "did:iota:testnet:0xabc";
const KID = `${DID}#sig-1`;
const NOW = 1_700_000_000_000;
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const VECTOR_KEY = new Uint8Array(32).fill(1);
const BODY = () => ({ score: 0.745, id: "D:x" });

function resolverFor(publicKey: Uint8Array, kid = KID) {
  const info: KeyInfo = { kid, ed25519Public: publicKey, x25519Public: null, revokedAtMs: null };
  return (k: string) => (k === kid ? info : null);
}

function withoutSig(env: Record<string, unknown>) {
  return Object.fromEntries(Object.entries(env).filter(([k]) => k !== "sig"));
}

describe("envelopes.json parity", () => {
  it.each(envelopes.cases.map((c: any) => [c.name, c] as const))("%s", (_name, c: any) => {
    const env = c.envelope;
    if (c.signing_input !== null) expect(jcs(withoutSig(env))).toBe(c.signing_input);
    const got = verifyEnvelope(env, c.block_tag, resolverFor(fromHex(c.public_key_hex), env.kid));
    expect(got.verdict).toBe(c.expected_verdict);
    if (got.verdict === MALFORMED) {
      expect([got.iss, got.kid, got.seq, got.iat, got.prev, got.corr]).toEqual([null, null, null, null, null, null]);
    } else {
      expect([got.iss, got.kid, got.seq, got.iat]).toEqual([env.iss, env.kid, env.seq, env.iat]);
      expect([got.prev, got.corr]).toEqual([env.prev ?? null, env.corr ?? null]);
    }
    if (got.verdict === PRODUCER_SIGNED || got.verdict === RELAY_ATTESTED) expect(got.reason).toBeNull();
    else expect(typeof got.reason).toBe("string");
  });

  it("covers every verdict the vectors name", () => {
    const names = envelopes.cases.map((c: any) => c.name);
    expect(new Set(names).size).toBe(names.length);
    expect(new Set(envelopes.cases.map((c: any) => c.expected_verdict))).toEqual(
      new Set([PRODUCER_SIGNED, RELAY_ATTESTED, FORGED, MALFORMED]),
    );
  });

  it("float_seq keeps its float type through parseJson (JSON.parse would lose it)", () => {
    const c = envelopes.cases.find((x: any) => x.name === "float_seq");
    expect(raw.envelopesText).toContain('"seq": 7.0');
    expect(c.envelope.seq).toBeInstanceOf(JsonNumber);
    const lossy = JSON.parse(raw.envelopesText).cases.find((x: any) => x.name === "float_seq");
    expect(lossy.envelope.seq).toBe(7);
  });
});

describe("sealEnvelope", () => {
  const opts = (over: Partial<SealOptions> = {}): SealOptions => ({
    iss: DID,
    kid: KID,
    signKey: VECTOR_KEY,
    seq: 7,
    attMode: "producer",
    nowMs: NOW,
    nonce: Uint8Array.from({ length: 16 }, (_, i) => i),
    ...over,
  });

  it("reproduces the Python-sealed vectors byte for byte", () => {
    const byName = (n: string) => envelopes.cases.find((c: any) => c.name === n).envelope;
    expect(sealEnvelope("trust.score", BODY(), opts())).toEqual(byName("valid_producer"));
    expect(sealEnvelope("trust.score", BODY(), opts({ seq: 8, attMode: "relay", attSub: "svc" }))).toEqual(
      byName("valid_relay"),
    );
    expect(
      sealEnvelope("trust.score", BODY(), opts({ seq: 9, prev: `0x${"11".repeat(32)}`, corr: "req-1" })),
    ).toEqual(byName("valid_prev_corr"));
  });

  it("accepts an OKP Ed25519 private JWK as the signing key", () => {
    const jwk = { kty: "OKP", crv: "Ed25519", d: b64urlEncode(VECTOR_KEY), x: "ignored" };
    expect(sealEnvelope("trust.score", BODY(), opts({ signKey: jwk }))).toEqual(
      sealEnvelope("trust.score", BODY(), opts()),
    );
  });

  it("omits unset optional fields and draws a fresh nonce", () => {
    const a = sealEnvelope("trust.score", BODY(), opts({ nonce: undefined }));
    const b = sealEnvelope("trust.score", BODY(), opts({ nonce: undefined }));
    expect("prev" in a || "corr" in a || "enc" in a).toBe(false);
    expect(a.nonce).not.toBe(b.nonce);
  });

  it("enc-only envelopes", () => {
    const env = sealEnvelope("trust.score", null, opts({ seq: 1, enc: { alg: "x" } }));
    expect("body" in env).toBe(false);
    expect(verifyEnvelope(env, "trust.score", resolverFor(ed25519.getPublicKey(VECTOR_KEY))).verdict).toBe(
      PRODUCER_SIGNED,
    );
    expect(() => sealEnvelope("trust.score", BODY(), opts({ enc: { alg: "x" } }))).toThrow();
  });

  it("refuses out-of-domain integers and nonces", () => {
    for (const seq of [-1, 2 ** 53, 1.5]) expect(() => sealEnvelope("t", BODY(), opts({ seq }))).toThrow();
    expect(() => sealEnvelope("t", BODY(), opts({ nowMs: -1 }))).toThrow();
    expect(() => sealEnvelope("t", BODY(), opts({ nonce: new Uint8Array(15) }))).toThrow();
    for (const bad of [NaN, Infinity, 2 ** 53, -(2 ** 53)]) {
      expect(() => sealEnvelope("t", { x: bad }, opts())).toThrow();
    }
  });
});

describe("verifyEnvelope (ported reference tests)", () => {
  const key = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(key);
  const seal = (over: Partial<SealOptions> = {}) =>
    sealEnvelope("trust.score", BODY(), { iss: DID, kid: KID, signKey: key, seq: 7, attMode: "producer", nowMs: NOW, ...over });
  const verdict = (env: unknown, tag = "trust.score", resolve = resolverFor(pub)) =>
    verifyEnvelope(env, tag, resolve).verdict;
  const noncanonical = (s: string) => s.slice(0, -1) + ALPHABET[ALPHABET.indexOf(s.at(-1)!) ^ 1];

  it("producer, relay and forged basics", () => {
    const env = seal();
    expect(isEnvelope(env)).toBe(true);
    const res = verifyEnvelope(env, "trust.score", resolverFor(pub));
    expect([res.verdict, res.iss, res.kid, res.seq, res.iat]).toEqual([PRODUCER_SIGNED, DID, KID, 7, NOW]);
    expect(verdict(seal({ attMode: "relay", attSub: "svc" }))).toBe(RELAY_ATTESTED);
    const tampered = clone(env);
    (tampered.body as any).score = 0.1;
    expect(verdict(tampered)).toBe(FORGED);
    const cross = verifyEnvelope(env, "LLO-K8s", resolverFor(pub));
    expect([cross.verdict, cross.reason]).toEqual([FORGED, "envelope tag does not match block tag"]);
    expect(verifyEnvelope(env, "trust.score", () => null).reason).toBe("signing key not resolvable");
    const other = "did:iota:testnet:0xdef#sig-1";
    expect(verifyEnvelope(seal({ kid: other }), "trust.score", resolverFor(pub, other)).reason).toBe(
      "kid does not belong to iss",
    );
    const wrongKey = verifyEnvelope(env, "trust.score", resolverFor(ed25519.getPublicKey(ed25519.utils.randomPrivateKey())));
    expect([wrongKey.verdict, wrongKey.reason]).toEqual([FORGED, "signature invalid"]);
    const noEd = verifyEnvelope(env, "trust.score", () => ({ kid: KID, ed25519Public: null, x25519Public: null, revokedAtMs: null }));
    expect(noEd.verdict).toBe(FORGED);
  });

  it("header fields are covered by the signature", () => {
    const env = seal({ nonce: Uint8Array.from({ length: 16 }, (_, i) => i) });
    expect(verdict({ ...env, tag: "LLO-K8s" }, "LLO-K8s")).toBe(FORGED);
    expect(verdict({ ...env, att: { mode: "relay", sub: "s" } })).toBe(FORGED);
    expect(verdict({ ...env, seq: 8 })).toBe(FORGED);
    expect(verdict({ ...env, iat: NOW + 1 })).toBe(FORGED);
    expect(verdict({ ...env, nonce: b64urlEncode(Uint8Array.from({ length: 16 }, (_, i) => i + 1)) })).toBe(FORGED);
  });

  it("sig and nonce encodings are strict", () => {
    const env = seal();
    const sig = env.sig as string;
    const nonce = env.nonce as string;
    expect([sig.length, nonce.length]).toEqual([86, 22]);
    const badSigs = [sig + "=", sig + "==", noncanonical(sig), sig.slice(0, -1) + "+", sig.slice(0, -2) + "/_",
      sig.slice(0, -1) + "!", sig.slice(0, -1), sig + "A", ""];
    for (const bad of badSigs) expect(verdict({ ...env, sig: bad })).toBe(MALFORMED);
    for (const bad of [nonce + "==", nonce.slice(0, -1) + "+", nonce.slice(0, -1), noncanonical(nonce), ""]) {
      expect(verdict({ ...env, nonce: bad })).toBe(MALFORMED);
    }
  });

  it("optional field types", () => {
    const env = seal({ bix: ["a"], cmt: { k: "v" }, prev: `0x${"ab".repeat(32)}`, corr: "c" });
    expect(verdict(env)).toBe(PRODUCER_SIGNED);
    const bad: Record<string, unknown>[] = [
      { bix: "a" }, { bix: [1] }, { cmt: [] }, { cmt: { k: 1 } }, { prev: `0x${"AB".repeat(32)}` },
      { prev: "0x12" }, { prev: 5 }, { corr: 5 }, { att: [] }, { att: { mode: "other" } },
      { att: { mode: "relay" } }, { att: { mode: "relay", sub: "" } }, { att: { mode: "producer", sub: 3 } },
      { extra: 1 }, { enc: { x: 1 } }, { body: [1] },
    ];
    for (const patch of bad) expect(verdict({ ...env, ...patch }), JSON.stringify(patch)).toBe(MALFORMED);
    const encOnly = Object.fromEntries(Object.entries(env).filter(([k]) => k !== "body"));
    expect(verdict({ ...encOnly, enc: [] })).toBe(MALFORMED);
    expect(verdict(encOnly)).toBe(MALFORMED);
  });

  it("integer rule: seq/iat/w must be JSON ints in [0, 2^53-1]", () => {
    const env = seal();
    for (const name of ["seq", "iat", "w"]) {
      for (const bad of [new JsonNumber("float", 7, "7.0"), true, -1, 2 ** 53, "7"]) {
        expect(verdict({ ...env, [name]: bad })).toBe(MALFORMED);
      }
    }
    expect(verdict(seal({ seq: 2 ** 53 - 1 }))).toBe(PRODUCER_SIGNED);
    expect(isEnvelope({ ...env, w: new JsonNumber("float", 1, "1.0") })).toBe(false);
  });

  it("non-canonicalizable bodies are MALFORMED", () => {
    const env = seal();
    for (const bad of [2 ** 53, NaN, Infinity, new JsonNumber("int", 2 ** 60, "1152921504606846976"), "\ud800"]) {
      const t = clone(env);
      (t.body as any).score = bad;
      const res = verifyEnvelope(t, "trust.score", resolverFor(pub));
      expect(res.verdict).toBe(MALFORMED);
      expect(res.reason).toMatch(/^not canonicalizable: /);
    }
  });

  it("verifies an envelope read from raw block bytes with Python number semantics", () => {
    const env = seal();
    const text = JSON.stringify(env);
    expect(verdict(parseJson(text))).toBe(PRODUCER_SIGNED);
    expect(verdict(parseJson(text.replace('"seq":7', '"seq":7.0')))).toBe(MALFORMED);
  });
});
