import { describe, expect, it } from "vitest";

import { fromHex, toHex } from "../src/bytes.js";
import {
  blockId,
  checkpointHash,
  JsonNumber,
  parseBlock,
  STEP_NAMES,
  UNRESOLVED_SIGNER,
  verifyBundle,
} from "../src/index.js";
import type { Ladder, StepResult, VerifierConfig, VerifyOptions } from "../src/index.js";
import { bundles, clone } from "./vectors.js";

const caseByName = (name: string) => bundles.cases.find((c: any) => c.name === name);

/** Wire a vector case exactly as the Python reference's `_verify_case` does. */
function wire(c: any, extra: Partial<VerifyOptions> = {}): [unknown, VerifierConfig, VerifyOptions] {
  const opts: VerifyOptions = { ...extra };
  if (c.fetcher !== null) opts.fetchAnchorRecord = () => clone(c.fetcher.record);
  if (c.resolver !== null) {
    const docs = bundles.resolvers[c.resolver];
    opts.resolveDid = (did: string) => (Object.hasOwn(docs, did) ? clone(docs[did]) : null);
  }
  return [clone(c.bundle), c.config, opts];
}

const run = (c: any, extra: Partial<VerifyOptions> = {}) => verifyBundle(...wire(c, extra));
const marks = (l: Ladder) => l.steps.map((s) => (s.ok === null ? "N" : s.ok ? "T" : "F")).join("") + " " + l.overall;

describe("bundles.json parity", () => {
  it("has the 32 named cases", () => {
    const names = bundles.cases.map((c: any) => c.name);
    expect(names).toHaveLength(32);
    expect(new Set(names).size).toBe(32);
  });

  it.each(bundles.cases.map((c: any) => [c.name, c] as const))("%s", async (_name, c: any) => {
    const ladder = await run(c);
    expect({
      overall: ladder.overall,
      steps: ladder.steps.map((s) => ({ name: s.name, ok: s.ok })),
    }).toEqual(c.expected);
    for (const s of ladder.steps) expect(typeof s.detail).toBe("string");
  });
});

/** Detail strings as the Python reference prints them for the same cases. */
const PYTHON_DETAILS: Record<string, Partial<Record<(typeof STEP_NAMES)[number], string>>> = {
  valid_anchored: {
    block_hash: "BLAKE2b-256(raw) = 0x435be807caeb2b8d8b1d599b22fc3a1abe0960e4dae50ad77233419cb780b769",
    inclusion: "1-step path reaches inclusionMerkleRoot 0x05fbe57ce3ac0098da19814b7b75a0beaa0947bfaf9a3d4d58dcd90351e977e6",
    milestone_signatures:
      "milestone 374 0xa6bc3be7eaa3cca15b859dd8c812b370f47e964f3df400a7d2962a04ebcd5f55: 2 valid signature(s) by pinned keys, threshold 2",
    envelope: "PRODUCER_SIGNED by did:iota:testnet:0x5e1f#sig-1",
    anchor: "checkpoint 0x099ceadead051f82464679deba54465c6e0322376c1f911ca4f19101202ed5ca matches the on-chain record",
  },
  partial_real_no_anchor: {
    inclusion: "2-step path reaches inclusionMerkleRoot 0xd6405d7a22d8af800c7f909c798e242491a6d367f77027b56a9987c19e072b6e",
    envelope: "unsigned legacy message",
    anchor: "bundle carries no anchor",
  },
  anchor_unreachable: { anchor: "anchor record unavailable" },
  signer_unresolved: { envelope: "signer identity not resolved (bundle snapshot is unauthenticated)" },
  raw_byte_flipped: {
    block_hash:
      "BLAKE2b-256(raw) is 0xb7d298bfd249cf1646fdc6f3bc6f4e8fb746febf985a18ad0dc8ed6dea274143, " +
      "bundle claims 0x435be807caeb2b8d8b1d599b22fc3a1abe0960e4dae50ad77233419cb780b769",
  },
  path_hash_corrupted: {
    inclusion: "Merkle path does not reach inclusionMerkleRoot 0x05fbe57ce3ac0098da19814b7b75a0beaa0947bfaf9a3d4d58dcd90351e977e6",
  },
  signature_corrupted: {
    milestone_signatures:
      "milestone 374 0xa6bc3be7eaa3cca15b859dd8c812b370f47e964f3df400a7d2962a04ebcd5f55: 1 valid signature(s) by pinned keys, threshold 2",
  },
  untrusted_key_set: {
    milestone_signatures:
      "milestone 374 0xa6bc3be7eaa3cca15b859dd8c812b370f47e964f3df400a7d2962a04ebcd5f55: 0 valid signature(s) by pinned keys, threshold 2",
  },
  envelope_forged: { envelope: "FORGED: signature invalid" },
  self_made_snapshot_resolved: { envelope: "FORGED: signature invalid" },
  snapshot_differs_from_registry: { envelope: "DID snapshot does not match resolved document" },
  key_revoked_before_inclusion: { envelope: "key revoked before inclusion" },
  resolved_doc_not_issuer: { envelope: "resolved DID document does not belong to the issuer" },
  anchor_mismatch: { anchor: "checkpoint does not match on-chain record" },
  milestone_not_in_window: { anchor: "milestone not in anchored checkpoint" },
  milestone_not_in_window_no_fetcher: { anchor: "milestone not in anchored checkpoint" },
  trail_unpinned: { anchor: "anchor not checked: verifier pins no Rebased trail" },
  rebased_network_unpinned: { anchor: "anchor not checked: verifier pins no Rebased trail" },
  envelope_malformed_no_resolver: { envelope: "MALFORMED: missing or invalid field: seq/iat" },
  envelope_retagged_no_resolver: { envelope: "FORGED: envelope tag does not match block tag" },
  bundle_network_not_pinned: {
    milestone_signatures: "bundle network 'private_tangle1' is not the pinned 'another_tangle'",
  },
  noncanonical_hex_raw: {
    block_hash: "block.raw: non-canonical hex (expected lowercase with 0x prefix)",
    envelope: "not evaluated: block does not parse",
  },
  noncanonical_hex_block_id: {
    block_hash: "block.id: non-canonical hex (expected lowercase with 0x prefix)",
    inclusion: "block.id: non-canonical hex (expected lowercase with 0x prefix)",
  },
  noncanonical_hex_inclusion_path: {
    inclusion: "inclusion.path[0].hash: non-canonical hex (expected lowercase with 0x prefix)",
  },
  noncanonical_hex_signature: {
    milestone_signatures: "milestone.signatures[1].sig: non-canonical hex (expected lowercase with 0x prefix)",
  },
  noncanonical_hex_ms_path: {
    anchor: "anchor.msPath[0].hash: non-canonical hex (expected lowercase with 0x prefix)",
  },
};

describe("ladder details match the Python reference", () => {
  it.each(Object.entries(PYTHON_DETAILS))("%s", async (name, expected) => {
    const ladder = await run(caseByName(name));
    const got = Object.fromEntries(ladder.steps.filter((s) => s.name in expected).map((s) => [s.name, s.detail]));
    expect(got).toEqual(expected);
  });
});

describe("onStep", () => {
  it("fires once per step, in ladder order, as each step completes", async () => {
    const events: string[] = [];
    const c = caseByName("valid_anchored");
    const [bundle, cfg, opts] = wire(c);
    const ladder = await verifyBundle(bundle, cfg, {
      resolveDid: async (did) => {
        events.push("resolveDid");
        return opts.resolveDid!(did);
      },
      fetchAnchorRecord: async (anchor) => {
        events.push("fetchAnchorRecord");
        return opts.fetchAnchorRecord!(anchor);
      },
      onStep: (step: StepResult) => {
        events.push(step.name);
      },
    });
    expect(events).toEqual([
      "block_hash",
      "inclusion",
      "milestone_signatures",
      "resolveDid",
      "envelope",
      "fetchAnchorRecord",
      "anchor",
    ]);
    expect(ladder.overall).toBe("VALID");
  });

  it("passes the same StepResult objects the ladder returns and awaits async callbacks", async () => {
    const seen: StepResult[] = [];
    let release!: () => void;
    let pending = 0;
    const promise = verifyBundle(...wire(caseByName("anchor_mismatch"), {
      onStep: (s) => {
        seen.push(s);
        pending++;
        return new Promise<void>((r) => {
          release = () => {
            pending--;
            r();
          };
        });
      },
    }));
    for (let i = 0; i < STEP_NAMES.length; i++) {
      await new Promise((r) => setTimeout(r, 0));
      expect(seen).toHaveLength(i + 1);
      expect(pending).toBe(1);
      release();
    }
    const ladder = await promise;
    expect(ladder.steps).toEqual(seen);
    expect(seen.map((s) => s.name)).toEqual([...STEP_NAMES]);
  });

  it("fires five failed steps for something that is not a bundle", async () => {
    const seen: string[] = [];
    const ladder = await verifyBundle([], caseByName("valid_anchored").config, { onStep: (s) => void seen.push(s.name) });
    expect(seen).toEqual([...STEP_NAMES]);
    expect(marks(ladder)).toBe("FFFFF INVALID");
    expect(ladder.steps.every((s) => s.detail === "not a witness-proof/v1 bundle")).toBe(true);
  });
});

describe("trusted lookups", () => {
  it("never authenticates a signer from the bundle snapshot alone", async () => {
    const ladder = await run({ ...caseByName("valid_anchored"), resolver: null });
    expect(ladder.steps[3]).toEqual({ name: "envelope", ok: null, detail: UNRESOLVED_SIGNER });
  });

  it("asks the resolver for the issuer and the fetcher for the bundle's anchor", async () => {
    const c = caseByName("valid_anchored");
    const [bundle, cfg, opts] = wire(c);
    const dids: string[] = [];
    const anchors: unknown[] = [];
    await verifyBundle(bundle, cfg, {
      resolveDid: (did) => (dids.push(did), opts.resolveDid!(did)),
      fetchAnchorRecord: (a) => (anchors.push(a), opts.fetchAnchorRecord!(a)),
    });
    expect(dids).toEqual(["did:iota:testnet:0x5e1f"]);
    expect(anchors).toEqual([c.bundle.anchor]);
  });

  it("an unreachable registry or chain is 'not evaluated', not a verdict", async () => {
    const boom = () => {
      throw new TypeError("offline");
    };
    const ladder = await run(caseByName("valid_anchored"), {});
    expect(marks(ladder)).toBe("TTTTT VALID");
    const [bundle, cfg] = wire(caseByName("valid_anchored"));
    const down = await verifyBundle(bundle, cfg, { resolveDid: boom, fetchAnchorRecord: async () => Promise.reject(new Error("x")) });
    expect(down.steps[3]).toEqual({ name: "envelope", ok: null, detail: UNRESOLVED_SIGNER });
    expect(down.steps[4]).toEqual({ name: "anchor", ok: null, detail: "anchor record unavailable (Error)" });
    const none = await verifyBundle(bundle, cfg, { resolveDid: () => null, fetchAnchorRecord: () => null });
    expect(marks(none)).toBe("TTTNN PARTIAL");
  });

  it.each([
    ["duplicate kid", (d: any) => d.keys.push(clone(d.keys[0])), false,
      "resolved DID document is malformed: DID snapshot lists did:iota:testnet:0x5e1f#sig-1 twice"],
    ["keys not a list", (d: any) => (d.keys = {}), false,
      "resolved DID document is malformed: DID snapshot must be an object with a keys list"],
    ["doc of another DID", (d: any) => (d.doc.id = "did:iota:testnet:0xother"), false,
      "resolved DID document does not belong to the issuer"],
    ["fragment kid", (d: any) => (d.keys[0].kid = "#sig-1"), true, "PRODUCER_SIGNED by did:iota:testnet:0x5e1f#sig-1"],
    ["uppercase key hex", (d: any) => (d.keys[0].publicKeyHex = `0x${d.keys[0].publicKeyHex.slice(2).toUpperCase()}`), true,
      "PRODUCER_SIGNED by did:iota:testnet:0x5e1f#sig-1"],
    ["float revokedAtMs", (d: any) => (d.keys[0].revokedAtMs = new JsonNumber("float", 1, "1.0")), false,
      "FORGED: signing key not resolvable"],
    ["revoked long ago", (d: any) => (d.keys[0].revokedAtMs = 5), false, "key revoked before inclusion"],
    ["junk entries skipped", (d: any) => d.keys.unshift(5, null, "x", { kid: 5 }), true,
      "PRODUCER_SIGNED by did:iota:testnet:0x5e1f#sig-1"],
  ])("registry document: %s (as the reference decides)", async (_name, mutate, ok, detail) => {
    const docs = clone(bundles.resolvers.registry);
    mutate(docs["did:iota:testnet:0x5e1f"]);
    const [bundle, cfg, opts] = wire(caseByName("valid_anchored"));
    const ladder = await verifyBundle(bundle, cfg, { ...opts, resolveDid: (did) => docs[did] ?? null });
    expect(ladder.steps[3]).toEqual({ name: "envelope", ok, detail });
  });

  it("malformed on-chain records fail the anchor step", async () => {
    const [bundle, cfg, opts] = wire(caseByName("valid_anchored"));
    for (const record of [5, [], {}, { checkpointHash: "0xAB" }, { checkpointHash: 7 }, { checkpoint: NaN }]) {
      const l = await verifyBundle(bundle, cfg, { ...opts, fetchAnchorRecord: () => record });
      expect(l.steps[4]).toEqual({ name: "anchor", ok: false, detail: "anchor record malformed" });
    }
    const cp = (bundle as any).anchor.checkpoint;
    const byCheckpoint = await verifyBundle(bundle, cfg, { ...opts, fetchAnchorRecord: () => ({ checkpoint: clone(cp) }) });
    expect(byCheckpoint.steps[4]!.ok).toBe(true);
  });
});

describe("envelope bytes read with Python's json.loads semantics", () => {
  // Re-encode valid_anchored's block around altered tagged data (block id recomputed),
  // then compare step 4 with what the Python reference printed for the same bytes.
  const c = caseByName("valid_anchored");
  const block = parseBlock(fromHex(c.bundle.block.raw));
  if (block.payload?.kind !== "tagged_data") throw new Error("vector block carries no tagged data");
  const { tag, data } = block.payload;
  const text = new TextDecoder().decode(data);
  const le = (n: number, size: number) => Uint8Array.from({ length: size }, (_, i) => Math.floor(n / 256 ** i) % 256);
  const cat = (...parts: Uint8Array[]) => {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    parts.reduce((o, p) => (out.set(p, o), o + p.length), 0);
    return out;
  };
  const withData = (bytes: Uint8Array, t: Uint8Array = tag) => {
    const payload = cat(le(5, 4), Uint8Array.of(t.length), t, le(bytes.length, 4), bytes);
    const raw = cat(Uint8Array.of(block.protocolVersion, block.parents.length), ...block.parents, le(payload.length, 4), payload, new Uint8Array(8));
    const b = clone(c.bundle);
    b.block = { id: toHex(blockId(raw)), raw: toHex(raw) };
    return b;
  };
  const utf8 = (s: string) => new TextEncoder().encode(s);
  const deep = (n: number) => `"body":{"a":${"[".repeat(n)}${"]".repeat(n)}}`;
  const body = /"body":\{[^}]*\}/;

  it.each([
    ["seq 1.0", text.replace('"seq":1', '"seq":1.0'), false, "MALFORMED: missing or invalid field: seq/iat"],
    ["seq 1e0", text.replace('"seq":1', '"seq":1e0'), false, "MALFORMED: missing or invalid field: seq/iat"],
    ["iat past 2^53", text.replace(/"iat":\d+/, '"iat":9007199254740993'), false, "MALFORMED: missing or invalid field: seq/iat"],
    ["score 1e400", text.replace('"score":0.82', '"score":1e400'), false, "MALFORMED: not canonicalizable: inf is not representable in JCS"],
    ["score NaN", text.replace('"score":0.82', '"score":NaN'), null, "unsigned legacy message"],
    ["score 2^64", text.replace('"score":0.82', '"score":18446744073709551616'), false,
      "MALFORMED: not canonicalizable: 18446744073709551616 exceeds safe integer domain for JSON floats"],
    ["lone surrogate", text.replace('"id":"', '"id":"\\ud800'), false, "MALFORMED: not canonicalizable: input contains non-UTF-8 codepoints"],
    ["duplicate key, last wins", text.replace('{"att"', '{"seq":5,"att"'), true, "PRODUCER_SIGNED by did:iota:testnet:0x5e1f#sig-1"],
    ["w 1.0", text.replace('"w":1', '"w":1.0'), null, "unsigned legacy message"],
    ["w true", text.replace('"w":1', '"w":true'), null, "unsigned legacy message"],
    ["whitespace around", ` \n${text}\t`, true, "PRODUCER_SIGNED by did:iota:testnet:0x5e1f#sig-1"],
    ["trailing data", `${text} x`, null, "unsigned legacy message"],
    ["nested 1500", text.replace(body, deep(1500)), false, "malformed bundle (RecursionError)"],
    ["nested 2995", text.replace(body, deep(2995)), false, "malformed bundle (RecursionError)"],
    ["nested 2996", text.replace(body, deep(2996)), null, "unsigned legacy message"],
  ] as const)("%s", async (_name, altered, ok, detail) => {
    const ladder = await run({ ...c, bundle: withData(utf8(altered)) });
    expect(ladder.steps[3]).toEqual({ name: "envelope", ok, detail });
  });

  it.each([
    ["UTF-8 BOM", cat(Uint8Array.of(0xef, 0xbb, 0xbf), utf8(text)), tag, null, "unsigned legacy message"],
    ["invalid UTF-8", cat(utf8(text.slice(0, 20)), Uint8Array.of(0xff), utf8(text.slice(20))), tag, null, "unsigned legacy message"],
    ["UTF-8-encoded surrogate", cat(utf8(text.slice(0, 50)), Uint8Array.of(0xed, 0xa0, 0x80), utf8(text.slice(50))), tag, null,
      "unsigned legacy message"],
    ["tag not UTF-8", data, Uint8Array.of(0x74, 0xff), false, "FORGED: block tag is not UTF-8"],
    ["tag with BOM", data, cat(Uint8Array.of(0xef, 0xbb, 0xbf), utf8("trust.score")), false, "FORGED: envelope tag does not match block tag"],
  ] as const)("%s", async (_name, bytes, t, ok, detail) => {
    const ladder = await run({ ...c, bundle: withData(bytes, t) });
    expect(ladder.steps[3]).toEqual({ name: "envelope", ok, detail });
  });
});

describe("checkpointHash", () => {
  it("matches the on-chain record of the anchored vector", () => {
    const c = caseByName("valid_anchored");
    expect(toHex(checkpointHash(c.bundle.anchor.checkpoint))).toBe(c.fetcher.record.checkpointHash);
  });
});

describe("hostile input never escapes as an exception", () => {
  // Small deterministic PRNG so failures reproduce.
  function rng(seed: number) {
    return () => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed / 0x7fffffff;
    };
  }
  const JUNK: unknown[] = [
    null, 0, -1, 1.5, 2 ** 60, true, "x", "", "0xZZ", "0X00", [], {}, [1, 2], { a: 1 },
    new JsonNumber("float", 1, "1.0"), new JsonNumber("int", 2 ** 64, "18446744073709551616"),
  ];

  function paths(v: unknown, prefix: (string | number)[] = [], out: (string | number)[][] = []) {
    out.push(prefix);
    if (Array.isArray(v)) v.forEach((x, i) => paths(x, [...prefix, i], out));
    else if (v !== null && typeof v === "object" && !(v instanceof JsonNumber)) {
      for (const [k, x] of Object.entries(v)) paths(x, [...prefix, k], out);
    }
    return out;
  }

  it("random structural mutations of a valid bundle", async () => {
    const next = rng(20261006);
    const c = caseByName("valid_anchored");
    const all = paths(c.bundle).filter((p) => p.length > 0);
    for (let i = 0; i < 400; i++) {
      const [bundle, cfg, opts] = wire(c);
      const path = all[Math.floor(next() * all.length)]!;
      let target: any = bundle;
      for (const k of path.slice(0, -1)) target = target[k];
      const last = path[path.length - 1]!;
      if (next() < 0.15 && !Array.isArray(target)) delete target[last];
      else target[last] = clone(JUNK[Math.floor(next() * JUNK.length)]);
      const ladder = await verifyBundle(bundle, cfg, opts);
      expect(ladder.steps.map((s) => s.name)).toEqual([...STEP_NAMES]);
      for (const s of ladder.steps) {
        expect([true, false, null]).toContain(s.ok);
        // The reference never reaches its catch-all on JSON-shaped input; neither may we.
        expect(s.detail, `${path.join(".")}`).not.toMatch(/^malformed bundle \(/);
      }
    }
  });

  it.each([null, undefined, 1, "x", [], {}, { v: 2 }, { v: true }, { v: new JsonNumber("float", 1, "1.0") }])(
    "non-bundle %j",
    async (bad) => {
      const ladder = await verifyBundle(bad, caseByName("valid_anchored").config);
      expect(marks(ladder)).toBe("FFFFF INVALID");
    },
  );
});
