/**
 * Step 5 against the pinned IOTA Rebased JSON-RPC, with the responses recorded
 * from testnet in core/tests/vectors/rebased_record.json. Each case mirrors
 * core/tests/test_rebased.py and must come out the same as in Python.
 */
import { describe, expect, it } from "vitest";

import {
  checkpointHash,
  fetchRecord,
  jcs,
  makeRebasedFetcher,
  RebasedError,
  toHex,
  verifyBundle,
  type Ladder,
  type VerifierConfig,
} from "../src/index.js";
import { bundles, clone, rebasedRecord as rec } from "./vectors.js";

/* eslint-disable @typescript-eslint/no-explicit-any */
const RPC = "https://rpc.example";
const NOT_FOUND = { jsonrpc: "2.0", id: 1, result: { error: { code: "dynamicFieldNotFound", parent_object_id: "0x1" } } };
const PACKAGE: string = rec.trailObject.result.data.type.split("::")[0];
const WRITER = "0xd40892daf5c81e3d67ffe9806575970b973ecf6625eb8a88562afae0d8c940c8";

interface Call {
  url: string;
  method: string;
  params: any[];
  redirect: RequestRedirect | undefined;
  signal: boolean;
}

/** A fetch answering the trail object and the record like the recorded fullnode did. */
function fakeFetch(trail: unknown, record: unknown = null, { status = 200, calls }: { status?: number; calls?: Call[] } = {}): typeof fetch {
  return (async (url: string, init: RequestInit) => {
    const body = JSON.parse(String(init.body));
    calls?.push({ url, method: body.method, params: body.params, redirect: init.redirect, signal: init.signal instanceof AbortSignal });
    const doc = body.method === "iota_getObject" ? trail : record;
    return new Response(JSON.stringify(doc), { status, headers: { "content-type": "application/json" } });
  }) as unknown as typeof fetch;
}

const fieldsOf = (doc: any) => doc.result.data.content.fields.value.fields.value.fields;

function fetch4(opts: { trail?: unknown; record?: unknown; index?: number; packageId?: string } = {}) {
  return fetchRecord(RPC, rec.trail, opts.index ?? 4, {
    packageId: opts.packageId ?? PACKAGE,
    fetch: fakeFetch(opts.trail ?? rec.trailObject, opts.record ?? rec.record),
  });
}

describe("fetchRecord over the recorded testnet responses", () => {
  it("decodes the record and recomputes the hash the chain metadata states", async () => {
    const got = await fetch4();
    const meta = JSON.parse(fieldsOf(rec.record).metadata);
    expect(got!.checkpointHash).toBe(meta.checkpointHash);
    expect(toHex(checkpointHash(got!.checkpoint))).toBe(meta.checkpointHash);
    expect((got!.checkpoint as any).kind).toBe("witness.checkpoint");
    expect(got!.addedBy).toBe(WRITER);
  });

  it("makes the two read-only RPC calls, nothing else", async () => {
    const calls: Call[] = [];
    await fetchRecord(RPC, rec.trail, 4, { packageId: PACKAGE, fetch: fakeFetch(rec.trailObject, rec.record, { calls }) });
    expect(calls.map((c) => c.method)).toEqual(["iota_getObject", "iotax_getDynamicFieldObject"]);
    expect(calls[0]!.params).toEqual([rec.trail, { showContent: true, showType: true }]);
    expect(calls[1]!.params[1]).toEqual({ type: "u64", value: "4" });
    // redirects are refused and every call has a timeout, as in the reference
    expect(calls.every((c) => c.url === RPC && c.redirect === "error" && c.signal)).toBe(true);
  });

  it("returns null when the trail has no such record", async () => {
    expect(await fetch4({ record: NOT_FOUND })).toBeNull();
  });

  it("rejects an object that is not an Audit Trail of the pinned package", async () => {
    await expect(fetch4({ packageId: "0x" + "ab".repeat(32) })).rejects.toThrow(/Audit Trail/);
    const other = clone(rec.trailObject);
    other.result.data.type = "0x2::coin::Coin<0x2::iota::IOTA>";
    await expect(fetch4({ trail: other })).rejects.toThrow(/Audit Trail/);
  });

  it("turns RPC and HTTP errors into RebasedError", async () => {
    const err = { jsonrpc: "2.0", id: 1, error: { code: -32602, message: "x" } };
    await expect(fetch4({ record: err })).rejects.toThrow("iotax_getDynamicFieldObject: RPC error -32602");
    await expect(
      fetchRecord(RPC, rec.trail, 4, { packageId: PACKAGE, fetch: fakeFetch(rec.trailObject, rec.record, { status: 503 }) }),
    ).rejects.toThrow("iota_getObject: HTTP 503");
    const unreadable = { jsonrpc: "2.0", id: 1, result: { error: { code: "dynamicFieldDeleted" } } };
    await expect(fetch4({ record: unreadable })).rejects.toThrow("reading record 4: dynamicFieldDeleted");
    const down = (async () => {
      throw new TypeError("Failed to fetch");
    }) as unknown as typeof fetch;
    await expect(fetchRecord(RPC, rec.trail, 4, { packageId: PACKAGE, fetch: down })).rejects.toThrow("iota_getObject: TypeError");
    const notJson = (async () => new Response("<html>", { status: 200 })) as unknown as typeof fetch;
    await expect(fetchRecord(RPC, rec.trail, 4, { packageId: PACKAGE, fetch: notJson })).rejects.toThrow("iota_getObject: response is not JSON");
  });

  it("gives up when the RPC does not answer in time", async () => {
    const hanging = (async (_url: string, init: RequestInit) =>
      new Promise<Response>((_resolve, reject) => init.signal!.addEventListener("abort", () => reject(init.signal!.reason)))) as unknown as typeof fetch;
    const started = Date.now();
    await expect(fetchRecord(RPC, rec.trail, 4, { packageId: PACKAGE, fetch: hanging, timeoutMs: 30 })).rejects.toThrow("iota_getObject: TimeoutError");
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it("refuses a redirect and a response over the size cap", async () => {
    const redirected = (async () => {
      throw new TypeError("fetch failed: redirect mode is set to error");
    }) as unknown as typeof fetch;
    await expect(fetchRecord(RPC, rec.trail, 4, { packageId: PACKAGE, fetch: redirected })).rejects.toThrow("iota_getObject: TypeError");
    const big = (async () => new Response("x".repeat(5000), { status: 200 })) as unknown as typeof fetch;
    await expect(fetchRecord(RPC, rec.trail, 4, { packageId: PACKAGE, fetch: big, maxBytes: 4096 })).rejects.toThrow(
      "iota_getObject: response over 4096 bytes",
    );
    const declared = (async () => new Response("{}", { status: 200, headers: { "content-length": String(10 * 1024 * 1024) } })) as unknown as typeof fetch;
    await expect(fetchRecord(RPC, rec.trail, 4, { packageId: PACKAGE, fetch: declared })).rejects.toThrow(/response over/);
  });

  it("fails closed on a nesting bomb, in the response or in the record data", async () => {
    const deep = "[".repeat(200_000) + "]".repeat(200_000);
    const bomb = (async () => new Response(deep, { status: 200 })) as unknown as typeof fetch;
    await expect(fetchRecord(RPC, rec.trail, 4, { packageId: PACKAGE, fetch: bomb, maxBytes: 1_000_000 })).rejects.toThrow(
      "iota_getObject: response is not JSON",
    );
    const record = clone(rec.record);
    fieldsOf(record).data.fields.pos0 = "[".repeat(100_000) + "]".repeat(100_000);
    await expect(fetch4({ record })).rejects.toThrow("record data or metadata is not valid JSON");
  });

  it("does not take a package id that is only a prefix of the trail's package", async () => {
    // the type check includes "::main::AuditTrail<", so a shorter id never matches a longer one
    await expect(fetch4({ packageId: PACKAGE.slice(0, 6) })).rejects.toThrow(/Audit Trail/);
    await expect(fetch4({ packageId: PACKAGE.slice(0, -1) })).rejects.toThrow(/Audit Trail/);
  });

  it("insists on https unless plain http is allowed explicitly", async () => {
    const f = fakeFetch(rec.trailObject, rec.record);
    await expect(fetchRecord("http://rpc.example", rec.trail, 4, { packageId: PACKAGE, fetch: f })).rejects.toThrow(/https/);
    expect(await fetchRecord("http://127.0.0.1:9000", rec.trail, 4, { packageId: PACKAGE, fetch: f, allowHttp: true })).not.toBeNull();
  });

  it("checks the record's sequence number against the index", async () => {
    await expect(fetch4({ index: 5 })).rejects.toThrow("record 5 reports sequence 4");
    for (const bad of [-1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
      await expect(fetch4({ index: bad })).rejects.toThrow("record index must be a non-negative integer");
    }
  });

  it("reads the Bytes variant like the Text one and refuses other variants", async () => {
    const record = clone(rec.record);
    const f = fieldsOf(record);
    const text: string = f.data.fields.pos0;
    f.data = { variant: "Bytes", fields: { pos0: [...new TextEncoder().encode(text)] } };
    expect(await fetch4({ record })).toEqual(await fetch4());
    f.data = { variant: "Bytes", fields: { pos0: [0xff, 0xfe] } };
    await expect(fetch4({ record })).rejects.toThrow("record bytes are not UTF-8 text");
    f.data = { variant: "Other", fields: { pos0: text } };
    await expect(fetch4({ record })).rejects.toThrow("unknown record data variant 'Other'");
  });

  it("accepts the metadata hash only if it is the hash of the data", async () => {
    const record = clone(rec.record);
    const f = fieldsOf(record);
    f.metadata = JSON.stringify({ kind: "witness.checkpoint", seq: 1, checkpointHash: "0x" + "00".repeat(32) });
    await expect(fetch4({ record })).rejects.toThrow("record metadata hash differs from the hash of its data");
    f.metadata = null;
    await expect(fetch4({ record })).rejects.toThrow("record metadata does not describe a witness checkpoint");
    f.metadata = "{";
    await expect(fetch4({ record })).rejects.toThrow("record data or metadata is not valid JSON");
  });

  it("refuses record data that is not a checkpoint", async () => {
    const record = clone(rec.record);
    fieldsOf(record).data.fields.pos0 = JSON.stringify({ kind: "something else" });
    await expect(fetch4({ record })).rejects.toThrow(/^record data is not a checkpoint: /);
  });
});

// ---------------------------------------------------------------- the ladder's step 5

const anchored = bundles.cases.find((c: any) => c.name === "valid_anchored");
const registry = bundles.resolvers.registry;
const did = Object.keys(registry)[0]!;

function cfgWith(extra: Partial<VerifierConfig> = {}, packageId = PACKAGE): VerifierConfig {
  return { ...anchored.config, rebasedRpc: RPC, auditTrailPackage: packageId, ...extra };
}

/** The recorded record, rewritten to carry checkpoint `cp` at `index` (Python `_record_for`). */
function recordFor(cp: unknown, index: number, metaHash?: string) {
  const record = clone(rec.record);
  const f = fieldsOf(record);
  f.data.fields.pos0 = jcs(cp);
  f.sequence_number = String(index);
  f.metadata = JSON.stringify({ kind: "witness.checkpoint", seq: 1, checkpointHash: metaHash ?? toHex(checkpointHash(cp)) });
  return record;
}

function ladder(record: unknown, cfg = cfgWith(), bundle = anchored.bundle, calls?: Call[]): Promise<Ladder> {
  const fetchAnchorRecord = makeRebasedFetcher(cfg, { fetch: fakeFetch(rec.trailObject, record, { calls }) });
  return verifyBundle(clone(bundle), cfg, { fetchAnchorRecord, resolveDid: () => clone(registry[did]) });
}

const a = anchored.bundle.anchor;

describe("step 5 with makeRebasedFetcher (parity with test_rebased.py)", () => {
  it("turns step 5 green when the chain holds the bundle's checkpoint", async () => {
    const l = await ladder(recordFor(a.checkpoint, a.rebased.record));
    expect(l.steps.map((s) => s.ok)).toEqual([true, true, true, true, true]);
    expect(l.overall).toBe("VALID");
    expect(l.steps[4]!.detail).toBe(`checkpoint ${toHex(checkpointHash(a.checkpoint))} matches the on-chain record`);
  });

  it("fails step 5 when the chain's checkpoint differs", async () => {
    const cp = clone(a.checkpoint);
    cp.msgCount += 1;
    const l = await ladder(recordFor(cp, a.rebased.record));
    expect(l.steps[4]!.ok).toBe(false);
    expect(l.overall).toBe("INVALID");
  });

  it("leaves step 5 unchecked (PARTIAL) for a missing record, an RPC error or the wrong package", async () => {
    const missing = await ladder(NOT_FOUND);
    expect(missing.overall).toBe("PARTIAL");
    expect(missing.steps[4]!.detail).toBe("anchor record unavailable");
    const err = { jsonrpc: "2.0", id: 1, error: { code: -32000, message: "boom" } };
    const failed = await ladder(err);
    expect(failed.overall).toBe("PARTIAL");
    expect(failed.steps[4]!.detail).toBe("anchor record unavailable (RebasedError)");
    const wrong = await ladder(recordFor(a.checkpoint, a.rebased.record), cfgWith({}, "0x" + "cd".repeat(32)));
    expect(wrong.steps[4]!.ok).toBeNull();
    expect(wrong.overall).toBe("PARTIAL");
  });

  it("needs the RPC, trail and package pins", async () => {
    const fetcher = makeRebasedFetcher({ trailId: null, rebasedRpc: null, auditTrailPackage: null });
    await expect(fetcher({ rebased: { record: 1 } })).rejects.toBeInstanceOf(RebasedError);
    // without them the ladder can never call the anchor VALID
    const l = await ladder(recordFor(a.checkpoint, a.rebased.record), { ...anchored.config });
    expect(l.steps[4]!.ok).toBeNull();
    expect(l.overall).toBe("PARTIAL");
  });

  it("fails step 5 for a record written by anyone but the pinned writer", async () => {
    const record = recordFor(a.checkpoint, a.rebased.record);
    expect(fieldsOf(record).added_by).toBe(WRITER);
    expect((await ladder(record, cfgWith({ anchorWriter: WRITER }))).overall).toBe("VALID");
    const other = await ladder(record, cfgWith({ anchorWriter: "0x" + "ee".repeat(32) }));
    expect(other.steps[4]!.ok).toBe(false);
    expect(other.steps[4]!.detail).toContain("writer");
    expect(other.overall).toBe("INVALID");
  });

  it("rejects a bundle naming another trail without ever querying it", async () => {
    const forged = clone(anchored.bundle);
    forged.anchor.rebased.trail = "0x" + "ab".repeat(32);
    const calls: Call[] = [];
    const l = await ladder(recordFor(a.checkpoint, a.rebased.record), cfgWith(), forged, calls);
    expect(l.steps[4]!.ok).toBe(false);
    expect(l.steps[4]!.detail).toContain("pinned trail");
    expect(calls).toEqual([]);
  });

  it("queries the pinned trail only", async () => {
    const calls: Call[] = [];
    const cfg = cfgWith();
    await makeRebasedFetcher(cfg, { fetch: fakeFetch(rec.trailObject, recordFor(a.checkpoint, a.rebased.record), { calls }) })(a);
    expect(calls[0]!.params[0]).toBe(cfg.trailId);
  });
});
