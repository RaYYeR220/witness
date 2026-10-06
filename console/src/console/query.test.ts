import { describe, expect, it } from "vitest";

import { dateBound, filterMessages, localCanonHash, type MessageSummary } from "@/api/client";

import { parseSearch } from "./query";

const BID = "0x972A878CF06F2CF6B7D4A1443DBB5F12FDDA376FA7537A82DAD8E7257A477967";
const DID = "did:iota:testnet:0x6b9a693ebf2ac6fb771a75d25b1284ba75aeb0ae16618eaf5d41d24828a6f7a2";

describe("the search box maps what you type to GET /messages", () => {
  it.each([
    [BID, { block_id: BID.toLowerCase() }],
    ["1284", { ms_from: 1284, ms_to: 1284 }],
    ["#1284", { ms_from: 1284, ms_to: 1284 }],
    ["1300..1280", { ms_from: 1280, ms_to: 1300 }],
    ["ms:1280-1300", { ms_from: 1280, ms_to: 1300 }],
    [DID, { iss: DID }],
    ["MyDomain:fa163e5e25ef", { ie: "MyDomain:fa163e5e25ef" }],
    ["trust.score", { tag: "trust.score" }],
    ["forged", { verdict: "FORGED" }],
    ["2026-10-06", { date_from: "2026-10-06", date_to: "2026-10-06" }],
    ["2026-10-06 to 2026-10-07", { date_from: "2026-10-06", date_to: "2026-10-07" }],
    ["2026-10-06T10:00:00Z..2026-10-06T11:00:00Z", { date_from: "2026-10-06T10:00:00Z", date_to: "2026-10-06T11:00:00Z" }],
    ["..2026-10-07", { date_to: "2026-10-07" }],
    ["event=scale", { jsonpath: "event=scale" }],
    ["kubernetes node", { q: "kubernetes node" }],
    ["", {}],
  ])("%s", (input, params) => {
    expect(parseSearch(input).params).toEqual(params);
  });

  it("combines several parts and names each one", () => {
    const p = parseSearch(`trust.score verdict:producer_signed ${DID} 2026-10-06 scale`);
    expect(p.params).toEqual({ tag: "trust.score", verdict: "PRODUCER_SIGNED", iss: DID, date_from: "2026-10-06", date_to: "2026-10-06", q: "scale" });
    expect(p.chips.map((c) => c.label)).toEqual(["Issuer", "Tag", "Verdict", "Day", "Text"]);
    expect(p.problem).toBeNull();
  });

  it("says what it could not use", () => {
    expect(parseSearch("verdict:great").problem).toMatch(/unknown verdict/);
    expect(parseSearch("ms:99999999999").problem).toBeTruthy();
    expect(parseSearch("block:0x12").problem).toMatch(/64 hex/);
  });
});

describe("replay search filters a recorded list like the API", () => {
  const base = { kind: null, status: null, kid: null, seq: null, prev: null, corr: null, nonce: null, encrypted: false, wfIndex: null, issuedAtMs: null, milestoneAtMs: null, receivedAtMs: null, confirmedAtMs: null, date: null, links: {} };
  const items: MessageSummary[] = [
    { ...base, blockId: "0xaa", tag: "trust.score", verdict: "PRODUCER_SIGNED", ieId: "D:1", iss: DID, msIndex: 10, dateMs: Date.parse("2026-10-06T10:00:00Z"), canonHash: "0x1", json: { w: 1, sig: "x", body: { id: "D:1", score: 0.5, event: "scale" } } },
    { ...base, blockId: "0xbb", tag: "trust.score", verdict: "FORGED", ieId: "D:2", iss: DID, msIndex: 12, dateMs: Date.parse("2026-10-07T10:00:00Z"), canonHash: "0x2", json: { id: "D:2" } },
  ];
  const ids = (q: object) => filterMessages(items, q).map((m) => m.blockId);

  it("by tag, verdict, milestone range, day and body field", () => {
    expect(ids({ tag: "trust.score" })).toEqual(["0xaa", "0xbb"]);
    expect(ids({ verdict: "FORGED" })).toEqual(["0xbb"]);
    expect(ids({ ms_from: 11, ms_to: 20 })).toEqual(["0xbb"]);
    expect(ids(parseSearch("2026-10-06").params)).toEqual(["0xaa"]);
    expect(ids(parseSearch("event=scale").params)).toEqual(["0xaa"]);
    expect(ids({ block_id: "0xAA" })).toEqual(["0xaa"]);
  });

  it("reads a bare date_to as the whole day", () => {
    expect(dateBound("2026-10-06", true)).toBe(Date.parse("2026-10-06T23:59:59.999Z"));
    expect(dateBound("1791283579000", false)).toBe(1791283579000);
  });

  it("hashes the canonical form, so key order and spacing do not matter", () => {
    const a = localCanonHash('{"b": 1, "a": [1, 2]}');
    const b = localCanonHash('{"a":[1,2],"b":1}');
    expect(a?.hash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(a).toEqual(b);
    expect(localCanonHash("{not json")).toBeNull();
  });
});
