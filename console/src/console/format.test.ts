import { describe, expect, it } from "vitest";

import { ago, clock, isoOf, shortDid, utc, verdictInfo } from "./format";

describe("format", () => {
  it("formats timestamps a Date can hold, and nothing else", () => {
    expect(utc(1791283579000)).toBe("2026-10-06 10:46:19 UTC");
    expect(clock(1791283579000)).toBe("10:46:19");
    // a signed iat may be any 53-bit integer: no RangeError, just nothing to show
    for (const bad of [Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, 8.64e15 + 1, NaN, Infinity, null, undefined]) {
      expect(isoOf(bad)).toBeNull();
      expect(utc(bad)).toBe("");
      expect(clock(bad)).toBe("");
      expect(ago(bad)).toBe("");
    }
  });

  it("does not read verdict names off the object prototype", () => {
    expect(verdictInfo("constructor")).toEqual({ label: "constructor", family: "unknown", gloss: "" });
    expect(verdictInfo("FORGED").family).toBe("rejected");
  });

  it("shortens a DID's object id and keeps its fragment", () => {
    expect(shortDid("did:iota:testnet:0x15eb8c4d90fa4fff1d49f3ae8b1676a61e09c883303acd383cbfaacb538db9ba#sig-1")).toBe("did:iota:testnet:0x15eb…b9ba#sig-1");
  });
});
