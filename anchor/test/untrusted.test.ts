import { describe, expect, it } from "vitest";

import { checkpointRecordMetadata, decodeCheckpointRecord } from "../src/checkpoint.js";
import { ANCHOR_TAG, mirrorOnNode } from "../src/mirror.js";
import { JsonTooDeepError, parseUntrusted } from "../src/untrusted.js";

// 2501 levels: past the cap every Witness entry point shares (2500), though JSON.parse reads it.
const nest = (n: number) => `{"a":${"[".repeat(n - 1)}${"]".repeat(n - 1)}}`;

describe("parseUntrusted", () => {
  it("applies the shared nesting cap before JSON.parse, valid JSON or not", () => {
    expect(parseUntrusted(nest(2500))).toHaveProperty("a");
    expect(() => JSON.parse(nest(2501))).not.toThrow();
    expect(() => parseUntrusted(nest(2501))).toThrow(JsonTooDeepError);
    expect(() => parseUntrusted("[".repeat(2501))).toThrow("JSON nested deeper than 2500 levels");
    expect(() => parseUntrusted("{nope")).toThrow(SyntaxError);
  });
});

describe("chain and Tangle reads past the cap", () => {
  const hash = "0x" + "11".repeat(32);

  it("a trail record whose data or metadata nests too deep is no checkpoint record", () => {
    expect(() => decodeCheckpointRecord(nest(2501), checkpointRecordMetadata(7, hash), 7)).toThrow(/record data is not JSON/);
    const deepMeta = `{"kind":"witness.checkpoint","seq":7,"x":${"[".repeat(2500)}${"]".repeat(2500)}}`;
    expect(() => decodeCheckpointRecord("{}", deepMeta, 7)).toThrow(/not a checkpoint/);
  });

  it("a posted block whose tagged data nests too deep is no mirror", async () => {
    const iss = "did:iota:testnet:0xabc";
    const body = (extra: string) =>
      new TextEncoder().encode(`{"iss":"${iss}","body":{"seq":3,"checkpointHash":"${hash}","x":${extra}}}`);
    const reader = (data: Uint8Array) => ({ taggedData: async () => ({ tag: ANCHOR_TAG, data }) });
    expect(await mirrorOnNode(reader(body("[]")), "0x01", iss)).toEqual({ seq: 3, checkpointHash: hash });
    const deep = body(`${"[".repeat(2500)}${"]".repeat(2500)}`);
    expect(await mirrorOnNode(reader(deep), "0x01", iss)).toBeNull();
  });
});
