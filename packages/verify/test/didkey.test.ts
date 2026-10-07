import { describe, expect, it } from "vitest";

import { didKeyDocument, didKeyPublic, isCanonicalDid, NON_CANONICAL_DID, toHex, verifyBundle, withDidKey } from "../src/index.js";
import { bundles, clone } from "./vectors.js";
import didKeyText from "../../../core/tests/vectors/did_key.json?raw";

const didKeys = JSON.parse(didKeyText) as { cases: { name: string; did: string; publicKeyHex: string | null; document: unknown }[] };

describe("did_key.json parity", () => {
  it.each(didKeys.cases.map((c) => [c.name, c] as const))("%s", (_name, c) => {
    const pub = didKeyPublic(c.did);
    expect(pub === null ? null : toHex(pub)).toBe(c.publicKeyHex);
    expect(didKeyDocument(c.did)).toEqual(c.document);
  });
});

describe("withDidKey", () => {
  const did = didKeys.cases.find((c) => c.name === "ed25519")!.did;

  it("answers a did:key locally and forwards any other DID", async () => {
    const asked: string[] = [];
    const resolve = withDidKey(async (d) => (asked.push(d), { doc: { id: d }, keys: [] }));
    expect(await resolve(did)).toEqual(didKeyDocument(did));
    expect(asked).toEqual([]);
    const iota = `did:iota:testnet:0x${"cd".repeat(32)}`;
    expect(await resolve(iota)).toEqual({ doc: { id: iota }, keys: [] });
    expect(asked).toEqual([iota]);
    expect(await withDidKey(null)(iota)).toBeNull();
  });

  it("evaluates step 4 for a did:key signer with no registry at all", async () => {
    for (const [name, ok] of [["did_key_signer", true], ["did_key_forged", false]] as const) {
      const c = bundles.cases.find((x: any) => x.name === name);
      const ladder = await verifyBundle(clone(c.bundle), c.config, {
        resolveDid: withDidKey(null),
        fetchAnchorRecord: () => clone(c.fetcher.record),
      });
      expect(ladder.steps.find((s) => s.name === "envelope")!.ok, name).toBe(ok);
    }
  });
});

describe("isCanonicalDid", () => {
  it("accepts only 64 lowercase hex for did:iota and leaves other methods alone", () => {
    const hex = "5e1fd05239fa76b9ce631486197f581a8f661997b616d18ba18c0045fd25eed7";
    expect(isCanonicalDid(`did:iota:testnet:0x${hex}`)).toBe(true);
    expect(isCanonicalDid(`did:iota:0x${hex}`)).toBe(true);
    expect(isCanonicalDid(`did:iota:testnet:0x${hex.toUpperCase()}`)).toBe(false);
    expect(isCanonicalDid("did:iota:testnet:0x5e1f")).toBe(false);
    expect(isCanonicalDid("did:key:z6Mk")).toBe(true);
    expect(NON_CANONICAL_DID).toBe("non-canonical DID");
  });
});
