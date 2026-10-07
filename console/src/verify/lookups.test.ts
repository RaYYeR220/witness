import { describe, expect, it } from "vitest";

import { wired } from "@/test/vectors";

import { createLadder, runLadder } from "./ladder";
import { createLookups } from "./lookups";

const DID = "did:iota:testnet:0x5e1f";

/** A resolver that never answers, until the request is aborted. */
const hanging = (async (_url: string, init: RequestInit = {}) =>
  new Promise<Response>((_resolve, reject) => {
    init.signal?.addEventListener("abort", () => reject(init.signal!.reason));
  })) as unknown as typeof fetch;

describe("trusted DID lookups", () => {
  it("asks the resolver without following redirects, with a timeout", async () => {
    const seen: RequestInit[] = [];
    const f = (async (_url: string, init: RequestInit) => {
      seen.push(init);
      return new Response(JSON.stringify({ doc: { id: DID }, keys: [] }), { status: 200 });
    }) as unknown as typeof fetch;
    const l = createLookups({ VITE_RESOLVER_URL: "/anchor" }, f);
    expect(await l.resolveDid(DID)).toEqual({ doc: { id: DID }, keys: [] });
    expect(seen[0]!.redirect).toBe("error");
    expect(seen[0]!.signal).toBeInstanceOf(AbortSignal);
  });

  it("gives up on a resolver that does not answer in time", async () => {
    const l = createLookups({}, hanging, { timeoutMs: 20 });
    await expect(l.resolveDid(DID)).rejects.toMatchObject({ name: "TimeoutError" });
  });

  it("so step 4 stays unresolved and the verdict PARTIAL, never VALID", async () => {
    const l = createLookups({}, hanging, { timeoutMs: 20 });
    const { text, config, lookups } = wired("valid_anchored");
    const state = createLadder();
    const ladder = await runLadder(state, text, { config, resolveDid: l.resolveDid, fetchAnchorRecord: lookups.fetchAnchorRecord });
    expect(state.steps[3]!.status).toBe("unknown");
    expect(state.steps[3]!.detail).toMatch(/signer identity not resolved/);
    expect(ladder?.overall).toBe("PARTIAL");
  });

  it("reads a missing DID as not found and an error status as a failure", async () => {
    const status = (code: number) => (async () => new Response("{}", { status: code })) as unknown as typeof fetch;
    expect(await createLookups({}, status(404)).resolveDid(DID)).toBeNull();
    await expect(createLookups({}, status(502)).resolveDid(DID)).rejects.toThrow(/502/);
  });
});
