// @vitest-environment jsdom
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { LiveAdapter, type Identity, type WitnessData } from "@/api/client";
import { didObjectId, explorerAddress, explorerObject, explorerTx } from "@/console/explorer";
import live from "@/fixtures/api/live.json";
import { mountScreen, until } from "@/test/mount";
import type { TrustedLookups } from "@/verify/lookups";
import IdentityView from "@/views/IdentityView.vue";

import { ForeignDocument, keyStatus, readIdentities, readIdentity, tagsFor } from "./model";

/* eslint-disable @typescript-eslint/no-explicit-any */
const ID = live.identity as unknown as Identity;
const TM = (ID.anchor.identities as any[]).find((i) => i.name === "trust-manager");
const REVOKED_AT = 1791300000000;

/** The resolver's answer for the trust manager, with its sig-1 rotated: the old key revoked, a new one in force. */
function resolvedTm() {
  const sig = TM.keys[0];
  return {
    doc: { id: TM.did },
    version: "1",
    historyComplete: false,
    keys: [
      { kid: sig.kid, type: "Ed25519", publicKeyHex: "11".repeat(32), revokedAtMs: REVOKED_AT },
      { kid: `${TM.did}#sig-0`, type: "Ed25519", publicKeyHex: "22".repeat(32), revokedAtMs: REVOKED_AT - 1000 },
      { kid: TM.keys[1].kid, type: "X25519", publicKeyHex: TM.keys[1].publicKeyHex, revokedAtMs: null },
    ],
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
});

describe("identity model", () => {
  it("reads published identities and drops what is not one", () => {
    const ids = readIdentities([...ID.anchor.identities, { name: "x" }, { did: "javascript:alert(1)" }, null, "did:iota:x"]);
    expect(ids.map((i) => i.name)).toEqual((ID.anchor.identities as any[]).map((i) => i.name));
    const domain = ids[0]!;
    expect(domain.controller).toEqual({ kind: "address", address: (ID.anchor.identities[0] as any).controller.address });
    expect(ids[1]!.controller?.kind).toBe("identity");
    expect(readIdentity({ did: TM.did, controller: { kind: "address", address: 7 } })!.controller).toBeNull();
  });

  it("reads key status from the resolver: in force, revoked, or unknown to it", () => {
    const tm = readIdentity(TM)!;
    const s = keyStatus(resolvedTm(), TM.did, tm.keys);
    expect(s.byKid.get(TM.keys[0].kid)).toEqual({ kind: "revoked", atMs: REVOKED_AT });
    expect(s.byKid.get(TM.keys[1].kid)).toEqual({ kind: "active" });
    expect(s.others).toEqual([{ kid: `${TM.did}#sig-0`, state: { kind: "revoked", atMs: REVOKED_AT - 1000 } }]);
    expect(s.historyComplete).toBe(false);
    const none = keyStatus({ doc: { id: TM.did }, keys: [] }, TM.did, tm.keys);
    expect(none.byKid.get(TM.keys[0].kid)).toEqual({ kind: "absent" });
    // a document of another DID is not an answer about this one
    expect(() => keyStatus(resolvedTm(), "did:iota:testnet:0x" + "00".repeat(32), tm.keys)).toThrow(ForeignDocument);
    expect(() => keyStatus({ keys: [] }, TM.did, tm.keys)).toThrow(ForeignDocument);
  });

  it("lists the tags a DID may write", () => {
    expect(tagsFor(TM.did, ID.policy)).toEqual(["audit.report", "trust.score"]);
    expect(tagsFor(TM.did, null)).toEqual([]);
  });
});

describe("explorer links", () => {
  it("builds https links on the explorer from well-formed ids only", () => {
    const obj = "0x0715cfc56779f78cea48a3afb75dd44d7b9694008286acdb27a16f2c6e3ab313";
    expect(explorerObject(obj, "testnet")).toBe(`https://explorer.iota.org/object/${obj}?network=testnet`);
    expect(explorerTx("5K3CqSHNQR7t3yuuUqjZYxk2cRmDPwtPHuHYQhy7coj5", "testnet")).toBe(
      "https://explorer.iota.org/txblock/5K3CqSHNQR7t3yuuUqjZYxk2cRmDPwtPHuHYQhy7coj5?network=testnet",
    );
    expect(explorerAddress("0xd408", "mainnet")).toBe("https://explorer.iota.org/address/0xd408?network=mainnet");
    for (const bad of ["javascript:alert(1)", "0x12/../../evil", "https://evil.example", "0xZZ", "", null, 42]) {
      expect(explorerObject(bad, "testnet")).toBeNull();
      expect(explorerTx(bad, "testnet")).toBeNull();
    }
    expect(explorerTx("5K3CqSHNQR7t3yuuUqjZYxk2cRmDPwtPHuHYQhy7coj0", "testnet")).toBeNull(); // 0 is not base58
    expect(explorerObject(obj, "test net")).toBeNull();
    expect(explorerObject(obj, "testnet&x=1")).toBeNull();
    expect(explorerObject(obj, null)).toBeNull();
    expect(didObjectId(TM.did)).toBe(TM.objectId);
    expect(didObjectId("did:key:z6Mk")).toBeNull();
  });
});

describe("Identity screen", () => {
  function setup(policyHash: string) {
    const d = Object.assign(Object.create(new LiveAdapter("/api")), {
      health: async () => ({ mode: "live", ok: true, network: "private_tangle1", version: "test", note: null }),
      identity: async () => structuredClone(ID),
      anchors: async () => [{ ...structuredClone(live.anchors.items[0]), checkpoint: { ...live.anchors.items[0]!.checkpoint, policyHash } }],
    }) as WitnessData;
    const asked: string[] = [];
    const lookups: TrustedLookups = {
      resolveDid: async (did: string) => {
        asked.push(did);
        if (did === TM.did) return resolvedTm();
        // the LLO's DID is answered with the trust manager's document
        if ((ID.anchor.identities as any[]).find((i) => i.name === "llo-k8s")?.did === did) return resolvedTm();
        return null;
      },
      fetchAnchorRecord: null,
      didSource: "the test resolver",
      anchorSource: "nowhere",
      recordedDids: true,
    };
    return { d, lookups, asked };
  }

  it("shows each key's status from the resolver and the policy hash against the newest checkpoint", async () => {
    const { d, lookups, asked } = setup(ID.policy!.hash);
    const { w } = await mountScreen(IdentityView, { path: "/identity", data: d, lookups });
    await until(() => w.findAll(".card").length === ID.anchor.identities.length && !w.text().includes("checking…"));
    expect(asked.sort()).toEqual((ID.anchor.identities as any[]).map((i) => i.did).sort());
    const tm = w.findAll(".card").find((c) => c.find(".name").text() === "trust-manager")!;
    const rows = tm.findAll("tbody tr");
    expect(rows[0]!.find(".st").text()).toContain("revoked 2026-");
    expect(rows[0]!.find(".st").attributes("data-tone")).toBe("bad");
    expect(rows[1]!.find(".st").text()).toContain("in force");
    expect(tm.find("tr.other").text()).toContain("#sig-0");
    expect(tm.text()).toContain("a revocation time may be an early bound");
    // a DID the resolver does not know is said so, never shown in force
    const other = w.findAll(".card").find((c) => c.find(".name").text() === "relay")!;
    expect(other.find(".st").text()).toContain("resolver did not answer");
    const llo = w.findAll(".card").find((c) => c.find(".name").text() === "llo-k8s")!;
    expect(llo.find(".st").text()).toContain("resolver answered for another DID");
    expect(llo.find(".st").attributes("data-tone")).toBe("bad");
    // explorer links: https, on the explorer, pinned network
    const hrefs = w.findAll("a[target=_blank]").map((a) => a.attributes("href")!);
    expect(hrefs.length).toBeGreaterThan(6);
    expect(hrefs.every((h) => h.startsWith("https://explorer.iota.org/") && h.includes("network="))).toBe(true);
    expect(w.findAll("a[target=_blank]").every((a) => a.attributes("rel")?.includes("noopener"))).toBe(true);
    // policy
    expect(w.find(".hashline .x-cmp").attributes("data-c")).toBe("consistent");
    const ts = w.findAll(".rules tbody tr").find((r) => r.find(".tag").exists() && r.find(".tag").text() === "trust.score")!;
    expect(ts.text()).toContain("trust-manager");
    expect(ts.text()).toContain("required");
    w.unmount();
  });

  it("flags a checkpoint committed to another policy, and passes axe", async () => {
    const { d, lookups } = setup("0x" + "00".repeat(32));
    const { w } = await mountScreen(IdentityView, { path: "/identity", data: d, lookups });
    await until(() => w.find(".hashline .x-cmp").exists() && !w.text().includes("checking…"));
    expect(w.find(".hashline .x-cmp").attributes("data-c")).toBe("differs");
    const res = await axe.run(document.body, { rules: { "color-contrast": { enabled: false } } });
    const bad = res.violations.filter((v) => v.impact === "critical" || v.impact === "serious");
    expect(bad.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`)).toEqual([]);
    w.unmount();
  });
});
