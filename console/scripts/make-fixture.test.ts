import { readFileSync } from "node:fs";
import { join } from "node:path";

import {
  blake2b256,
  fromHex,
  merkleRoot,
  milestoneId,
  parseBlock,
  parseMilestoneEssence,
  toHex,
  verifyBundleText,
  type VerifierConfig,
} from "@witness/verify";
import { describe, expect, it } from "vitest";

import {
  IDENTITY_FILE,
  makeFixture,
  domainController,
  makeVerifierConfig,
  OUT_FILE,
  REBASED_NETWORKS,
  readBlock,
  VECTORS_DIR,
  VERIFIER_FILE,
  whiteFlagCone,
} from "./make-fixture.mjs";

const fixture = makeFixture();
const nodes = new Map(fixture.graph.nodes.map((n: { id: string }) => [n.id, n]));
const vectors = JSON.parse(readFileSync(join(VECTORS_DIR, "bundles.json"), "utf8"));

describe("make-fixture", () => {
  it("matches the committed landing-sample.json (run `pnpm --filter console fixture` after changing the vectors)", () => {
    const committed = readFileSync(OUT_FILE, "utf8");
    expect(JSON.parse(committed)).toEqual(fixture);
  });

  it("is deterministic", () => {
    expect(JSON.stringify(makeFixture())).toBe(JSON.stringify(fixture));
  });

  it("takes the sample and the forged twin from the vectors unchanged", () => {
    for (const [which, name] of [
      ["sample", "valid_anchored"],
      ["forged", "envelope_forged"],
    ] as const) {
      const c = vectors.cases.find((x: { name: string }) => x.name === name);
      const t = fixture[which];
      expect(t.case).toBe(name);
      expect(t.bundle).toEqual(c.bundle);
      expect(t.config).toEqual(c.config);
      expect(t.recordedAnchor).toEqual(c.fetcher.record);
      expect(t.recordedDids).toEqual(vectors.resolvers[c.resolver]);
    }
  });

  it("gives the inputs on which the library reproduces the vectors' verdicts", async () => {
    for (const [which, name] of [
      ["sample", "valid_anchored"],
      ["forged", "envelope_forged"],
    ] as const) {
      const t = fixture[which];
      const expected = vectors.cases.find((x: { name: string }) => x.name === name).expected;
      const ladder = await verifyBundleText(JSON.stringify(t.bundle), t.config as VerifierConfig, {
        resolveDid: (did) => t.recordedDids[did] ?? null,
        fetchAnchorRecord: () => t.recordedAnchor,
      });
      expect(ladder.overall).toBe(expected.overall);
      expect(ladder.steps.map((s) => ({ name: s.name, ok: s.ok }))).toEqual(expected.steps);
    }
  });

  it("reads every block's parents and payload from its raw bytes", () => {
    for (const n of fixture.graph.nodes) {
      if (!n.raw) continue;
      const raw = fromHex(n.raw);
      expect(toHex(blake2b256(raw))).toBe(n.id);
      const block = parseBlock(raw);
      expect(block.parents.map(toHex)).toEqual(n.parents);
      if (n.kind === "milestone") {
        expect(block.payload?.kind).toBe("milestone");
        if (block.payload?.kind === "milestone") expect(block.payload.essence.index).toBe(n.msIndex);
      }
    }
  });

  it("links every edge to a node in the graph and every block to a milestone", () => {
    for (const n of fixture.graph.nodes) {
      for (const p of n.parents) expect(nodes.has(p)).toBe(true);
      if (!(n.kind === "milestone" && n.virtual)) expect(nodes.has(n.confirmedBy)).toBe(true);
    }
  });

  it("names milestones by the hash of their essence and lists their real cones", () => {
    for (const ms of fixture.graph.milestones) {
      const essence = fromHex(ms.essence);
      const parsed = parseMilestoneEssence(essence);
      expect(toHex(milestoneId(essence))).toBe(ms.id);
      expect(parsed.index).toBe(ms.index);
      // the cone in white-flag order rebuilds the root the coordinators signed
      expect(toHex(merkleRoot(ms.cone.map(fromHex)))).toBe(toHex(parsed.inclusionMerkleRoot));
    }
  });

  it("recomputes milestone 374's cone from the graph", () => {
    const ms = fixture.graph.milestones.filter((m: { index: number }) => m.index === 374);
    expect(ms.map((m: { universe: string }) => m.universe)).toEqual(["sample", "forged"]);
    expect(ms[0]!.cone).toEqual(["0xd6119fd6c74c0372206ed5799e22195bfc12e7537ad94600c307155ccea2437a", fixture.sample.bundle.block.id]);
    expect(ms[1]!.cone[1]).toBe(fixture.forged.bundle.block.id);
  });

  it("orders a cone depth-first, parents before children, skipping confirmed blocks", () => {
    const parents = new Map([
      ["c", ["a", "b"]],
      ["b", ["a", "x"]],
      ["a", ["x"]],
    ]);
    expect(whiteFlagCone(["c"], parents, new Set(["x"]))).toEqual(["a", "b", "c"]);
    expect(() => whiteFlagCone(["c"], parents, new Set())).toThrow(/parents are not in the vectors/);
  });

  it("parses a tagged-data block header", () => {
    const sample = readBlock(fixture.sample.bundle.block.raw);
    expect(sample.parents).toHaveLength(2);
    expect(sample.payload).toEqual({ kind: "tagged_data", tag: "trust.score" });
  });
});

describe("pinned verifier config", () => {
  const pinned = JSON.parse(readFileSync(VERIFIER_FILE, "utf8"));
  const coordinator = JSON.parse(readFileSync(join(VECTORS_DIR, "coordinator_keys.json"), "utf8"));
  const identity = JSON.parse(readFileSync(IDENTITY_FILE, "utf8"));

  it("pins the coordinator keys the stack's protocol config lists", () => {
    // coordinator_keys.json was captured from the same protocol config (scripts/capture_vectors.py)
    expect(pinned.trustedCoordinatorKeys).toEqual(coordinator.publicKeys);
    expect(pinned.threshold).toBe(coordinator.publicKeys.length);
  });

  it("pins the stack's Tangle network and Rebased network", () => {
    for (const c of vectors.cases) if (c.bundle?.network) expect(c.bundle.network).toBe(pinned.network);
    expect(pinned.rebasedNetwork).toBe(identity.network);
    expect(pinned.trailId === null || /^0x[0-9a-f]{64}$/.test(pinned.trailId)).toBe(true);
  });

  it("is built from a protocol config the way the stack writes it", () => {
    const protocol = {
      targetNetworkName: "private_tangle1",
      milestonePublicKeyCount: 2,
      publicKeyRanges: [
        { key: "ED3C3F1A319FF4E909CF2771D79FECE0AC9BD9FD2EE49EA6C0885C9CB3B1248C", start: 0, end: 0 },
        { key: "f6752f5f46a53364e2ee9c4d662d762a81efd51010282a75cd6bd03f28ef349c", start: 0, end: 0 },
        { key: "f6752f5f46a53364e2ee9c4d662d762a81efd51010282a75cd6bd03f28ef349c", start: 10, end: 20 },
      ],
    };
    const cfg = makeVerifierConfig({ protocol, identity: { network: "testnet" }, trailId: null });
    expect(cfg.network).toBe("private_tangle1");
    expect(cfg.trustedCoordinatorKeys).toEqual(coordinator.publicKeys);
    expect(cfg.threshold).toBe(2);
    expect(cfg.rebasedNetwork).toBe("testnet");
    expect(cfg.trailId).toBeNull();
    expect(() => makeVerifierConfig({ protocol: { ...protocol, milestonePublicKeyCount: 3 }, identity, trailId: null })).toThrow();
    expect(() => makeVerifierConfig({ protocol, identity, trailId: "0x1234" })).toThrow();
  });

  it("pins where step 5 reads the anchor on IOTA Rebased", () => {
    // the public testnet fullnode, and the package the trail object's Move type names
    expect(pinned.rebasedRpc).toBe(REBASED_NETWORKS.testnet.rpc);
    expect(pinned.rebasedRpc).toBe("https://api.testnet.iota.cafe");
    expect(pinned.auditTrailPackage).toBe("0x51368931f28620c7f65b4ae2c5167b42390e69729357a6347be378755b46e7df");
    const recorded = JSON.parse(readFileSync(join(VECTORS_DIR, "rebased_record.json"), "utf8"));
    expect(recorded.trailObject.result.data.type.startsWith(`${pinned.auditTrailPackage}::main::AuditTrail<`)).toBe(true);
    // the writer is the wallet that controls the domain DID: the one that added the recorded record
    expect(pinned.anchorWriter).toBe(domainController(identity));
    expect(recorded.record.result.data.content.fields.value.fields.value.fields.added_by).toBe(pinned.anchorWriter);
  });

  it("takes the Rebased pins from the environment first, and keeps committed Tangle pins without a protocol config", () => {
    const tangle = { network: "n", trustedCoordinatorKeys: coordinator.publicKeys, threshold: 1 };
    const env = {
      WITNESS_REBASED_RPC: "https://rpc.example",
      IOTA_AUDIT_TRAIL_ORIGINAL_PKG_ID: "0x" + "AB".repeat(32),
      ANCHOR_WRITER_ADDRESS: "0x" + "cd".repeat(32),
    };
    const cfg = makeVerifierConfig({ tangle, identity, trailId: null, env });
    expect(cfg).toMatchObject({ network: "n", threshold: 1, rebasedRpc: "https://rpc.example" });
    expect(cfg.auditTrailPackage).toBe("0x" + "ab".repeat(32));
    expect(cfg.anchorWriter).toBe("0x" + "cd".repeat(32));
    expect(() => makeVerifierConfig({ tangle, identity, trailId: null, env: { WITNESS_REBASED_RPC: "http://rpc.example" } })).toThrow(/https/);
    // an unknown Rebased network pins nothing to read: step 5 stays "not checked"
    const none = makeVerifierConfig({ tangle, identity: { network: "devnet" }, trailId: null });
    expect([none.rebasedRpc, none.auditTrailPackage, none.anchorWriter]).toEqual([null, null, null]);
  });
});
