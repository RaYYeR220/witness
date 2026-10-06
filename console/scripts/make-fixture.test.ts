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

import { makeFixture, OUT_FILE, readBlock, VECTORS_DIR, whiteFlagCone } from "./make-fixture.mjs";

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
      expect(t.anchorRecord).toEqual(c.fetcher.record);
      expect(t.trustedDids).toEqual(vectors.resolvers[c.resolver]);
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
        resolveDid: (did) => t.trustedDids[did] ?? null,
        fetchAnchorRecord: () => t.anchorRecord,
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
