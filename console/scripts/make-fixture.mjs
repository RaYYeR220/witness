#!/usr/bin/env node
/**
 * Builds console/src/fixtures/landing-sample.json from the shared test vectors
 * in core/tests/vectors. The landing page verifies this sample in the browser
 * with @witness/verify; nothing in the fixture is a verdict, only inputs:
 *
 *   sample  the `valid_anchored` bundle, the verifier config it is checked
 *           against, the trusted DID registry record of its issuer and the
 *           on-chain checkpoint record its anchor points at
 *   forged  the `envelope_forged` twin with the same kind of inputs
 *   graph   the Tangle around them: every block of blocks.json with its
 *           parents read from the raw bytes, the cones of milestones 370..373
 *           from cones.json, and the cone of milestone 374 recomputed here in
 *           white-flag order from the bundle's milestone essence
 *
 * Run: node scripts/make-fixture.mjs  (or pnpm --filter console fixture)
 */

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
export const VECTORS_DIR = resolve(here, "../../core/tests/vectors");
export const OUT_FILE = resolve(here, "../src/fixtures/landing-sample.json");

const SAMPLE_CASE = "valid_anchored";
const FORGED_CASE = "envelope_forged";
const PAYLOAD_TAGGED_DATA = 5;
const PAYLOAD_MILESTONE = 7;

// ------------------------------------------------------------ byte helpers

function unhex(h) {
  if (typeof h !== "string" || !/^0x([0-9a-f]{2})*$/.test(h)) throw new Error(`not canonical hex: ${String(h).slice(0, 20)}`);
  return Buffer.from(h.slice(2), "hex");
}
const hex = (b) => "0x" + Buffer.from(b).toString("hex");
const u32 = (b, o) => b.readUInt32LE(o);

/** Parents and payload kind of a raw TIP-24 block. */
export function readBlock(rawHex) {
  const b = unhex(rawHex);
  const n = b[1];
  const parents = [];
  for (let i = 0; i < n; i++) parents.push(hex(b.subarray(2 + 32 * i, 34 + 32 * i)));
  let o = 2 + 32 * n;
  const plen = u32(b, o);
  o += 4;
  const out = { parents, payload: null };
  if (plen === 0) return out;
  const type = u32(b, o);
  if (type === PAYLOAD_TAGGED_DATA) {
    const tlen = b[o + 4];
    out.payload = { kind: "tagged_data", tag: b.subarray(o + 5, o + 5 + tlen).toString("utf8") };
  } else if (type === PAYLOAD_MILESTONE) {
    out.payload = { kind: "milestone", index: u32(b, o + 4) };
  } else {
    out.payload = { kind: "other", type };
  }
  return out;
}

/** Index, timestamp and parents of a milestone essence. */
export function readEssence(essenceHex) {
  const e = unhex(essenceHex);
  const index = u32(e, 0);
  const timestamp = u32(e, 4);
  const n = e[41];
  const parents = [];
  for (let i = 0; i < n; i++) parents.push(hex(e.subarray(42 + 32 * i, 74 + 32 * i)));
  return { index, timestamp, parents };
}

/** White-flag order: depth-first over parents in block order, post-order, skipping confirmed blocks. */
export function whiteFlagCone(tips, parentsOf, confirmed) {
  const out = [];
  const seen = new Set();
  const visit = (id) => {
    if (seen.has(id) || confirmed.has(id)) return;
    seen.add(id);
    const ps = parentsOf.get(id);
    if (ps === undefined) throw new Error(`cone reaches ${id}, whose parents are not in the vectors`);
    for (const p of ps) visit(p);
    out.push(id);
  };
  for (const t of tips) visit(t);
  return out;
}

// ------------------------------------------------------------ fixture

function caseInputs(bundles, name) {
  const c = bundles.cases.find((x) => x.name === name);
  if (!c) throw new Error(`bundles.json has no case ${name}`);
  if (!c.resolver || !c.fetcher) throw new Error(`case ${name} needs a resolver and an anchor record`);
  const block = readBlock(c.bundle.block.raw);
  return {
    case: name,
    bundle: c.bundle,
    config: c.config,
    trustedDids: bundles.resolvers[c.resolver],
    anchorRecord: c.fetcher.record,
    parents: block.parents,
  };
}

export function makeFixture(dir = VECTORS_DIR) {
  const read = (f) => JSON.parse(readFileSync(join(dir, f), "utf8"));
  const bundles = read("bundles.json");
  const blocks = read("blocks.json");
  const milestones = read("milestones.json");
  const cones = read("cones.json");

  const sample = caseInputs(bundles, SAMPLE_CASE);
  const forged = caseInputs(bundles, FORGED_CASE);

  // Blocks with raw bytes: parents and payload come from the bytes, not from the JSON labels.
  const nodes = new Map();
  const parentsOf = new Map();
  for (const blk of blocks) {
    const info = readBlock(blk.raw);
    parentsOf.set(blk.blockId, info.parents);
    nodes.set(blk.blockId, {
      id: blk.blockId,
      kind: info.payload?.kind === "milestone" ? "milestone" : "block",
      parents: info.parents,
      raw: blk.raw,
      ...(info.payload?.kind === "tagged_data" ? { tag: info.payload.tag } : {}),
      ...(info.payload?.kind === "milestone" ? { msIndex: info.payload.index } : {}),
    });
  }
  for (const t of [sample, forged]) {
    parentsOf.set(t.bundle.block.id, t.parents);
    nodes.set(t.bundle.block.id, {
      id: t.bundle.block.id,
      kind: "block",
      role: t === sample ? "sample" : "forged",
      parents: t.parents,
      raw: t.bundle.block.raw,
      tag: readBlock(t.bundle.block.raw).payload?.tag ?? null,
    });
  }

  // Milestones 370..373: the cone from cones.json, the essence and signatures from milestones.json.
  const msBlock = new Map();
  for (const n of nodes.values()) if (n.kind === "milestone") msBlock.set(n.msIndex, n.id);
  const msOut = [];
  const confirmed = new Set();
  for (const ms of milestones) {
    const cone = cones.find((c) => c.index === ms.index);
    if (!cone) throw new Error(`cones.json has no cone for milestone ${ms.index}`);
    const nodeId = msBlock.get(ms.index);
    if (!nodeId) throw new Error(`blocks.json has no block carrying milestone ${ms.index}`);
    for (const id of cone.blockIdsWhiteFlagOrder) {
      confirmed.add(id);
      if (!nodes.has(id)) nodes.set(id, { id, kind: "block", parents: [], raw: null });
    }
    msOut.push({
      index: ms.index,
      id: ms.milestoneId,
      nodeId,
      universe: "shared",
      timestamp: ms.timestamp,
      essence: ms.essence,
      signatures: ms.signatures,
      cone: cone.blockIdsWhiteFlagOrder,
    });
  }

  // Milestone 374 of each bundle: no block carries it in the vectors, so its
  // node is the milestone itself (id = BLAKE2b-256 of the essence, parents =
  // the essence's parents) and its cone is recomputed from the graph.
  for (const t of [sample, forged]) {
    const m = t.bundle.milestone;
    const ess = readEssence(m.essence);
    if (ess.index !== m.index) throw new Error(`${t.case}: milestone index ${m.index} != essence ${ess.index}`);
    const cone = whiteFlagCone(ess.parents, parentsOf, confirmed);
    const inc = t.bundle.inclusion;
    if (cone.length !== inc.leafCount || cone[inc.leafIndex] !== t.bundle.block.id) {
      throw new Error(`${t.case}: recomputed cone does not match the bundle's inclusion leaf ${inc.leafIndex}/${inc.leafCount}`);
    }
    const universe = t === sample ? "sample" : "forged";
    nodes.set(m.id, { id: m.id, kind: "milestone", virtual: true, role: universe, msIndex: m.index, parents: ess.parents, raw: null });
    msOut.push({
      index: m.index,
      id: m.id,
      nodeId: m.id,
      universe,
      timestamp: ess.timestamp,
      essence: m.essence,
      signatures: m.signatures,
      cone,
    });
  }

  // Which milestone node confirmed each block (cones are disjoint within one universe).
  for (const ms of msOut) {
    for (const id of ms.cone) {
      const n = nodes.get(id);
      if (ms.universe === "forged" && n.role !== "forged") continue; // the shared blocks keep the sample's milestone
      n.confirmedBy = ms.nodeId;
    }
  }
  for (const n of nodes.values()) for (const p of n.parents) if (!nodes.has(p)) throw new Error(`${n.id} has unknown parent ${p}`);

  return {
    about:
      "Generated by console/scripts/make-fixture.mjs from core/tests/vectors. Inputs only: " +
      "every verdict on the landing page is computed in the browser by @witness/verify.",
    sources: {
      sample: `bundles.json#${SAMPLE_CASE}`,
      forged: `bundles.json#${FORGED_CASE}`,
      graph: ["blocks.json", "milestones.json", "cones.json", "bundles.json"],
    },
    sample: omitParents(sample),
    forged: omitParents(forged),
    graph: {
      nodes: [...nodes.values()].map((n) => ({ confirmedBy: null, ...n })),
      milestones: msOut,
    },
  };
}

function omitParents({ parents: _parents, ...rest }) {
  return rest;
}

export function writeFixture(file = OUT_FILE, dir = VECTORS_DIR) {
  const text = JSON.stringify(makeFixture(dir), null, 1) + "\n";
  writeFileSync(file, text);
  return text;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const text = writeFixture();
  const f = JSON.parse(text);
  console.log(`wrote ${OUT_FILE}: ${f.graph.nodes.length} nodes, ${f.graph.milestones.length} milestones`);
}
