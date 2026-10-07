#!/usr/bin/env node
/**
 * Writes three files for the console.
 *
 * src/fixtures/landing-sample.json, from the shared test vectors in
 * core/tests/vectors. The landing page verifies this sample in the browser
 * with @witness/verify; nothing in the fixture is a verdict, only inputs:
 *
 *   sample  the `valid_anchored` bundle, the verifier config the vectors check
 *           it against (with their test anchor trail), and recorded copies of
 *           the issuer's DID document and of the anchor record: what the
 *           vectors' resolver and fetcher return. They are not live reads of
 *           the DID registry or of IOTA Rebased.
 *   forged  the `envelope_forged` twin with the same kind of inputs
 *   graph   the Tangle around them: every block of blocks.json with its
 *           parents read from the raw bytes, the cones of milestones 370..373
 *           from cones.json, and the cone of milestone 374 recomputed here in
 *           white-flag order from the bundle's milestone essence
 *
 * src/config/verifier.json, the console's pinned verifier config, from the
 * stack's own configuration: network name, coordinator keys and threshold
 * from the private Tangle's protocol config (vendor/iota-tangle, or the file
 * named by WITNESS_TANGLE_CONFIG), the Rebased network from
 * deploy/identity/testnet.json, and the anchor trail from ANCHOR_TRAIL_ID.
 * Step 5 reads the anchor record from IOTA Rebased itself, so the file also
 * pins where and what to read: rebasedRpc (WITNESS_REBASED_RPC, else the
 * network's public fullnode), auditTrailPackage (IOTA_AUDIT_TRAIL_ORIGINAL_PKG_ID,
 * else the network's Audit Trail package as Move types name it) and
 * anchorWriter (ANCHOR_WRITER_ADDRESS, else the address that controls the
 * domain DID in the identity file, the wallet the anchor writes with).
 * reportSigner (REPORT_SIGNER_DID, else the identity file's domain DID) is the
 * DID whose audit.report messages the Reports screen accepts as anchoring a report.
 * Without the protocol config the committed Tangle pins are kept; without
 * ANCHOR_TRAIL_ID the committed trail is kept.
 *
 * src/fixtures/forged-milestone.json, the Verify screen's forged proof: a
 * bundle of the test vectors with a milestone signed offline with IOTA's
 * public sample coordinator keys, pointed at a record of the pinned trail
 * (see makeForgedDemo). It needs the pins above, so it is written last.
 *
 * Run: node scripts/make-fixture.mjs  (or pnpm --filter console fixture)
 */

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
export const VECTORS_DIR = resolve(here, "../../core/tests/vectors");
export const OUT_FILE = resolve(here, "../src/fixtures/landing-sample.json");
export const VERIFIER_FILE = resolve(here, "../src/config/verifier.json");
export const STACK_CONFIG =
  process.env.WITNESS_TANGLE_CONFIG ?? resolve(here, "../../vendor/iota-tangle/docker/config_private_tangle.json");
export const IDENTITY_FILE = resolve(here, "../../deploy/identity/testnet.json");

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
    recordedDids: bundles.resolvers[c.resolver],
    recordedAnchor: c.fetcher.record,
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
      "every verdict on the landing page is computed in the browser by @witness/verify. " +
      "recordedDids and recordedAnchor are copies from the test vectors, not live reads.",
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

// ------------------------------------------------------------ forged-milestone demo

export const DEMO_FILE = resolve(here, "../src/fixtures/forged-milestone.json");
const DEMO_CASE = "did_key_signer";
/** The trail record the demo claims: record 1 is the checkpoint of milestones 1 to 720, where a real milestone 374 is. */
export const DEMO_RECORD = 1;

/**
 * The Verify screen's forged proof, from the `did_key_signer` case of the test
 * vectors: a trust.score signed by a did:key, confirmed by a milestone 374 made
 * offline and signed with IOTA's public sample coordinator keys, and a
 * checkpoint over that milestone. Only `anchor.rebased` changes: it names the
 * Rebased network and trail the console pins, and record DEMO_RECORD, as anyone
 * holding the sample keys would present it. Against the console's pins checks
 * 1 to 4 pass (the sample keys are the pinned keys, and a did:key needs no
 * lookup); check 5 reads that record from IOTA Rebased and finds another
 * checkpoint. The bundle is kept as text: the console verifies these bytes.
 */
export function makeForgedDemo(pins, dir = VECTORS_DIR) {
  const bundles = JSON.parse(readFileSync(join(dir, "bundles.json"), "utf8"));
  const c = bundles.cases.find((x) => x.name === DEMO_CASE);
  if (!c) throw new Error(`bundles.json has no case ${DEMO_CASE}`);
  if (!pins?.trailId || !pins.rebasedNetwork) throw new Error("the forged-milestone demo needs a pinned anchor trail");
  if (c.bundle.network !== pins.network) throw new Error(`the demo is on ${c.bundle.network}, the console pins ${pins.network}`);
  const pinned = new Set(pins.trustedCoordinatorKeys.map((k) => k.toLowerCase()));
  const signers = c.config.trustedCoordinatorKeys.filter((k) => pinned.has(k.toLowerCase()));
  if (signers.length < pins.threshold) {
    throw new Error("the console does not pin IOTA's sample coordinator keys: a sample-key milestone would fail check 3, not check 5");
  }
  const bundle = structuredClone(c.bundle);
  bundle.anchor.rebased = { network: pins.rebasedNetwork, trail: pins.trailId, record: DEMO_RECORD };
  return {
    about:
      "Generated by console/scripts/make-fixture.mjs. A forged proof for the Verify screen: the test vectors' " +
      `${DEMO_CASE} bundle (a milestone signed offline with IOTA's public sample coordinator keys), its anchor ` +
      `pointed at record ${DEMO_RECORD} of the trail this console pins. Nothing here is a verdict.`,
    source: `core/tests/vectors/bundles.json#${DEMO_CASE}`,
    record: DEMO_RECORD,
    bundle: JSON.stringify(bundle),
  };
}

export function writeForgedDemo(file = DEMO_FILE, pins = JSON.parse(readFileSync(VERIFIER_FILE, "utf8")), dir = VECTORS_DIR) {
  const demo = makeForgedDemo(pins, dir);
  writeFileSync(file, JSON.stringify(demo, null, 1) + "\n");
  return demo;
}

// ------------------------------------------------------------ pinned verifier config

const HEX32 = /^0x[0-9a-f]{64}$/;

/**
 * Public fullnode and Audit Trail package per Rebased network, as the anchor
 * service uses them (anchor/src/config.ts). The package is the original id:
 * the one the trail object's Move type names.
 */
export const REBASED_NETWORKS = {
  testnet: {
    rpc: "https://api.testnet.iota.cafe",
    auditTrailPackage: "0x51368931f28620c7f65b4ae2c5167b42390e69729357a6347be378755b46e7df",
  },
  mainnet: {
    rpc: "https://api.mainnet.iota.cafe",
    auditTrailPackage: "0x960d8a375af7bd09d19f08a9648940caf7e76289de90aa258b9e8e30a84f1b8a",
  },
};

/** The domain DID's controller address in the identity file: the wallet that writes the trail. */
export function domainController(identity) {
  const domain = (identity?.identities ?? []).find((i) => i?.did === identity?.domain) ?? null;
  const address = domain?.controller?.kind === "address" ? String(domain.controller.address).toLowerCase() : null;
  return address && HEX32.test(address) ? address : null;
}

/**
 * Where and what step 5 reads on IOTA Rebased. `env` may override each pin
 * (WITNESS_REBASED_RPC, IOTA_AUDIT_TRAIL_ORIGINAL_PKG_ID, ANCHOR_WRITER_ADDRESS).
 */
export function rebasedPins(identity, env = {}) {
  const net = REBASED_NETWORKS[identity?.network] ?? null;
  const rpc = env.WITNESS_REBASED_RPC ?? net?.rpc ?? null;
  const pkg = (env.IOTA_AUDIT_TRAIL_ORIGINAL_PKG_ID ?? net?.auditTrailPackage ?? null)?.toLowerCase() ?? null;
  const writer = (env.ANCHOR_WRITER_ADDRESS ?? domainController(identity))?.toLowerCase() ?? null;
  if (rpc !== null && !/^https:\/\//.test(rpc)) throw new Error(`the Rebased RPC must be https: ${rpc}`);
  if (pkg !== null && !HEX32.test(pkg)) throw new Error(`bad Audit Trail package id ${pkg}`);
  if (writer !== null && !HEX32.test(writer)) throw new Error(`bad anchor writer address ${writer}`);
  return { rebasedRpc: rpc, auditTrailPackage: pkg, anchorWriter: writer };
}

const DID_IOTA = /^did:iota:(?:[a-z0-9]+:)?0x[0-9a-f]{64}$/;

/** The DID that signs audit.report messages: REPORT_SIGNER_DID, else the domain DID of the identity file. */
export function reportSigner(identity, env = {}) {
  const did = env.REPORT_SIGNER_DID ?? identity?.domain ?? null;
  if (did === null) return null;
  if (typeof did !== "string" || !DID_IOTA.test(did)) throw new Error(`bad report signer DID ${did}`);
  return did;
}

const SOURCES = {
  network: "private Tangle protocol config: protocol.targetNetworkName",
  trustedCoordinatorKeys: "private Tangle protocol config: protocol.publicKeyRanges[].key",
  threshold: "private Tangle protocol config: protocol.milestonePublicKeyCount",
  rebasedNetwork: "deploy/identity/testnet.json: network",
  trailId: "ANCHOR_TRAIL_ID (null until the anchor trail exists)",
  rebasedRpc: "WITNESS_REBASED_RPC, else the public fullnode of rebasedNetwork",
  auditTrailPackage: "IOTA_AUDIT_TRAIL_ORIGINAL_PKG_ID, else the Audit Trail package of rebasedNetwork (original id, as Move types name it)",
  anchorWriter: "ANCHOR_WRITER_ADDRESS, else deploy/identity/testnet.json: the domain DID's controller address",
  reportSigner: "REPORT_SIGNER_DID, else deploy/identity/testnet.json: domain (the DID that signs audit.report)",
};

const ABOUT =
  "The console's pinned verifier config, generated by console/scripts/make-fixture.mjs from the stack's " +
  "configuration. Proofs are checked against these pins only, never against pins served by an API.";

/** The Tangle pins from a private Tangle protocol config (targetNetworkName, milestonePublicKeyCount, publicKeyRanges). */
export function tanglePins(protocol) {
  if (typeof protocol?.targetNetworkName !== "string") throw new Error("protocol config has no targetNetworkName");
  const keys = [...new Set((protocol.publicKeyRanges ?? []).map((r) => "0x" + String(r.key).toLowerCase().replace(/^0x/, "")))];
  if (!keys.length || keys.some((k) => !HEX32.test(k))) throw new Error("protocol config has no usable coordinator keys");
  const threshold = protocol.milestonePublicKeyCount;
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > keys.length) throw new Error(`bad milestonePublicKeyCount ${threshold}`);
  return { network: protocol.targetNetworkName, trustedCoordinatorKeys: keys, threshold };
}

/**
 * The verifier pins from the stack's configuration. `protocol` is the private
 * Tangle's protocol config (or `tangle`, the Tangle pins already committed),
 * `identity` the deploy/identity file of the Rebased network.
 *
 * @param {{ protocol?: any, tangle?: any, identity: any, trailId: string | null, env?: Record<string, string | undefined> }} opts
 */
export function makeVerifierConfig({ protocol, tangle, identity, trailId, env = {} }) {
  const t = protocol !== undefined ? tanglePins(protocol) : tangle;
  if (!t) throw new Error("no Tangle pins: give a protocol config or the committed pins");
  if (typeof identity?.network !== "string") throw new Error("identity file has no network");
  if (trailId !== null && !HEX32.test(trailId)) throw new Error(`bad anchor trail id ${trailId}`);
  return {
    about: ABOUT,
    sources: SOURCES,
    network: t.network,
    trustedCoordinatorKeys: [...t.trustedCoordinatorKeys],
    threshold: t.threshold,
    rebasedNetwork: identity.network,
    trailId,
    ...rebasedPins(identity, env),
    reportSigner: reportSigner(identity, env),
  };
}

export function writeVerifierConfig(file = VERIFIER_FILE, stackConfig = STACK_CONFIG, identityFile = IDENTITY_FILE, env = process.env) {
  const current = existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : null;
  const haveStack = existsSync(stackConfig);
  if (!haveStack && !current) return null;
  const trailId = env.ANCHOR_TRAIL_ID?.toLowerCase() ?? current?.trailId ?? null;
  const cfg = makeVerifierConfig({
    ...(haveStack ? { protocol: JSON.parse(readFileSync(stackConfig, "utf8")).protocol } : { tangle: current }),
    identity: JSON.parse(readFileSync(identityFile, "utf8")),
    trailId,
    env,
  });
  writeFileSync(file, JSON.stringify(cfg, null, 2) + "\n");
  return { cfg, fromStack: haveStack };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const text = writeFixture();
  const f = JSON.parse(text);
  console.log(`wrote ${OUT_FILE}: ${f.graph.nodes.length} nodes, ${f.graph.milestones.length} milestones`);
  const out = writeVerifierConfig();
  if (!out) console.log(`no stack protocol config at ${STACK_CONFIG} and no committed ${VERIFIER_FILE}`);
  else {
    const { cfg, fromStack } = out;
    console.log(
      `wrote ${VERIFIER_FILE}: ${cfg.network}, ${cfg.trustedCoordinatorKeys.length} keys, threshold ${cfg.threshold}` +
        `${fromStack ? "" : ` (Tangle pins kept: no protocol config at ${STACK_CONFIG})`}; ` +
        `trail ${cfg.trailId ?? "none"}, RPC ${cfg.rebasedRpc ?? "none"}, writer ${cfg.anchorWriter ?? "none"}`,
    );
  }
  try {
    const demo = writeForgedDemo();
    console.log(`wrote ${DEMO_FILE}: forged milestone claiming record ${demo.record} of the pinned trail`);
  } catch (e) {
    console.warn(`no forged-milestone demo: ${e.message}`);
  }
}
