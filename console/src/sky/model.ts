/**
 * The sky: the real Tangle of the landing sample, drawn as stars, inside a
 * field of decorative stars.
 *
 * Real stars come from the fixture (blocks of milestones 370..374, the sample
 * trust message and its forged twin, their milestones) with their real parent
 * edges. Decorative stars are scenery: they have no id, no edges and no
 * verdict, and nothing on the page ever describes them as data.
 *
 * World units: the real constellation spans roughly x -0.86..0.86, y -0.35..0.35.
 */

import { ed25519Verify, fromHex, milestoneId, toHex } from "@witness/verify";

import { landing, type GraphNode, type Which } from "@/verify/sample";

export type StarKind = "block" | "milestone" | "deco";

export interface Star {
  i: number;
  kind: StarKind;
  real: boolean;
  id: string | null;
  role: Which | null;
  msIndex: number | null;
  /** A milestone with no block in the sample: the node is the milestone itself. */
  virtual: boolean;
  tag: string | null;
  raw: Uint8Array | null;
  parents: number[];
  approvers: number[];
  /** Star of the milestone that confirmed this block. */
  confirmedBy: number | null;
  /** Index of the milestone whose cone holds this block. */
  window: number | null;
  wx: number;
  wy: number;
  /** Depth 0.25..1: brightness and parallax. */
  z: number;
  /** Twinkle phase 0..1. */
  tw: number;
  /** Dust is the faint far layer that fills the whole page. */
  dust: boolean;
}

export interface MilestoneFacts {
  index: number;
  id: string;
  universe: "shared" | Which;
  star: number;
  cone: number[];
  /** Computed here: BLAKE2b-256 of the essence equals the id. */
  idMatches: boolean;
  /** Computed here: signatures by the pinned coordinator keys that verify over the milestone id. */
  sigValid: number;
  sigTotal: number;
  threshold: number;
}

export interface SkyModel {
  stars: Star[];
  realCount: number;
  byId: Map<string, number>;
  sample: number;
  forged: number;
  /** Milestone 374 star of each bundle. */
  msOf: Record<Which, number>;
  milestones: MilestoneFacts[];
  /** Real approval edges [child, parent]. */
  edges: [number, number][];
}

export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function gauss(r: () => number): number {
  let u = 0;
  let v = 0;
  while (u === 0) u = r();
  while (v === 0) v = r();
  return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
}

/** A value in -1..1 taken from the block id itself, so the layout is a function of the data. */
function laneOf(id: string): number {
  const b = parseInt(id.slice(4, 8), 16);
  return (b / 0xffff) * 2 - 1;
}

function blank(i: number, kind: StarKind): Star {
  return {
    i,
    kind,
    real: kind !== "deco",
    id: null,
    role: null,
    msIndex: null,
    virtual: false,
    tag: null,
    raw: null,
    parents: [],
    approvers: [],
    confirmedBy: null,
    window: null,
    wx: 0,
    wy: 0,
    z: 1,
    tw: 0,
    dust: false,
  };
}

export function buildSky(opts: { mobile: boolean; seed?: number }): SkyModel {
  const { nodes, milestones } = landing.graph;
  const stars: Star[] = [];
  const byId = new Map<string, number>();
  const nodeById = new Map<string, GraphNode>(nodes.map((n) => [n.id, n]));

  // ---- real stars, in time order: the cones of 370..374 (white-flag order), then milestone 374
  const sampleMs = milestones.find((m) => m.universe === "sample")!;
  const forgedMs = milestones.find((m) => m.universe === "forged")!;
  const shared = milestones.filter((m) => m.universe === "shared").sort((a, b) => a.index - b.index);
  const windows = [...shared, sampleMs];
  let rank = 0;
  const placed: { id: string; rank: number; window: number }[] = [];
  for (const ms of windows) {
    for (const id of ms.cone) placed.push({ id, rank: rank++, window: ms.index });
    rank += 0.9; // a little air between milestone windows
  }
  placed.push({ id: sampleMs.nodeId, rank: rank - 0.5, window: sampleMs.index });
  const span = placed[placed.length - 1]!.rank;

  const add = (n: GraphNode): Star => {
    const s = blank(stars.length, n.kind);
    s.id = n.id;
    s.role = n.role ?? null;
    s.msIndex = n.msIndex ?? null;
    s.virtual = !!n.virtual;
    s.tag = n.tag ?? null;
    s.raw = n.raw ? fromHex(n.raw) : null;
    s.tw = (parseInt(n.id.slice(-4), 16) / 0xffff) % 1;
    byId.set(n.id, s.i);
    stars.push(s);
    return s;
  };

  for (const p of placed) {
    const s = add(nodeById.get(p.id)!);
    s.window = p.window;
    s.wx = -0.86 + (p.rank / span) * 1.72;
    const isMs = s.kind === "milestone";
    s.wy = isMs ? laneOf(s.id!) * 0.05 : laneOf(s.id!) * 0.3;
    s.z = isMs || s.role ? 1 : 0.72 + 0.28 * ((laneOf(s.id!) + 1) / 2);
  }
  // keep the sample just above the centre line, so its twin can sit below it
  const sample = byId.get(landing.sample.bundle.block.id)!;
  stars[sample]!.wy = -0.08;

  // the forged twin and its milestone: a reflection of the sample and of milestone 374, just below them
  const forgedNode = add(nodeById.get(landing.forged.bundle.block.id)!);
  forgedNode.window = forgedMs.index;
  forgedNode.wx = stars[sample]!.wx + 0.03;
  forgedNode.wy = 0.1;
  const msSample = byId.get(sampleMs.nodeId)!;
  const msForged = add(nodeById.get(forgedMs.nodeId)!);
  msForged.window = forgedMs.index;
  msForged.wx = stars[msSample]!.wx + 0.02;
  msForged.wy = 0.12;
  stars[msSample]!.wy = -0.06;

  relax(stars, 0.075);

  // ---- edges and confirmation, all from the fixture
  const edges: [number, number][] = [];
  for (const s of stars) {
    const n = nodeById.get(s.id!)!;
    for (const pid of n.parents) {
      const p = byId.get(pid);
      if (p === undefined) continue;
      s.parents.push(p);
      stars[p]!.approvers.push(s.i);
      edges.push([s.i, p]);
    }
    s.confirmedBy = n.confirmedBy ? (byId.get(n.confirmedBy) ?? null) : null;
  }
  const realCount = stars.length;

  // ---- milestone facts, computed with the library against the pinned coordinator keys
  const cfg = landing.sample.config;
  const pinned = new Set(cfg.trustedCoordinatorKeys.map((k) => k.toLowerCase()));
  const facts: MilestoneFacts[] = milestones.map((m) => {
    const essence = fromHex(m.essence);
    const mid = milestoneId(essence);
    const valid = new Set<string>();
    for (const sig of m.signatures) {
      if (!pinned.has(sig.pk) || valid.has(sig.pk)) continue;
      if (ed25519Verify(fromHex(sig.pk), fromHex(sig.sig), mid)) valid.add(sig.pk);
    }
    return {
      index: m.index,
      id: m.id,
      universe: m.universe,
      star: byId.get(m.nodeId)!,
      cone: m.cone.map((id) => byId.get(id)!).filter((i) => i !== undefined),
      idMatches: toHex(mid) === m.id,
      sigValid: valid.size,
      sigTotal: m.signatures.length,
      threshold: cfg.threshold,
    };
  });

  // ---- decorative stars: a river of scenery around the constellation, and far dust
  const r = mulberry32(opts.seed ?? 0x5e1f374);
  const nBand = opts.mobile ? 230 : 440;
  const nDust = opts.mobile ? 120 : 260;
  const tooClose = (x: number, y: number, d: number) => {
    for (let k = 0; k < realCount; k++) {
      const s = stars[k]!;
      if (Math.abs(s.wx - x) < d && Math.abs(s.wy - y) < d && Math.hypot(s.wx - x, s.wy - y) < d) return true;
    }
    return false;
  };
  let guard = 0;
  for (let k = 0; k < nBand && guard < 20000; guard++) {
    const x = (r() * 2 - 1) * 1.3;
    const y = Math.max(-0.75, Math.min(0.75, gauss(r) * 0.25 + Math.sin(x * 2.1) * 0.05));
    if (tooClose(x, y, 0.05)) continue;
    const s = blank(stars.length, "deco");
    s.wx = x;
    s.wy = y;
    s.z = 0.25 + r() * 0.75;
    s.tw = r();
    stars.push(s);
    k++;
  }
  for (let k = 0; k < nDust; k++) {
    const s = blank(stars.length, "deco");
    s.wx = (r() * 2 - 1) * 4.6;
    s.wy = (r() * 2 - 1) * 2.4;
    if (tooClose(s.wx, s.wy, 0.05)) continue;
    s.z = 0.15 + r() * 0.35;
    s.tw = r();
    s.dust = true;
    stars.push(s);
  }

  return {
    stars,
    realCount,
    byId,
    sample,
    forged: forgedNode.i,
    msOf: { sample: msSample, forged: msForged.i },
    milestones: facts,
    edges,
  };
}

/** Push apart real stars closer than `d` (a few deterministic passes, y only, so time order stays). */
function relax(stars: Star[], d: number) {
  for (let pass = 0; pass < 24; pass++) {
    let moved = false;
    for (let a = 0; a < stars.length; a++) {
      for (let b = a + 1; b < stars.length; b++) {
        const A = stars[a]!;
        const B = stars[b]!;
        const dx = A.wx - B.wx;
        const dy = A.wy - B.wy;
        const dist = Math.hypot(dx, dy);
        if (dist >= d) continue;
        const push = (d - dist) / 2 + 0.002;
        const dir = dy === 0 ? (a % 2 ? 1 : -1) : Math.sign(dy);
        const pinA = A.role !== null || A.kind === "milestone";
        const pinB = B.role !== null || B.kind === "milestone";
        if (!pinA) A.wy += dir * push * (pinB ? 2 : 1);
        if (!pinB) B.wy -= dir * push * (pinA ? 2 : 1);
        moved = true;
      }
    }
    if (!moved) break;
  }
}

/**
 * The shortest chain of approvals from star `i` forward to the milestone that
 * confirmed it (breadth-first over approvers inside the same milestone window).
 */
export function pathToMilestone(model: SkyModel, i: number): number[] | null {
  const stars = model.stars;
  const start = stars[i];
  if (!start || !start.real) return null;
  const goal = start.confirmedBy;
  if (goal === null) return start.kind === "milestone" ? [i] : null;
  const prev = new Map<number, number>();
  const seen = new Set([i]);
  const queue = [i];
  while (queue.length) {
    const c = queue.shift()!;
    if (c === goal) break;
    for (const a of stars[c]!.approvers) {
      if (seen.has(a)) continue;
      const sa = stars[a]!;
      if (a !== goal && sa.confirmedBy !== goal) continue;
      seen.add(a);
      prev.set(a, c);
      queue.push(a);
    }
  }
  if (!seen.has(goal)) return null;
  const out = [goal];
  while (out[0] !== i) out.unshift(prev.get(out[0]!)!);
  return out;
}

export function milestoneFacts(model: SkyModel, star: number): MilestoneFacts | null {
  return model.milestones.find((m) => m.star === star) ?? null;
}
