/**
 * The landing page's sample: a real bundle from the shared test vectors, its
 * forged twin, and the inputs each one is checked against (see
 * scripts/make-fixture.mjs). This module only hands out inputs; every verdict
 * comes from @witness/verify at runtime.
 *
 * The DID document and the anchor record are recorded copies from the test
 * vectors. Nothing here reads the DID registry or IOTA Rebased live, and the
 * page says so next to the checks.
 */

import {
  fromHex,
  isEnvelope,
  JsonNumber,
  parseBlock,
  parseJson,
  toHex,
  type VerifierConfig,
  type VerifyOptions,
} from "@witness/verify";

import fixture from "@/fixtures/landing-sample.json";

export type Which = "sample" | "forged";

interface TrustInputs {
  case: string;
  bundle: Record<string, unknown> & { block: { id: string; raw: string } };
  config: VerifierConfig & { trustedCoordinatorKeys: string[] };
  /** Recorded copies of the issuer's DID document, by DID (test vectors). */
  recordedDids: Record<string, unknown>;
  /** Recorded copy of the anchor record the bundle points at (test vectors). */
  recordedAnchor: unknown;
}

export interface GraphNode {
  id: string;
  kind: "block" | "milestone";
  role?: Which;
  virtual?: boolean;
  msIndex?: number;
  tag?: string | null;
  parents: string[];
  raw: string | null;
  confirmedBy: string | null;
}

export interface GraphMilestone {
  index: number;
  id: string;
  nodeId: string;
  universe: "shared" | Which;
  timestamp: number;
  essence: string;
  signatures: { pk: string; sig: string }[];
  cone: string[];
}

export interface LandingFixture {
  sample: TrustInputs;
  forged: TrustInputs;
  graph: { nodes: GraphNode[]; milestones: GraphMilestone[] };
}

export const landing = fixture as unknown as LandingFixture;

export function inputs(which: Which): TrustInputs {
  return landing[which];
}

/** The block's raw bytes as the bundle carries them. */
export function rawBytes(which: Which): Uint8Array {
  return fromHex(landing[which].bundle.block.raw);
}

export function claimedId(which: Which): string {
  return landing[which].bundle.block.id;
}

/** The bundle as text, optionally with the block bytes replaced (for "flip a byte"). */
export function bundleText(which: Which, raw?: Uint8Array): string {
  const bundle = landing[which].bundle;
  const block = raw ? { ...bundle.block, raw: toHex(raw) } : bundle.block;
  return JSON.stringify({ ...bundle, block });
}

/**
 * The pins the test vectors check this sample against, including their test
 * anchor trail. Not the console's pinned config (verify/pinned.ts): the
 * sample predates the stack's trail.
 */
export function sampleConfig(which: Which): VerifierConfig {
  const c = landing[which].config;
  return { ...c, trustedCoordinatorKeys: [...c.trustedCoordinatorKeys] };
}

/**
 * The two lookups the ladder needs, answered from recorded copies the way the
 * test vectors define them: the issuer's DID document as the vectors' resolver
 * returns it, and the anchor record as the vectors' fetcher returns it. These
 * are not live reads of the DID registry or of IOTA Rebased.
 */
export function recordedLookups(which: Which): Pick<VerifyOptions, "resolveDid" | "fetchAnchorRecord"> {
  const t = landing[which];
  return {
    resolveDid: (did: string) => structuredClone(t.recordedDids[did] ?? null),
    fetchAnchorRecord: () => structuredClone(t.recordedAnchor),
  };
}

/** Run options that check the sample against its own pins and recorded copies. */
export function sampleRun(which: Which) {
  return { config: sampleConfig(which), ...recordedLookups(which) };
}

export interface TrustMessage {
  score: number | null;
  /** The score exactly as written in the envelope, e.g. "0.82". */
  scoreText: string | null;
  entity: string | null;
  issuer: string | null;
  kid: string | null;
  tag: string | null;
  parents: number;
}

/** What the block says about itself, read from its bytes (null fields if they do not parse). */
export function readTrustMessage(raw: Uint8Array): TrustMessage {
  const out: TrustMessage = { score: null, scoreText: null, entity: null, issuer: null, kid: null, tag: null, parents: 0 };
  let block;
  try {
    block = parseBlock(raw);
  } catch {
    return out;
  }
  out.parents = block.parents.length;
  const p = block.payload;
  if (!p || p.kind !== "tagged_data") return out;
  try {
    out.tag = new TextDecoder("utf-8", { fatal: true }).decode(p.tag);
    const env = parseJson(new TextDecoder("utf-8", { fatal: true }).decode(p.data));
    if (!isEnvelope(env)) return out;
    const e = env as Record<string, unknown>;
    const body = e.body as Record<string, unknown> | undefined;
    const score = body?.score;
    if (score instanceof JsonNumber) {
      out.score = score.value;
      out.scoreText = score.literal;
    } else if (typeof score === "number") {
      out.score = score;
      out.scoreText = String(score);
    }
    out.entity = typeof body?.id === "string" ? body.id : null;
    out.issuer = typeof e.iss === "string" ? e.iss : null;
    out.kid = typeof e.kid === "string" ? e.kid : null;
  } catch {
    /* not UTF-8 or not JSON: the fields stay null */
  }
  return out;
}

export interface ByteField {
  name: string;
  from: number;
  to: number;
}

/**
 * Field layout of a TIP-24 block with a tagged-data payload, read from its
 * length prefixes. Used to say which part of the block a byte belongs to.
 */
export function blockFields(raw: Uint8Array): ByteField[] {
  const f: ByteField[] = [];
  const u32 = (o: number) => (raw[o]! | (raw[o + 1]! << 8) | (raw[o + 2]! << 16) | (raw[o + 3]! << 24)) >>> 0;
  try {
    f.push({ name: "protocol version", from: 0, to: 1 });
    const n = raw[1]!;
    f.push({ name: "parent count", from: 1, to: 2 });
    for (let i = 0; i < n; i++) f.push({ name: `parent ${i + 1}`, from: 2 + 32 * i, to: 34 + 32 * i });
    let o = 2 + 32 * n;
    f.push({ name: "payload length", from: o, to: o + 4 });
    o += 4;
    f.push({ name: "payload type", from: o, to: o + 4 });
    const tlen = raw[o + 4]!;
    f.push({ name: "tag length", from: o + 4, to: o + 5 });
    f.push({ name: "tag", from: o + 5, to: o + 5 + tlen });
    o += 5 + tlen;
    const dlen = u32(o);
    f.push({ name: "data length", from: o, to: o + 4 });
    f.push({ name: "signed envelope", from: o + 4, to: o + 4 + dlen });
    o += 4 + dlen;
    f.push({ name: "nonce", from: o, to: raw.length });
  } catch {
    return [{ name: "block", from: 0, to: raw.length }];
  }
  return f;
}

export function fieldOf(fields: ByteField[], i: number): ByteField | null {
  return fields.find((x) => i >= x.from && i < x.to) ?? null;
}

/** Index of the hundredths digit of the envelope's score, the most telling byte to flip. */
export function scoreDigitIndex(raw: Uint8Array, fields: ByteField[]): number {
  const env = fields.find((x) => x.name === "signed envelope");
  if (!env) return Math.floor(raw.length / 2);
  const text = new TextDecoder().decode(raw.subarray(env.from, env.to));
  const at = text.indexOf('"score":');
  if (at < 0) return env.from;
  const m = /^"score":\s*-?\d+\.(\d)(\d)?/.exec(text.slice(at));
  const offset = m ? m[0].length - 1 : 8;
  return env.from + new TextEncoder().encode(text.slice(0, at)).length + offset;
}

export const shortHex = (h: string) => (h.length > 14 ? `${h.slice(0, 6)}…${h.slice(-4)}` : h);

export const hexOf = toHex;
