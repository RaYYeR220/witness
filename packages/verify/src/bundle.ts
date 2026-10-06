/**
 * `witness-proof/v1` bundles and the offline verifier ladder (Python `bundle`).
 *
 * A bundle carries raw block bytes, the milestone essence and its signatures,
 * the Merkle audit path, a DID document snapshot and, optionally, an anchor
 * checkpoint. The verifier trusts only its pinned `VerifierConfig` plus two
 * trusted lookups (on-chain anchor record, DID registry) and recomputes every
 * id and root from raw bytes; claims written into the bundle (block id aside,
 * which step 1 checks) are cross-checked, never relied on. The DID snapshot is
 * for offline display only: it never authenticates a signer, it can only
 * contradict the registry.
 *
 * Ladder: block_hash, inclusion, milestone_signatures, envelope, anchor. Each
 * step is ok (true), failed (false) or not evaluated (null).
 */

import { blake2b256 } from "./blake2b.js";
import { bytesEqual, fromHex, isBytes, isCanonicalHex, toHex, utf8DecodeStrict } from "./bytes.js";
import { checkpointHash, checkpointShapeError } from "./checkpoint.js";
import {
  DecodeError,
  milestoneId,
  parseBlock,
  parseMilestoneEssence,
  PUBKEY_LEN,
  SIG_LEN,
  type Ed25519Sig,
  type MilestoneEssence,
} from "./codec.js";
import { ed25519Verify } from "./ed25519.js";
import { isEnvelope, verifyEnvelope, type KeyInfo } from "./envelope.js";
import { get, has, isDict, isNone, isUint, JsonParseError, parseJson, pyRepr, type Json, type JsonObject } from "./json.js";
import { verifyPath, type PathStep } from "./merkle.js";
import { FORGED, MALFORMED, PRODUCER_SIGNED, RELAY_ATTESTED } from "./verdicts.js";

export type StepName = "block_hash" | "inclusion" | "milestone_signatures" | "envelope" | "anchor";
export type Overall = "VALID" | "INVALID" | "PARTIAL";
export const STEP_NAMES: readonly StepName[] = ["block_hash", "inclusion", "milestone_signatures", "envelope", "anchor"];
export const BUNDLE_VERSION = 1;
export const UNRESOLVED_SIGNER = "signer identity not resolved (bundle snapshot is unauthenticated)";

/** What the verifier pins out of band; everything else comes from the bundle. */
export interface VerifierConfig {
  network: string;
  /** Coordinator Ed25519 public keys, as hex strings or raw bytes. */
  trustedCoordinatorKeys: Iterable<string | Uint8Array>;
  threshold: number;
  rebasedNetwork?: string | null;
  trailId?: string | null;
  /** HTTPS JSON-RPC of an IOTA Rebased fullnode to read the anchor record from (see `makeRebasedFetcher`). */
  rebasedRpc?: string | null;
  /** Audit Trail package id as it appears in the trail object's Move type. */
  auditTrailPackage?: string | null;
  /** Address that writes the anchor's trail records; when pinned, a record by anyone else fails step 5. */
  anchorWriter?: string | null;
}

export interface StepResult {
  name: StepName;
  ok: boolean | null;
  detail: string;
}

export interface Ladder {
  steps: StepResult[];
  overall: Overall;
}

type Awaitable<T> = T | Promise<T>;

export interface VerifyOptions {
  /**
   * Returns the on-chain checkpoint record (`{checkpointHash}` and/or
   * `{checkpoint}`, plus `addedBy` when `anchorWriter` is pinned; null when
   * the trail has no such record) for the bundle's `anchor` section;
   * `makeRebasedFetcher` builds one that reads the pinned chain.
   * It must read record `anchor.rebased.record` from the verifier's pinned
   * trail on the pinned Rebased network and ignore the bundle's `tx` and
   * `network`. Only called once checkpoint, membership path and pins have
   * passed locally.
   */
  fetchAnchorRecord?: ((anchor: JsonObject) => Awaitable<unknown>) | null;
  /** Returns the issuer's DID document from the trusted registry (`{doc, version, keys}`) or null. */
  resolveDid?: ((did: string) => Awaitable<unknown>) | null;
  /**
   * Called with a frozen copy of each step as soon as it is decided, in ladder
   * order; awaited when it returns a promise. A callback that throws or
   * rejects aborts the ladder: `verifyBundle` rejects with that error.
   */
  onStep?: ((step: Readonly<StepResult>) => void | Promise<void>) | null;
}

/** The step failed; the message is its detail. */
class Fail extends Error {}

/** The step cannot be evaluated; the message is its detail. */
class Skip extends Error {}

/** A DID document snapshot is not usable (Python raises ValueError). */
export class DidSnapshotError extends Error {
  override name = "DidSnapshotError";
}

type Outcome = [boolean | null, string];

interface PinnedConfig {
  network: string;
  trusted: Set<string>;
  threshold: unknown;
  rebasedNetwork: string | null;
  trailId: string | null;
  rebasedRpc: string | null;
  auditTrailPackage: string | null;
  anchorWriter: string | null;
}

function normalizeConfig(cfg: VerifierConfig): PinnedConfig {
  if (typeof cfg !== "object" || cfg === null) throw new TypeError("verifier config must be an object");
  if (typeof cfg.network !== "string") throw new TypeError("verifier config: network must be a string");
  const keys = cfg.trustedCoordinatorKeys;
  if (keys === null || typeof keys !== "object" || !(Symbol.iterator in keys) || typeof keys === "string") {
    throw new TypeError("verifier config: trustedCoordinatorKeys must be a list of public keys");
  }
  const trusted = new Set<string>();
  for (const k of keys) {
    if (typeof k === "string") trusted.add(toHex(fromHex(k)));
    else if (isBytes(k)) trusted.add(toHex(k));
    else throw new TypeError("verifier config: trustedCoordinatorKeys entries must be hex strings or bytes");
  }
  const optional = (v: unknown, name: string): string | null => {
    if (isNone(v)) return null;
    if (typeof v !== "string") throw new TypeError(`verifier config: ${name} must be a string or null`);
    return v;
  };
  return {
    network: cfg.network,
    trusted,
    threshold: cfg.threshold,
    rebasedNetwork: optional(cfg.rebasedNetwork, "rebasedNetwork"),
    trailId: optional(cfg.trailId, "trailId"),
    rebasedRpc: optional(cfg.rebasedRpc, "rebasedRpc"),
    auditTrailPackage: optional(cfg.auditTrailPackage, "auditTrailPackage"),
    anchorWriter: optional(cfg.anchorWriter, "anchorWriter"),
  };
}

// ---------------------------------------------------------------- DID snapshot

function keyBytes(entry: JsonObject): Uint8Array | null {
  const pk = get(entry, "publicKeyHex");
  if (typeof pk !== "string") return null;
  try {
    const raw = fromHex(pk);
    return raw.length === 32 ? raw : null;
  } catch {
    return null;
  }
}

/** `kid` -> key, optionally as it stood at `atMs` (epoch ms); the current key when omitted. */
export type TimedKeyResolver = (kid: string, atMs?: number | null) => KeyInfo | null;

/**
 * Every key entry of a DID document in the anchor service's resolve shape, per
 * kid (Python `bundle.snapshot_keys`): `{doc: {id}, version, keys: [{kid, type,
 * publicKeyHex, revokedAtMs}]}`. The lists cover the key history: a kid whose
 * key was replaced in place appears once per key, each entry with its own
 * revocation time (null while current), in document order. Fragment kids
 * (`#sig-1`) are expanded against `doc.id`; entries naming another DID are
 * ignored. Fails closed: a kid with any entry that cannot be read (unknown
 * type, bad key, bad revocation time) is left out entirely. Throws
 * `DidSnapshotError` if the document is not usable at all.
 */
export function snapshotKeys(snapshot: unknown): Map<string, KeyInfo[]> {
  const entries = isDict(snapshot) ? get(snapshot, "keys") : undefined;
  if (!isDict(snapshot) || !Array.isArray(entries)) {
    throw new DidSnapshotError("DID snapshot must be an object with a keys list");
  }
  const doc = get(snapshot, "doc");
  const rawDid = isDict(doc) ? get(doc, "id") : undefined;
  const did = typeof rawDid === "string" ? rawDid : null;
  const table = new Map<string, KeyInfo[]>();
  const unreadable = new Set<string>();
  for (const entry of entries) {
    if (!isDict(entry) || typeof get(entry, "kid") !== "string") continue;
    let kid = entry.kid as string;
    if (kid.startsWith("#") && did !== null) kid = did + kid;
    if (did !== null && kid.split("#")[0] !== did) continue;
    const type = get(entry, "type");
    const slot = type === "Ed25519" ? "ed" : type === "X25519" ? "x" : null;
    const publicKey = keyBytes(entry);
    const revoked = get(entry, "revokedAtMs");
    if (slot === null || publicKey === null || !(isNone(revoked) || isUint(revoked))) {
      unreadable.add(kid);
      continue;
    }
    const keys = table.get(kid) ?? [];
    keys.push({
      kid,
      ed25519Public: slot === "ed" ? publicKey : null,
      x25519Public: slot === "x" ? publicKey : null,
      revokedAtMs: isUint(revoked) ? revoked : null,
    });
    table.set(kid, keys);
  }
  for (const kid of unreadable) table.delete(kid);
  return table;
}

/**
 * The key in force at `atMs`, or the current one when `atMs` is null (Python
 * `bundle._in_force`). Valid at `atMs`: not revoked, or revoked at or after it.
 * Among the valid keys the one that expires first was in force; ties go to the
 * entry listed last. With nothing valid, the key revoked last, so the caller
 * sees the revocation instead of nothing.
 */
function inForce(keys: KeyInfo[], atMs: number | null): KeyInfo | null {
  if (keys.length === 0) return null;
  const expiry = (k: KeyInfo) => (k.revokedAtMs === null ? Infinity : k.revokedAtMs);
  const valid = keys.filter((k) => k.revokedAtMs === null || (atMs !== null && k.revokedAtMs >= atMs));
  const pool = valid.length > 0 ? valid : keys;
  // Scan from the last entry so ties keep the one listed last, as Python's min/max over reversed().
  let best = pool[pool.length - 1]!;
  for (let i = pool.length - 2; i >= 0; i--) {
    const k = pool[i]!;
    if (valid.length > 0 ? expiry(k) < expiry(best) : expiry(k) > expiry(best)) best = k;
  }
  return best;
}

/**
 * Key lookup over a DID document (see `snapshotKeys`), time-aware for replaced
 * keys (Python `bundle.snapshot_resolver`): `resolve(kid)` serves the current
 * key, `resolve(kid, atMs)` the key in force at that time. A kid listing both
 * an Ed25519 and an X25519 key gets both, each chosen by time; `revokedAtMs` is
 * the earlier revocation of the two. Throws `DidSnapshotError` if the document
 * is not usable.
 */
export function snapshotResolver(snapshot: unknown): TimedKeyResolver {
  const table = snapshotKeys(snapshot);
  return (kid: string, atMs: number | null = null) => {
    const keys = typeof kid === "string" ? table.get(kid) : undefined;
    if (keys === undefined || keys.length === 0) return null;
    const ed = inForce(keys.filter((k) => k.ed25519Public !== null), atMs);
    const x = inForce(keys.filter((k) => k.x25519Public !== null), atMs);
    const revoked = [ed, x].flatMap((k) => (k !== null && k.revokedAtMs !== null ? [k.revokedAtMs] : []));
    return {
      kid,
      ed25519Public: ed === null ? null : ed.ed25519Public,
      x25519Public: x === null ? null : x.x25519Public,
      revokedAtMs: revoked.length > 0 ? Math.min(...revoked) : null,
    };
  };
}

// ---------------------------------------------------------------- parsing helpers

function obj(v: unknown, what: string): JsonObject {
  if (!isDict(v)) throw new Fail(`${what} is missing or not an object`);
  return v;
}

/** Decode strict lowercase 0x-hex; anything a canonical builder would not emit fails. */
function hex(v: unknown, what: string, size?: number): Uint8Array {
  if (typeof v !== "string") throw new Fail(`${what} is missing or not a hex string`);
  if (!isCanonicalHex(v)) {
    try {
      fromHex(v);
    } catch {
      throw new Fail(`${what} is not valid hex`);
    }
    throw new Fail(`${what}: non-canonical hex (expected lowercase with 0x prefix)`);
  }
  const raw = fromHex(v);
  if (size !== undefined && raw.length !== size) throw new Fail(`${what} must be ${size} bytes`);
  return raw;
}

function path(v: unknown, what: string): PathStep[] {
  if (!Array.isArray(v)) throw new Fail(`${what} is missing or not a list`);
  return v.map((s, i) => {
    const step = obj(s, `${what}[${i}]`);
    const side = get(step, "side");
    if (side !== "L" && side !== "R") throw new Fail(`${what}[${i}].side must be L or R`);
    return { side, hash: hex(get(step, "hash"), `${what}[${i}].hash`, 32) };
  });
}

const blockRaw = (b: JsonObject) => hex(get(obj(get(b, "block"), "block"), "raw"), "block.raw");
const claimedBlockId = (b: JsonObject) => hex(get(obj(get(b, "block"), "block"), "id"), "block.id", 32);

function essenceOf(b: JsonObject): [Uint8Array, MilestoneEssence] {
  const ms = obj(get(b, "milestone"), "milestone");
  const essenceBytes = hex(get(ms, "essence"), "milestone.essence");
  try {
    return [essenceBytes, parseMilestoneEssence(essenceBytes)];
  } catch (e) {
    if (e instanceof DecodeError) throw new Fail(`milestone essence does not parse: ${e.message}`);
    throw e;
  }
}

/**
 * Tagged-data JSON as Python's `json.loads` reads it; null only when the bytes
 * are not UTF-8 or not JSON. Text nested past `PY_JSON_MAX_DEPTH` (valid JSON
 * or not) throws RecursionError, which is rethrown so the step fails closed,
 * exactly as the reference does with the same cap (`bundle._json`).
 */
function jsonOf(data: Uint8Array): Json {
  let text: string;
  try {
    text = utf8DecodeStrict(data);
  } catch {
    return null;
  }
  try {
    return parseJson(text);
  } catch (e) {
    if (e instanceof JsonParseError) return null;
    throw e;
  }
}

function errorName(e: unknown): string {
  return e instanceof Error ? e.name : "Error";
}

// ---------------------------------------------------------------- steps

function stepBlockHash(b: JsonObject): Outcome {
  const raw = blockRaw(b);
  const claimed = claimedBlockId(b);
  const actual = blake2b256(raw);
  if (!bytesEqual(actual, claimed)) {
    return [false, `BLAKE2b-256(raw) is ${toHex(actual)}, bundle claims ${toHex(claimed)}`];
  }
  try {
    parseBlock(raw);
  } catch (e) {
    if (e instanceof DecodeError) return [false, `block does not parse: ${e.message}`];
    throw e;
  }
  return [true, `BLAKE2b-256(raw) = ${toHex(actual)}`];
}

function stepInclusion(b: JsonObject): Outcome {
  const bid = claimedBlockId(b);
  const [, essence] = essenceOf(b);
  const steps = path(get(obj(get(b, "inclusion"), "inclusion"), "path"), "inclusion.path");
  const root = essence.inclusionMerkleRoot;
  if (verifyPath(bid, steps, root)) return [true, `${steps.length}-step path reaches inclusionMerkleRoot ${toHex(root)}`];
  return [false, `Merkle path does not reach inclusionMerkleRoot ${toHex(root)}`];
}

/**
 * The distinct pinned coordinator keys (lowercase 0x hex) that validly signed milestone id `mid`:
 * the core of step 3, shared with services that check milestones outside a bundle.
 */
export function pinnedSignatures(mid: Uint8Array, signatures: readonly Ed25519Sig[], trusted: ReadonlySet<string>): Set<string> {
  const valid = new Set<string>();
  for (const { publicKey, signature } of signatures) {
    const key = toHex(publicKey);
    if (!trusted.has(key) || valid.has(key)) continue;
    if (ed25519Verify(publicKey, signature, mid)) valid.add(key);
  }
  return valid;
}

function stepSignatures(b: JsonObject, cfg: PinnedConfig): Outcome {
  const threshold = cfg.threshold;
  if (typeof threshold !== "number" || !Number.isInteger(threshold) || threshold < 1) {
    return [false, "verifier threshold must be at least 1"];
  }
  if (get(b, "network") !== cfg.network) {
    // Coordinator keys are pinned for one network; a foreign label is a foreign milestone.
    return [false, `bundle network ${pyRepr(get(b, "network"))} is not the pinned ${pyRepr(cfg.network)}`];
  }
  const [essenceBytes, essence] = essenceOf(b);
  const ms = obj(get(b, "milestone"), "milestone");
  const mid = milestoneId(essenceBytes);
  if (has(ms, "id") && !bytesEqual(hex(ms.id, "milestone.id", 32), mid)) {
    return [false, `milestone.id does not match BLAKE2b-256(essence) = ${toHex(mid)}`];
  }
  if (has(ms, "index") && !(isUint(ms.index) && ms.index === essence.index)) {
    return [false, `milestone.index does not match the essence index ${essence.index}`];
  }
  const sigs = get(ms, "signatures");
  if (!Array.isArray(sigs)) throw new Fail("milestone.signatures is missing or not a list");
  const parsed = sigs.map((item, i) => {
    const entry = obj(item, `milestone.signatures[${i}]`);
    return {
      publicKey: hex(get(entry, "pk"), `milestone.signatures[${i}].pk`, PUBKEY_LEN),
      signature: hex(get(entry, "sig"), `milestone.signatures[${i}].sig`, SIG_LEN),
    };
  });
  const valid = pinnedSignatures(mid, parsed, cfg.trusted);
  const summary = `${valid.size} valid signature(s) by pinned keys, threshold ${threshold}`;
  return [valid.size >= threshold, `milestone ${essence.index} ${toHex(mid)}: ${summary}`];
}

/** Keys of `iss` from the trusted resolver; null if it cannot be resolved. */
async function trustedKeys(resolveDid: VerifyOptions["resolveDid"], iss: string): Promise<TimedKeyResolver | null> {
  if (!resolveDid) return null;
  let resolved: unknown;
  try {
    resolved = await resolveDid(iss);
  } catch {
    return null; // an unreachable registry is not a verdict
  }
  if (isNone(resolved)) return null;
  const doc = isDict(resolved) ? get(resolved, "doc") : undefined;
  if (!isDict(doc) || get(doc, "id") !== iss) throw new Fail("resolved DID document does not belong to the issuer");
  try {
    return snapshotResolver(resolved);
  } catch (e) {
    if (e instanceof DidSnapshotError) throw new Fail(`resolved DID document is malformed: ${e.message}`);
    throw e;
  }
}

/** The bundle's snapshot is display-only, but it must not contradict the registry. */
function snapshotMatches(b: JsonObject, kid: string, trusted: KeyInfo, atMs: number | null): void {
  const section = get(b, "envelope");
  const snapshot = isDict(section) ? get(section, "didDoc") : undefined;
  if (isNone(snapshot)) return;
  let claimed: KeyInfo | null;
  try {
    claimed = snapshotResolver(snapshot)(kid, atMs);
  } catch (e) {
    if (!(e instanceof DidSnapshotError)) throw e;
    claimed = null;
  }
  const a = claimed?.ed25519Public ?? null;
  const t = trusted.ed25519Public;
  if (claimed === null || !(a === null ? t === null : t !== null && bytesEqual(a, t))) {
    throw new Fail("DID snapshot does not match resolved document");
  }
}

async function stepEnvelope(b: JsonObject, resolveDid: VerifyOptions["resolveDid"]): Promise<Outcome> {
  let block;
  try {
    block = parseBlock(blockRaw(b));
  } catch (e) {
    if (e instanceof Fail || e instanceof DecodeError) throw new Skip("not evaluated: block does not parse");
    throw e;
  }
  const payload = block.payload;
  if (payload === null || payload.kind !== "tagged_data") return [null, "block carries no tagged data"];
  const env = jsonOf(payload.data);
  if (!isEnvelope(env)) return [null, "unsigned legacy message"];
  let tag: string;
  try {
    tag = utf8DecodeStrict(payload.tag);
  } catch {
    return [false, `${FORGED}: block tag is not UTF-8`];
  }
  // Structure, tag binding and kid/iss binding do not depend on any key.
  const offline = verifyEnvelope(env, tag, () => null);
  if (offline.verdict === MALFORMED) return [false, `${offline.verdict}: ${offline.reason}`];
  const iss = env.iss as string;
  const kid = env.kid as string;
  if (env.tag !== tag || kid.split("#")[0] !== iss) return [false, `${offline.verdict}: ${offline.reason}`];
  // Signer keys come only from the trusted resolver, never from the bundle.
  const trusted = await trustedKeys(resolveDid, iss);
  if (trusted === null) return [null, UNRESOLVED_SIGNER];
  // A key replaced in place has several entries; use the one in force through the whole
  // inclusion second (milestone timestamps have second precision).
  let ts: number | null;
  try {
    ts = essenceOf(b)[1].timestamp;
  } catch (e) {
    if (!(e instanceof Fail)) throw e;
    ts = null;
  }
  const atMs = ts === null ? null : (ts + 1) * 1000;
  const check = verifyEnvelope(env, tag, (k) => trusted(k, atMs));
  if (check.verdict !== PRODUCER_SIGNED && check.verdict !== RELAY_ATTESTED) return [false, `${check.verdict}: ${check.reason}`];
  const info = trusted(kid, atMs);
  if (!info) return [false, "signing key not resolvable"]; // unreachable: verifyEnvelope just resolved it
  snapshotMatches(b, kid, info, atMs);
  if (info.revokedAtMs !== null) {
    if (ts === null) return [false, "key revoked; inclusion time unknown"];
    // A revocation anywhere in the inclusion second, or before it, revokes (Python `valid_through_second`).
    if (info.revokedAtMs < ts * 1000) return [false, "key revoked before inclusion"];
    if (info.revokedAtMs < (ts + 1) * 1000) return [false, "key revoked within the inclusion second"];
  }
  return [true, `${check.verdict} by ${kid}`];
}

function recordMatches(record: unknown, expected: Uint8Array): Outcome {
  if (!isDict(record) || !(has(record, "checkpointHash") || has(record, "checkpoint"))) {
    return [false, "anchor record malformed"];
  }
  if (has(record, "checkpointHash")) {
    let onchain: Uint8Array;
    try {
      onchain = hex(record.checkpointHash, "record.checkpointHash", 32);
    } catch (e) {
      if (e instanceof Fail) return [false, "anchor record malformed"];
      throw e;
    }
    if (!bytesEqual(onchain, expected)) return [false, "checkpoint does not match on-chain record"];
  }
  if (has(record, "checkpoint")) {
    let onchain: Uint8Array;
    try {
      onchain = checkpointHash(record.checkpoint);
    } catch {
      return [false, "anchor record malformed"]; // JCS rejects NaN, huge ints, ...
    }
    if (!bytesEqual(onchain, expected)) return [false, "checkpoint does not match on-chain record"];
  }
  return [true, `checkpoint ${toHex(expected)} matches the on-chain record`];
}

async function stepAnchor(b: JsonObject, cfg: PinnedConfig, fetch: VerifyOptions["fetchAnchorRecord"]): Promise<Outcome> {
  if (isNone(get(b, "anchor"))) return [null, "bundle carries no anchor"];
  const anchor = obj(get(b, "anchor"), "anchor");
  const cp = get(anchor, "checkpoint");
  const problem = checkpointShapeError(cp);
  if (problem !== null) return [false, `malformed checkpoint: ${problem}`];
  const checkpoint = cp as JsonObject;
  const from = checkpoint.from as JsonObject;
  const to = checkpoint.to as JsonObject;
  if (!(checkpoint.network === get(b, "network") && get(b, "network") === cfg.network)) {
    return [
      false,
      `checkpoint network ${pyRepr(checkpoint.network)} does not match bundle ` +
        `${pyRepr(get(b, "network"))} / pinned ${pyRepr(cfg.network)}`,
    ];
  }
  const [essenceBytes, essence] = essenceOf(b);
  const mid = milestoneId(essenceBytes);
  const msPath = path(get(anchor, "msPath"), "anchor.msPath");
  const inRange = (from.index as number) <= essence.index && essence.index <= (to.index as number);
  if (!(inRange && verifyPath(mid, msPath, fromHex(checkpoint.msRoot as string)))) {
    return [false, "milestone not in anchored checkpoint"];
  }
  const rebased = obj(get(anchor, "rebased"), "anchor.rebased");
  if (!isUint(get(rebased, "record"))) return [false, "anchor.rebased.record must be an unsigned integer"];
  if (cfg.trailId === null || cfg.rebasedNetwork === null) {
    return [null, "anchor not checked: verifier pins no Rebased trail"];
  }
  if (get(rebased, "trail") !== cfg.trailId) return [false, "anchor trail is not the pinned trail"];
  if (get(rebased, "network") !== cfg.rebasedNetwork) return [false, "anchor is not on the pinned Rebased network"];
  if (!fetch) return [null, "anchor not checked: no record fetcher"];
  let record: unknown;
  try {
    record = await fetch(anchor);
  } catch (e) {
    return [null, `anchor record unavailable (${errorName(e)})`]; // an unreachable chain is not a verdict
  }
  if (isNone(record)) return [null, "anchor record unavailable"];
  if (cfg.anchorWriter !== null && !(isDict(record) && get(record, "addedBy") === cfg.anchorWriter)) {
    return [false, "anchor record was not written by the pinned anchor writer"];
  }
  return recordMatches(record, checkpointHash(cp));
}

// ---------------------------------------------------------------- ladder

async function run(name: StepName, fn: () => Awaitable<Outcome>): Promise<StepResult> {
  try {
    const [ok, detail] = await fn();
    return { name, ok, detail };
  } catch (e) {
    if (e instanceof Fail) return { name, ok: false, detail: e.message };
    if (e instanceof Skip) return { name, ok: null, detail: e.message };
    // Hostile input must never escape as an exception.
    return { name, ok: false, detail: `malformed bundle (${errorName(e)})` };
  }
}

function overallOf(steps: StepResult[]): Overall {
  if (steps.some((s) => s.ok === false)) return "INVALID";
  if (steps.every((s) => s.ok === true)) return "VALID";
  return "PARTIAL";
}

/**
 * Run the five-step ladder over an already parsed bundle. Never rejects on bad
 * bundle input (a malformed `cfg` is a TypeError; a throwing `onStep` aborts).
 * Without `resolveDid` and `fetchAnchorRecord`, steps 4 and 5 can be at best
 * unevaluated (null): the bundle's own snapshot never authenticates a signer,
 * and an anchor is never confirmed without the on-chain record. Local
 * contradictions are red either way.
 *
 * The bundle must come from `parseJson`: `JSON.parse` folds `1.0` into `1` and
 * rounds big integers, so it would accept bundles the reference rejects. Code
 * that holds the raw text or bytes (the console, a fetch) should call
 * `verifyBundleText` instead.
 */
export async function verifyBundle(bundle: unknown, cfg: VerifierConfig, options: VerifyOptions = {}): Promise<Ladder> {
  const pinned = normalizeConfig(cfg);
  const { fetchAnchorRecord, resolveDid, onStep } = options;
  const steps: StepResult[] = [];
  const emit = async (step: StepResult) => {
    steps.push(step);
    // A copy, frozen, so a callback cannot touch what decides `overall`.
    if (onStep) await onStep(Object.freeze({ ...step }));
  };
  if (!isDict(bundle) || !isUint(get(bundle, "v")) || get(bundle, "v") !== BUNDLE_VERSION) {
    for (const name of STEP_NAMES) await emit({ name, ok: false, detail: "not a witness-proof/v1 bundle" });
    return { steps, overall: "INVALID" };
  }
  const b = bundle;
  await emit(await run("block_hash", () => stepBlockHash(b)));
  await emit(await run("inclusion", () => stepInclusion(b)));
  await emit(await run("milestone_signatures", () => stepSignatures(b, pinned)));
  await emit(await run("envelope", () => stepEnvelope(b, resolveDid)));
  await emit(await run("anchor", () => stepAnchor(b, pinned, fetchAnchorRecord)));
  return { steps, overall: overallOf(steps) };
}

/**
 * Parse a bundle the way the Python reference reads it (`parseJson`) and run
 * the ladder. Bytes must be UTF-8; a leading BOM is ignored. Input that is not
 * UTF-8, not JSON or nested past the parser's cap fails closed: five failed
 * steps, "not a witness-proof/v1 bundle".
 */
export async function verifyBundleText(
  input: string | Uint8Array,
  cfg: VerifierConfig,
  options: VerifyOptions = {},
): Promise<Ladder> {
  let bundle: unknown;
  try {
    const text = typeof input === "string" ? input : utf8DecodeStrict(input);
    bundle = parseJson(text.replace(/^\uFEFF/, ""));
  } catch {
    bundle = undefined;
  }
  return verifyBundle(bundle, cfg, options);
}
