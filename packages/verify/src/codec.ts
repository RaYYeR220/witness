/**
 * Binary codec for IOTA Stardust blocks, tagged data and milestones
 * (TIP-24 block, TIP-23 tagged data, TIP-29 milestone). Little-endian
 * integers, pure functions. Error messages match the Python reference.
 */

import { blake2b256 } from "./blake2b.js";

export const PAYLOAD_TAGGED_DATA = 5;
export const PAYLOAD_MILESTONE = 7;
export const SIG_ED25519 = 0;
export const ID_LEN = 32;
export const PUBKEY_LEN = 32;
export const SIG_LEN = 64;
/** Milestone option types (TIP-29 / TIP-34). */
export const OPT_RECEIPT = 0;
export const OPT_PROTOCOL_PARAMS = 1;
/** Treasury Transaction payload (TIP-34), carried inside a receipt. */
export const PAYLOAD_TREASURY_TRANSACTION = 4;
const TREASURY_INPUT_TYPE = 1;
const TREASURY_OUTPUT_TYPE = 2;
const ED25519_ADDRESS_TYPE = 0;
const TAIL_TX_HASH_LEN = 49;

/** The bytes do not form a valid Stardust structure. */
export class DecodeError extends Error {
  override name = "DecodeError";
}

export interface TaggedData {
  kind: "tagged_data";
  tag: Uint8Array;
  data: Uint8Array;
}

export interface Ed25519Sig {
  publicKey: Uint8Array;
  signature: Uint8Array;
}

export interface MilestoneEssence {
  index: number;
  timestamp: number;
  protocolVersion: number;
  previousMilestoneId: Uint8Array;
  parents: Uint8Array[];
  inclusionMerkleRoot: Uint8Array;
  appliedMerkleRoot: Uint8Array;
  metadata: Uint8Array;
  /** Raw bytes after the optionsCount byte. */
  options: Uint8Array;
}

export interface MilestonePayload {
  kind: "milestone";
  essence: MilestoneEssence;
  /** Essence as signed and hashed (no payload type word). */
  essenceBytes: Uint8Array;
  signatures: Ed25519Sig[];
}

export interface OtherPayload {
  kind: "other";
  type: number;
  raw: Uint8Array;
}

export type Payload = TaggedData | MilestonePayload | OtherPayload;

export interface Block {
  protocolVersion: number;
  parents: Uint8Array[];
  payload: Payload | null;
  nonce: bigint;
}

class Reader {
  pos = 0;

  constructor(
    readonly buf: Uint8Array,
    readonly what: string,
  ) {}

  take(n: number, field: string): Uint8Array {
    if (this.pos + n > this.buf.length) {
      throw new DecodeError(
        `${this.what}: truncated reading ${field} ` +
          `(need ${n} bytes at offset ${this.pos}, have ${this.buf.length - this.pos})`,
      );
    }
    const out = this.buf.slice(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  /** Unsigned little-endian integer of 1, 2 or 4 bytes. */
  uint(n: 1 | 2 | 4, field: string): number {
    const b = this.take(n, field);
    let v = 0;
    for (let i = n - 1; i >= 0; i--) v = v * 256 + b[i]!;
    return v;
  }

  u64(field: string): bigint {
    const b = this.take(8, field);
    let v = 0n;
    for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[i]!);
    return v;
  }

  finish(): void {
    if (this.pos !== this.buf.length) {
      throw new DecodeError(`${this.what}: ${this.buf.length - this.pos} trailing bytes after offset ${this.pos}`);
    }
  }
}

function readParents(r: Reader): Uint8Array[] {
  const count = r.uint(1, "parentsCount");
  const out: Uint8Array[] = [];
  for (let i = 0; i < count; i++) out.push(r.take(ID_LEN, `parent[${i}]`));
  return out;
}

/** Advance past one milestone option, validating its layout. */
function scanOption(r: Reader, i: number): void {
  const name = `option[${i}]`;
  const otype = r.uint(1, `${name}.type`);
  if (otype === OPT_PROTOCOL_PARAMS) {
    r.take(4 + 1, `${name}.targetMilestoneIndex/protocolVersion`);
    r.take(r.uint(2, `${name}.paramsLength`), `${name}.params`);
  } else if (otype === OPT_RECEIPT) {
    r.take(4 + 1, `${name}.migratedAt/final`);
    const funds = r.uint(2, `${name}.fundsCount`);
    for (let j = 0; j < funds; j++) {
      r.take(TAIL_TX_HASH_LEN, `${name}.funds[${j}].tailTransactionHash`);
      const atype = r.uint(1, `${name}.funds[${j}].addressType`);
      if (atype !== ED25519_ADDRESS_TYPE) {
        throw new DecodeError(`milestone ${name}.funds[${j}]: unsupported address type ${atype}`);
      }
      r.take(32 + 8, `${name}.funds[${j}].pubKeyHash/deposit`);
    }
    const ptype = r.uint(4, `${name}.treasury.payloadType`);
    if (ptype !== PAYLOAD_TREASURY_TRANSACTION) {
      throw new DecodeError(`milestone ${name}: expected treasury transaction, got ${ptype}`);
    }
    if (r.uint(1, `${name}.treasury.inputType`) !== TREASURY_INPUT_TYPE) {
      throw new DecodeError(`milestone ${name}: bad treasury input type`);
    }
    r.take(32, `${name}.treasury.milestoneId`);
    if (r.uint(1, `${name}.treasury.outputType`) !== TREASURY_OUTPUT_TYPE) {
      throw new DecodeError(`milestone ${name}: bad treasury output type`);
    }
    r.take(8, `${name}.treasury.amount`);
  } else {
    throw new DecodeError(`milestone ${name}: unsupported option type ${otype}`);
  }
}

function readEssence(r: Reader): [MilestoneEssence, Uint8Array] {
  const begin = r.pos;
  const index = r.uint(4, "index");
  const timestamp = r.uint(4, "timestamp");
  const protocolVersion = r.uint(1, "protocolVersion");
  const previousMilestoneId = r.take(ID_LEN, "previousMilestoneId");
  const parents = readParents(r);
  const inclusionMerkleRoot = r.take(32, "inclusionMerkleRoot");
  const appliedMerkleRoot = r.take(32, "appliedMerkleRoot");
  const metadata = r.take(r.uint(2, "metadataLength"), "metadata");
  const count = r.uint(1, "optionsCount");
  const optStart = r.pos;
  for (let i = 0; i < count; i++) scanOption(r, i);
  const options = r.buf.slice(optStart, r.pos);
  const essence: MilestoneEssence = {
    index,
    timestamp,
    protocolVersion,
    previousMilestoneId,
    parents,
    inclusionMerkleRoot,
    appliedMerkleRoot,
    metadata,
    options,
  };
  return [essence, r.buf.slice(begin, r.pos)];
}

function readMilestone(r: Reader): MilestonePayload {
  const [essence, essenceBytes] = readEssence(r);
  const signatures: Ed25519Sig[] = [];
  const count = r.uint(1, "signaturesCount");
  for (let i = 0; i < count; i++) {
    const stype = r.uint(1, `signature[${i}].type`);
    if (stype !== SIG_ED25519) throw new DecodeError(`milestone signature[${i}]: unsupported type ${stype}`);
    const publicKey = r.take(PUBKEY_LEN, `signature[${i}].publicKey`);
    const signature = r.take(SIG_LEN, `signature[${i}].signature`);
    signatures.push({ publicKey, signature });
  }
  return { kind: "milestone", essence, essenceBytes, signatures };
}

/** Milestone id: BLAKE2b-256 of the essence (payload type word excluded). */
export function milestoneId(essenceBytes: Uint8Array): Uint8Array {
  return blake2b256(essenceBytes);
}

/** Parse a milestone payload including its leading u32 type word. */
export function parseMilestonePayload(rawPayload: Uint8Array): MilestonePayload {
  const r = new Reader(rawPayload, "milestone payload");
  const ptype = r.uint(4, "payload type");
  if (ptype !== PAYLOAD_MILESTONE) throw new DecodeError(`milestone payload: expected type 7, got ${ptype}`);
  const out = readMilestone(r);
  r.finish();
  return out;
}

/** Decode a bare essence by wrapping it as a milestone payload with no signatures. */
export function parseMilestoneEssence(essenceBytes: Uint8Array): MilestoneEssence {
  const wrapped = new Uint8Array(4 + essenceBytes.length + 1);
  wrapped[0] = PAYLOAD_MILESTONE;
  wrapped.set(essenceBytes, 4);
  return parseMilestonePayload(wrapped).essence;
}

function parsePayload(raw: Uint8Array): Payload {
  const r = new Reader(raw, "payload");
  const ptype = r.uint(4, "payload type");
  if (ptype === PAYLOAD_TAGGED_DATA) {
    const tag = r.take(r.uint(1, "tagLength"), "tag");
    const data = r.take(r.uint(4, "dataLength"), "data");
    r.finish();
    return { kind: "tagged_data", tag, data };
  }
  if (ptype === PAYLOAD_MILESTONE) {
    const out = readMilestone(r);
    r.finish();
    return out;
  }
  return { kind: "other", type: ptype, raw };
}

export function parseBlock(raw: Uint8Array): Block {
  const r = new Reader(raw, "block");
  const protocolVersion = r.uint(1, "protocolVersion");
  const parents = readParents(r);
  const plen = r.uint(4, "payloadLength");
  const payload = plen ? parsePayload(r.take(plen, "payload")) : null;
  const nonce = r.u64("nonce");
  r.finish();
  return { protocolVersion, parents, payload, nonce };
}

/** Block id: BLAKE2b-256 of the raw block bytes. */
export function blockId(raw: Uint8Array): Uint8Array {
  return blake2b256(raw);
}
