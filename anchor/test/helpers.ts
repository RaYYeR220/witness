import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { b64urlDecode, blake2b256, fromHex, jcsBytes, toHex, verifyEnvelope, type Envelope, type KeyInfo } from "@witness/verify";
import { checkpointRecordData, checkpointRecordMetadata, type MilestoneSource } from "../src/checkpoint.js";
import type { Window } from "../src/checkpoint.js";
import type { WindowVerifier } from "../src/hornet.js";
import { MirrorSigner, RelayError, type UploadOutcome } from "../src/mirror.js";
import type { Checkpoint } from "../src/checkpoint.js";
import type { LoopTrail } from "../src/loop.js";
import type { AppendResult, PendingAppend, ResumeResult, TrailRecord } from "../src/trail.js";

export const TRAIL = "0x" + "7".repeat(64);
export const WRITER = "0x" + "d4".repeat(32);
export const ANCHOR_DID = "did:iota:testnet:0x" + "a1".repeat(32);

const dirs: string[] = [];
export function tmpDir(): string {
  const d = mkdtempSync(path.join(os.tmpdir(), "anchor-loop-"));
  dirs.push(d);
  return d;
}
export function cleanupDirs(): void {
  dirs.splice(0).forEach((d) => rmSync(d, { recursive: true, force: true }));
}

export const mid = (i: number) => blake2b256(new TextEncoder().encode(`ms-${i}`));

/** Milestone source over an in-memory Tangle with milestones 1..latest indexed. */
export class FakeTangle implements MilestoneSource {
  latest: number;
  /** False: the source does not report msgCount (like the HORNET stub). */
  msgCount = true;
  calls: [number, number][] = [];
  constructor(latest: number) {
    this.latest = latest;
  }
  async milestones(from: number, to: number) {
    this.calls.push([from, to]);
    if (to > this.latest) return { complete: false, ids: [], msgCount: null };
    const ids = [];
    for (let i = from; i <= to; i++) ids.push(mid(i));
    return { complete: true, ids, msgCount: this.msgCount ? to - from : null };
  }
}

interface StoredRecord {
  data: string;
  metadata: string | null;
  addedBy: string;
  addedAtMs: number;
  tx: string;
}

/**
 * In-memory Audit Trail with the durable-append semantics of TrailService: an append persists the
 * signed transaction first; `crashNext` makes it die after that (the transaction may or may not
 * reach the chain, see `landOnCrash`).
 */
export class FakeTrail implements LoopTrail {
  records: StoredRecord[] = [{ data: '{"kind":"witness.trail"}', metadata: "sha256:00", addedBy: WRITER, addedAtMs: 1, tx: "TxCreate" }];
  appends = 0;
  crashNext = false;
  landOnCrash = true;
  failReads = false;
  #n = 0;
  #inflight = new Map<string, { data: string; metadata: string | null }>();
  #landed = new Map<string, AppendResult>();

  async ensureTrail(): Promise<string> {
    return TRAIL;
  }

  #land(digest: string, data: string, metadata: string | null): AppendResult {
    this.records.push({ data, metadata, addedBy: WRITER, addedAtMs: 1000 + this.records.length, tx: digest });
    this.appends++;
    const r: AppendResult = {
      trailId: TRAIL,
      recordIndex: this.records.length - 1,
      tx: digest,
      timestampMs: 1000 + this.records.length - 1,
      addedBy: WRITER,
      metadata,
      gasNanos: "5000000",
      links: { tx: `tx:${digest}`, trail: `obj:${TRAIL}` },
    };
    this.#landed.set(digest, r);
    return r;
  }

  async appendRecordDurable(
    trailId: string,
    data: string | Uint8Array,
    opts: { metadata?: string | null; persist: (p: PendingAppend) => void | Promise<void> },
  ): Promise<AppendResult> {
    if (trailId !== TRAIL) throw new Error("wrong trail");
    const digest = `Tx${++this.#n}`;
    const metadata = opts.metadata ?? null;
    await opts.persist({ digest, txBytes: "AAAA", signature: "BBBB", trailId, metadata });
    if (this.crashNext) {
      this.crashNext = false;
      if (this.landOnCrash) this.#land(digest, data as string, metadata);
      else this.#inflight.set(digest, { data: data as string, metadata });
      throw new Error("socket hang up");
    }
    return this.#land(digest, data as string, metadata);
  }

  resumeCalls: string[] = [];
  resumeError: Error | null = null;
  async resumeAppend(p: PendingAppend): Promise<ResumeResult> {
    this.resumeCalls.push(p.digest);
    if (this.resumeError) throw this.resumeError;
    const done = this.#landed.get(p.digest);
    if (done) return { status: "done", result: done };
    const inflight = this.#inflight.get(p.digest);
    if (inflight) {
      this.#inflight.delete(p.digest);
      return { status: "done", result: this.#land(p.digest, inflight.data, inflight.metadata) };
    }
    return { status: "dropped", reason: "never executed" };
  }

  async trailHead(): Promise<{ records: number; tail: number | null }> {
    if (this.failReads) throw new Error("rpc down");
    return { records: this.records.length, tail: this.records.length - 1 };
  }

  async readRecord(trailId: string, index: number): Promise<TrailRecord | null> {
    if (this.failReads) throw new Error("rpc down");
    const r = this.records[index];
    if (!r || trailId !== TRAIL) return null;
    return {
      trailId,
      recordIndex: index,
      data: r.data,
      dataKind: "text",
      metadata: r.metadata,
      tag: null,
      addedAtMs: r.addedAtMs,
      addedBy: r.addedBy,
      tx: null,
      links: { trail: `obj:${trailId}`, tx: null },
    };
  }

  async findRecordTx(_trailId: string, index: number): Promise<string | null> {
    return this.records[index]?.tx ?? null;
  }

  link(kind: "object" | "txblock", id: string): string {
    return `https://explorer.test/${kind}/${id}`;
  }

  /** Writes a checkpoint record directly, as an earlier deployment would have. */
  seed(seq: number, cp: Checkpoint, hash: string, addedBy = WRITER): void {
    this.records.push({ data: checkpointRecordData(cp), metadata: checkpointRecordMetadata(seq, hash), addedBy, addedAtMs: 5000 + seq, tx: `TxSeed${seq}` });
  }
}

export function makeSigner(did = ANCHOR_DID): { signer: MirrorSigner; keyInfo: KeyInfo; jwk: Record<string, string> } {
  const { privateKey } = generateKeyPairSync("ed25519");
  const jwk: Record<string, string> = { ...(privateKey.export({ format: "jwk" }) as Record<string, string>), kid: `${did}#sig-1`, alg: "EdDSA" };
  const keyInfo: KeyInfo = { kid: jwk.kid!, ed25519Public: b64urlDecode(jwk.x!)!, x25519Public: null, revokedAtMs: null };
  return { signer: MirrorSigner.fromJwk(jwk), keyInfo, jwk };
}

/**
 * witness-relay stand-in: verifies producer envelopes, refuses a seq that is not newer than the
 * issuer's last one (REPLAY), keeps receipts. `down` refuses connections; `loseReply` accepts the
 * message but loses the answer.
 */
export class FakeRelay {
  posted: { tag: string; env: Envelope; blockId: string }[] = [];
  down = false;
  loseReply = false;
  /** Seqs the relay claims without a receipt (sent to a node that then failed). */
  claimWithoutReceipt = new Set<number>();
  #last = new Map<string, number>();
  constructor(readonly keys: KeyInfo[]) {}

  async upload(tag: string, env: Envelope): Promise<UploadOutcome> {
    if (this.down) throw new RelayError("relay unreachable: ECONNREFUSED");
    const chk = verifyEnvelope(env, tag, (kid) => this.keys.find((k) => k.kid === kid));
    if (chk.verdict !== "PRODUCER_SIGNED") return { kind: "rejected", status: 403, error: chk.reason ?? chk.verdict };
    const last = this.#last.get(chk.iss!) ?? 0;
    if (chk.seq! <= last) return { kind: "replay", error: `seq ${chk.seq} is not newer than the last from ${chk.iss}` };
    this.#last.set(chk.iss!, chk.seq!);
    if (this.claimWithoutReceipt.delete(chk.seq!)) throw new RelayError("relay unreachable: reset");
    const blockId = toHex(blake2b256(jcsBytes(env)));
    this.posted.push({ tag, env, blockId });
    if (this.loseReply) {
      this.loseReply = false;
      throw new RelayError("relay unreachable: timeout");
    }
    return { kind: "posted", blockId };
  }

  async findReceipt(iss: string, tag: string, seq: number): Promise<string | null> {
    return this.posted.find((p) => p.tag === tag && p.env.iss === iss && p.env.seq === seq)?.blockId ?? null;
  }
}

/** Window verifier stand-in: passes unless `fail` is set; records what it was asked. */
export class FakeVerifier implements WindowVerifier {
  fail: Error | null = null;
  calls: { window: Window; ids: number; prevId: string | null }[] = [];
  async verifyWindow(window: Window, ids: readonly Uint8Array[], prevId: Uint8Array | null): Promise<void> {
    this.calls.push({ window, ids: ids.length, prevId: prevId ? toHex(prevId) : null });
    if (this.fail) throw this.fail;
  }
}

export const POLICY_HASH = fromHex("0x" + "ab".repeat(32));
