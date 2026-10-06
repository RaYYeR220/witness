import {
  buildNextCheckpoint,
  checkpointRecordData,
  checkpointRecordMetadata,
  decodeCheckpointRecord,
  RECORD_KIND,
  type CheckpointParams,
  type MilestoneSource,
  type Window,
} from "./checkpoint.js";
import { log } from "./log.js";
import { postMirror, type MirrorSigner, type RelayClient } from "./mirror.js";
import { chainProblem, emptyState, type AnchorState, type CheckpointEntry, type StateStore } from "./state.js";
import type { AppendResult, PendingAppend, ResumeResult, TrailRecord, TrailService } from "./trail.js";

/** What the loop needs from the trail backend (a TrailService, or a fake in tests). */
export type LoopTrail = Pick<TrailService, "ensureTrail" | "appendRecordDurable" | "resumeAppend" | "trailHead" | "readRecord" | "findRecordTx">;

export interface LoopDeps {
  /** IOTA Rebased network name of the trail (`testnet`, `mainnet`). */
  network: string;
  /** Address that writes the records; recovery only adopts records it added. */
  writer: string;
  trail: LoopTrail;
  source: MilestoneSource;
  relay: Pick<RelayClient, "upload" | "findReceipt">;
  signer: MirrorSigner;
  store: StateStore;
  params: CheckpointParams;
  every: number;
  startIndex: number;
  pollMs: number;
  /** Development only: anchor windows whose message count the source does not report, as 0. */
  allowMissingMsgCount?: boolean;
  /** Most records scanned backwards when rebuilding a lost state file from the chain. */
  recoverMax?: number;
}

export type TickResult =
  | {
      status: "anchored";
      seq: number;
      window: Window;
      checkpointHash: string;
      record: number;
      tx: string;
      mirrored: boolean;
      mirrorError?: string;
    }
  | { status: "waiting"; window: Window; reason: string; cause: "incomplete" | "no-msgcount" }
  | { status: "error"; stage: "trail" | "state" | "pending" | "source" | "append"; error: string };

export interface LoopStatus {
  running: boolean;
  lastRunAt: string | null;
  lastResult: TickResult | null;
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function entryFrom(seq: number, cp: CheckpointEntry["checkpoint"], hash: string, r: AppendResult): CheckpointEntry {
  return {
    seq,
    checkpoint: cp,
    checkpointHash: hash,
    trail: r.trailId,
    record: r.recordIndex,
    tx: r.tx,
    timestampMs: r.timestampMs,
    addedBy: r.addedBy,
    anchoredAt: new Date().toISOString(),
    mirror: null,
  };
}

/**
 * The anchoring loop: every tick it settles a pending append, posts missing mirrors, then anchors
 * the next complete window. Each step is saved before the next one starts, so a restart at any
 * point resumes without anchoring a window twice:
 *
 * - the add_record transaction is signed and saved before it is submitted; on restart the saved
 *   transaction is looked up by digest or submitted again (identical bytes), never rebuilt;
 * - a checkpoint is recorded as anchored before its mirror is posted; unmirrored checkpoints are
 *   mirrored, in order, on the next tick.
 */
export class AnchorLoop {
  readonly #d: LoopDeps;
  #running: Promise<TickResult> | null = null;
  #timer: NodeJS.Timeout | null = null;
  #stopped = true;
  #lastRunAt: string | null = null;
  #lastResult: TickResult | null = null;
  #warnedWindow: number | null = null;

  constructor(deps: LoopDeps) {
    this.#d = deps;
  }

  status(): LoopStatus {
    return { running: this.#running !== null, lastRunAt: this.#lastRunAt, lastResult: this.#lastResult };
  }

  /** Runs one tick now; joins the tick already running instead of starting a second one. */
  runOnce(): Promise<TickResult> {
    this.#running ??= this.#tick()
      .then((r) => {
        this.#lastResult = r;
        return r;
      })
      .finally(() => {
        this.#lastRunAt = new Date().toISOString();
        this.#running = null;
      });
    return this.#running;
  }

  start(): void {
    if (!this.#stopped) return;
    this.#stopped = false;
    const loop = async () => {
      const r = await this.runOnce().catch((err: unknown): TickResult => ({ status: "error", stage: "state", error: message(err) }));
      if (r.status === "error") log.warn("anchor tick failed", { stage: r.stage, error: r.error });
      if (!this.#stopped) this.#timer = setTimeout(loop, this.#d.pollMs);
    };
    void loop();
  }

  async stop(): Promise<void> {
    this.#stopped = true;
    if (this.#timer) clearTimeout(this.#timer);
    this.#timer = null;
    await this.#running?.catch(() => undefined);
  }

  async #tick(): Promise<TickResult> {
    const d = this.#d;
    let trailId: string;
    try {
      trailId = await d.trail.ensureTrail();
    } catch (err) {
      return { status: "error", stage: "trail", error: message(err) };
    }

    let state: AnchorState | null;
    try {
      state = d.store.load();
      if (state === null) {
        state = await this.#recover(trailId);
        d.store.save(state);
      }
    } catch (err) {
      return { status: "error", stage: "state", error: message(err) };
    }
    if (state.network !== d.network || state.trail !== trailId) {
      return {
        status: "error",
        stage: "trail",
        error: `${d.store.path} belongs to trail ${state.trail} on ${state.network}, not ${trailId} on ${d.network}; move it aside to start a new chain`,
      };
    }

    if (state.pending) {
      try {
        await this.#settlePending(state);
      } catch (err) {
        return { status: "error", stage: "pending", error: `append of checkpoint ${state.pending.seq} still unsettled: ${message(err)}` };
      }
    }

    await this.#mirrorBacklog(state);

    const last = state.checkpoints.at(-1) ?? null;
    let next;
    try {
      next = await buildNextCheckpoint(d.source, d.params, last, d.startIndex, d.every, { allowMissingMsgCount: d.allowMissingMsgCount });
    } catch (err) {
      return { status: "error", stage: "source", error: message(err) };
    }
    if (next.status === "waiting") {
      if (next.cause === "no-msgcount" && this.#warnedWindow !== next.window.from) {
        this.#warnedWindow = next.window.from;
        log.warn("window not anchored: the milestone source does not report msgCount", { from: next.window.from, to: next.window.to });
      }
      return next;
    }

    const seq = (last?.seq ?? 0) + 1;
    const { checkpoint, checkpointHash } = next;
    const st = state;
    let appended: AppendResult;
    try {
      appended = await d.trail.appendRecordDurable(trailId, checkpointRecordData(checkpoint), {
        metadata: checkpointRecordMetadata(seq, checkpointHash),
        persist: (append: PendingAppend) => {
          st.pending = { seq, checkpoint, checkpointHash, append, since: new Date().toISOString() };
          d.store.save(st);
        },
      });
    } catch (err) {
      // If the transaction was persisted, the next tick settles it before building anything new.
      return { status: "error", stage: "append", error: message(err) };
    }
    const entry = entryFrom(seq, checkpoint, checkpointHash, appended);
    state.checkpoints.push(entry);
    state.pending = null;
    d.store.save(state);
    log.info("checkpoint anchored", { seq, from: checkpoint.from.index, to: checkpoint.to.index, record: entry.record, tx: entry.tx, checkpointHash });

    await this.#mirrorBacklog(state);
    return {
      status: "anchored",
      seq,
      window: next.window,
      checkpointHash,
      record: entry.record,
      tx: appended.tx,
      mirrored: entry.mirror !== null,
      ...(entry.mirrorError ? { mirrorError: entry.mirrorError } : {}),
    };
  }

  async #settlePending(state: AnchorState): Promise<void> {
    const p = state.pending!;
    const r: ResumeResult = await this.#d.trail.resumeAppend(p.append);
    if (r.status === "done") {
      const entry = entryFrom(p.seq, p.checkpoint, p.checkpointHash, r.result);
      state.checkpoints.push(entry);
      log.info("pending checkpoint append confirmed", { seq: p.seq, record: entry.record, tx: entry.tx });
    } else {
      // The transaction never added a record; the same window is built again from scratch.
      log.warn("pending checkpoint append dropped", { seq: p.seq, tx: p.append.digest, reason: r.reason });
    }
    state.pending = null;
    this.#d.store.save(state);
  }

  /** Posts the mirrors still missing, oldest first, stopping at the first failure (the `prev` chain is ordered). */
  async #mirrorBacklog(state: AnchorState): Promise<void> {
    const d = this.#d;
    for (const entry of state.checkpoints) {
      if (entry.mirror !== null) continue;
      if (!entry.tx) {
        entry.mirrorError = "transaction of the record unknown";
        d.store.save(state);
        return;
      }
      let out;
      try {
        out = await postMirror(entry, state.mirror, d.signer, d.relay, d.network);
      } catch (err) {
        out = { ok: false as const, error: message(err) };
      }
      if (!out.ok) {
        entry.mirrorError = out.error;
        if (out.burntSeq !== undefined) state.mirror.lastSeq = Math.max(state.mirror.lastSeq, out.burntSeq);
        d.store.save(state);
        log.warn("checkpoint mirror not posted; retrying next tick", { seq: entry.seq, error: out.error });
        return;
      }
      entry.mirror = { status: "posted", blockId: out.blockId, envelopeSeq: out.envelopeSeq, at: new Date().toISOString(), ...(out.recovered ? { recovered: true } : {}) };
      entry.mirrorError = null;
      state.mirror = { lastSeq: out.envelopeSeq, lastBlockId: out.blockId };
      d.store.save(state);
      log.info("checkpoint mirrored", { seq: entry.seq, blockId: out.blockId, envelopeSeq: out.envelopeSeq });
    }
  }

  /**
   * Rebuilds the state when its file is missing: checkpoint records this writer added to the
   * trail are read back (newest first, down to seq 1) so the chain continues instead of starting
   * over. Whether they were mirrored is unknown, so they are not mirrored again.
   */
  async #recover(trailId: string): Promise<AnchorState> {
    const d = this.#d;
    const state = emptyState(d.network, trailId);
    const head = await d.trail.trailHead(trailId);
    if (head.tail === null) return state;
    const found: CheckpointEntry[] = [];
    const max = d.recoverMax ?? 1000;
    for (let i = head.tail, scanned = 0; i >= 0 && scanned < max; i--, scanned++) {
      const rec: TrailRecord | null = await d.trail.readRecord(trailId, i, { withTx: false });
      if (!rec || rec.addedBy !== d.writer || rec.metadata === null) continue;
      let meta: { kind?: unknown; seq?: unknown } | null = null;
      try {
        meta = JSON.parse(rec.metadata);
      } catch {
        continue;
      }
      if (meta?.kind !== RECORD_KIND || typeof meta.seq !== "number") continue;
      const { checkpoint, checkpointHash } = decodeCheckpointRecord(rec.data, rec.metadata, meta.seq);
      found.push({
        seq: meta.seq,
        checkpoint,
        checkpointHash,
        trail: trailId,
        record: rec.recordIndex,
        tx: await d.trail.findRecordTx(trailId, rec.recordIndex),
        timestampMs: rec.addedAtMs,
        addedBy: rec.addedBy,
        anchoredAt: new Date(rec.addedAtMs).toISOString(),
        mirror: { status: "unknown", at: new Date().toISOString() },
      });
      if (meta.seq === 1) break;
    }
    if (found.length === 0) return state;
    found.sort((a, b) => a.seq - b.seq);
    const problem = chainProblem(found);
    if (problem) throw new Error(`state file ${d.store.path} is missing and the trail's checkpoints do not form one chain (${problem})`);
    state.checkpoints = found;
    state.mirror.lastSeq = found.at(-1)!.seq;
    log.warn("state file missing; checkpoint chain rebuilt from the trail", { checkpoints: found.length, last: found.at(-1)!.seq });
    return state;
  }
}
