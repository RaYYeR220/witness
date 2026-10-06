import { decodeCheckpointRecord, type Checkpoint } from "./checkpoint.js";
import { log } from "./log.js";
import type { StateStore } from "./state.js";
import type { TrailService } from "./trail.js";

export type ReaderTrail = Pick<TrailService, "readRecord" | "findRecordTx" | "trailHead" | "link">;

/** Body of `GET /checkpoints/:seq`, consumed by the indexer's R11 and the console. */
export interface CheckpointReply {
  seq: number;
  checkpoint: Checkpoint;
  checkpointHash: string;
  tx: string | null;
  record: number;
  /** IOTA Rebased network of the trail. */
  network: string;
  trail: string;
  /** Always "chain": the checkpoint was read from the trail for this request. */
  source: "chain";
  /** Address that added the record; verifiers compare it with the anchor's writer. */
  addedBy: string;
  timestampMs: number;
  links: { tx: string | null; trail: string };
}

export class CheckpointNotFound extends Error {
  constructor(seq: number) {
    super(`no checkpoint ${seq}`);
    this.name = "CheckpointNotFound";
  }
}

/** The chain could not be read, or its record is not the checkpoint the state points at. */
export class ChainReadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ChainReadError";
  }
}

export interface CheckpointSummary {
  seq: number;
  from: { index: number; id: string };
  to: { index: number; id: string };
  msRoot: string;
  checkpointHash: string;
  record: number;
  tx: string | null;
  timestampMs: number;
  mirror: { status: string; blockId?: string; envelopeSeq?: number } | null;
  mirrorError: string | null;
  links: { tx: string | null; trail: string };
}

export interface CheckpointList {
  network: string;
  trail: string | null;
  /** Record count of the trail read from the chain for this request; null when unreadable. */
  chain: { records: number; tail: number | null } | null;
  chainError?: string;
  pending: { seq: number; tx: string; since: string } | null;
  mirror: { lastSeq: number; lastBlockId: string | null } | null;
  checkpoints: CheckpointSummary[];
}

/**
 * Read side of the checkpoints. The state file only says which record holds checkpoint `seq`;
 * the checkpoint itself is read from the trail on every request, and a failed read is an error,
 * never a stale copy.
 */
export class CheckpointReader {
  readonly #store: StateStore;
  readonly #trail: ReaderTrail;
  readonly #network: string;
  readonly #fallbackTrail: () => string | null;

  constructor(store: StateStore, trail: ReaderTrail, network: string, fallbackTrail: () => string | null = () => null) {
    this.#store = store;
    this.#trail = trail;
    this.#network = network;
    this.#fallbackTrail = fallbackTrail;
  }

  async get(seq: number): Promise<CheckpointReply> {
    const entry = this.#store.load()?.checkpoints.find((c) => c.seq === seq);
    if (!entry) throw new CheckpointNotFound(seq);
    let rec;
    try {
      rec = await this.#trail.readRecord(entry.trail, entry.record, { withTx: false });
    } catch (err) {
      throw new ChainReadError(`reading record ${entry.record} of ${entry.trail} failed: ${(err as Error).message}`);
    }
    if (!rec) throw new ChainReadError(`record ${entry.record} of ${entry.trail} is not on chain`);
    let decoded;
    try {
      decoded = decodeCheckpointRecord(rec.data, rec.metadata, seq);
    } catch (err) {
      throw new ChainReadError(`record ${entry.record} of ${entry.trail}: ${(err as Error).message}`);
    }
    if (decoded.checkpointHash !== entry.checkpointHash) {
      log.warn("state disagrees with the chain; serving the chain", { seq, record: entry.record, state: entry.checkpointHash, chain: decoded.checkpointHash });
    }
    let tx = entry.tx;
    if (!tx) tx = await this.#trail.findRecordTx(entry.trail, entry.record).catch(() => null);
    return {
      seq,
      checkpoint: decoded.checkpoint,
      checkpointHash: decoded.checkpointHash,
      tx,
      record: entry.record,
      network: this.#network,
      trail: entry.trail,
      source: "chain",
      addedBy: rec.addedBy,
      timestampMs: rec.addedAtMs,
      links: { tx: tx ? this.#trail.link("txblock", tx) : null, trail: this.#trail.link("object", entry.trail) },
    };
  }

  async list(limit = 100): Promise<CheckpointList> {
    const state = this.#store.load();
    const trail = state?.trail ?? this.#fallbackTrail();
    let chain: CheckpointList["chain"] = null;
    let chainError: string | undefined;
    if (trail) {
      try {
        chain = await this.#trail.trailHead(trail);
      } catch (err) {
        chainError = `trail unreadable: ${(err as Error).message}`;
      }
    }
    const checkpoints = (state?.checkpoints ?? [])
      .slice(-limit)
      .reverse()
      .map(
        (c): CheckpointSummary => ({
          seq: c.seq,
          from: c.checkpoint.from,
          to: c.checkpoint.to,
          msRoot: c.checkpoint.msRoot,
          checkpointHash: c.checkpointHash,
          record: c.record,
          tx: c.tx,
          timestampMs: c.timestampMs,
          mirror:
            c.mirror === null
              ? null
              : c.mirror.status === "posted"
                ? { status: "posted", blockId: c.mirror.blockId, envelopeSeq: c.mirror.envelopeSeq }
                : { status: c.mirror.status },
          mirrorError: c.mirrorError ?? null,
          links: { tx: c.tx ? this.#trail.link("txblock", c.tx) : null, trail: this.#trail.link("object", c.trail) },
        }),
      );
    return {
      network: this.#network,
      trail,
      chain,
      ...(chainError ? { chainError } : {}),
      pending: state?.pending ? { seq: state.pending.seq, tx: state.pending.append.digest, since: state.pending.since } : null,
      mirror: state ? state.mirror : null,
      checkpoints,
    };
  }
}
