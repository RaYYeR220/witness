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
  /** Transaction that added the record; `txVerified` says whether the chain confirmed it. */
  tx: string | null;
  txVerified: boolean;
  record: number;
  /** IOTA Rebased network of the trail. */
  network: string;
  trail: string;
  /** Always "chain": the checkpoint was read from the trail, at `readAtMs`. */
  source: "chain";
  readAtMs: number;
  /** Address that added the record (checked against the anchor's writer when it is known). */
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

/**
 * The chain could not be read, or its record is not the checkpoint the state points at. The
 * message is safe to return to clients; `detail` (raw node errors) is for the log only.
 */
export class ChainReadError extends Error {
  readonly detail: string | null;
  constructor(message: string, detail: string | null = null) {
    super(message);
    this.name = "ChainReadError";
    this.detail = detail;
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

export interface ReaderOptions {
  /** Address that must have added every checkpoint record; null when this instance does not know it. */
  writer?: string | null;
  /** The configured trail; a checkpoint the state places on another trail is refused. */
  trailId?: () => string | null;
  /** How long a chain read is served again (at most 10 s; 0 disables). */
  ttlMs?: number;
  now?: () => number;
}

export const MAX_READ_TTL_MS = 10_000;
const MAX_CACHED = 1024;

/**
 * Read side of the checkpoints. The state file only says which record holds checkpoint `seq`;
 * the checkpoint itself is read from the trail (served again for a few seconds at most, with
 * the time of the read), and a failed read is an error, never a stale copy.
 */
export class CheckpointReader {
  readonly #store: StateStore;
  readonly #trail: ReaderTrail;
  readonly #network: string;
  readonly #writer: string | null;
  readonly #trailId: () => string | null;
  readonly #ttlMs: number;
  readonly #now: () => number;
  readonly #cache = new Map<number, { expires: number; reply: CheckpointReply }>();
  readonly #inflight = new Map<number, Promise<CheckpointReply>>();
  /** Transactions confirmed on chain per `${trail}:${record}`; records never change. */
  readonly #txs = new Map<string, string>();

  constructor(store: StateStore, trail: ReaderTrail, network: string, opts: ReaderOptions = {}) {
    this.#store = store;
    this.#trail = trail;
    this.#network = network;
    this.#writer = opts.writer ?? null;
    this.#trailId = opts.trailId ?? (() => null);
    this.#ttlMs = Math.min(Math.max(opts.ttlMs ?? 5_000, 0), MAX_READ_TTL_MS);
    this.#now = opts.now ?? Date.now;
  }

  get(seq: number): Promise<CheckpointReply> {
    const hit = this.#cache.get(seq);
    if (hit && hit.expires > this.#now()) return Promise.resolve(hit.reply);
    if (hit) this.#cache.delete(seq);
    const pending = this.#inflight.get(seq);
    if (pending) return pending;
    const p = this.#read(seq)
      .then((reply) => {
        if (this.#ttlMs > 0) {
          if (this.#cache.size >= MAX_CACHED) this.#cache.delete(this.#cache.keys().next().value!);
          this.#cache.set(seq, { expires: this.#now() + this.#ttlMs, reply });
        }
        return reply;
      })
      .finally(() => this.#inflight.delete(seq));
    this.#inflight.set(seq, p);
    return p;
  }

  async #read(seq: number): Promise<CheckpointReply> {
    const entry = this.#store.load()?.checkpoints.find((c) => c.seq === seq);
    if (!entry) throw new CheckpointNotFound(seq);
    const configured = this.#trailId();
    if (configured && entry.trail !== configured) throw new ChainReadError(`checkpoint ${seq} is on trail ${entry.trail}, not the configured trail`);
    let rec;
    try {
      rec = await this.#trail.readRecord(entry.trail, entry.record, { withTx: false });
    } catch (err) {
      throw new ChainReadError("the trail could not be read from IOTA Rebased", (err as Error).message);
    }
    if (!rec) throw new ChainReadError(`record ${entry.record} of the trail is not on chain`);
    let decoded;
    try {
      decoded = decodeCheckpointRecord(rec.data, rec.metadata, seq);
    } catch (err) {
      throw new ChainReadError(`record ${entry.record} of the trail: ${(err as Error).message}`);
    }
    if (this.#writer && rec.addedBy !== this.#writer) {
      throw new ChainReadError(`record ${entry.record} was added by ${rec.addedBy}, not by the anchor's writer`);
    }
    if (decoded.checkpointHash !== entry.checkpointHash) {
      log.warn("state disagrees with the chain; serving the chain", { seq, record: entry.record, state: entry.checkpointHash, chain: decoded.checkpointHash });
    }
    const key = `${entry.trail}:${entry.record}`;
    let verified = this.#txs.get(key) ?? null;
    if (!verified) {
      const found = await this.#trail.findRecordTx(entry.trail, entry.record).catch((err: unknown) => {
        log.warn("could not look up the transaction of a checkpoint record", { seq, record: entry.record, error: err });
        return null;
      });
      if (found) {
        if (entry.tx && found !== entry.tx) throw new ChainReadError(`the chain names another transaction for record ${entry.record} than the state`);
        this.#txs.set(key, found);
        verified = found;
      }
    }
    const tx = verified ?? entry.tx;
    return {
      seq,
      checkpoint: decoded.checkpoint,
      checkpointHash: decoded.checkpointHash,
      tx,
      txVerified: verified !== null,
      record: entry.record,
      network: this.#network,
      trail: entry.trail,
      source: "chain",
      readAtMs: this.#now(),
      addedBy: rec.addedBy,
      timestampMs: rec.addedAtMs,
      links: { tx: tx ? this.#trail.link("txblock", tx) : null, trail: this.#trail.link("object", entry.trail) },
    };
  }

  async list(limit = 100): Promise<CheckpointList> {
    const state = this.#store.load();
    const trail = state?.trail ?? this.#trailId();
    let chain: CheckpointList["chain"] = null;
    let chainError: string | undefined;
    if (trail) {
      try {
        chain = await this.#trail.trailHead(trail);
      } catch (err) {
        log.warn("trail head unreadable", { trail, error: err });
        chainError = "the trail could not be read from IOTA Rebased";
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
