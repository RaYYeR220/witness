import type { Checkpoint } from "@witness/verify";
import { checkpointHashHex, checkpointShapeError } from "./checkpoint.js";
import { readJsonIfExists, writeJsonAtomic } from "./fsutil.js";
import type { PendingAppend } from "./trail.js";

export type MirrorInfo =
  /** Posted through the relay; `blockId` is the `witness.anchor` block on the private Tangle. */
  | { status: "posted"; blockId: string; envelopeSeq: number; at: string; recovered?: boolean }
  /** Rebuilt from the chain after the state file was lost: whether it was mirrored is unknown. */
  | { status: "unknown"; at: string };

export interface CheckpointEntry {
  seq: number;
  checkpoint: Checkpoint;
  checkpointHash: string;
  trail: string;
  record: number;
  tx: string | null;
  timestampMs: number;
  addedBy: string;
  anchoredAt: string;
  mirror: MirrorInfo | null;
  /** Last mirror failure, cleared once the mirror is posted. */
  mirrorError?: string | null;
}

export interface PendingCheckpoint {
  seq: number;
  checkpoint: Checkpoint;
  checkpointHash: string;
  append: PendingAppend;
  since: string;
}

export interface AnchorState {
  v: 1;
  /** IOTA Rebased network of the trail. */
  network: string;
  trail: string;
  checkpoints: CheckpointEntry[];
  /** A checkpoint whose append was signed and persisted but not yet confirmed. */
  pending: PendingCheckpoint | null;
  /** Envelope chain of the `witness.anchor` mirror: last seq used and last block posted. */
  mirror: { lastSeq: number; lastBlockId: string | null };
}

export class StateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StateError";
  }
}

export function emptyState(network: string, trail: string): AnchorState {
  return { v: 1, network, trail, checkpoints: [], pending: null, mirror: { lastSeq: 0, lastBlockId: null } };
}

/**
 * Checks that checkpoints form one chain: seq 1, 2, 3…, each `prev` the hash of the one before,
 * each window starting right after the previous one, every stored hash the hash of its checkpoint.
 */
export function chainProblem(entries: readonly Pick<CheckpointEntry, "seq" | "checkpoint" | "checkpointHash">[]): string | null {
  let prev: Pick<CheckpointEntry, "seq" | "checkpoint" | "checkpointHash"> | null = null;
  for (const e of entries) {
    const shape = checkpointShapeError(e.checkpoint);
    if (shape) return `checkpoint ${e.seq}: ${shape}`;
    if (checkpointHashHex(e.checkpoint) !== e.checkpointHash) return `checkpoint ${e.seq}: stored hash is not the hash of the checkpoint`;
    if (e.seq !== (prev ? prev.seq + 1 : 1)) return `checkpoint ${e.seq} follows ${prev ? prev.seq : "nothing"}`;
    if (e.checkpoint.prev !== (prev ? prev.checkpointHash : null)) return `checkpoint ${e.seq}: prev does not link to checkpoint ${prev?.seq ?? "(none)"}`;
    if (prev && e.checkpoint.from.index !== prev.checkpoint.to.index + 1) {
      return `checkpoint ${e.seq}: window starts at ${e.checkpoint.from.index}, expected ${prev.checkpoint.to.index + 1}`;
    }
    prev = e;
  }
  return null;
}

/** The anchor loop's state file. Holds no secrets; written atomically after every step. */
export class StateStore {
  readonly path: string;

  constructor(file: string) {
    this.path = file;
  }

  load(): AnchorState | null {
    const s = readJsonIfExists<AnchorState>(this.path);
    if (s === null) return null;
    if (s.v !== 1 || !Array.isArray(s.checkpoints) || typeof s.trail !== "string" || typeof s.mirror?.lastSeq !== "number") {
      throw new StateError(`${this.path} is not an anchor state file`);
    }
    const problem = chainProblem(s.checkpoints);
    if (problem) throw new StateError(`${this.path}: ${problem}`);
    return s;
  }

  save(s: AnchorState): void {
    writeJsonAtomic(this.path, s);
  }
}
