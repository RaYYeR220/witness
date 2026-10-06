import {
  fromHex,
  milestoneId,
  parseMilestonePayload,
  pinnedSignatures,
  toHex,
  type MilestonePayload,
} from "@witness/verify";
import type { Window } from "./checkpoint.js";

/** The node could not be asked, or did not have what was asked for. Nothing is decided. */
export class HornetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HornetError";
  }
}

/** The milestone source disagrees with the node, or a milestone is not properly signed. */
export class MilestoneMismatch extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MilestoneMismatch";
  }
}

const HEX = /^0x(?:[0-9a-fA-F]{2})*$/;

/** Read-only client of a HORNET node's core REST API. */
export class HornetClient {
  readonly #base: string;
  readonly #timeoutMs: number;
  readonly #fetch: typeof fetch;

  constructor(baseUrl: string, timeoutMs = 10_000, fetchImpl: typeof fetch = fetch) {
    this.#base = baseUrl.replace(/\/+$/, "");
    this.#timeoutMs = timeoutMs;
    this.#fetch = fetchImpl;
  }

  async #get(path: string, accept: string): Promise<Response | null> {
    let res: Response;
    try {
      res = await this.#fetch(`${this.#base}${path}`, { headers: { accept }, signal: AbortSignal.timeout(this.#timeoutMs) });
    } catch (err) {
      throw new HornetError(`HORNET unreachable: ${(err as Error).message}`);
    }
    if (res.status === 404) return null;
    if (!res.ok) throw new HornetError(`HORNET answered HTTP ${res.status} for ${path}`);
    return res;
  }

  /** Milestone `index` parsed from its raw bytes (TIP-29), or null when the node does not have it. */
  async milestone(index: number): Promise<MilestonePayload | null> {
    const res = await this.#get(`/api/core/v2/milestones/by-index/${index}`, "application/vnd.iota.serializer-v1");
    if (!res) return null;
    try {
      return parseMilestonePayload(new Uint8Array(await res.arrayBuffer()));
    } catch (err) {
      throw new MilestoneMismatch(`HORNET milestone ${index} does not parse: ${(err as Error).message}`);
    }
  }

  /** Tag and data of a tagged-data block, or null when the node does not have the block. */
  async taggedData(blockId: string): Promise<{ tag: string; data: Uint8Array } | null> {
    const res = await this.#get(`/api/core/v2/blocks/${encodeURIComponent(blockId)}`, "application/json");
    if (!res) return null;
    let body: any;
    try {
      body = await res.json();
    } catch {
      throw new HornetError(`HORNET sent no JSON for block ${blockId}`);
    }
    const p = body?.payload;
    if (p?.type !== 5 || typeof p.tag !== "string" || typeof p.data !== "string" || !HEX.test(p.tag) || !HEX.test(p.data)) return null;
    return { tag: Buffer.from(fromHex(p.tag)).toString("utf8"), data: fromHex(p.data) };
  }
}

/** Coordinator keys and signature threshold pinned for the private Tangle. */
export interface Coordinator {
  keys: ReadonlySet<string>;
  threshold: number;
}

export interface WindowVerifier {
  /**
   * Resolves when every milestone of the window, read from the node, has the id the source
   * gave, is signed by at least `threshold` pinned coordinator keys and links to the previous
   * milestone. Throws MilestoneMismatch otherwise, HornetError when that cannot be decided.
   */
  verifyWindow(window: Window, ids: readonly Uint8Array[], prevId: Uint8Array | null): Promise<void>;
}

/**
 * Checks a window's milestone ids against the node itself. The anchor never takes milestone ids
 * from the indexer database on trust: each one is recomputed from the raw milestone HORNET
 * serves (BLAKE2b-256 of the essence) and its coordinator signatures are checked.
 */
export class HornetWindowVerifier implements WindowVerifier {
  readonly #hornet: Pick<HornetClient, "milestone">;
  readonly #coordinator: Coordinator;
  readonly #concurrency: number;

  constructor(hornet: Pick<HornetClient, "milestone">, coordinator: Coordinator, concurrency = 8) {
    if (coordinator.keys.size === 0 || coordinator.threshold < 1 || coordinator.threshold > coordinator.keys.size) {
      throw new RangeError("coordinator threshold must be between 1 and the number of pinned keys");
    }
    this.#hornet = hornet;
    this.#coordinator = coordinator;
    this.#concurrency = concurrency;
  }

  async #check(index: number, expected: Uint8Array, prev: Uint8Array | null): Promise<void> {
    const ms = await this.#hornet.milestone(index);
    if (!ms) throw new HornetError(`HORNET has no milestone ${index}`);
    if (ms.essence.index !== index) throw new MilestoneMismatch(`HORNET returned milestone ${ms.essence.index} when asked for ${index}`);
    const mid = milestoneId(ms.essenceBytes);
    if (toHex(mid) !== toHex(expected)) {
      throw new MilestoneMismatch(`milestone ${index} is ${toHex(mid)} on the node, the milestone source says ${toHex(expected)}`);
    }
    const valid = pinnedSignatures(mid, ms.signatures, this.#coordinator.keys);
    if (valid.size < this.#coordinator.threshold) {
      throw new MilestoneMismatch(`milestone ${index} has ${valid.size} valid pinned coordinator signature(s), threshold ${this.#coordinator.threshold}`);
    }
    if (prev && toHex(ms.essence.previousMilestoneId) !== toHex(prev)) {
      throw new MilestoneMismatch(`milestone ${index} follows ${toHex(ms.essence.previousMilestoneId)}, not ${toHex(prev)}`);
    }
  }

  async verifyWindow(window: Window, ids: readonly Uint8Array[], prevId: Uint8Array | null): Promise<void> {
    if (ids.length !== window.to - window.from + 1) throw new MilestoneMismatch(`window ${window.from}..${window.to} has ${ids.length} ids`);
    let next = 0;
    const worker = async () => {
      for (let k = next++; k < ids.length; k = next++) {
        await this.#check(window.from + k, ids[k]!, k === 0 ? prevId : ids[k - 1]!);
      }
    };
    await Promise.all(Array.from({ length: Math.min(this.#concurrency, ids.length) }, worker));
  }
}
