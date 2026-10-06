import { createPrivateKey, createPublicKey } from "node:crypto";
import { inspect } from "node:util";
import path from "node:path";
import { sealEnvelope, type Ed25519PrivateJwk, type Envelope, type JsonObject } from "@witness/verify";
import { SIG_FRAGMENT, componentKeyDir, type PublicIdentity } from "./did.js";
import { readJsonIfExists } from "./fsutil.js";
import type { CheckpointEntry } from "./state.js";
import { parseUntrusted } from "./untrusted.js";

export const ANCHOR_TAG = "witness.anchor";
const BLOCK_ID = /^0x[0-9a-f]{64}$/;

/** Signs `witness.anchor` envelopes with a component's `#sig-1` key. The key never leaves this object. */
export class MirrorSigner {
  readonly iss: string;
  readonly kid: string;
  readonly #jwk: Ed25519PrivateJwk;

  private constructor(iss: string, kid: string, jwk: Ed25519PrivateJwk) {
    this.iss = iss;
    this.kid = kid;
    this.#jwk = jwk;
  }

  /** From an OKP Ed25519 private JWK carrying its `kid` (`did:…#sig-1`), as did.ts writes them. */
  static fromJwk(jwk: unknown, label = "signing key"): MirrorSigner {
    const j = jwk as { kty?: unknown; crv?: unknown; d?: unknown; x?: unknown; kid?: unknown } | null;
    if (!j || j.kty !== "OKP" || j.crv !== "Ed25519" || typeof j.d !== "string" || typeof j.x !== "string") {
      throw new Error(`${label} is not an Ed25519 private JWK`);
    }
    if (typeof j.kid !== "string" || !j.kid.includes("#")) throw new Error(`${label} carries no kid`);
    let derived: string | undefined;
    try {
      const priv = createPrivateKey({ key: { kty: "OKP", crv: "Ed25519", d: j.d, x: j.x }, format: "jwk" });
      derived = (createPublicKey(priv).export({ format: "jwk" }) as { x?: string }).x;
    } catch {
      throw new Error(`${label} could not be decoded`);
    }
    if (derived !== j.x) throw new Error(`${label} does not derive its own public key`);
    return new MirrorSigner(j.kid.split("#")[0]!, j.kid, { kty: "OKP", crv: "Ed25519", d: j.d, x: j.x });
  }

  /** `${secretsDir}/<component>/sig-1.jwk.json`, checked against the public identity file when given. */
  static load(secretsDir: string, component: string, identities?: { identities?: PublicIdentity[] } | null): MirrorSigner {
    const file = path.join(componentKeyDir(secretsDir, component), `${SIG_FRAGMENT}.jwk.json`);
    const jwk = readJsonIfExists<unknown>(file);
    if (jwk === null) throw new Error(`no signing key for component "${component}" at ${file}`);
    const signer = MirrorSigner.fromJwk(jwk, file);
    const pub = identities?.identities?.find((i) => i.name === component);
    if (pub) {
      if (pub.did !== signer.iss) throw new Error(`${file} belongs to ${signer.iss}, the identity file names ${pub.did}`);
      const key = pub.keys.find((k) => k.kid === signer.kid);
      if (!key || key.publicKeyJwk.x !== signer.publicX) throw new Error(`${file} is not the published ${signer.kid}`);
    }
    return signer;
  }

  get publicX(): string {
    return this.#jwk.x!;
  }

  seal(tag: string, body: JsonObject, seq: number, prev: string | null): Envelope {
    return sealEnvelope(tag, body, { iss: this.iss, kid: this.kid, signKey: this.#jwk, seq, attMode: "producer", prev });
  }

  toJSON(): unknown {
    return { kid: this.kid };
  }

  [inspect.custom](): string {
    return `MirrorSigner(${this.kid})`;
  }
}

/** Body of the `witness.anchor` message: the checkpoint and where it sits on IOTA Rebased. */
export function mirrorBody(entry: CheckpointEntry, rebasedNetwork: string): JsonObject {
  return {
    seq: entry.seq,
    checkpoint: entry.checkpoint as unknown as JsonObject,
    checkpointHash: entry.checkpointHash,
    rebased: { network: rebasedNetwork, trail: entry.trail, record: entry.record, tx: entry.tx ?? "" },
  };
}

export type UploadOutcome =
  | { kind: "posted"; blockId: string }
  /** The relay already holds a message of this issuer with this seq (or a newer one). */
  | { kind: "replay"; error: string }
  | { kind: "rejected"; status: number; error: string };

export class RelayError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RelayError";
  }
}

function short(text: string): string {
  return text.replace(/\s+/g, " ").slice(0, 200);
}

/** Client of witness-relay, the modified Messages API (`POST /upload?node=`, `GET /receipts`). */
export class RelayClient {
  readonly #base: string;
  readonly #node: string;
  readonly #timeoutMs: number;
  readonly #fetch: typeof fetch;

  constructor(baseUrl: string, node: string, timeoutMs = 10_000, fetchImpl: typeof fetch = fetch) {
    this.#base = baseUrl.replace(/\/+$/, "");
    this.#node = node;
    this.#timeoutMs = timeoutMs;
    this.#fetch = fetchImpl;
  }

  async #request(url: string, init: RequestInit): Promise<{ status: number; text: string }> {
    let res: Response;
    try {
      res = await this.#fetch(url, { ...init, signal: AbortSignal.timeout(this.#timeoutMs) });
    } catch (err) {
      throw new RelayError(`relay unreachable: ${(err as Error).message}`);
    }
    return { status: res.status, text: await res.text() };
  }

  async upload(tag: string, message: Envelope): Promise<UploadOutcome> {
    const { status, text } = await this.#request(`${this.#base}/upload?node=${encodeURIComponent(this.#node)}`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ tag, message }),
    });
    let body: any = null;
    try {
      body = JSON.parse(text);
    } catch {
      body = null;
    }
    if (status === 200) {
      let blockId = body?.witness?.blockId;
      if (typeof blockId !== "string" && typeof body?.return_payload === "string") {
        try {
          blockId = JSON.parse(body.return_payload).blockId;
        } catch {
          blockId = undefined;
        }
      }
      if (typeof blockId !== "string" || !BLOCK_ID.test(blockId)) throw new RelayError("relay accepted the message but returned no block id");
      return { kind: "posted", blockId };
    }
    const error = short(typeof body?.error === "string" ? body.error : text);
    if (status === 403 && body?.verdict === "REPLAY") return { kind: "replay", error };
    return { kind: "rejected", status, error };
  }

  /** The relay's receipts of `iss` on `tag` (newest first, at most `limit`), as {blockId, seq}. */
  async receipts(iss: string, tag: string, limit = RECEIPTS_LIMIT): Promise<Receipt[]> {
    const q = new URLSearchParams({ iss, tag, limit: String(limit) });
    const { status, text } = await this.#request(`${this.#base}/receipts?${q}`, { headers: { accept: "application/json" } });
    if (status !== 200) throw new RelayError(`relay receipts answered HTTP ${status}`);
    let body: any;
    try {
      body = JSON.parse(text);
    } catch {
      throw new RelayError("relay receipts sent no JSON");
    }
    return (Array.isArray(body?.receipts) ? body.receipts : [])
      .filter((r: any) => r?.iss === iss && r?.tag === tag && Number.isSafeInteger(r?.seq) && typeof r?.blockId === "string" && BLOCK_ID.test(r.blockId))
      .map((r: any) => ({ blockId: r.blockId, seq: r.seq }));
  }
}

/** Most receipts asked for at once (the relay's own cap). */
export const RECEIPTS_LIMIT = 1000;

export interface Receipt {
  blockId: string;
  seq: number;
}

/** What the mirror needs to read posted blocks back (HornetClient). */
export interface BlockReader {
  taggedData(blockId: string): Promise<{ tag: string; data: Uint8Array } | null>;
}

/** The mirror body a posted block carries, read from the node; null if it is no mirror of `iss`. */
export async function mirrorOnNode(blocks: BlockReader, blockId: string, iss: string): Promise<{ seq: number; checkpointHash: string } | null> {
  const td = await blocks.taggedData(blockId);
  if (!td || td.tag !== ANCHOR_TAG) return null;
  let env: any;
  try {
    env = parseUntrusted(Buffer.from(td.data).toString("utf8"));
  } catch {
    return null;
  }
  const body = env?.body;
  if (env?.iss !== iss || !Number.isSafeInteger(body?.seq) || typeof body?.checkpointHash !== "string") return null;
  return { seq: body.seq, checkpointHash: body.checkpointHash };
}

export interface MirrorChain {
  lastSeq: number;
  lastBlockId: string | null;
}

export type MirrorOutcome =
  | { ok: true; blockId: string; envelopeSeq: number; recovered: boolean }
  /**
   * `error` is safe to show; `detail` is for the log. `burntSeq`: a seq the relay already holds
   * for something else (or without a receipt); never use it again.
   */
  | { ok: false; error: string; detail?: string; burntSeq?: number };

/**
 * Posts one checkpoint's `witness.anchor` envelope. The envelope seq is the checkpoint seq unless
 * the issuer's chain is already past it; `prev` is the previous mirror block. A REPLAY answer
 * means an earlier attempt with this seq reached the relay (say its reply was lost). The receipt
 * with that seq is adopted only if the block it names, read back from the node, mirrors this very
 * checkpoint (same seq and checkpoint hash); otherwise the seq is burnt and the next attempt uses
 * a newer one.
 */
export async function postMirror(
  entry: CheckpointEntry,
  chain: MirrorChain,
  signer: MirrorSigner,
  relay: Pick<RelayClient, "upload" | "receipts">,
  rebasedNetwork: string,
  blocks: BlockReader,
): Promise<MirrorOutcome> {
  const envelopeSeq = Math.max(entry.seq, chain.lastSeq + 1);
  const env = signer.seal(ANCHOR_TAG, mirrorBody(entry, rebasedNetwork), envelopeSeq, chain.lastBlockId);
  let out: UploadOutcome;
  try {
    out = await relay.upload(ANCHOR_TAG, env);
  } catch (err) {
    return { ok: false, error: "relay unreachable", detail: (err as Error).message };
  }
  if (out.kind === "posted") return { ok: true, blockId: out.blockId, envelopeSeq, recovered: false };
  if (out.kind === "rejected") return { ok: false, error: `relay refused the mirror (HTTP ${out.status})`, detail: out.error };
  let candidates: Receipt[];
  try {
    candidates = (await relay.receipts(signer.iss, ANCHOR_TAG)).filter((r) => r.seq === envelopeSeq);
  } catch (err) {
    return { ok: false, error: "relay receipts unavailable", detail: (err as Error).message };
  }
  for (const r of candidates) {
    let onNode;
    try {
      onNode = await mirrorOnNode(blocks, r.blockId, signer.iss);
    } catch (err) {
      return { ok: false, error: "node unreachable while confirming a mirror receipt", detail: (err as Error).message };
    }
    if (onNode && onNode.seq === entry.seq && onNode.checkpointHash === entry.checkpointHash) {
      return { ok: true, blockId: r.blockId, envelopeSeq, recovered: true };
    }
  }
  return { ok: false, error: `seq ${envelopeSeq} is already used without a mirror of this checkpoint`, burntSeq: envelopeSeq };
}
