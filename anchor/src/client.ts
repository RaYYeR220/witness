import dns from "node:dns";
import { readFileSync } from "node:fs";
import { inspect } from "node:util";
import { IotaClient, IotaHTTPTransport, type IotaTransactionBlockResponse } from "@iota/iota-sdk/client";
import { decodeIotaPrivateKey, type PublicKey } from "@iota/iota-sdk/cryptography";
import { Ed25519Keypair } from "@iota/iota-sdk/keypairs/ed25519";
import { TransactionDataBuilder, type Transaction } from "@iota/iota-sdk/transactions";
import type { AnchorConfig } from "./config.js";

/**
 * Error raised while loading the signing key. Messages name the keystore path and the selected
 * entry only; they never carry key material, and no underlying error is chained as `cause`
 * (decoder errors can quote their input).
 */
export class KeystoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KeystoreError";
  }
}

export class TransactionFailedError extends Error {
  readonly digest: string;
  constructor(digest: string, reason: string) {
    super(`transaction ${digest} failed: ${reason}`);
    this.name = "TransactionFailedError";
    this.digest = digest;
  }
}

interface KeystoreEntry {
  alias?: unknown;
  address?: unknown;
  key?: { type?: unknown; value?: unknown };
}

const ED25519_FLAG = 0x00;

function decodeSecret(value: string, label: string): Uint8Array {
  if (value.startsWith("iotaprivkey")) {
    let decoded: ReturnType<typeof decodeIotaPrivateKey>;
    try {
      decoded = decodeIotaPrivateKey(value);
    } catch {
      throw new KeystoreError(`keystore entry ${label} could not be decoded`);
    }
    if (decoded.schema !== "ED25519") throw new KeystoreError(`keystore entry ${label} is not an Ed25519 key`);
    if (decoded.secretKey.length !== 32) throw new KeystoreError(`keystore entry ${label} has an unexpected key length`);
    return decoded.secretKey;
  }
  // Older keystores store base64(flag || secret).
  const raw = Buffer.from(value, "base64");
  if (raw.length !== 33) throw new KeystoreError(`keystore entry ${label} could not be decoded`);
  if (raw[0] !== ED25519_FLAG) throw new KeystoreError(`keystore entry ${label} is not an Ed25519 key`);
  return new Uint8Array(raw.subarray(1));
}

function keypairFromSecret(secret: Uint8Array, label: string): Ed25519Keypair {
  try {
    return Ed25519Keypair.fromSecretKey(secret);
  } catch {
    throw new KeystoreError(`keystore entry ${label} could not be decoded`);
  }
}

/**
 * Reads an IOTA CLI keystore and returns the Ed25519 key pair of the entry selected by `selector`
 * (a 0x address or an alias). Supports the current `{version, keys: [{alias, address, key}]}`
 * layout with bech32 `iotaprivkey…` values and the older flat array of base64 keys.
 * The derived address must equal the selected address.
 */
export function loadKeystoreKeypair(keystorePath: string, selector: string): Ed25519Keypair {
  let text: string;
  try {
    text = readFileSync(keystorePath, "utf8");
  } catch {
    throw new KeystoreError(`keystore not readable: ${keystorePath}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    // JSON.parse messages quote the input, so they are not passed on.
    throw new KeystoreError(`keystore is not valid JSON: ${keystorePath}`);
  }

  const byAddress = selector.startsWith("0x");
  const wanted = byAddress ? selector.toLowerCase() : selector;

  if (Array.isArray(parsed)) {
    if (!byAddress) throw new KeystoreError("this keystore has no aliases; select the key by its 0x address");
    for (const item of parsed) {
      if (typeof item !== "string") continue;
      let kp: Ed25519Keypair;
      try {
        kp = keypairFromSecret(decodeSecret(item, "?"), "?");
      } catch {
        continue;
      }
      if (kp.toIotaAddress() === wanted) return kp;
    }
    throw new KeystoreError(`keystore has no Ed25519 entry for ${wanted}`);
  }

  const keys = (parsed as { keys?: unknown } | null)?.keys;
  if (!Array.isArray(keys)) throw new KeystoreError(`keystore has an unknown layout: ${keystorePath}`);
  const entry = (keys as KeystoreEntry[]).find((k) =>
    byAddress ? typeof k?.address === "string" && k.address.toLowerCase() === wanted : k?.alias === wanted,
  );
  if (!entry) throw new KeystoreError(`keystore has no entry for ${wanted}`);

  const label = typeof entry.address === "string" ? entry.address : wanted;
  if (entry.key?.type !== "key_pair" || typeof entry.key.value !== "string") {
    throw new KeystoreError(`keystore entry ${label} does not hold a local key pair`);
  }
  const kp = keypairFromSecret(decodeSecret(entry.key.value, label), label);
  if (typeof entry.address === "string" && kp.toIotaAddress() !== entry.address.toLowerCase()) {
    throw new KeystoreError(`keystore entry ${label} does not derive its own address`);
  }
  return kp;
}

/**
 * Signer interface expected by the identity and audit-trail WASM clients
 * (`TransactionSigner` from @iota/iota-interaction-ts).
 */
export interface WasmTransactionSigner {
  sign(txDataBcs: Uint8Array): Promise<string>;
  publicKey(): Promise<PublicKey>;
  iotaPublicKeyBytes(): Promise<Uint8Array>;
  keyId(): string;
}

class KeypairTransactionSigner implements WasmTransactionSigner {
  readonly #keypair: Ed25519Keypair;
  constructor(keypair: Ed25519Keypair) {
    this.#keypair = keypair;
  }
  async sign(txDataBcs: Uint8Array): Promise<string> {
    return (await this.#keypair.signTransaction(txDataBcs)).signature;
  }
  async publicKey(): Promise<PublicKey> {
    return this.#keypair.getPublicKey();
  }
  async iotaPublicKeyBytes(): Promise<Uint8Array> {
    return this.#keypair.getPublicKey().toIotaBytes();
  }
  keyId(): string {
    return this.#keypair.toIotaAddress();
  }
  toJSON(): unknown {
    return { address: this.keyId() };
  }
  [inspect.custom](): string {
    return `TransactionSigner(${this.keyId()})`;
  }
}

/**
 * A signed transaction that has not necessarily been executed yet. Persisting it before
 * submission lets a restarted process find out whether it landed (by digest) or submit the very
 * same bytes again; it never builds a second, different transaction for the same work.
 * Nothing here is secret: the bytes and signature become public once executed.
 */
export interface SignedTransaction {
  digest: string;
  /** BCS transaction data, base64. */
  txBytes: string;
  /** Serialized user signature, base64. */
  signature: string;
}

const RESPONSE_OPTIONS = { showEffects: true, showEvents: true } as const;

/** Executes (or re-executes: identical bytes are idempotent) a signed transaction and waits for it. */
async function submitSigned(client: IotaClient, signed: SignedTransaction): Promise<IotaTransactionBlockResponse> {
  const sent = await client.executeTransactionBlock({ transactionBlock: signed.txBytes, signature: signed.signature, options: RESPONSE_OPTIONS });
  if (sent.digest !== signed.digest) throw new Error(`node executed ${sent.digest}, expected ${signed.digest}`);
  const res = await client.waitForTransaction({ digest: signed.digest, options: RESPONSE_OPTIONS });
  assertSuccess(res);
  return res;
}

/** The transaction with this digest, or null when the node does not know it (yet). */
export async function findTransaction(client: Pick<IotaClient, "getTransactionBlock">, digest: string): Promise<IotaTransactionBlockResponse | null> {
  try {
    return await client.getTransactionBlock({ digest, options: RESPONSE_OPTIONS });
  } catch (err) {
    if (/could not find the referenced transaction|not found/i.test((err as Error).message ?? "")) return null;
    throw err;
  }
}

/**
 * True for errors meaning the transaction can never execute: one of its owned inputs (the gas coin,
 * the writer capability) was consumed at that version by another transaction, or it expired.
 */
export function isPermanentlyInvalid(err: unknown): boolean {
  const msg = (err as Error)?.message ?? "";
  return /unavailable for consumption|not available for consumption|ObjectVersionUnavailable|ObjectNotFound|TransactionExpired|has been deleted|needs to be rebuilt/i.test(
    msg,
  );
}

/** The service's gas and sender account. The key pair is held privately and never serialized. */
export class AnchorWallet {
  readonly address: string;
  readonly #keypair: Ed25519Keypair;

  private constructor(keypair: Ed25519Keypair) {
    this.#keypair = keypair;
    this.address = keypair.toIotaAddress();
  }

  static fromKeypair(keypair: Ed25519Keypair): AnchorWallet {
    return new AnchorWallet(keypair);
  }

  static fromKeystore(keystorePath: string, selector: string): AnchorWallet {
    return new AnchorWallet(loadKeystoreKeypair(keystorePath, selector));
  }

  static fromConfig(cfg: Pick<AnchorConfig, "keystorePath" | "address">): AnchorWallet {
    if (!cfg.keystorePath || !cfg.address) {
      throw new KeystoreError("ANCHOR_KEYSTORE_PATH and ANCHOR_ADDRESS are required for on-chain writes");
    }
    return AnchorWallet.fromKeystore(cfg.keystorePath, cfg.address);
  }

  transactionSigner(): WasmTransactionSigner {
    return new KeypairTransactionSigner(this.#keypair);
  }

  #queue: Promise<unknown> = Promise.resolve();

  /**
   * Runs `fn` once every earlier exclusive call has settled. Transactions from one sender go out
   * one at a time, so two of them never spend the same gas coin or capability version at once
   * (which would lock those objects until the epoch ends).
   */
  exclusive<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.#queue.then(fn, fn);
    this.#queue = run.catch(() => undefined);
    return run;
  }

  /** Signs, executes and waits for a transaction; throws if its effects report a failure. */
  execute(client: IotaClient, tx: Transaction): Promise<IotaTransactionBlockResponse> {
    return this.exclusive(async () => {
      tx.setSenderIfNotSet(this.address);
      const submitted = await client.signAndExecuteTransaction({
        signer: this.#keypair,
        transaction: tx,
        options: { showEffects: true, showEvents: true },
      });
      const res = await client.waitForTransaction({
        digest: submitted.digest,
        options: { showEffects: true, showEvents: true },
      });
      assertSuccess(res);
      return res;
    });
  }

  /**
   * Builds and signs `tx`, hands the signed transaction to `beforeSubmit` (which must persist it
   * durably), then executes it. A crash after `beforeSubmit` leaves enough on disk for
   * `resubmit` to finish the same transaction instead of building another one.
   */
  executeDurable(
    client: IotaClient,
    tx: Transaction,
    beforeSubmit: (signed: SignedTransaction) => void | Promise<void>,
  ): Promise<IotaTransactionBlockResponse> {
    return this.exclusive(async () => {
      tx.setSenderIfNotSet(this.address);
      const bytes = await tx.build({ client });
      const { signature, bytes: b64 } = await this.#keypair.signTransaction(bytes);
      const signed: SignedTransaction = { digest: TransactionDataBuilder.getDigestFromBytes(bytes), txBytes: b64, signature };
      await beforeSubmit(signed);
      return submitSigned(client, signed);
    });
  }

  /** Submits a previously signed transaction again; a no-op for the chain if it already ran. */
  resubmit(client: IotaClient, signed: SignedTransaction): Promise<IotaTransactionBlockResponse> {
    return this.exclusive(() => submitSigned(client, signed));
  }

  toJSON(): unknown {
    return { address: this.address };
  }

  [inspect.custom](): string {
    return `AnchorWallet(${this.address})`;
  }
}

export function assertSuccess(res: IotaTransactionBlockResponse): void {
  const status = res.effects?.status;
  if (!status) throw new TransactionFailedError(res.digest, "no effects returned");
  if (status.status !== "success") throw new TransactionFailedError(res.digest, status.error ?? "unknown error");
}

export function gasUsedNanos(res: IotaTransactionBlockResponse): bigint | null {
  const g = res.effects?.gasUsed;
  if (!g) return null;
  return BigInt(g.computationCost) + BigInt(g.storageCost) - BigInt(g.storageRebate);
}

/** JSON-RPC client whose every request is aborted after `timeoutMs`, so a stalled node cannot hang callers. */
export function createIotaClient(cfg: Pick<AnchorConfig, "rpcUrl">, timeoutMs = 20_000): IotaClient {
  const fetchWithTimeout: typeof fetch = (input, init) => {
    const timeout = AbortSignal.timeout(timeoutMs);
    return fetch(input, { ...init, signal: init?.signal ? AbortSignal.any([init.signal, timeout]) : timeout });
  };
  return new IotaClient({ transport: new IotaHTTPTransport({ url: cfg.rpcUrl, fetch: fetchWithTimeout }) });
}

/**
 * The identity and audit-trail WASM packages are CommonJS and are typed against the CommonJS
 * build of @iota/iota-sdk, while this package uses the ESM build: the same class at runtime, two
 * nominally different types for TypeScript.
 */
export function forWasm<T>(iota: IotaClient): T {
  return iota as unknown as T;
}

export class ChainMismatchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ChainMismatchError";
  }
}

/** Refuses to continue when the RPC endpoint serves a different chain than the configured network. */
export async function assertChain(client: IotaClient, cfg: Pick<AnchorConfig, "chainId" | "network" | "rpcUrl">): Promise<void> {
  const chainId = await client.getChainIdentifier();
  if (chainId !== cfg.chainId) {
    throw new ChainMismatchError(`${cfg.rpcUrl} serves chain ${chainId}, expected ${cfg.network} (${cfg.chainId})`);
  }
}

/**
 * Resolve hostnames to IPv4 first. The public IOTA endpoints publish AAAA records, and hosts
 * without a working IPv6 route otherwise stall on connect until fetch times out.
 */
export function preferIpv4(): void {
  dns.setDefaultResultOrder("ipv4first");
}
