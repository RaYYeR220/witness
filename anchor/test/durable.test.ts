import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import type { IotaClient } from "@iota/iota-sdk/client";
import { Ed25519Keypair } from "@iota/iota-sdk/keypairs/ed25519";
import { TransactionDataBuilder, type Transaction } from "@iota/iota-sdk/transactions";
import { afterAll, describe, expect, it } from "vitest";
import { AnchorWallet, isPermanentlyInvalid, type SignedTransaction } from "../src/client.js";
import { loadConfig, NETWORKS } from "../src/config.js";
import { TrailService, type PendingAppend } from "../src/trail.js";

const PKGS = NETWORKS.testnet.packages;
const TRAIL = "0x" + "7".repeat(64);
const RECORD_ADDED = `${PKGS.auditTrailOriginal}::main::RecordAdded`;

const dirs: string[] = [];
afterAll(() => dirs.forEach((d) => rmSync(d, { recursive: true, force: true })));
function config() {
  const dir = mkdtempSync(path.join(os.tmpdir(), "anchor-durable-"));
  dirs.push(dir);
  return loadConfig({ SECRETS_DIR: dir }, dir);
}

const okResponse = (digest: string, seq = 4) => ({
  digest,
  effects: { status: { status: "success" }, gasUsed: { computationCost: "1000000", storageCost: "5000000", storageRebate: "1000000" } },
  events: [{ type: RECORD_ADDED, parsedJson: { trail_id: TRAIL, sequence_number: String(seq), added_by: "0xd4", timestamp: "400" } }],
});

/** Node fake: transactions it has executed, and how it answers a (re)submission. */
function fakeNode(opts: { known?: Record<string, unknown>; onExecute?: (digest: string) => unknown } = {}) {
  const known = new Map<string, unknown>(Object.entries(opts.known ?? {}));
  const log: string[] = [];
  const node = {
    async getTransactionBlock({ digest }: { digest: string }) {
      log.push(`get ${digest}`);
      if (!known.has(digest)) throw new Error(`Could not find the referenced transaction [TransactionDigest(${digest})].`);
      return known.get(digest);
    },
    async executeTransactionBlock({ transactionBlock }: { transactionBlock: string }) {
      const digest = TransactionDataBuilder.getDigestFromBytes(Buffer.from(transactionBlock, "base64"));
      log.push(`execute ${digest}`);
      const res = opts.onExecute ? opts.onExecute(digest) : okResponse(digest);
      if (res instanceof Error) throw res;
      known.set(digest, res);
      return { digest };
    },
    async waitForTransaction({ digest }: { digest: string }) {
      return known.get(digest);
    },
  };
  return { node: node as unknown as IotaClient, log, known };
}

function signedFor(bytes: Uint8Array): Promise<SignedTransaction> {
  const kp = Ed25519Keypair.generate();
  return kp.signTransaction(bytes).then(({ signature, bytes: b64 }) => ({ digest: TransactionDataBuilder.getDigestFromBytes(bytes), txBytes: b64, signature }));
}

describe("AnchorWallet.executeDurable", () => {
  it("persists the signed transaction before submitting it", async () => {
    const wallet = AnchorWallet.fromKeypair(Ed25519Keypair.generate());
    const { node, log } = fakeNode();
    const bytes = new Uint8Array([1, 2, 3, 4, 5]);
    let sender: string | null = null;
    const tx = {
      setSenderIfNotSet: (a: string) => (sender = a),
      build: async () => bytes,
    } as unknown as Transaction;
    let saved: SignedTransaction | null = null;
    const res = await wallet.executeDurable(node, tx, (s) => {
      saved = s;
      log.push("persist");
    });
    expect(sender).toBe(wallet.address);
    expect(log).toEqual(["persist", `execute ${saved!.digest}`]);
    expect(res.digest).toBe(saved!.digest);
    expect(saved!.digest).toBe(TransactionDataBuilder.getDigestFromBytes(bytes));
    expect(Buffer.from(saved!.txBytes, "base64")).toEqual(Buffer.from(bytes));
  });

  it("does not submit when persisting fails", async () => {
    const wallet = AnchorWallet.fromKeypair(Ed25519Keypair.generate());
    const { node, log } = fakeNode();
    const tx = { setSenderIfNotSet: () => undefined, build: async () => new Uint8Array([9]) } as unknown as Transaction;
    await expect(
      wallet.executeDurable(node, tx, () => {
        throw new Error("disk full");
      }),
    ).rejects.toThrow(/disk full/);
    expect(log).toEqual([]);
  });
});

describe("TrailService.resumeAppend", () => {
  const wallet = AnchorWallet.fromKeypair(Ed25519Keypair.generate());
  async function pending(): Promise<PendingAppend> {
    return { ...(await signedFor(new Uint8Array([7, 7, 7]))), trailId: TRAIL, metadata: '{"seq":1}' };
  }

  it("adopts a transaction that already executed, without resubmitting", async () => {
    const p = await pending();
    const { node, log } = fakeNode({ known: { [p.digest]: okResponse(p.digest, 6) } });
    const r = await new TrailService(config(), node, wallet).resumeAppend(p);
    expect(r).toMatchObject({ status: "done", result: { recordIndex: 6, tx: p.digest, metadata: '{"seq":1}' } });
    expect(log).toEqual([`get ${p.digest}`]);
  });

  it("submits the same signed bytes again when the node never saw them", async () => {
    const p = await pending();
    const { node, log } = fakeNode();
    const r = await new TrailService(config(), node, wallet).resumeAppend(p);
    expect(r).toMatchObject({ status: "done", result: { recordIndex: 4, tx: p.digest } });
    expect(log).toEqual([`get ${p.digest}`, `execute ${p.digest}`]);
  });

  it("drops a transaction that failed or can never execute", async () => {
    const p = await pending();
    const failed = { ...okResponse(p.digest), effects: { status: { status: "failure", error: "MoveAbort" } } };
    expect(await new TrailService(config(), fakeNode({ known: { [p.digest]: failed } }).node, wallet).resumeAppend(p)).toMatchObject({ status: "dropped" });

    const stale = fakeNode({ onExecute: () => new Error("Transaction needs to be rebuilt because object 0xab version 0x5 is unavailable for consumption") });
    expect(await new TrailService(config(), stale.node, wallet).resumeAppend(p)).toMatchObject({ status: "dropped", reason: expect.stringMatching(/no longer execute/) });
  });

  it("keeps it pending (throws) when the outcome cannot be decided", async () => {
    const p = await pending();
    const flaky = fakeNode({ onExecute: () => new Error("fetch failed") });
    await expect(new TrailService(config(), flaky.node, wallet).resumeAppend(p)).rejects.toThrow(/fetch failed/);
  });

  it("classifies permanent validity errors", () => {
    expect(isPermanentlyInvalid(new Error("Object 0x1 version 3 is unavailable for consumption"))).toBe(true);
    expect(isPermanentlyInvalid(new Error("TransactionExpired"))).toBe(true);
    expect(isPermanentlyInvalid(new Error("fetch failed"))).toBe(false);
  });
});

describe("TrailService.trailHead", () => {
  it("reads the record count and tail from the trail object", async () => {
    const node = {
      async getObject() {
        return {
          data: {
            type: `${PKGS.auditTrailOriginal}::main::AuditTrail<${PKGS.auditTrailOriginal}::record::Data>`,
            content: { dataType: "moveObject", fields: { records: { fields: { id: { id: "0x1" }, size: "5", head: "0", tail: "4" } } } },
          },
        };
      },
    } as unknown as IotaClient;
    expect(await new TrailService(config(), node, null).trailHead(TRAIL)).toEqual({ records: 5, tail: 4 });
  });
});
