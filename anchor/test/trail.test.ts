import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { bcs } from "@iota/iota-sdk/bcs";
import type { IotaClient } from "@iota/iota-sdk/client";
import { Ed25519Keypair } from "@iota/iota-sdk/keypairs/ed25519";
import type { Transaction } from "@iota/iota-sdk/transactions";
import { afterAll, describe, expect, it } from "vitest";
import { AnchorWallet } from "../src/client.js";
import { loadConfig, NETWORKS } from "../src/config.js";
import { MAX_RECORD_BYTES, TrailService, buildAddRecordTx, parseRecordFields } from "../src/trail.js";

const PKGS = NETWORKS.testnet.packages;
const TRAIL = "0x" + "7".repeat(64);
const CAP = "0x" + "c".repeat(64);
const TABLE = "0x" + "e".repeat(64);
const RECORD_ADDED = `${PKGS.auditTrailOriginal}::main::RecordAdded`;

const dirs: string[] = [];
afterAll(() => dirs.forEach((d) => rmSync(d, { recursive: true, force: true })));

function config() {
  const dir = mkdtempSync(path.join(os.tmpdir(), "anchor-trail-"));
  dirs.push(dir);
  return loadConfig({ SECRETS_DIR: dir }, dir);
}

function pureBytes(tx: Transaction, arg: unknown): Uint8Array {
  const input = tx.getData().inputs[(arg as { Input: number }).Input]!;
  return Buffer.from(input.Pure!.bytes, "base64");
}

describe("buildAddRecordTx", () => {
  it("calls the latest package with the original package's Data type", () => {
    const tx = buildAddRecordTx(PKGS, TRAIL, CAP, '{"seq":1}', "sha256:00ff", 50_000_000n);
    const [newText, addRecord] = tx.getData().commands.map((c) => c.MoveCall!);
    expect(newText).toMatchObject({ package: PKGS.auditTrail, module: "record", function: "new_text" });
    expect(addRecord).toMatchObject({
      package: PKGS.auditTrail,
      module: "main",
      function: "add_record",
      typeArguments: [`${PKGS.auditTrailOriginal}::record::Data`],
    });
    expect(bcs.string().parse(pureBytes(tx, newText!.arguments[0]))).toBe('{"seq":1}');
    const [trailArg, capArg, dataArg, metaArg, tagArg, clockArg] = addRecord!.arguments;
    const inputs = tx.getData().inputs;
    expect(inputs[(trailArg as { Input: number }).Input]!.UnresolvedObject!.objectId).toBe(TRAIL);
    expect(inputs[(capArg as { Input: number }).Input]!.UnresolvedObject!.objectId).toBe(CAP);
    expect(dataArg).toEqual(expect.objectContaining({ Result: 0 }));
    expect(bcs.option(bcs.string()).parse(pureBytes(tx, metaArg))).toBe("sha256:00ff");
    expect(bcs.option(bcs.string()).parse(pureBytes(tx, tagArg))).toBeNull();
    expect(inputs[(clockArg as { Input: number }).Input]!.Object!.SharedObject!.objectId).toMatch(/0x0+6$/);
    expect(tx.getData().gasData.budget).toBe("50000000");
  });

  it("uses new_bytes for binary data", () => {
    const tx = buildAddRecordTx(PKGS, TRAIL, CAP, new Uint8Array([1, 2, 3]), null, 50_000_000n);
    const first = tx.getData().commands[0]!.MoveCall!;
    expect(first.function).toBe("new_bytes");
    expect([...bcs.vector(bcs.u8()).parse(pureBytes(tx, first.arguments[0]))]).toEqual([1, 2, 3]);
  });
});

describe("parseRecordFields", () => {
  const base = { metadata: "sha256:ab", tag: null, sequence_number: "2", added_by: "0xd4", added_at: "1791283442498" };
  it("decodes text and byte records", () => {
    expect(parseRecordFields({ ...base, data: { variant: "Text", fields: { pos0: "hello" } } })).toEqual({
      recordIndex: 2,
      data: "hello",
      dataKind: "text",
      metadata: "sha256:ab",
      tag: null,
      addedAtMs: 1791283442498,
      addedBy: "0xd4",
    });
    const bytes = parseRecordFields({ ...base, data: { variant: "Bytes", fields: { pos0: [0, 255] } } });
    expect(bytes.dataKind).toBe("bytes");
    expect(bytes.data).toEqual(new Uint8Array([0, 255]));
  });
});

/** Fake node: the trail object, its records table and its transaction history. */
function fakeNode() {
  const executed: Transaction[] = [];
  const added = (seq: number) => ({ type: RECORD_ADDED, parsedJson: { trail_id: TRAIL, sequence_number: String(seq), added_by: "0xd4", timestamp: String(seq * 100) } });
  const history = [
    { digest: "TxBatch", events: [added(4), added(5)] },
    { digest: "TxRec3", events: [added(3)] },
    { digest: "TxOther", events: [{ type: `${PKGS.tfComponents}::role_map::CapabilityIssued`, parsedJson: {} }] },
    { digest: "TxRec2", events: [{ type: RECORD_ADDED, parsedJson: { trail_id: TRAIL, sequence_number: "2", added_by: "0xd4", timestamp: "200" } }] },
    { digest: "TxCreate", events: [] },
  ];
  const node = {
    async getObject({ id }: { id: string }) {
      if (id !== TRAIL) throw new Error(`unexpected object ${id}`);
      return {
        data: {
          objectId: TRAIL,
          type: `${PKGS.auditTrailOriginal}::main::AuditTrail<${PKGS.auditTrailOriginal}::record::Data>`,
          content: { dataType: "moveObject", fields: { records: { fields: { id: { id: TABLE }, size: "4" } } } },
        },
      };
    },
    async getDynamicFieldObject({ parentObjectId, name }: { parentObjectId: string; name: { type: string; value: string } }) {
      expect(parentObjectId).toBe(TABLE);
      expect(name.type).toBe("u64");
      if (name.value !== "2") return { error: { code: "dynamicFieldNotFound", parent_object_id: TABLE } };
      return {
        data: {
          content: {
            dataType: "moveObject",
            fields: {
              name: "2",
              value: {
                fields: {
                  next: "3",
                  prev: "1",
                  value: {
                    fields: {
                      data: { variant: "Text", fields: { pos0: '{"seq":2}' } },
                      metadata: "sha256:x",
                      tag: null,
                      sequence_number: "2",
                      added_by: "0xd4",
                      added_at: "200",
                    },
                  },
                },
              },
            },
          },
        },
      };
    },
    async queryTransactionBlocks(input: { order?: string; limit?: number; cursor?: string | null }) {
      const list = input.order === "ascending" ? [...history].reverse() : history;
      const start = input.cursor ? Number(input.cursor) : 0;
      const page = list.slice(start, start + 2);
      const more = start + 2 < list.length;
      return { data: page, hasNextPage: more, nextCursor: more ? String(start + 2) : null };
    },
    async signAndExecuteTransaction({ transaction }: { transaction: Transaction }) {
      executed.push(transaction);
      return { digest: "TxNew" };
    },
    async waitForTransaction({ digest }: { digest: string }) {
      return {
        digest,
        effects: { status: { status: "success" }, gasUsed: { computationCost: "1000000", storageCost: "5000000", storageRebate: "1000000" } },
        events: [
          { type: RECORD_ADDED, parsedJson: { trail_id: "0x" + "1".repeat(64), sequence_number: "9", added_by: "0x0", timestamp: "1" } },
          { type: RECORD_ADDED, parsedJson: { trail_id: TRAIL, sequence_number: "4", added_by: "0xd4", timestamp: "400" } },
        ],
      };
    },
  };
  return { node: node as unknown as IotaClient, executed };
}

describe("TrailService", () => {
  it("reads a record back with the transaction that added it", async () => {
    const { node } = fakeNode();
    const svc = new TrailService(config(), node, null);
    const rec = await svc.readRecord(TRAIL, 2);
    expect(rec).toMatchObject({ trailId: TRAIL, recordIndex: 2, data: '{"seq":2}', dataKind: "text", addedAtMs: 200, tx: "TxRec2" });
    expect(rec!.links.tx).toBe("https://explorer.iota.org/txblock/TxRec2?network=testnet");
    expect(await svc.readRecord(TRAIL, 7)).toBeNull();
  });

  it("finds the genesis record's transaction and stops early on missing ones", async () => {
    const { node } = fakeNode();
    const svc = new TrailService(config(), node, null);
    expect(await svc.findRecordTx(TRAIL, 0)).toBe("TxCreate");
    expect(await svc.findRecordTx(TRAIL, 1)).toBeNull();
  });

  it("finds a record added as the second of several in one transaction", async () => {
    const { node } = fakeNode();
    const svc = new TrailService(config(), node, null);
    expect(await svc.findRecordTx(TRAIL, 5)).toBe("TxBatch");
    expect(await svc.findRecordTx(TRAIL, 4)).toBe("TxBatch");
    expect(await svc.findRecordTx(TRAIL, 3)).toBe("TxRec3");
  });

  it("appends through the hand-built transaction and reports the new record", async () => {
    const { node, executed } = fakeNode();
    const wallet = AnchorWallet.fromKeypair(Ed25519Keypair.generate());
    const svc = new TrailService(config(), node, wallet);
    const payload = '{"kind":"witness.test"}';
    const res = await svc.appendRecord(TRAIL, payload, { writerCapId: CAP });
    expect(res).toEqual({
      trailId: TRAIL,
      recordIndex: 4,
      tx: "TxNew",
      timestampMs: 400,
      addedBy: "0xd4",
      metadata: `sha256:${createHash("sha256").update(payload).digest("hex")}`,
      gasNanos: "5000000",
      links: {
        tx: "https://explorer.iota.org/txblock/TxNew?network=testnet",
        trail: `https://explorer.iota.org/object/${TRAIL}?network=testnet`,
      },
    });
    expect(executed).toHaveLength(1);
    expect(executed[0]!.getData().sender).toBe(wallet.address);
    expect(executed[0]!.getData().commands[1]!.MoveCall!.function).toBe("add_record");
  });

  it("refuses oversized records and writes without a wallet", async () => {
    const { node } = fakeNode();
    const wallet = AnchorWallet.fromKeypair(Ed25519Keypair.generate());
    await expect(new TrailService(config(), node, wallet).appendRecord(TRAIL, "x".repeat(MAX_RECORD_BYTES + 1), { writerCapId: CAP })).rejects.toThrow(
      /limit/,
    );
    await expect(new TrailService(config(), node, null).appendRecord(TRAIL, "x", { writerCapId: CAP })).rejects.toThrow(/ANCHOR_KEYSTORE_PATH/);
  });
});
