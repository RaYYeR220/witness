import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { inspect } from "node:util";
import { decodeIotaPrivateKey, encodeIotaPrivateKey } from "@iota/iota-sdk/cryptography";
import { Ed25519Keypair } from "@iota/iota-sdk/keypairs/ed25519";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AnchorWallet, KeystoreError, loadKeystoreKeypair } from "../src/client.js";

let dir: string;
const a = Ed25519Keypair.generate();
const b = Ed25519Keypair.generate();
const encodedA = a.getSecretKey();
const encodedB = b.getSecretKey();
const rawB = decodeIotaPrivateKey(encodedB).secretKey;

/** Every textual form of B's secret that must never show up in errors or logs. */
const secretForms = [encodedB, Buffer.from(rawB).toString("hex"), Buffer.from(rawB).toString("base64"), encodedB.slice(12, 40)];

function write(name: string, content: unknown): string {
  const file = path.join(dir, name);
  writeFileSync(file, typeof content === "string" ? content : JSON.stringify(content));
  return file;
}

function errorOf(fn: () => unknown): Error {
  try {
    fn();
  } catch (err) {
    return err as Error;
  }
  throw new Error("expected an error");
}

function expectNoSecret(text: string): void {
  for (const s of secretForms) expect(text).not.toContain(s);
}

beforeAll(() => {
  dir = mkdtempSync(path.join(os.tmpdir(), "anchor-keystore-"));
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const keystore = () => ({
  version: 2,
  keys: [
    { alias: "first", address: a.toIotaAddress(), key: { type: "key_pair", value: encodedA } },
    { alias: "veles-testnet", address: b.toIotaAddress(), key: { type: "key_pair", value: encodedB } },
  ],
});

describe("loadKeystoreKeypair", () => {
  it("picks the entry whose address matches ANCHOR_ADDRESS", () => {
    const file = write("ks.json", keystore());
    expect(loadKeystoreKeypair(file, b.toIotaAddress()).toIotaAddress()).toBe(b.toIotaAddress());
    expect(loadKeystoreKeypair(file, a.toIotaAddress()).toIotaAddress()).toBe(a.toIotaAddress());
  });

  it("selects by alias as well", () => {
    const file = write("ks-alias.json", keystore());
    expect(loadKeystoreKeypair(file, "veles-testnet").toIotaAddress()).toBe(b.toIotaAddress());
  });

  it("reads the legacy flat array of base64(flag || secret)", () => {
    const legacy = (kp: Ed25519Keypair) =>
      Buffer.concat([Buffer.from([0]), Buffer.from(decodeIotaPrivateKey(kp.getSecretKey()).secretKey)]).toString("base64");
    const file = write("legacy.json", [legacy(a), legacy(b)]);
    expect(loadKeystoreKeypair(file, b.toIotaAddress()).toIotaAddress()).toBe(b.toIotaAddress());
  });

  it("reports a missing entry without key material", () => {
    const file = write("ks-missing.json", keystore());
    const err = errorOf(() => loadKeystoreKeypair(file, "0x" + "9".repeat(64)));
    expect(err).toBeInstanceOf(KeystoreError);
    expect(err.message).toContain("no entry");
    expectNoSecret(err.message + String(err.stack));
  });

  it("does not leak the file content when the JSON is broken", () => {
    const file = write("broken.json", `{"keys":[{"address":"${b.toIotaAddress()}","key":{"value":"${encodedB}"}`);
    const err = errorOf(() => loadKeystoreKeypair(file, b.toIotaAddress()));
    expect(err).toBeInstanceOf(KeystoreError);
    expect(err.message).toContain("not valid JSON");
    expect((err as Error & { cause?: unknown }).cause).toBeUndefined();
    expectNoSecret(err.message + String(err.stack));
  });

  it("does not leak a corrupted key value", () => {
    const corrupted = encodedB.slice(0, -1) + (encodedB.endsWith("q") ? "p" : "q");
    const ks = keystore();
    ks.keys[1]!.key.value = corrupted;
    const file = write("corrupt.json", ks);
    const err = errorOf(() => loadKeystoreKeypair(file, b.toIotaAddress()));
    expect(err).toBeInstanceOf(KeystoreError);
    expect(err.message).toContain("could not be decoded");
    expect(err.message).not.toContain(corrupted.slice(12, 40));
    expectNoSecret(err.message + String(err.stack));
  });

  it("refuses an entry whose key does not derive its address", () => {
    const ks = keystore();
    ks.keys[0]!.key.value = encodedB;
    const file = write("mismatch.json", ks);
    const err = errorOf(() => loadKeystoreKeypair(file, a.toIotaAddress()));
    expect(err.message).toContain("does not derive its own address");
    expectNoSecret(err.message);
  });

  it("refuses keys that are not Ed25519", () => {
    const ks = keystore();
    ks.keys[1]!.key.value = encodeIotaPrivateKey(rawB, "Secp256k1");
    const file = write("secp.json", ks);
    const err = errorOf(() => loadKeystoreKeypair(file, b.toIotaAddress()));
    expect(err.message).toContain("not an Ed25519 key");
    expectNoSecret(err.message);
  });

  it("reports an unreadable keystore by path only", () => {
    const err = errorOf(() => loadKeystoreKeypair(path.join(dir, "nope.json"), b.toIotaAddress()));
    expect(err).toBeInstanceOf(KeystoreError);
    expect(err.message).toContain("not readable");
  });
});

describe("AnchorWallet", () => {
  it("never serializes or prints its key", async () => {
    const file = write("ks-wallet.json", keystore());
    const wallet = AnchorWallet.fromKeystore(file, b.toIotaAddress());
    const signer = wallet.transactionSigner();
    const views = [JSON.stringify(wallet), inspect(wallet, { showHidden: true, depth: 5 }), JSON.stringify(signer), inspect(signer, { showHidden: true, depth: 5 }), String(Object.keys(wallet))];
    for (const v of views) expectNoSecret(v);
    expect(wallet.address).toBe(b.toIotaAddress());
    expect(signer.keyId()).toBe(b.toIotaAddress());
    expect(await signer.iotaPublicKeyBytes()).toEqual(b.getPublicKey().toIotaBytes());
  });

  it("runs transactions one at a time, even after a failure", async () => {
    const wallet = AnchorWallet.fromKeypair(Ed25519Keypair.generate());
    const order: string[] = [];
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const first = wallet.exclusive(async () => {
      order.push("first:start");
      await gate;
      order.push("first:end");
      throw new Error("boom");
    });
    const second = wallet.exclusive(async () => {
      order.push("second");
      return 2;
    });
    await new Promise((r) => setTimeout(r, 20));
    expect(order).toEqual(["first:start"]);
    release();
    await expect(first).rejects.toThrow("boom");
    await expect(second).resolves.toBe(2);
    expect(order).toEqual(["first:start", "first:end", "second"]);
  });

  it("asks for keystore settings when they are missing", () => {
    const err = errorOf(() => AnchorWallet.fromConfig({ keystorePath: null, address: null }));
    expect(err.message).toContain("ANCHOR_KEYSTORE_PATH");
  });
});
