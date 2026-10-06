import { createHash } from "node:crypto";
import path from "node:path";
import type { IotaClient, IotaEvent, IotaTransactionBlockResponse } from "@iota/iota-sdk/client";
import { Transaction } from "@iota/iota-sdk/transactions";
import { assertSuccess, forWasm, gasUsedNanos, type AnchorWallet } from "./client.js";
import { explorerLink, type AnchorConfig, type PackageIds } from "./config.js";
import { readJsonIfExists, writeJsonAtomic } from "./fsutil.js";
import { log } from "./log.js";

export const WRITER_ROLE = "writer";
/** Records stay locked against deletion for this long (100 years); the trail itself can never be deleted. */
const RECORD_DELETE_LOCK_SECONDS = 100n * 365n * 24n * 3600n;
/** The protocol caps a single pure argument at 16 KiB. */
export const MAX_RECORD_BYTES = 16 * 1024 - 64;

export interface TrailState {
  network: string;
  trailId: string;
  createTx?: string;
  adminCapId?: string;
  roleTx?: string;
  writerCapId?: string;
  capTx?: string;
  createdAt?: string;
}

export interface AppendResult {
  trailId: string;
  recordIndex: number;
  tx: string;
  timestampMs: number;
  addedBy: string;
  metadata: string | null;
  gasNanos: string | null;
  links: { tx: string; trail: string };
}

export interface TrailRecord {
  trailId: string;
  recordIndex: number;
  data: string | Uint8Array;
  dataKind: "text" | "bytes";
  metadata: string | null;
  tag: string | null;
  addedAtMs: number;
  addedBy: string;
  /** Transaction that added the record, when it could be found. */
  tx: string | null;
  links: { trail: string; tx: string | null };
}

export function sha256Metadata(data: string | Uint8Array): string {
  return `sha256:${createHash("sha256").update(data).digest("hex")}`;
}

/**
 * Builds the `add_record` transaction by hand against the latest Audit Trail package.
 * `@iota/audit-trails` 0.1.3 tags record data with the latest package id, which the upgraded
 * testnet package rejects; Move type tags must use the original package id instead.
 */
export function buildAddRecordTx(
  pkgs: Pick<PackageIds, "auditTrail" | "auditTrailOriginal">,
  trailId: string,
  writerCapId: string,
  data: string | Uint8Array,
  metadata: string | null,
  gasBudget: bigint,
): Transaction {
  const tx = new Transaction();
  const value =
    typeof data === "string"
      ? tx.moveCall({ target: `${pkgs.auditTrail}::record::new_text`, arguments: [tx.pure.string(data)] })
      : tx.moveCall({ target: `${pkgs.auditTrail}::record::new_bytes`, arguments: [tx.pure.vector("u8", data)] });
  tx.moveCall({
    target: `${pkgs.auditTrail}::main::add_record`,
    typeArguments: [`${pkgs.auditTrailOriginal}::record::Data`],
    arguments: [
      tx.object(trailId),
      tx.object(writerCapId),
      value,
      tx.pure.option("string", metadata),
      tx.pure.option("string", null),
      tx.object.clock(),
    ],
  });
  tx.setGasBudget(gasBudget);
  return tx;
}

interface RecordAddedJson {
  trail_id: string;
  sequence_number: string;
  added_by: string;
  timestamp: string;
}

function recordAddedEvents(events: IotaEvent[] | null | undefined, pkgs: Pick<PackageIds, "auditTrailOriginal">, trailId: string): RecordAddedJson[] {
  const type = `${pkgs.auditTrailOriginal}::main::RecordAdded`;
  return (events ?? [])
    .filter((e) => e.type === type)
    .map((e) => e.parsedJson as RecordAddedJson)
    .filter((j) => j?.trail_id === trailId);
}

interface RecordFields {
  data: { variant: string; fields: { pos0: unknown } };
  metadata: string | null;
  tag: string | null;
  sequence_number: string;
  added_by: string;
  added_at: string;
}

/** Decodes the `Record<Data>` value of a records table entry as returned by JSON-RPC. */
export function parseRecordFields(fields: RecordFields): Omit<TrailRecord, "trailId" | "tx" | "links"> {
  const { variant, fields: inner } = fields.data;
  let data: string | Uint8Array;
  let dataKind: "text" | "bytes";
  if (variant === "Text" && typeof inner.pos0 === "string") {
    data = inner.pos0;
    dataKind = "text";
  } else if (variant === "Bytes" && Array.isArray(inner.pos0)) {
    data = Uint8Array.from(inner.pos0 as number[]);
    dataKind = "bytes";
  } else {
    throw new Error(`unknown record data variant ${variant}`);
  }
  return {
    recordIndex: Number(fields.sequence_number),
    data,
    dataKind,
    metadata: fields.metadata ?? null,
    tag: fields.tag ?? null,
    addedAtMs: Number(fields.added_at),
    addedBy: fields.added_by,
  };
}

export type TrailRpc = Pick<IotaClient, "getObject" | "getDynamicFieldObject" | "queryTransactionBlocks" | "getOwnedObjects">;

type AuditTrailWasm = typeof import("@iota/audit-trails/node/index.js");
let auditTrailModule: Promise<AuditTrailWasm> | null = null;
function auditTrailWasm(): Promise<AuditTrailWasm> {
  auditTrailModule ??= import("@iota/audit-trails/node/index.js");
  return auditTrailModule;
}

/** Audit Trail backend: one trail per deployment, written through a writer-role capability. */
export class TrailService {
  readonly #cfg: AnchorConfig;
  readonly #iota: IotaClient;
  readonly #wallet: AnchorWallet | null;
  readonly #tables = new Map<string, string>();

  constructor(cfg: AnchorConfig, iota: IotaClient, wallet: AnchorWallet | null) {
    this.#cfg = cfg;
    this.#iota = iota;
    this.#wallet = wallet;
  }

  get statePath(): string {
    return path.join(this.#cfg.secretsDir, `trail-${this.#cfg.network}.json`);
  }

  #readState(): TrailState | null {
    const s = readJsonIfExists<TrailState>(this.statePath);
    if (s && s.network !== this.#cfg.network) throw new Error(`${this.statePath} belongs to ${s.network}`);
    return s;
  }

  #saveState(s: TrailState): void {
    writeJsonAtomic(this.statePath, s, { secret: true });
  }

  #requireWallet(): AnchorWallet {
    if (!this.#wallet) throw new Error("trail writes need ANCHOR_KEYSTORE_PATH and ANCHOR_ADDRESS");
    return this.#wallet;
  }

  link(kind: "object" | "txblock", id: string): string {
    return explorerLink(this.#cfg, kind, id);
  }

  async #client() {
    const wallet = this.#requireWallet();
    const w = await auditTrailWasm();
    const ro = await w.AuditTrailClientReadOnly.create(forWasm(this.#iota));
    const pkg = ro.packageId();
    const tf = ro.tfComponentsPackageId();
    if (pkg !== this.#cfg.packages.auditTrail) throw new Error(`audit-trail package ${pkg} differs from IOTA_AUDIT_TRAIL_PKG_ID`);
    if (tf !== this.#cfg.packages.tfComponents) throw new Error(`TF components package ${tf} differs from IOTA_TF_COMPONENTS_PKG_ID`);
    return { w, client: await w.AuditTrailClient.create(ro, wallet.transactionSigner()) };
  }

  /**
   * Returns the deployment's trail id, creating what is missing: the trail (with a genesis
   * record), a `writer` role that may only add records, and a writer capability for our address.
   * Progress is saved after every step, so an interrupted run resumes where it stopped.
   */
  async ensureTrail(): Promise<string> {
    const wallet = this.#requireWallet();
    let state = this.#readState();
    if (this.#cfg.trailId && state?.trailId !== this.#cfg.trailId) {
      state = { network: this.#cfg.network, trailId: this.#cfg.trailId };
    }
    if (state?.writerCapId && (await this.#ownsWriterCap(state.trailId, state.writerCapId))) return state.trailId;

    const gas = this.#cfg.gasBudget;
    if (!state) {
      const { w, client } = await this.#client();
      const genesis = JSON.stringify({ v: 1, kind: "witness.trail", network: this.#cfg.network, purpose: "aeriOS private Tangle checkpoints" });
      const { output: trail, response } = await wallet.exclusive(() =>
        client
          .createTrail()
          .withTrailMetadata("witness-anchor", "Witness checkpoints of the aeriOS private Tangle")
          .withLockingConfig(
            new w.LockingConfig(w.LockingWindow.withTimeBased(RECORD_DELETE_LOCK_SECONDS), w.TimeLock.withInfinite(), w.TimeLock.withNone()),
          )
          .withInitialRecordString(genesis, sha256Metadata(genesis))
          .finish()
          .withGasBudget(gas)
          .buildAndExecute(client),
      );
      assertSuccess(response as IotaTransactionBlockResponse);
      state = { network: this.#cfg.network, trailId: trail.id, createTx: response.digest, createdAt: new Date().toISOString() };
      state.adminCapId = (await this.#initialAdminCap(trail.id)) ?? undefined;
      this.#saveState(state);
      log.info("trail created", { trailId: trail.id, tx: response.digest });
    }

    const found = await this.#findWriterCap(state.trailId);
    if (found) {
      state.writerCapId = found;
      this.#saveState(state);
      return state.trailId;
    }

    const { w, client } = await this.#client();
    const role = client.trail(state.trailId).access().forRole(WRITER_ROLE);
    if (!state.roleTx) {
      const created = await wallet.exclusive(() =>
        role.create(new w.PermissionSet([w.Permission.AddRecord])).withGasBudget(gas).buildAndExecute(client),
      );
      assertSuccess(created.response as IotaTransactionBlockResponse);
      state.roleTx = created.response.digest;
      this.#saveState(state);
      log.info("writer role created", { trailId: state.trailId, tx: state.roleTx });
    }
    const issued = await wallet.exclusive(() =>
      role.issueCapability(new w.CapabilityIssueOptions(wallet.address)).withGasBudget(gas).buildAndExecute(client),
    );
    assertSuccess(issued.response as IotaTransactionBlockResponse);
    state.writerCapId = issued.output.capabilityId;
    state.capTx = issued.response.digest;
    this.#saveState(state);
    log.info("writer capability issued", { trailId: state.trailId, capability: state.writerCapId, tx: state.capTx });
    return state.trailId;
  }

  async #initialAdminCap(trailId: string): Promise<string | null> {
    const obj = await this.#iota.getObject({ id: trailId, options: { showContent: true } });
    const fields = obj.data?.content?.dataType === "moveObject" ? (obj.data.content.fields as Record<string, any>) : null;
    const ids = fields?.roles?.fields?.initial_admin_cap_ids?.fields?.contents;
    return Array.isArray(ids) && typeof ids[0] === "string" ? ids[0] : null;
  }

  async #ownsWriterCap(trailId: string, capId: string): Promise<boolean> {
    const obj = await this.#iota.getObject({ id: capId, options: { showContent: true, showOwner: true } });
    const owner = obj.data?.owner;
    const fields = obj.data?.content?.dataType === "moveObject" ? (obj.data.content.fields as Record<string, unknown>) : null;
    return (
      typeof owner === "object" &&
      owner !== null &&
      "AddressOwner" in owner &&
      owner.AddressOwner === this.#wallet?.address &&
      fields?.target_key === trailId &&
      fields?.role === WRITER_ROLE
    );
  }

  /** Looks for a writer capability for `trailId` among the objects our address owns. */
  async #findWriterCap(trailId: string): Promise<string | null> {
    const wallet = this.#requireWallet();
    let cursor: string | null | undefined = null;
    for (let page = 0; page < 20; page++) {
      const res = await this.#iota.getOwnedObjects({
        owner: wallet.address,
        filter: { StructType: `${this.#cfg.packages.tfComponents}::capability::Capability` },
        options: { showContent: true },
        cursor,
      });
      for (const o of res.data) {
        const f = o.data?.content?.dataType === "moveObject" ? (o.data.content.fields as Record<string, unknown>) : null;
        const until = f?.valid_until;
        const expired = typeof until === "string" && Number(until) <= Date.now();
        if (f?.target_key === trailId && f.role === WRITER_ROLE && !expired && o.data) return o.data.objectId;
      }
      if (!res.hasNextPage || !res.nextCursor) break;
      cursor = res.nextCursor;
    }
    return null;
  }

  /** Appends one record (text or bytes). Metadata defaults to `sha256:<hex>` of the data. */
  async appendRecord(
    trailId: string,
    data: string | Uint8Array,
    opts: { metadata?: string | null; writerCapId?: string } = {},
  ): Promise<AppendResult> {
    const wallet = this.#requireWallet();
    const size = typeof data === "string" ? Buffer.byteLength(data, "utf8") : data.length;
    if (size > MAX_RECORD_BYTES) throw new Error(`record is ${size} bytes, the limit is ${MAX_RECORD_BYTES}`);
    const state = this.#readState();
    const writerCapId =
      opts.writerCapId ?? (state?.trailId === trailId ? state.writerCapId : undefined) ?? (await this.#findWriterCap(trailId));
    if (!writerCapId) throw new Error(`no writer capability for trail ${trailId} owned by ${wallet.address}`);

    const metadata = opts.metadata === undefined ? sha256Metadata(data) : opts.metadata;
    const tx = buildAddRecordTx(this.#cfg.packages, trailId, writerCapId, data, metadata, this.#cfg.gasBudget);
    const res = await wallet.execute(this.#iota, tx);
    const ev = recordAddedEvents(res.events, this.#cfg.packages, trailId)[0];
    if (!ev) throw new Error(`transaction ${res.digest} emitted no RecordAdded event for ${trailId}`);
    const gas = gasUsedNanos(res);
    return {
      trailId,
      recordIndex: Number(ev.sequence_number),
      tx: res.digest,
      timestampMs: Number(ev.timestamp),
      addedBy: ev.added_by,
      metadata,
      gasNanos: gas === null ? null : gas.toString(),
      links: { tx: this.link("txblock", res.digest), trail: this.link("object", trailId) },
    };
  }

  async #recordsTable(trailId: string): Promise<string> {
    const cached = this.#tables.get(trailId);
    if (cached) return cached;
    const obj = await this.#iota.getObject({ id: trailId, options: { showContent: true, showType: true } });
    const expected = `${this.#cfg.packages.auditTrailOriginal}::main::AuditTrail<`;
    if (!obj.data?.type?.startsWith(expected)) throw new Error(`${trailId} is not an Audit Trail`);
    const fields = obj.data.content?.dataType === "moveObject" ? (obj.data.content.fields as Record<string, any>) : null;
    const tableId = fields?.records?.fields?.id?.id;
    if (typeof tableId !== "string") throw new Error(`${trailId} has no records table`);
    this.#tables.set(trailId, tableId);
    return tableId;
  }

  /** Reads a record by its sequence number. Returns null when the trail has no such record. */
  async readRecord(trailId: string, index: number, opts: { withTx?: boolean } = {}): Promise<TrailRecord | null> {
    if (!Number.isSafeInteger(index) || index < 0) throw new Error("record index must be a non-negative integer");
    const tableId = await this.#recordsTable(trailId);
    const res = await this.#iota.getDynamicFieldObject({
      parentObjectId: tableId,
      name: { type: "u64", value: String(index) },
      options: { showContent: true },
    });
    if (res.error) {
      if (res.error.code === "dynamicFieldNotFound") return null;
      throw new Error(`reading record ${index} of ${trailId} failed: ${res.error.code}`);
    }
    const content = res.data?.content;
    const node = content?.dataType === "moveObject" ? (content.fields as Record<string, any>) : null;
    const recordFields = node?.value?.fields?.value?.fields as RecordFields | undefined;
    if (!recordFields) throw new Error(`record ${index} of ${trailId} has an unexpected shape`);
    const record = parseRecordFields(recordFields);
    const tx = opts.withTx === false ? null : await this.findRecordTx(trailId, index);
    return { ...record, trailId, tx, links: { trail: this.link("object", trailId), tx: tx ? this.link("txblock", tx) : null } };
  }

  /**
   * Finds the transaction that added a record. The record's table entry is rewritten when the
   * next record is linked in, so its `previousTransaction` is not reliable; the trail's
   * transaction history (newest first) and its RecordAdded events are.
   */
  async findRecordTx(trailId: string, index: number, maxPages = 20): Promise<string | null> {
    if (index === 0) {
      // The genesis record is written by the transaction that created the trail.
      const first = await this.#iota.queryTransactionBlocks({ filter: { ChangedObject: trailId }, limit: 1, order: "ascending" });
      return first.data[0]?.digest ?? null;
    }
    let cursor: string | null | undefined = null;
    for (let page = 0; page < maxPages; page++) {
      const res = await this.#iota.queryTransactionBlocks({
        filter: { ChangedObject: trailId },
        options: { showEvents: true },
        cursor,
        limit: 50,
        order: "descending",
      });
      for (const t of res.data) {
        // One transaction can add several records; look at all of them before giving up.
        const seqs = recordAddedEvents(t.events, this.#cfg.packages, trailId).map((ev) => Number(ev.sequence_number));
        if (seqs.includes(index)) return t.digest;
        if (seqs.length > 0 && Math.max(...seqs) < index) return null;
      }
      if (!res.hasNextPage || !res.nextCursor) break;
      cursor = res.nextCursor;
    }
    return null;
  }
}
