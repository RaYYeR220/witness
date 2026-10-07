import { generateKeyPairSync, type JsonWebKey } from "node:crypto";
import { existsSync, mkdirSync, renameSync } from "node:fs";
import path from "node:path";
import type { IotaClient, IotaObjectData, IotaTransactionBlockResponse } from "@iota/iota-sdk/client";
import type { ControllerToken, IdentityClient, IotaDocument, OnChainIdentity } from "@iota/identity-wasm/node/index.js";
import { assertSuccess, forWasm, type AnchorWallet } from "./client.js";
import { explorerLink, type AnchorConfig, type NetworkName } from "./config.js";
import {
  InvalidDidError,
  collectMethods,
  decodeStateMetadata,
  methodIdentity,
  methodPublicKey,
  parseDid,
  withRealDid,
  type DidDocumentJson,
  type KeyType,
  type MethodJson,
  type ParsedDid,
  type PublicJwk,
} from "./didcodec.js";
import { readJsonIfExists, writeJsonAtomic } from "./fsutil.js";
import { log } from "./log.js";

export { InvalidDidError } from "./didcodec.js";

export const SIG_FRAGMENT = "sig-1";
export const KEX_FRAGMENT = "kex-1";
export const COMPONENT_NAME = /^[a-z][a-z0-9-]{0,31}$/;
const FRAGMENT = /^[A-Za-z0-9._-]{1,64}$/;

export class DidNotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DidNotFoundError";
  }
}

// ---------------------------------------------------------------------------------------------
// Resolution: current document plus revocation times from the Identity object's version history
// ---------------------------------------------------------------------------------------------

export interface RevokedMethod {
  kid: string;
  /**
   * When the method stopped being valid. Errs early: when the removing transaction cannot be
   * pinned down (unreadable versions, page cap, index lag), this is the earliest time it could
   * have happened, never a later one.
   */
  revokedAtMs: number;
  /** The removing transaction, or the first transaction of the window it happened in. */
  tx: string;
  /** True when the removal was seen between two consecutive readable versions. */
  exact: boolean;
  /** The method as it was published before removal (carries the public key). */
  method: MethodJson;
}

export interface ResolvedDid {
  did: string;
  objectId: string;
  doc: DidDocumentJson;
  meta: { created: string | null; updated: string | null; deactivated: boolean };
  /** Identity object version the document was read at. */
  version: string;
  revokedMethods: RevokedMethod[];
  /** False when part of the history could not be read (pruned versions, page cap, index lag). */
  historyComplete: boolean;
}

export interface ResolvedKey {
  kid: string;
  type: KeyType;
  publicKeyHex: string;
  revokedAtMs: number | null;
}

export type DidRpc = Pick<IotaClient, "getObject" | "queryTransactionBlocks" | "tryGetPastObject">;

interface IdentityFields {
  created?: string;
  updated?: string;
  deleted?: boolean;
  did_doc?: { fields?: { controlled_value?: number[] | null } };
}

function identityFields(data: IotaObjectData | null | undefined): IdentityFields | null {
  const content = data?.content;
  if (!content || content.dataType !== "moveObject") return null;
  return content.fields as unknown as IdentityFields;
}

function msToIso(ms: string | undefined): string | null {
  return ms && /^\d+$/.test(ms) ? new Date(Number(ms)).toISOString() : null;
}

function documentAt(fields: IdentityFields, did: string): { doc: DidDocumentJson | null; deactivated: boolean } {
  const decoded = decodeStateMetadata(fields.did_doc?.fields?.controlled_value);
  if (decoded === null || fields.deleted) return { doc: null, deactivated: true };
  const doc = withRealDid(decoded.doc, did) as DidDocumentJson;
  const meta = decoded.meta as { deactivated?: unknown } | null;
  return { doc, deactivated: meta?.deactivated === true };
}

type MethodSet = Map<string, { kid: string; method: MethodJson }>;

/** Methods valid in a document version, keyed by id plus key material. A deactivated document has none. */
function validMethods(state: { doc: DidDocumentJson | null; deactivated: boolean }): MethodSet {
  const out: MethodSet = new Map();
  if (state.deactivated || !state.doc) return out;
  for (const [kid, method] of collectMethods(state.doc)) out.set(methodIdentity(kid, method), { kid, method });
  return out;
}

function refFor(tx: IotaTransactionBlockResponse, objectId: string): { version: string; gone: boolean } | null {
  const effects = tx.effects;
  if (!effects) return null;
  const live = [...(effects.created ?? []), ...(effects.mutated ?? []), ...(effects.unwrapped ?? [])].find(
    (o) => o.reference.objectId === objectId,
  );
  if (live) return { version: String(live.reference.version), gone: false };
  const gone = [...(effects.deleted ?? []), ...(effects.wrapped ?? []), ...(effects.unwrappedThenDeleted ?? [])].find(
    (o) => o.objectId === objectId,
  );
  return gone ? { version: String(gone.version), gone: true } : null;
}

interface ChangePoint {
  ms: number;
  tx: string;
  exact: boolean;
}

function diffInto(revoked: Map<string, RevokedMethod>, before: MethodSet, after: MethodSet, at: ChangePoint): void {
  for (const [key, { kid, method }] of before) {
    if (!after.has(key)) revoked.set(key, { kid, revokedAtMs: at.ms, tx: at.tx, exact: at.exact, method });
  }
  // The same key coming back under the same id is valid again.
  for (const key of after.keys()) revoked.delete(key);
}

/**
 * Resolves a did:iota DID from IOTA Rebased JSON-RPC.
 *
 * The current document comes from the Identity object. Revocations come from its history: every
 * transaction that changed the object (`iotax_queryTransactionBlocks` with `ChangedObject`), the
 * object as it was after each of them (`iota_tryGetPastObject`), and a diff of the valid method
 * sets of consecutive versions. Methods are compared by id and key material, so a key replaced
 * under the same id revokes the old key. A method that disappears is revoked at the checkpoint
 * time of the transaction that removed it; when that transaction cannot be identified, at the
 * earliest transaction of the window it must have happened in.
 */
export async function resolveDid(
  rpc: DidRpc,
  cfg: Pick<AnchorConfig, "didNetwork" | "packages">,
  didInput: string,
  opts: { maxPages?: number; pageSize?: number } = {},
): Promise<ResolvedDid> {
  const parsed = parseDid(didInput);
  if (parsed.network !== cfg.didNetwork) {
    throw new InvalidDidError(`DID belongs to network "${parsed.network ?? "iota"}", this resolver serves "${cfg.didNetwork ?? "iota"}"`);
  }
  const { did, objectId } = parsed;

  const current = await rpc.getObject({
    id: objectId,
    options: { showContent: true, showType: true, showPreviousTransaction: true },
  });
  if (!current.data) throw new DidNotFoundError(`${did} not found`);
  const expectedType = `${cfg.packages.identityOriginal}::identity::Identity`;
  if (current.data.type !== expectedType) throw new DidNotFoundError(`${did} is not an IOTA Identity object`);
  const fields = identityFields(current.data);
  if (!fields) throw new DidNotFoundError(`${did} has no readable content`);
  const now = documentAt(fields, did);
  const currentMethods = validMethods(now);
  const currentVersion = BigInt(current.data.version);

  const revoked = new Map<string, RevokedMethod>();
  let complete = true;
  let previous: MethodSet | null = null;
  let lastVersion: bigint | null = null;
  let lastMs: number | null = null;
  // First transaction after the last readable version whose own version could not be read.
  let gap: ChangePoint | null = null;
  let cursor: string | null | undefined = null;
  const maxPages = opts.maxPages ?? 20;
  const pageSize = opts.pageSize ?? 50;
  const after = (ms: number | null) => (ms ?? 0) + 1;

  for (let page = 0; ; page++) {
    if (page === maxPages) {
      complete = false;
      // The earliest unread transaction bounds any change hidden behind the page cap.
      const next = await rpc.queryTransactionBlocks({ filter: { ChangedObject: objectId }, cursor, limit: 1, order: "ascending" });
      const first = next.data[0];
      const firstMs = Number(first?.timestampMs ?? NaN);
      gap ??= { ms: Number.isFinite(firstMs) ? firstMs : after(lastMs), tx: first?.digest ?? "unknown", exact: false };
      break;
    }
    const res = await rpc.queryTransactionBlocks({
      filter: { ChangedObject: objectId },
      options: { showEffects: true },
      cursor,
      limit: pageSize,
      order: "ascending",
    });
    for (const tx of res.data) {
      const ref = refFor(tx, objectId);
      // Changes newer than the document read above belong to the next resolution.
      if (!ref || BigInt(ref.version) > currentVersion) continue;
      const txMs = Number(tx.timestampMs ?? NaN);
      const at: ChangePoint = { ms: Number.isFinite(txMs) ? txMs : after(lastMs), tx: tx.digest, exact: true };
      let methods: MethodSet | null = null;
      if (ref.gone) {
        methods = new Map();
      } else {
        const past = await rpc.tryGetPastObject({ id: objectId, version: Number(ref.version), options: { showContent: true } });
        const pastFields = past.status === "VersionFound" ? identityFields(past.details) : null;
        if (pastFields) {
          try {
            methods = validMethods(documentAt(pastFields, did));
          } catch (err) {
            log.warn("undecodable DID version", { did, version: ref.version, error: err });
          }
        }
      }
      if (methods === null) {
        complete = false;
        gap ??= { ...at, exact: false };
        continue;
      }
      if (previous) diffInto(revoked, previous, methods, gap ?? at);
      gap = null;
      previous = methods;
      lastVersion = BigInt(ref.version);
      lastMs = at.ms;
    }
    if (!res.hasNextPage || !res.nextCursor) break;
    cursor = res.nextCursor;
  }

  // Close the window between the last readable version and the live object. The transaction
  // index can lag behind the object, so a change there is dated just after the last one seen.
  if (previous && lastVersion !== null && lastVersion < currentVersion) {
    complete = false;
    const at = gap ?? { ms: after(lastMs), tx: current.data.previousTransaction ?? "unknown", exact: false };
    diffInto(revoked, previous, currentMethods, at);
  }
  if (previous === null) complete = false;
  for (const key of currentMethods.keys()) revoked.delete(key);

  return {
    did,
    objectId,
    doc: now.doc ?? { id: did },
    meta: { created: msToIso(fields.created), updated: msToIso(fields.updated), deactivated: now.deactivated },
    version: current.data.version,
    revokedMethods: [...revoked.values()].sort((a, b) => a.revokedAtMs - b.revokedAtMs),
    historyComplete: complete,
  };
}

/** Flattens a resolution into the key list served by `GET /resolve/:did`. */
export function resolvedKeys(r: ResolvedDid): ResolvedKey[] {
  const keys: ResolvedKey[] = [];
  if (!r.meta.deactivated) {
    for (const [kid, method] of collectMethods(r.doc)) {
      const k = methodPublicKey(method);
      if (k) keys.push({ kid, type: k.type, publicKeyHex: k.publicKeyHex, revokedAtMs: null });
    }
  }
  for (const rm of r.revokedMethods) {
    const k = methodPublicKey(rm.method);
    if (k) keys.push({ kid: rm.kid, type: k.type, publicKeyHex: k.publicKeyHex, revokedAtMs: rm.revokedAtMs });
  }
  return keys;
}

// ---------------------------------------------------------------------------------------------
// Component identities: creation, key storage, registry
// ---------------------------------------------------------------------------------------------

/** Who holds the ControllerCap of an identity: an address (the domain) or another identity. */
export type IdentityController = { kind: "address"; address: string } | { kind: "identity"; did: string; objectId: string };

export interface ComponentIdentity {
  name: string;
  did: string;
  objectId: string;
  sigKid: string;
  kexKid: string;
  sigPublicJwk: PublicJwk;
  kexPublicJwk: PublicJwk;
  controller: IdentityController;
  createdTx: string;
  createdAt: string;
}

export interface IdentityRegistry {
  network: NetworkName;
  identities: Record<string, ComponentIdentity>;
}

export interface PublicIdentity {
  name: string;
  did: string;
  objectId: string;
  controller: IdentityController | null;
  keys: { kid: string; type: KeyType; relationships: string[]; publicKeyHex: string; publicKeyJwk: PublicJwk }[];
  createdTx: string;
  createdAt: string;
  links: { identity: string; createdTx: string };
}

/** The shareable view of a component identity: DID, controller, public keys and explorer links. */
export function publicIdentity(cfg: Pick<AnchorConfig, "explorerUrl" | "network">, entry: ComponentIdentity): PublicIdentity {
  const key = (kid: string, jwk: PublicJwk, relationships: string[]) => {
    const k = methodPublicKey({ id: kid, publicKeyJwk: jwk });
    if (!k) throw new Error(`registry entry ${entry.name} holds an unsupported key for ${kid}`);
    return { kid, type: k.type, relationships, publicKeyHex: k.publicKeyHex, publicKeyJwk: jwk };
  };
  return {
    name: entry.name,
    did: entry.did,
    objectId: entry.objectId,
    controller: entry.controller ?? null,
    keys: [
      key(entry.sigKid, entry.sigPublicJwk, ["authentication", "assertionMethod"]),
      key(entry.kexKid, entry.kexPublicJwk, ["keyAgreement"]),
    ],
    createdTx: entry.createdTx,
    createdAt: entry.createdAt,
    links: { identity: explorerLink(cfg, "object", entry.objectId), createdTx: explorerLink(cfg, "txblock", entry.createdTx) },
  };
}

/** A verification method a DID removed, as the deploy file records it (public data only). */
export interface RevokedKeyRecord {
  kid: string;
  revokedAtMs: number;
  revokedAt: string;
  /** The removing transaction (or the first of the window it happened in when not exact). */
  tx: string;
  exact: boolean;
  link: string;
}

/** The revocation of `kid` in a resolution, or null while the method is current or never existed. */
export function revocationOf(cfg: Pick<AnchorConfig, "explorerUrl" | "network">, r: ResolvedDid, kid: string): RevokedKeyRecord | null {
  if (!r.meta.deactivated && collectMethods(r.doc).has(kid)) return null;
  const m = r.revokedMethods.find((x) => x.kid === kid);
  if (!m) return null;
  return {
    kid,
    revokedAtMs: m.revokedAtMs,
    revokedAt: new Date(m.revokedAtMs).toISOString(),
    tx: m.tx,
    exact: m.exact,
    link: explorerLink(cfg, "txblock", m.tx),
  };
}

export function registryPath(secretsDir: string): string {
  return path.join(secretsDir, "identities.json");
}

export function loadIdentityRegistry(cfg: Pick<AnchorConfig, "secretsDir" | "network">): IdentityRegistry {
  const reg = readJsonIfExists<IdentityRegistry>(registryPath(cfg.secretsDir));
  if (!reg) return { network: cfg.network, identities: {} };
  if (reg.network !== cfg.network) {
    throw new Error(`${registryPath(cfg.secretsDir)} holds ${reg.network} identities, but IOTA_NETWORK is ${cfg.network}`);
  }
  return { network: reg.network, identities: reg.identities ?? {} };
}

function saveIdentityRegistry(cfg: Pick<AnchorConfig, "secretsDir">, reg: IdentityRegistry): void {
  writeJsonAtomic(registryPath(cfg.secretsDir), reg, { secret: true });
}

/** Directory holding a component's private JWKs (`sig-1.jwk.json`, `kex-1.jwk.json`). */
export function componentKeyDir(secretsDir: string, name: string): string {
  if (!COMPONENT_NAME.test(name)) throw new Error(`invalid component name "${name}"`);
  return path.join(secretsDir, name);
}

/**
 * Moves the registry and every registered component's keys to `${SECRETS_DIR}/.stale/retired-<ts>/`.
 * Nothing is deleted. Returns the retired entries so their public records can be kept.
 */
export function retireIdentities(cfg: Pick<AnchorConfig, "secretsDir" | "network">): ComponentIdentity[] {
  const registry = loadIdentityRegistry(cfg);
  const retired = Object.values(registry.identities);
  if (retired.length === 0) return [];
  const dest = path.join(cfg.secretsDir, ".stale", `retired-${new Date().toISOString().replace(/[:.]/g, "-")}`);
  mkdirSync(dest, { recursive: true, mode: 0o700 });
  for (const entry of retired) {
    const dir = componentKeyDir(cfg.secretsDir, entry.name);
    if (existsSync(dir)) renameSync(dir, path.join(dest, entry.name));
  }
  renameSync(registryPath(cfg.secretsDir), path.join(dest, "identities.json"));
  return retired;
}

/** Splits `did#frag`, `#frag` or `frag` into a fragment, checking that a full kid names `did`. */
export function methodFragment(did: string, method: string): string {
  let fragment = method;
  const hash = method.indexOf("#");
  if (hash > 0) {
    if (parseDid(method.slice(0, hash)).did !== did) throw new InvalidDidError(`${method} is not a method of ${did}`);
    fragment = method.slice(hash + 1);
  } else if (hash === 0) {
    fragment = method.slice(1);
  }
  if (!FRAGMENT.test(fragment)) throw new Error(`invalid method fragment "${fragment}"`);
  return fragment;
}

function generateOkp(curve: "ed25519" | "x25519"): { publicJwk: PublicJwk; privateJwk: JsonWebKey } {
  const { privateKey } = generateKeyPairSync(curve as "ed25519");
  const jwk = privateKey.export({ format: "jwk" });
  const publicJwk: PublicJwk = { kty: "OKP", crv: String(jwk.crv), x: String(jwk.x) };
  if (curve === "ed25519") publicJwk.alg = "EdDSA";
  return { publicJwk, privateJwk: { ...publicJwk, d: jwk.d } };
}

type IdentityWasm = typeof import("@iota/identity-wasm/node/index.js");
let identityWasmModule: Promise<IdentityWasm> | null = null;

/** The identity WASM module is loaded on first use, so read-only paths never pay for it. */
export function identityWasm(): Promise<IdentityWasm> {
  identityWasmModule ??= import("@iota/identity-wasm/node/index.js");
  return identityWasmModule;
}

/**
 * Builds an unpublished DID document with an Ed25519 `#sig-1` method (authentication and
 * assertionMethod) and an X25519 `#kex-1` keyAgreement method, both as public JWKs. With
 * `controllerDid`, the document's `controller` property names the controlling DID.
 */
export async function buildComponentDocument(
  network: string,
  sigPublicJwk: PublicJwk,
  kexPublicJwk: PublicJwk,
  controllerDid?: string,
): Promise<IotaDocument> {
  const w = await identityWasm();
  const doc = new w.IotaDocument(network);
  const sig = w.VerificationMethod.newFromJwk(doc.id(), w.Jwk.fromJSON(sigPublicJwk), `#${SIG_FRAGMENT}`);
  doc.insertMethod(sig, w.MethodScope.VerificationMethod());
  doc.attachMethodRelationship(doc.id().join(`#${SIG_FRAGMENT}`), w.MethodRelationship.Authentication);
  doc.attachMethodRelationship(doc.id().join(`#${SIG_FRAGMENT}`), w.MethodRelationship.AssertionMethod);
  const kex = w.VerificationMethod.newFromJwk(doc.id(), w.Jwk.fromJSON(kexPublicJwk), `#${KEX_FRAGMENT}`);
  doc.insertMethod(kex, w.MethodScope.KeyAgreement());
  if (controllerDid) doc.setController([w.IotaDID.parse(controllerDid)]);
  return doc;
}

export interface RevokeResult {
  tx: string;
  link: string;
  /** Identity whose controller token authorized the update: the DID itself or its controlling identity. */
  via: string;
  /** True when the update became a proposal that still needs other controllers' approval. */
  pendingProposal: boolean;
}

/** did:iota operations for the deployment's components. Writes need a wallet; resolution does not. */
export class DidService {
  readonly #cfg: AnchorConfig;
  readonly #iota: IotaClient;
  readonly #wallet: AnchorWallet | null;
  #client: Promise<IdentityClient> | null = null;

  constructor(cfg: AnchorConfig, iota: IotaClient, wallet: AnchorWallet | null) {
    this.#cfg = cfg;
    this.#iota = iota;
    this.#wallet = wallet;
  }

  resolve(did: string): Promise<ResolvedDid> {
    return resolveDid(this.#iota, this.#cfg, did);
  }

  registry(): IdentityRegistry {
    return loadIdentityRegistry(this.#cfg);
  }

  #requireWallet(): AnchorWallet {
    if (!this.#wallet) throw new Error("DID writes need ANCHOR_KEYSTORE_PATH and ANCHOR_ADDRESS");
    return this.#wallet;
  }

  #identityClient(): Promise<IdentityClient> {
    let wallet: AnchorWallet;
    try {
      wallet = this.#requireWallet();
    } catch (err) {
      return Promise.reject(err);
    }
    this.#client ??= (async () => {
      const w = await identityWasm();
      const ro = await w.IdentityClientReadOnly.create(forWasm(this.#iota));
      // IdentityClient.create takes ownership of `ro`; read everything needed from it first.
      const network = ro.network();
      const original = ro.packageHistory()[0];
      const expected = this.#cfg.didNetwork ?? "iota";
      if (network !== expected) throw new Error(`identity client is on network "${network}", expected "${expected}"`);
      if (original !== this.#cfg.packages.identityOriginal) {
        throw new Error(`identity package ${original} differs from IOTA_IDENTITY_ORIGINAL_PKG_ID ${this.#cfg.packages.identityOriginal}`);
      }
      return w.IdentityClient.create(ro, wallet.transactionSigner());
    })().catch((err: unknown) => {
      this.#client = null;
      throw err;
    });
    return this.#client;
  }

  /**
   * Creates and publishes a DID for a component. Without `controller` the identity is controlled
   * by the wallet address (the domain DID); with it, the ControllerCap goes to the controlling
   * identity and the document names it as `controller`. Private keys are written under
   * `${SECRETS_DIR}/<name>/` before the transaction is sent, so a crash can never leave a
   * published DID without its keys. Returns public information only.
   */
  async createComponentDid(name: string, controller?: { did: string; objectId: string }): Promise<ComponentIdentity> {
    const dir = componentKeyDir(this.#cfg.secretsDir, name);
    const registry = loadIdentityRegistry(this.#cfg);
    const existing = registry.identities[name];
    if (existing) throw new Error(`component "${name}" already has ${existing.did}`);
    const wallet = this.#requireWallet();
    const client = await this.#identityClient();
    if (controller) parseDid(controller.did);

    if (existsSync(dir)) {
      // Keys without a registry entry come from an interrupted run. Keep them, out of the way.
      const aside = path.join(this.#cfg.secretsDir, ".stale", `${name}-${Date.now()}`);
      mkdirSync(path.dirname(aside), { recursive: true, mode: 0o700 });
      renameSync(dir, aside);
      log.warn("moved unregistered component keys aside", { component: name, to: aside });
    }

    const sig = generateOkp("ed25519");
    const kex = generateOkp("x25519");
    const sigFile = path.join(dir, `${SIG_FRAGMENT}.jwk.json`);
    const kexFile = path.join(dir, `${KEX_FRAGMENT}.jwk.json`);
    writeJsonAtomic(sigFile, sig.privateJwk, { secret: true });
    writeJsonAtomic(kexFile, kex.privateJwk, { secret: true });

    const doc = await buildComponentDocument(client.network(), sig.publicJwk, kex.publicJwk, controller?.did);
    const { output: identity, response } = await wallet.exclusive(() => {
      const builder = client.createIdentity(doc);
      return (controller ? builder.controller(controller.objectId, 1n) : builder)
        .finish()
        .withGasBudget(this.#cfg.gasBudget)
        .buildAndExecute(client);
    });
    assertSuccess(response as IotaTransactionBlockResponse);

    const published = identity.didDocument();
    const did = published.id().toString();
    const sigKid = `${did}#${SIG_FRAGMENT}`;
    const kexKid = `${did}#${KEX_FRAGMENT}`;
    const json = (published.toJSON() as { doc: DidDocumentJson }).doc;
    const methods = collectMethods(json);
    if (methods.get(sigKid)?.publicKeyJwk?.x !== sig.publicJwk.x || methods.get(kexKid)?.publicKeyJwk?.x !== kex.publicJwk.x) {
      throw new Error(`published document of ${did} does not carry the generated keys`);
    }
    if (controller && json.controller !== controller.did && !(Array.isArray(json.controller) && json.controller.includes(controller.did))) {
      throw new Error(`published document of ${did} does not name ${controller.did} as controller`);
    }

    writeJsonAtomic(sigFile, { ...sig.privateJwk, kid: sigKid }, { secret: true });
    writeJsonAtomic(kexFile, { ...kex.privateJwk, kid: kexKid }, { secret: true });

    const entry: ComponentIdentity = {
      name,
      did,
      objectId: identity.id(),
      sigKid,
      kexKid,
      sigPublicJwk: sig.publicJwk,
      kexPublicJwk: kex.publicJwk,
      controller: controller ? { kind: "identity", did: controller.did, objectId: controller.objectId } : { kind: "address", address: wallet.address },
      createdTx: response.digest,
      createdAt: new Date().toISOString(),
    };
    registry.identities[name] = entry;
    saveIdentityRegistry(this.#cfg, registry);
    return entry;
  }

  /**
   * Finds an identity that holds a ControllerCap of `objectId` and that the wallet controls.
   * ControllerCaps are listed in the identity's `controllers` map; one transferred to another
   * identity is owned by that identity's object address.
   */
  async #controllingIdentity(client: IdentityClient, objectId: string): Promise<{ identity: OnChainIdentity; token: ControllerToken } | null> {
    const obj = await this.#iota.getObject({ id: objectId, options: { showContent: true } });
    const fields = obj.data?.content?.dataType === "moveObject" ? (obj.data.content.fields as Record<string, any>) : null;
    const entries: unknown[] = fields?.did_doc?.fields?.controllers?.fields?.contents ?? [];
    for (const entry of entries) {
      const capId = (entry as { fields?: { key?: unknown } })?.fields?.key;
      if (typeof capId !== "string") continue;
      const cap = await this.#iota.getObject({ id: capId, options: { showOwner: true } });
      const owner = cap.data?.owner;
      const holder = owner && typeof owner === "object" && "AddressOwner" in owner ? owner.AddressOwner : null;
      if (!holder || holder === this.#wallet?.address) continue;
      let parent: OnChainIdentity | undefined;
      try {
        parent = (await client.getIdentity(holder)).toFullFledged();
      } catch {
        continue;
      }
      if (!parent) continue;
      const token = await parent.getControllerToken(client);
      if (token) return { identity: parent, token };
    }
    return null;
  }

  /**
   * Removes a verification method (`did#frag`, `#frag` or `frag`) from a DID document; the
   * removal time becomes its revocation time. Component DIDs are updated through their
   * controlling (domain) identity.
   */
  async revokeMethod(didInput: string, method: string): Promise<RevokeResult> {
    const parsed: ParsedDid = parseDid(didInput);
    if (parsed.network !== this.#cfg.didNetwork) throw new InvalidDidError(`DID does not belong to ${this.#cfg.network}`);
    const fragment = methodFragment(parsed.did, method);
    const wallet = this.#requireWallet();
    const w = await identityWasm();
    const client = await this.#identityClient();

    const iotaDid = w.IotaDID.parse(parsed.did);
    const doc = await client.resolveDid(iotaDid);
    if (!doc.removeMethod(iotaDid.join(`#${fragment}`))) throw new Error(`${parsed.did} has no method #${fragment}`);

    const identity = (await client.getIdentity(parsed.objectId)).toFullFledged();
    if (!identity) throw new Error(`${parsed.did} is not an IOTA Rebased identity`);
    const gas = this.#cfg.gasBudget;

    let via = parsed.did;
    let result: { output: unknown; response: unknown };
    const direct = await identity.getControllerToken(client);
    if (direct) {
      result = await wallet.exclusive(() => identity.updateDidDocument(doc.clone(), direct).withGasBudget(gas).buildAndExecute(client));
    } else {
      const parent = await this.#controllingIdentity(client, parsed.objectId);
      if (!parent) throw new Error(`${wallet.address} controls neither ${parsed.did} nor an identity that controls it`);
      via = parent.identity.didDocument().id().toString();
      const updated = doc.clone();
      result = await wallet.exclusive(() =>
        parent.identity
          .accessSubIdentity(parent.token, identity, async (sub, subToken) => sub.updateDidDocument(updated.clone(), subToken).transaction)
          .withGasBudget(gas)
          .buildAndExecute(client),
      );
    }
    const response = result.response as IotaTransactionBlockResponse;
    assertSuccess(response);
    return {
      tx: response.digest,
      link: explorerLink(this.#cfg, "txblock", response.digest),
      via,
      pendingProposal: result.output != null,
    };
  }
}
