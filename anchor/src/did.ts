import { generateKeyPairSync, type JsonWebKey } from "node:crypto";
import { existsSync, mkdirSync, renameSync } from "node:fs";
import path from "node:path";
import type { IotaClient, IotaObjectData, IotaTransactionBlockResponse } from "@iota/iota-sdk/client";
import type { IdentityClient, IotaDocument } from "@iota/identity-wasm/node/index.js";
import { assertSuccess, forWasm, type AnchorWallet } from "./client.js";
import { explorerLink, type AnchorConfig, type NetworkName } from "./config.js";
import {
  InvalidDidError,
  collectMethods,
  decodeStateMetadata,
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
  /** Timestamp of the checkpoint that included the transaction removing the method. */
  revokedAtMs: number;
  tx: string;
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
  /** False when part of the history could not be read (pruned versions, page cap). */
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

function diffInto(
  revoked: Map<string, RevokedMethod>,
  before: Map<string, MethodJson>,
  after: Map<string, MethodJson>,
  atMs: number,
  tx: string,
): void {
  for (const [kid, method] of before) if (!after.has(kid)) revoked.set(kid, { kid, revokedAtMs: atMs, tx, method });
  // A method that comes back under the same id is current again.
  for (const kid of after.keys()) revoked.delete(kid);
}

/**
 * Resolves a did:iota DID from IOTA Rebased JSON-RPC.
 *
 * The current document comes from the Identity object. Revocations come from its history: every
 * transaction that changed the object (`iotax_queryTransactionBlocks` with `ChangedObject`), the
 * object as it was after each of them (`iota_tryGetPastObject`), and a diff of the method sets of
 * consecutive versions. A method that disappears is revoked at that transaction's checkpoint time.
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
  const currentMethods = collectMethods(now.doc);
  const currentVersion = BigInt(current.data.version);

  const revoked = new Map<string, RevokedMethod>();
  let complete = true;
  let previous: Map<string, MethodJson> | null = null;
  let lastVersion: string | null = null;
  let cursor: string | null | undefined = null;
  const maxPages = opts.maxPages ?? 20;
  for (let page = 0; ; page++) {
    if (page === maxPages) {
      complete = false;
      break;
    }
    const res = await rpc.queryTransactionBlocks({
      filter: { ChangedObject: objectId },
      options: { showEffects: true },
      cursor,
      limit: opts.pageSize ?? 50,
      order: "ascending",
    });
    for (const tx of res.data) {
      const ref = refFor(tx, objectId);
      // Changes newer than the document read above belong to the next resolution.
      if (!ref || BigInt(ref.version) > currentVersion) continue;
      let methods: Map<string, MethodJson>;
      if (ref.gone) {
        methods = new Map();
      } else {
        const past = await rpc.tryGetPastObject({ id: objectId, version: Number(ref.version), options: { showContent: true } });
        const pastFields = past.status === "VersionFound" ? identityFields(past.details) : null;
        if (!pastFields) {
          complete = false;
          continue;
        }
        try {
          methods = collectMethods(documentAt(pastFields, did).doc);
        } catch (err) {
          log.warn("skipping undecodable DID version", { did, version: ref.version, error: err });
          complete = false;
          continue;
        }
      }
      if (previous) {
        const atMs = Number(tx.timestampMs ?? NaN);
        diffInto(revoked, previous, methods, Number.isFinite(atMs) ? atMs : Number(fields.updated ?? 0), tx.digest);
      }
      previous = methods;
      lastVersion = ref.version;
    }
    if (!res.hasNextPage || !res.nextCursor) break;
    cursor = res.nextCursor;
  }

  // The transaction index can lag behind the object itself; close the gap with the live version.
  if (previous && lastVersion !== null && BigInt(lastVersion) < currentVersion) {
    diffInto(revoked, previous, currentMethods, Number(fields.updated ?? 0), current.data.previousTransaction ?? "unknown");
  }
  for (const kid of currentMethods.keys()) revoked.delete(kid);

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
  for (const [kid, method] of collectMethods(r.doc)) {
    const k = methodPublicKey(method);
    if (k) keys.push({ kid, type: k.type, publicKeyHex: k.publicKeyHex, revokedAtMs: null });
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

export interface ComponentIdentity {
  name: string;
  did: string;
  objectId: string;
  sigKid: string;
  kexKid: string;
  sigPublicJwk: PublicJwk;
  kexPublicJwk: PublicJwk;
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
  keys: { kid: string; type: KeyType; relationships: string[]; publicKeyHex: string; publicKeyJwk: PublicJwk }[];
  createdTx: string;
  createdAt: string;
  links: { identity: string; createdTx: string };
}

/** The shareable view of a component identity: DID, public keys and explorer links. */
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
    keys: [
      key(entry.sigKid, entry.sigPublicJwk, ["authentication", "assertionMethod"]),
      key(entry.kexKid, entry.kexPublicJwk, ["keyAgreement"]),
    ],
    createdTx: entry.createdTx,
    createdAt: entry.createdAt,
    links: { identity: explorerLink(cfg, "object", entry.objectId), createdTx: explorerLink(cfg, "txblock", entry.createdTx) },
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
 * assertionMethod) and an X25519 `#kex-1` keyAgreement method, both as public JWKs.
 */
export async function buildComponentDocument(network: string, sigPublicJwk: PublicJwk, kexPublicJwk: PublicJwk): Promise<IotaDocument> {
  const w = await identityWasm();
  const doc = new w.IotaDocument(network);
  const sig = w.VerificationMethod.newFromJwk(doc.id(), w.Jwk.fromJSON(sigPublicJwk), `#${SIG_FRAGMENT}`);
  doc.insertMethod(sig, w.MethodScope.VerificationMethod());
  doc.attachMethodRelationship(doc.id().join(`#${SIG_FRAGMENT}`), w.MethodRelationship.Authentication);
  doc.attachMethodRelationship(doc.id().join(`#${SIG_FRAGMENT}`), w.MethodRelationship.AssertionMethod);
  const kex = w.VerificationMethod.newFromJwk(doc.id(), w.Jwk.fromJSON(kexPublicJwk), `#${KEX_FRAGMENT}`);
  doc.insertMethod(kex, w.MethodScope.KeyAgreement());
  return doc;
}

export interface RevokeResult {
  tx: string;
  link: string;
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

  #identityClient(): Promise<IdentityClient> {
    const wallet = this.#wallet;
    if (!wallet) return Promise.reject(new Error("DID writes need ANCHOR_KEYSTORE_PATH and ANCHOR_ADDRESS"));
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
   * Creates and publishes a DID for a component. Private keys are written under
   * `${SECRETS_DIR}/<name>/` before the transaction is sent, so a crash can never leave a
   * published DID without its keys. Returns public information only.
   */
  async createComponentDid(name: string): Promise<ComponentIdentity> {
    const dir = componentKeyDir(this.#cfg.secretsDir, name);
    const registry = loadIdentityRegistry(this.#cfg);
    const existing = registry.identities[name];
    if (existing) throw new Error(`component "${name}" already has ${existing.did}`);
    const client = await this.#identityClient();

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

    const doc = await buildComponentDocument(client.network(), sig.publicJwk, kex.publicJwk);
    const { output: identity, response } = await this.#wallet!.exclusive(() =>
      client.createIdentity(doc).finish().withGasBudget(this.#cfg.gasBudget).buildAndExecute(client),
    );
    assertSuccess(response as IotaTransactionBlockResponse);

    const published = identity.didDocument();
    const did = published.id().toString();
    const sigKid = `${did}#${SIG_FRAGMENT}`;
    const kexKid = `${did}#${KEX_FRAGMENT}`;
    const methods = collectMethods((published.toJSON() as { doc: unknown }).doc);
    if (methods.get(sigKid)?.publicKeyJwk?.x !== sig.publicJwk.x || methods.get(kexKid)?.publicKeyJwk?.x !== kex.publicJwk.x) {
      throw new Error(`published document of ${did} does not carry the generated keys`);
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
      createdTx: response.digest,
      createdAt: new Date().toISOString(),
    };
    registry.identities[name] = entry;
    saveIdentityRegistry(this.#cfg, registry);
    return entry;
  }

  /** Removes a verification method from a DID document. The removal time becomes its revocation time. */
  async revokeMethod(didInput: string, fragment: string): Promise<RevokeResult> {
    const parsed: ParsedDid = parseDid(didInput);
    if (parsed.network !== this.#cfg.didNetwork) throw new InvalidDidError(`DID does not belong to ${this.#cfg.network}`);
    if (!FRAGMENT.test(fragment)) throw new Error(`invalid method fragment "${fragment}"`);
    const w = await identityWasm();
    const client = await this.#identityClient();

    const iotaDid = w.IotaDID.parse(parsed.did);
    const doc = await client.resolveDid(iotaDid);
    if (!doc.removeMethod(iotaDid.join(`#${fragment}`))) throw new Error(`${parsed.did} has no method #${fragment}`);

    const identity = (await client.getIdentity(parsed.objectId)).toFullFledged();
    if (!identity) throw new Error(`${parsed.did} is not an IOTA Rebased identity`);
    const token = await identity.getControllerToken(client);
    if (!token) throw new Error(`${this.#wallet?.address} is not a controller of ${parsed.did}`);

    const { output, response } = await this.#wallet!.exclusive(() =>
      identity.updateDidDocument(doc.clone(), token).withGasBudget(this.#cfg.gasBudget).buildAndExecute(client),
    );
    assertSuccess(response as IotaTransactionBlockResponse);
    return {
      tx: response.digest,
      link: explorerLink(this.#cfg, "txblock", response.digest),
      pendingProposal: output != null,
    };
  }
}
