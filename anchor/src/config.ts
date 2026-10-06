import path from "node:path";
import { fileURLToPath } from "node:url";

export type NetworkName = "testnet" | "mainnet";

export interface PackageIds {
  /** Latest Audit Trail package: the one whose functions we call. */
  auditTrail: string;
  /** Original Audit Trail package: Move type tags always use this id. */
  auditTrailOriginal: string;
  tfComponents: string;
  /** Original Identity package: used to check that a DID's object really is an Identity. */
  identityOriginal: string;
}

export interface AnchorConfig {
  network: NetworkName;
  chainId: string;
  /** Network segment used in DIDs on this network (`did:iota:<segment>:0x…`); null when omitted. */
  didNetwork: string | null;
  rpcUrl: string;
  graphqlUrl: string;
  explorerUrl: string;
  packages: PackageIds;
  keystorePath: string | null;
  /** Keystore entry to use as sender and gas owner: a 0x address or a keystore alias. */
  address: string | null;
  secretsDir: string;
  /** Public identity file (DIDs, keys, links) written by bootstrap-identities and served at /identities. */
  identitiesFile: string;
  host: string;
  port: number;
  adminToken: string | null;
  trailId: string | null;
  gasBudget: bigint;
  resolveCacheMs: number;
}

interface NetworkDefaults {
  chainId: string;
  didNetwork: string | null;
  rpcUrl: string;
  graphqlUrl: string;
  packages: PackageIds;
}

// Package ids come from the upstream Move.lock files:
// iotaledger/notarization audit-trail-move, iotaledger/product-core components_move,
// iotaledger/identity identity_iota_core/packages/iota_identity.
export const NETWORKS: Record<NetworkName, NetworkDefaults> = {
  testnet: {
    chainId: "2304aa97",
    didNetwork: "testnet",
    rpcUrl: "https://api.testnet.iota.cafe",
    graphqlUrl: "https://graphql.testnet.iota.cafe",
    packages: {
      auditTrail: "0x385307a0da2859851d5820646efe617e1a957a3ea172a0f2a63487c987c93d88",
      auditTrailOriginal: "0x51368931f28620c7f65b4ae2c5167b42390e69729357a6347be378755b46e7df",
      tfComponents: "0xd45732966e800d52b28044cf3758088bfc4606618dfc96d1ec9b21587379b3d9",
      identityOriginal: "0x222741bbdff74b42df48a7b4733185e9b24becb8ccfbafe8eac864ab4e4cc555",
    },
  },
  mainnet: {
    chainId: "6364aad5",
    didNetwork: null,
    rpcUrl: "https://api.mainnet.iota.cafe",
    graphqlUrl: "https://graphql.mainnet.iota.cafe",
    packages: {
      auditTrail: "0x5439fccfc27e98ddd3f1163f2d1f22ed8384fe109177514093f020a5c0280b1a",
      auditTrailOriginal: "0x960d8a375af7bd09d19f08a9648940caf7e76289de90aa258b9e8e30a84f1b8a",
      tfComponents: "0x715d1661b457e96d508ee2108624d04dd4263ce496f3223ba36a7627edd75211",
      identityOriginal: "0x84cf5d12de2f9731a89bb519bc0c982a941b319a33abefdd5ed2054ad931de08",
    },
  },
};

export const DEFAULT_EXPLORER_URL = "https://explorer.iota.org";
export const DEFAULT_PORT = 7300;
export const DEFAULT_GAS_BUDGET = 50_000_000n;
const MAX_GAS_BUDGET = 1_000_000_000n;
const MIN_ADMIN_TOKEN_LENGTH = 16;

/** `deploy/identity/` of the repository, from either `anchor/src` or `anchor/dist`. */
export const DEPLOY_IDENTITY_DIR = fileURLToPath(new URL("../../deploy/identity/", import.meta.url));

const OBJECT_ID = /^0x[0-9a-f]{64}$/;
const ALIAS = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;

export class ConfigError extends Error {
  readonly issues: string[];
  constructor(issues: string[]) {
    super(`invalid anchor configuration:\n${issues.map((i) => `  - ${i}`).join("\n")}`);
    this.name = "ConfigError";
    this.issues = issues;
  }
}

type Env = Record<string, string | undefined>;

function opt(env: Env, key: string): string | undefined {
  const v = env[key]?.trim();
  return v ? v : undefined;
}

function httpUrl(issues: string[], key: string, value: string): string {
  try {
    const u = new URL(value);
    if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error("scheme");
    return value.replace(/\/+$/, "");
  } catch {
    issues.push(`${key} must be an http(s) URL`);
    return value;
  }
}

function objectId(issues: string[], key: string, value: string): string {
  const v = value.toLowerCase();
  if (!OBJECT_ID.test(v)) issues.push(`${key} must be 0x followed by 64 hex characters`);
  return v;
}

function integer(issues: string[], key: string, value: string, min: number, max: number): number {
  if (!/^\d+$/.test(value) || Number(value) < min || Number(value) > max) {
    issues.push(`${key} must be an integer between ${min} and ${max}`);
    return min;
  }
  return Number(value);
}

/**
 * Builds the anchor configuration from environment variables. Every problem is collected and
 * reported at once. Values of secret settings are never echoed back in error messages.
 */
export function loadConfig(env: Env = process.env, cwd: string = process.cwd()): AnchorConfig {
  const issues: string[] = [];

  const networkRaw = opt(env, "IOTA_NETWORK") ?? "testnet";
  if (networkRaw !== "testnet" && networkRaw !== "mainnet") {
    throw new ConfigError([`IOTA_NETWORK must be "testnet" or "mainnet" (got "${networkRaw.slice(0, 32)}")`]);
  }
  const network: NetworkName = networkRaw;
  const defaults = NETWORKS[network];

  const rpcUrl = httpUrl(issues, "IOTA_RPC_URL", opt(env, "IOTA_RPC_URL") ?? defaults.rpcUrl);
  const graphqlUrl = httpUrl(issues, "IOTA_GRAPHQL_URL", opt(env, "IOTA_GRAPHQL_URL") ?? defaults.graphqlUrl);
  const explorerUrl = httpUrl(issues, "IOTA_EXPLORER_URL", opt(env, "IOTA_EXPLORER_URL") ?? DEFAULT_EXPLORER_URL);

  const packages: PackageIds = {
    auditTrail: objectId(issues, "IOTA_AUDIT_TRAIL_PKG_ID", opt(env, "IOTA_AUDIT_TRAIL_PKG_ID") ?? defaults.packages.auditTrail),
    auditTrailOriginal: objectId(
      issues,
      "IOTA_AUDIT_TRAIL_ORIGINAL_PKG_ID",
      opt(env, "IOTA_AUDIT_TRAIL_ORIGINAL_PKG_ID") ?? defaults.packages.auditTrailOriginal,
    ),
    tfComponents: objectId(issues, "IOTA_TF_COMPONENTS_PKG_ID", opt(env, "IOTA_TF_COMPONENTS_PKG_ID") ?? defaults.packages.tfComponents),
    identityOriginal: objectId(
      issues,
      "IOTA_IDENTITY_ORIGINAL_PKG_ID",
      opt(env, "IOTA_IDENTITY_ORIGINAL_PKG_ID") ?? defaults.packages.identityOriginal,
    ),
  };

  const keystorePath = opt(env, "ANCHOR_KEYSTORE_PATH") ?? null;
  let address = opt(env, "ANCHOR_ADDRESS") ?? null;
  if (address !== null) {
    if (address.startsWith("0x") || address.startsWith("0X")) address = objectId(issues, "ANCHOR_ADDRESS", address);
    else if (!ALIAS.test(address)) issues.push("ANCHOR_ADDRESS must be a 0x address or a keystore alias");
  }
  if ((keystorePath === null) !== (address === null)) {
    issues.push("ANCHOR_KEYSTORE_PATH and ANCHOR_ADDRESS must be set together");
  }

  const secretsDir = path.resolve(cwd, opt(env, "SECRETS_DIR") ?? "secrets");
  const identitiesRaw = opt(env, "ANCHOR_IDENTITIES_FILE");
  const identitiesFile = identitiesRaw ? path.resolve(cwd, identitiesRaw) : path.join(DEPLOY_IDENTITY_DIR, `${network}.json`);
  const host = opt(env, "ANCHOR_HOST") ?? "127.0.0.1";
  const portRaw = opt(env, "ANCHOR_PORT");
  const port = portRaw === undefined ? DEFAULT_PORT : integer(issues, "ANCHOR_PORT", portRaw, 1, 65535);

  const adminToken = opt(env, "ANCHOR_ADMIN_TOKEN") ?? null;
  if (adminToken !== null && adminToken.length < MIN_ADMIN_TOKEN_LENGTH) {
    issues.push(`ANCHOR_ADMIN_TOKEN must be at least ${MIN_ADMIN_TOKEN_LENGTH} characters`);
  }

  const trailRaw = opt(env, "ANCHOR_TRAIL_ID");
  const trailId = trailRaw === undefined ? null : objectId(issues, "ANCHOR_TRAIL_ID", trailRaw);

  let gasBudget = DEFAULT_GAS_BUDGET;
  const gasRaw = opt(env, "ANCHOR_GAS_BUDGET");
  if (gasRaw !== undefined) {
    if (!/^\d+$/.test(gasRaw) || BigInt(gasRaw) < 1_000_000n || BigInt(gasRaw) > MAX_GAS_BUDGET) {
      issues.push(`ANCHOR_GAS_BUDGET must be an integer number of nanos between 1000000 and ${MAX_GAS_BUDGET}`);
    } else {
      gasBudget = BigInt(gasRaw);
    }
  }

  const cacheRaw = opt(env, "ANCHOR_RESOLVE_CACHE_MS");
  const resolveCacheMs = cacheRaw === undefined ? 60_000 : integer(issues, "ANCHOR_RESOLVE_CACHE_MS", cacheRaw, 0, 3_600_000);

  if (issues.length > 0) throw new ConfigError(issues);

  return {
    network,
    chainId: defaults.chainId,
    didNetwork: defaults.didNetwork,
    rpcUrl,
    graphqlUrl,
    explorerUrl,
    packages,
    keystorePath,
    address,
    secretsDir,
    identitiesFile,
    host,
    port,
    adminToken,
    trailId,
    gasBudget,
    resolveCacheMs,
  };
}

export type ExplorerKind = "object" | "txblock" | "address";

export function explorerLink(cfg: Pick<AnchorConfig, "explorerUrl" | "network">, kind: ExplorerKind, id: string): string {
  return `${cfg.explorerUrl}/${kind}/${encodeURIComponent(id)}?network=${cfg.network}`;
}
