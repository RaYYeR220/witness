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
  checkpoints: CheckpointConfig;
}

/** Settings of the checkpoint loop (window selection, sources, state and the mirror). */
export interface CheckpointConfig {
  /** Run the anchoring loop (ANCHOR_LOOP=on); needs the keystore and the writer policy. Off by default. */
  loop: boolean;
  /** witness-api base URL serving `GET /milestones?from=&to=`. */
  apiUrl: string;
  /** witness-relay base URL (`POST /upload?node=`) the `witness.anchor` mirror goes through. */
  relayUrl: string;
  /** Node name passed to the relay as `?node=`. */
  relayNode: string;
  /** Milestones per checkpoint window. */
  every: number;
  /** First milestone index of the first window, when no checkpoint exists yet. */
  startIndex: number;
  /** `domain` written into checkpoints; null means the domain DID of the identities file. */
  domain: string | null;
  /** Network name of the private Tangle (`network` of checkpoints and bundles). */
  tangleNetwork: string;
  /** Writer policy JSON whose hash every checkpoint commits to. */
  policyPath: string | null;
  /** Loop state: checkpoints written, the pending append, the mirror chain. */
  statePath: string;
  /** Component whose `#sig-1` key signs the mirror envelopes. */
  identity: string;
  pollMs: number;
  httpTimeoutMs: number;
  /** Development only (HORNET stub): commit msgCount 0 when the source does not report it. */
  allowMissingMsgCount: boolean;
  /** HORNET node every milestone id of a window is checked against; required for the loop. */
  hornetUrl: string | null;
  /**
   * Ticks without a new checkpoint before /healthz reports the loop stalled. Default:
   * max(60, 2 x the ticks one window takes), so a healthy loop never looks stalled.
   */
  stallTicks: number;
  /** Expected time between milestones of the private Tangle (only sizes the stall default). */
  milestoneIntervalMs: number;
  /** Address whose records the read API accepts (defaults to the loop's wallet). */
  writerAddress: string | null;
  /** How long a checkpoint read from the chain is served again (at most 10 s). */
  readCacheMs: number;
  /** Pinned coordinator public keys (lowercase 0x hex) and signature threshold. */
  coordinatorKeys: string[];
  coordinatorThreshold: number;
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

export const DEFAULT_API_URL = "http://127.0.0.1:7200";
export const DEFAULT_RELAY_URL = "http://127.0.0.1:5555";
export const DEFAULT_EVERY = 60;
export const MAX_EVERY = 10_000;
export const DEFAULT_TANGLE_NETWORK = "private_tangle1";

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

  const checkpoints = checkpointConfig(env, cwd, issues, secretsDir, keystorePath !== null);

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
    checkpoints,
  };
}

function flag(issues: string[], key: string, value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const v = value.toLowerCase();
  if (["1", "true", "on", "yes"].includes(v)) return true;
  if (["0", "false", "off", "no"].includes(v)) return false;
  issues.push(`${key} must be on or off`);
  return fallback;
}

function checkpointConfig(env: Env, cwd: string, issues: string[], secretsDir: string, hasKeystore: boolean): CheckpointConfig {
  const loop = flag(issues, "ANCHOR_LOOP", opt(env, "ANCHOR_LOOP"), false);
  if (loop && !hasKeystore) issues.push("ANCHOR_LOOP needs ANCHOR_KEYSTORE_PATH and ANCHOR_ADDRESS (it writes to the trail)");

  const everyRaw = opt(env, "ANCHOR_EVERY");
  const every = everyRaw === undefined ? DEFAULT_EVERY : integer(issues, "ANCHOR_EVERY", everyRaw, 1, MAX_EVERY);
  const startRaw = opt(env, "ANCHOR_START_INDEX");
  const startIndex = startRaw === undefined ? 1 : integer(issues, "ANCHOR_START_INDEX", startRaw, 0, 0xffff_ffff);
  const pollRaw = opt(env, "ANCHOR_POLL_MS");
  const pollMs = pollRaw === undefined ? 10_000 : integer(issues, "ANCHOR_POLL_MS", pollRaw, 500, 86_400_000);
  const timeoutRaw = opt(env, "ANCHOR_HTTP_TIMEOUT_MS");
  const httpTimeoutMs = timeoutRaw === undefined ? 10_000 : integer(issues, "ANCHOR_HTTP_TIMEOUT_MS", timeoutRaw, 100, 120_000);

  const relayNode = opt(env, "ANCHOR_RELAY_NODE") ?? "iota-hornet";
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(relayNode)) issues.push("ANCHOR_RELAY_NODE must be a plain node name");
  const identity = opt(env, "ANCHOR_IDENTITY") ?? "anchor";
  if (!/^[a-z][a-z0-9-]{0,31}$/.test(identity)) issues.push("ANCHOR_IDENTITY must be a component name");
  const domain = opt(env, "ANCHOR_DOMAIN") ?? null;
  if (domain !== null && domain.length > 256) issues.push("ANCHOR_DOMAIN must be at most 256 characters");
  const tangleNetwork = opt(env, "ANCHOR_NETWORK_NAME") ?? DEFAULT_TANGLE_NETWORK;
  if (tangleNetwork.length > 64) issues.push("ANCHOR_NETWORK_NAME must be at most 64 characters");

  const hornetRaw = opt(env, "ANCHOR_HORNET_URL");
  const hornetUrl = hornetRaw === undefined ? null : httpUrl(issues, "ANCHOR_HORNET_URL", hornetRaw);
  const coordinatorKeys = (opt(env, "ANCHOR_COORDINATOR_KEYS") ?? "")
    .split(",")
    .map((k) => k.trim().toLowerCase())
    .filter(Boolean);
  if (coordinatorKeys.some((k) => !OBJECT_ID.test(k))) issues.push("ANCHOR_COORDINATOR_KEYS must be 0x-prefixed 32-byte hex keys, comma-separated");
  const thresholdRaw = opt(env, "ANCHOR_COORDINATOR_THRESHOLD");
  const coordinatorThreshold =
    thresholdRaw === undefined ? coordinatorKeys.length : integer(issues, "ANCHOR_COORDINATOR_THRESHOLD", thresholdRaw, 1, Math.max(coordinatorKeys.length, 1));
  if (loop) {
    // The anchor never takes milestone ids from the indexer on trust: it re-derives them from the node.
    if (hornetUrl === null) issues.push("ANCHOR_HORNET_URL is required when ANCHOR_LOOP is on (every milestone id is checked against the node)");
    if (coordinatorKeys.length === 0) issues.push("ANCHOR_COORDINATOR_KEYS is required when ANCHOR_LOOP is on (milestone signatures are checked)");
  }

  const intervalRaw = opt(env, "ANCHOR_MILESTONE_INTERVAL_MS");
  const milestoneIntervalMs = intervalRaw === undefined ? 5_000 : integer(issues, "ANCHOR_MILESTONE_INTERVAL_MS", intervalRaw, 100, 3_600_000);
  const stallRaw = opt(env, "ANCHOR_STALL_TICKS");
  const stallTicks =
    stallRaw === undefined
      ? Math.max(60, Math.ceil((2 * every * milestoneIntervalMs) / pollMs))
      : integer(issues, "ANCHOR_STALL_TICKS", stallRaw, 1, 100_000);
  const writerRaw = opt(env, "ANCHOR_WRITER_ADDRESS");
  const writerAddress = writerRaw === undefined ? null : objectId(issues, "ANCHOR_WRITER_ADDRESS", writerRaw);
  const readCacheRaw = opt(env, "ANCHOR_CHECKPOINT_CACHE_MS");
  const readCacheMs = readCacheRaw === undefined ? 5_000 : integer(issues, "ANCHOR_CHECKPOINT_CACHE_MS", readCacheRaw, 0, 10_000);

  const policyRaw = opt(env, "ANCHOR_POLICY_PATH");
  if (loop && !policyRaw) issues.push("ANCHOR_POLICY_PATH is required when ANCHOR_LOOP is on (checkpoints commit to the writer policy hash)");
  const stateRaw = opt(env, "ANCHOR_STATE_PATH");
  return {
    loop,
    apiUrl: httpUrl(issues, "ANCHOR_API_URL", opt(env, "ANCHOR_API_URL") ?? DEFAULT_API_URL),
    relayUrl: httpUrl(issues, "ANCHOR_RELAY_URL", opt(env, "ANCHOR_RELAY_URL") ?? DEFAULT_RELAY_URL),
    relayNode,
    every,
    startIndex,
    domain,
    tangleNetwork,
    policyPath: policyRaw ? path.resolve(cwd, policyRaw) : null,
    // Next to the secrets, not inside them: the state holds nothing secret and is safe to back up.
    statePath: stateRaw ? path.resolve(cwd, stateRaw) : path.join(path.dirname(secretsDir), "data", "anchor-state.json"),
    identity,
    pollMs,
    httpTimeoutMs,
    allowMissingMsgCount: flag(issues, "ANCHOR_ALLOW_MISSING_MSGCOUNT", opt(env, "ANCHOR_ALLOW_MISSING_MSGCOUNT"), false),
    hornetUrl,
    stallTicks,
    milestoneIntervalMs,
    writerAddress,
    readCacheMs,
    coordinatorKeys,
    coordinatorThreshold,
  };
}

export type ExplorerKind = "object" | "txblock" | "address";

export function explorerLink(cfg: Pick<AnchorConfig, "explorerUrl" | "network">, kind: ExplorerKind, id: string): string {
  return `${cfg.explorerUrl}/${kind}/${encodeURIComponent(id)}?network=${cfg.network}`;
}
