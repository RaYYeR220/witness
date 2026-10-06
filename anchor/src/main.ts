import { ApiMilestoneSource, loadPolicyHash } from "./checkpoint.js";
import { CheckpointReader } from "./checkpoint-api.js";
import { AnchorWallet, ChainMismatchError, assertChain, createIotaClient, preferIpv4 } from "./client.js";
import { ConfigError, loadConfig } from "./config.js";
import { DidService, type PublicIdentity } from "./did.js";
import { readJsonIfExists } from "./fsutil.js";
import { HornetClient, HornetWindowVerifier } from "./hornet.js";
import { LockError, acquireLock } from "./lock.js";
import { log } from "./log.js";
import { AnchorLoop } from "./loop.js";
import { MirrorSigner, RelayClient } from "./mirror.js";
import { createAnchorServer, type IdentitiesBody } from "./server.js";
import { StateStore } from "./state.js";
import { TrailService } from "./trail.js";

interface IdentitiesFile extends IdentitiesBody {
  domain?: string;
}

async function main(): Promise<void> {
  preferIpv4();
  const cfg = loadConfig();
  const cp = cfg.checkpoints;
  const iota = createIotaClient(cfg);
  try {
    await assertChain(iota, cfg);
  } catch (err) {
    if (err instanceof ChainMismatchError) throw err;
    log.warn("could not verify the chain id at startup; continuing", { rpc: cfg.rpcUrl, error: err });
  }

  // Resolver and checkpoint reads need no key; only the anchoring loop loads the wallet.
  const wallet = cp.loop ? AnchorWallet.fromConfig(cfg) : null;
  const dids = new DidService(cfg, iota, null);
  const trail = new TrailService(cfg, iota, wallet);
  const store = new StateStore(cp.statePath);
  const identities = () => readJsonIfExists<IdentitiesFile>(cfg.identitiesFile);

  let loop: AnchorLoop | null = null;
  let release = () => {};
  if (wallet) {
    // One writer per state file and wallet: a second loop would race the first one's appends.
    release = acquireLock(`${cp.statePath}.lock`);
    process.on("exit", () => release());
    const hornet = new HornetClient(cp.hornetUrl!, cp.httpTimeoutMs);
    const ids = identities();
    const domain = cp.domain ?? ids?.domain ?? null;
    if (!domain) throw new ConfigError([`ANCHOR_DOMAIN is not set and ${cfg.identitiesFile} names no domain DID`]);
    loop = new AnchorLoop({
      network: cfg.network,
      writer: wallet.address,
      trail,
      source: new ApiMilestoneSource(cp.apiUrl, cp.httpTimeoutMs),
      blocks: hornet,
      verifier: new HornetWindowVerifier(hornet, {
        keys: new Set(cp.coordinatorKeys),
        threshold: cp.coordinatorThreshold,
      }),
      relay: new RelayClient(cp.relayUrl, cp.relayNode, cp.httpTimeoutMs),
      signer: MirrorSigner.load(cfg.secretsDir, cp.identity, ids as { identities?: PublicIdentity[] } | null),
      store,
      params: { network: cp.tangleNetwork, domain, policyHash: loadPolicyHash(cp.policyPath!) },
      every: cp.every,
      startIndex: cp.startIndex,
      pollMs: cp.pollMs,
      allowMissingMsgCount: cp.allowMissingMsgCount,
      stallTicks: cp.stallTicks,
    });
    if (cp.allowMissingMsgCount) log.warn("ANCHOR_ALLOW_MISSING_MSGCOUNT is on: checkpoints may commit msgCount 0 (development only)");
  }

  const server = createAnchorServer({
    network: cfg.network,
    resolve: (did) => dids.resolve(did),
    // Served from the committed public file, so the read-only service needs no secrets volume.
    identities,
    cacheTtlMs: cfg.resolveCacheMs,
    checkpoints: new CheckpointReader(store, trail, cfg.network, {
      // Records must come from the writer this deployment uses, on the trail it is configured for.
      writer: wallet?.address ?? cp.writerAddress ?? (cfg.address?.startsWith("0x") ? cfg.address : null),
      trailId: () => trail.knownTrailId(),
      ttlMs: cp.readCacheMs,
    }),
    loop,
    adminToken: cfg.adminToken,
  });

  server.listen(cfg.port, cfg.host, () => {
    log.info("anchor listening", { host: cfg.host, port: cfg.port, network: cfg.network, rpc: cfg.rpcUrl, anchoring: loop !== null });
    if (loop) {
      log.info("anchoring loop started", { api: cp.apiUrl, relay: cp.relayUrl, every: cp.every, state: cp.statePath, writer: wallet!.address });
      loop.start();
    }
  });

  const stop = (signal: string) => {
    log.info("shutting down", { signal });
    setTimeout(() => process.exit(0), 5000).unref();
    void (loop?.stop() ?? Promise.resolve()).finally(() => {
      release();
      server.close(() => process.exit(0));
    });
  };
  process.on("SIGINT", () => stop("SIGINT"));
  process.on("SIGTERM", () => stop("SIGTERM"));
}

main().catch((err: unknown) => {
  if (err instanceof ConfigError || err instanceof LockError) process.stderr.write(`${err.message}\n`);
  else log.error("anchor failed to start", { error: err });
  process.exit(1);
});
