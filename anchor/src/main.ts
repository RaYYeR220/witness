import { ChainMismatchError, assertChain, createIotaClient, preferIpv4 } from "./client.js";
import { ConfigError, loadConfig } from "./config.js";
import { DidService } from "./did.js";
import { readJsonIfExists } from "./fsutil.js";
import { log } from "./log.js";
import { createAnchorServer, type IdentitiesBody } from "./server.js";

async function main(): Promise<void> {
  preferIpv4();
  const cfg = loadConfig();
  const iota = createIotaClient(cfg);
  try {
    await assertChain(iota, cfg);
  } catch (err) {
    if (err instanceof ChainMismatchError) throw err;
    log.warn("could not verify the chain id at startup; continuing", { rpc: cfg.rpcUrl, error: err });
  }

  // The HTTP surface only reads from the chain, so it runs without the signing key.
  const dids = new DidService(cfg, iota, null);
  const server = createAnchorServer({
    network: cfg.network,
    resolve: (did) => dids.resolve(did),
    // Served from the committed public file, so the read-only service needs no secrets volume.
    identities: () => readJsonIfExists<IdentitiesBody>(cfg.identitiesFile),
    cacheTtlMs: cfg.resolveCacheMs,
  });

  server.listen(cfg.port, cfg.host, () => {
    log.info("anchor listening", { host: cfg.host, port: cfg.port, network: cfg.network, rpc: cfg.rpcUrl });
  });

  const stop = (signal: string) => {
    log.info("shutting down", { signal });
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
  };
  process.on("SIGINT", () => stop("SIGINT"));
  process.on("SIGTERM", () => stop("SIGTERM"));
}

main().catch((err: unknown) => {
  if (err instanceof ConfigError) process.stderr.write(`${err.message}\n`);
  else log.error("anchor failed to start", { error: err });
  process.exit(1);
});
