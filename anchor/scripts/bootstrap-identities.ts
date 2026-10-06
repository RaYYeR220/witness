// Creates the did:iota identities of a Witness deployment on IOTA Rebased and writes their public
// description (DIDs, controller, public keys, explorer links) to deploy/identity/<network>.json.
//
// The domain DID is created first and is controlled by the wallet address. Every other component
// DID is controlled by the domain identity: its ControllerCap belongs to the domain identity and
// its document names the domain DID as `controller`.
//
// Idempotent: components already listed in ${SECRETS_DIR}/identities.json are skipped.
// --retire-existing moves the current registry and keys to ${SECRETS_DIR}/.stale/ and keeps the
// retired public records under `previous` in the deploy file. Private keys only ever go to
// ${SECRETS_DIR}/<component>/.
//
//   pnpm --filter @witness/anchor bootstrap:identities [--retire-existing]
import path from "node:path";
import { AnchorWallet, assertChain, createIotaClient, preferIpv4 } from "../src/client.js";
import { explorerLink, loadConfig } from "../src/config.js";
import { DidService, publicIdentity, retireIdentities, type PublicIdentity } from "../src/did.js";
import { readJsonIfExists, writeJsonAtomic } from "../src/fsutil.js";

export const DOMAIN = "domain";
export const COMPONENTS = [DOMAIN, "trust-manager", "llo-k8s", "self-orchestrator", "relay", "anchor"];

interface RetiredIdentity extends PublicIdentity {
  retiredAt: string;
  reason: string;
}

interface DeployFile {
  network: string;
  chainId: string;
  domain: string | null;
  identities: PublicIdentity[];
  previous: RetiredIdentity[];
}

function iota(nanos: bigint | string): string {
  return (Number(BigInt(nanos)) / 1e9).toFixed(4);
}

async function main(): Promise<void> {
  const retire = process.argv.includes("--retire-existing");
  preferIpv4();
  const cfg = loadConfig();
  const client = createIotaClient(cfg);
  await assertChain(client, cfg);
  const wallet = AnchorWallet.fromConfig(cfg);
  const before = await client.getBalance({ owner: wallet.address });
  console.log(`network ${cfg.network} (${cfg.chainId}), sender ${wallet.address}, balance ${iota(before.totalBalance)} IOTA`);

  const out = cfg.identitiesFile;
  let previous = readJsonIfExists<DeployFile>(out)?.previous ?? [];
  if (retire) {
    const retiredAt = new Date().toISOString();
    const retired = retireIdentities(cfg);
    previous = [
      ...previous,
      ...retired.map((e) => ({ ...publicIdentity(cfg, e), retiredAt, reason: "replaced by identities controlled by the domain DID" })),
    ];
    // Record the retired identities right away, so an interrupted run cannot lose them.
    writeJsonAtomic(out, { network: cfg.network, chainId: cfg.chainId, domain: null, identities: [], previous } satisfies DeployFile);
    console.log(`retired ${retired.length} identities to ${path.join(cfg.secretsDir, ".stale")}`);
  }

  const dids = new DidService(cfg, client, wallet);
  for (const [name, entry] of Object.entries(dids.registry().identities)) {
    if (name !== DOMAIN && entry.controller?.kind !== "identity") {
      throw new Error(`${name} (${entry.did}) is not controlled by the domain DID; re-run with --retire-existing`);
    }
  }

  const report = (verb: string, name: string, did: string, tx?: string) => {
    console.log(`${verb.padEnd(7)} ${name.padEnd(18)} ${did}`);
    if (tx) console.log(`        ${"".padEnd(18)} ${explorerLink(cfg, "txblock", tx)}`);
  };

  let domain = dids.registry().identities[DOMAIN];
  if (domain) report("skip", DOMAIN, domain.did);
  else {
    domain = await dids.createComponentDid(DOMAIN);
    report("created", DOMAIN, domain.did, domain.createdTx);
  }
  const controller = { did: domain.did, objectId: domain.objectId };
  for (const name of COMPONENTS.filter((n) => n !== DOMAIN)) {
    const existing = dids.registry().identities[name];
    if (existing) {
      report("skip", name, existing.did);
      continue;
    }
    const created = await dids.createComponentDid(name, controller);
    report("created", name, created.did, created.createdTx);
  }

  const registry = dids.registry();
  const names = [...COMPONENTS, ...Object.keys(registry.identities).filter((n) => !COMPONENTS.includes(n)).sort()];
  const file: DeployFile = {
    network: cfg.network,
    chainId: cfg.chainId,
    domain: domain.did,
    identities: names.flatMap((n) => (registry.identities[n] ? [publicIdentity(cfg, registry.identities[n])] : [])),
    previous,
  };
  writeJsonAtomic(out, file);

  const after = await client.getBalance({ owner: wallet.address });
  console.log(`wrote ${path.relative(process.cwd(), out)}; spent ${iota(BigInt(before.totalBalance) - BigInt(after.totalBalance))} IOTA`);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? `${err.name}: ${err.message}` : err);
  process.exit(1);
});
