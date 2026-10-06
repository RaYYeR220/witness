// Creates a did:iota identity for every Witness component on IOTA Rebased and writes their public
// description (DIDs, public keys, explorer links) to deploy/identity/<network>.json.
// Idempotent: components already listed in ${SECRETS_DIR}/identities.json are skipped.
// Private keys only ever go to ${SECRETS_DIR}/<component>/.
//
//   pnpm --filter @witness/anchor bootstrap:identities
import path from "node:path";
import { fileURLToPath } from "node:url";
import { AnchorWallet, assertChain, createIotaClient, preferIpv4 } from "../src/client.js";
import { explorerLink, loadConfig } from "../src/config.js";
import { DidService, publicIdentity } from "../src/did.js";
import { writeJsonAtomic } from "../src/fsutil.js";

export const COMPONENTS = ["domain", "trust-manager", "llo-k8s", "self-orchestrator", "relay", "anchor"];

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

function iota(nanos: string): string {
  return (Number(BigInt(nanos)) / 1e9).toFixed(4);
}

async function main(): Promise<void> {
  preferIpv4();
  const cfg = loadConfig();
  const client = createIotaClient(cfg);
  await assertChain(client, cfg);
  const wallet = AnchorWallet.fromConfig(cfg);
  const before = await client.getBalance({ owner: wallet.address });
  console.log(`network ${cfg.network} (${cfg.chainId}), sender ${wallet.address}, balance ${iota(before.totalBalance)} IOTA`);

  const dids = new DidService(cfg, client, wallet);
  for (const name of COMPONENTS) {
    const existing = dids.registry().identities[name];
    if (existing) {
      console.log(`skip    ${name.padEnd(18)} ${existing.did}`);
      continue;
    }
    const created = await dids.createComponentDid(name);
    console.log(`created ${name.padEnd(18)} ${created.did}`);
    console.log(`        ${"".padEnd(18)} ${explorerLink(cfg, "txblock", created.createdTx)}`);
  }

  const registry = dids.registry();
  const names = [...COMPONENTS, ...Object.keys(registry.identities).filter((n) => !COMPONENTS.includes(n)).sort()];
  const out = path.join(repoRoot, "deploy", "identity", `${cfg.network}.json`);
  writeJsonAtomic(out, {
    network: cfg.network,
    chainId: cfg.chainId,
    identities: names.flatMap((n) => (registry.identities[n] ? [publicIdentity(cfg, registry.identities[n])] : [])),
  });

  const after = await client.getBalance({ owner: wallet.address });
  console.log(`wrote ${path.relative(process.cwd(), out)}; spent ${iota(String(BigInt(before.totalBalance) - BigInt(after.totalBalance)))} IOTA`);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? `${err.name}: ${err.message}` : err);
  process.exit(1);
});
