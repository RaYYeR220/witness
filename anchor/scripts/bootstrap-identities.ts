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
// --chaos-revoked also creates `chaos-revoked`, a test identity for the fault-injection eval
// (class A05): controlled by the domain DID like the components, with its #sig-1 removed
// right after creation, so anything it signs later is REVOKED_KEY. No writer policy lists it.
// Its keys go to ${SECRETS_DIR}/chaos-revoked/ like a component's; the deploy file lists it
// under `eval` with the revocation, never among the components.
//
//   pnpm --filter @witness/anchor bootstrap:identities [--retire-existing] [--chaos-revoked]
import path from "node:path";
import { AnchorWallet, assertChain, createIotaClient, preferIpv4 } from "../src/client.js";
import { explorerLink, loadConfig } from "../src/config.js";
import {
  DidService,
  SIG_FRAGMENT,
  publicIdentity,
  retireIdentities,
  revocationOf,
  type PublicIdentity,
  type ResolvedDid,
  type RevokedKeyRecord,
} from "../src/did.js";
import { readJsonIfExists, writeJsonAtomic } from "../src/fsutil.js";

export const DOMAIN = "domain";
export const COMPONENTS = [DOMAIN, "trust-manager", "llo-k8s", "self-orchestrator", "relay", "anchor"];
export const CHAOS_REVOKED = "chaos-revoked";
/** Test identities: in the registry like the components, listed apart in the deploy file. */
const EVAL = [CHAOS_REVOKED];

interface RetiredIdentity extends PublicIdentity {
  retiredAt: string;
  reason: string;
}

interface EvalIdentity extends PublicIdentity {
  purpose: string;
  revoked: RevokedKeyRecord[];
}

interface DeployFile {
  network: string;
  chainId: string;
  domain: string | null;
  identities: PublicIdentity[];
  previous: RetiredIdentity[];
  eval?: EvalIdentity[];
}

function iota(nanos: bigint | string): string {
  return (Number(BigInt(nanos)) / 1e9).toFixed(4);
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function main(): Promise<void> {
  const retire = process.argv.includes("--retire-existing");
  const chaosRevoked = process.argv.includes("--chaos-revoked");
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

  if (chaosRevoked) {
    let entry = dids.registry().identities[CHAOS_REVOKED];
    if (entry) report("skip", CHAOS_REVOKED, entry.did);
    else {
      entry = await dids.createComponentDid(CHAOS_REVOKED, controller);
      report("created", CHAOS_REVOKED, entry.did, entry.createdTx);
    }
    // The fresh object may not be readable at once; the revocation needs its current document.
    let resolved: ResolvedDid | null = null;
    for (let attempt = 0; resolved === null; attempt++) {
      try {
        resolved = await dids.resolve(entry.did);
      } catch (err) {
        if (attempt >= 10) throw err;
        await sleep(2000);
      }
    }
    if (revocationOf(cfg, resolved, entry.sigKid)) report("skip", `${CHAOS_REVOKED} #${SIG_FRAGMENT} revoked`, entry.did);
    else {
      const revoked = await dids.revokeMethod(entry.did, `#${SIG_FRAGMENT}`);
      if (revoked.pendingProposal) throw new Error(`revoking ${entry.sigKid} became a proposal that still needs approval`);
      report("revoked", `${CHAOS_REVOKED} #${SIG_FRAGMENT}`, entry.did, revoked.tx);
    }
  }

  const registry = dids.registry();
  const names = [...COMPONENTS, ...Object.keys(registry.identities).filter((n) => !COMPONENTS.includes(n) && !EVAL.includes(n)).sort()];
  const evalIdentities: EvalIdentity[] = [];
  for (const name of EVAL) {
    const entry = registry.identities[name];
    if (!entry) continue;
    // The transaction index can lag the object for a few seconds after the update.
    let record: RevokedKeyRecord | null = null;
    for (let attempt = 0; record === null; attempt++) {
      record = revocationOf(cfg, await dids.resolve(entry.did), entry.sigKid);
      if (record === null) {
        if (attempt >= 15) throw new Error(`${entry.sigKid} is not revoked on ${cfg.network}; re-run with --chaos-revoked`);
        await sleep(2000);
      }
    }
    evalIdentities.push({
      ...publicIdentity(cfg, entry),
      purpose: "fault-injection eval only (A05): its signing key was revoked right after creation; never a writer",
      revoked: [record],
    });
  }
  const file: DeployFile = {
    network: cfg.network,
    chainId: cfg.chainId,
    domain: domain.did,
    identities: names.flatMap((n) => (registry.identities[n] ? [publicIdentity(cfg, registry.identities[n])] : [])),
    previous,
    ...(evalIdentities.length > 0 ? { eval: evalIdentities } : {}),
  };
  writeJsonAtomic(out, file);

  const after = await client.getBalance({ owner: wallet.address });
  console.log(`wrote ${path.relative(process.cwd(), out)}; spent ${iota(BigInt(before.totalBalance) - BigInt(after.totalBalance))} IOTA`);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? `${err.name}: ${err.message}` : err);
  process.exit(1);
});
