// Makes sure the deployment's Audit Trail exists (creating the trail, the writer role and the
// writer capability when missing), appends one test record and reads it back from the chain.
//
//   pnpm --filter @witness/anchor trail:smoke
import { setTimeout as sleep } from "node:timers/promises";
import { AnchorWallet, assertChain, createIotaClient, preferIpv4 } from "../src/client.js";
import { loadConfig } from "../src/config.js";
import { TrailService } from "../src/trail.js";

async function main(): Promise<void> {
  preferIpv4();
  const cfg = loadConfig();
  const client = createIotaClient(cfg);
  await assertChain(client, cfg);
  const trails = new TrailService(cfg, client, AnchorWallet.fromConfig(cfg));

  const trailId = await trails.ensureTrail();
  console.log(`trail    ${trailId}`);
  console.log(`         ${trails.link("object", trailId)}`);

  const payload = JSON.stringify({ v: 1, kind: "witness.selftest", network: cfg.network, at: new Date().toISOString() });
  const added = await trails.appendRecord(trailId, payload);
  console.log(`appended record #${added.recordIndex} at ${new Date(added.timestampMs).toISOString()} (gas ${added.gasNanos} nanos)`);
  console.log(`         ${added.links.tx}`);

  // The transaction index can trail execution by a moment; give it a few tries.
  let back = await trails.readRecord(trailId, added.recordIndex);
  for (let i = 0; i < 5 && back && back.tx === null; i++) {
    await sleep(2000);
    back = await trails.readRecord(trailId, added.recordIndex);
  }
  if (!back) throw new Error(`record #${added.recordIndex} not found on chain`);
  const checks = {
    data: back.data === payload,
    metadata: back.metadata === added.metadata,
    addedAt: back.addedAtMs === added.timestampMs,
    tx: back.tx === added.tx,
  };
  console.log(`read back record #${back.recordIndex}: ${JSON.stringify(checks)}`);
  console.log(`         data ${typeof back.data === "string" ? back.data : Buffer.from(back.data).toString("hex")}`);
  console.log(`         metadata ${back.metadata}`);
  if (!Object.values(checks).every(Boolean)) throw new Error("record read back does not match what was written");
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? `${err.name}: ${err.message}` : err);
  process.exit(1);
});
