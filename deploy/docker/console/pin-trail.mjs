// Pins this deployment's anchor trail (and, when given, the trail's writer address) into the
// console's verifier config before the build:
//   ANCHOR_TRAIL_ID=0x… [ANCHOR_WRITER_ADDRESS=0x…] node pin-trail.mjs console/src/config/verifier.json
// Unset values keep the committed pins. Everything else (network, coordinator keys, threshold,
// Rebased RPC, Audit Trail package) comes from the committed file (console/scripts/make-fixture.mjs).
import { readFileSync, writeFileSync } from "node:fs";

const HEX32 = /^0x[0-9a-f]{64}$/;
const file = process.argv[2];
if (!file) {
  console.error("usage: node pin-trail.mjs <verifier.json>");
  process.exit(2);
}
const cfg = JSON.parse(readFileSync(file, "utf8"));
let changed = false;
for (const [env, field] of [
  ["ANCHOR_TRAIL_ID", "trailId"],
  ["ANCHOR_WRITER_ADDRESS", "anchorWriter"],
]) {
  const value = (process.env[env] ?? "").trim().toLowerCase();
  if (!value) continue;
  if (!HEX32.test(value)) {
    console.error(`${env} must be 0x followed by 64 hex digits`);
    process.exit(1);
  }
  cfg[field] = value;
  changed = true;
}
if (changed) writeFileSync(file, JSON.stringify(cfg, null, 2) + "\n");
console.log(
  `verifier pins: ${cfg.network}, ${cfg.trustedCoordinatorKeys.length} coordinator keys, ` +
    `threshold ${cfg.threshold}, Rebased ${cfg.rebasedNetwork} at ${cfg.rebasedRpc ?? "?"}, ` +
    `trail ${cfg.trailId ?? "none"}, writer ${cfg.anchorWriter ?? "none"}`,
);
