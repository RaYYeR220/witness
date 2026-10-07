// Pins the anchor trail into the console's verifier config before the build.
//   ANCHOR_TRAIL_ID=0x… node pin-trail.mjs console/src/config/verifier.json
// Without ANCHOR_TRAIL_ID the committed pins are kept. Only the trail changes here: the network,
// coordinator keys and threshold come from the committed file (console/scripts/make-fixture.mjs).
import { readFileSync, writeFileSync } from "node:fs";

const file = process.argv[2];
if (!file) {
  console.error("usage: node pin-trail.mjs <verifier.json>");
  process.exit(2);
}
const cfg = JSON.parse(readFileSync(file, "utf8"));
const trail = (process.env.ANCHOR_TRAIL_ID ?? "").trim().toLowerCase();
if (trail) {
  if (!/^0x[0-9a-f]{64}$/.test(trail)) {
    console.error("ANCHOR_TRAIL_ID must be 0x followed by 64 hex digits");
    process.exit(1);
  }
  cfg.trailId = trail;
  writeFileSync(file, JSON.stringify(cfg, null, 2) + "\n");
}
console.log(
  `verifier pins: ${cfg.network}, ${cfg.trustedCoordinatorKeys.length} coordinator keys, ` +
    `threshold ${cfg.threshold}, Rebased ${cfg.rebasedNetwork}, trail ${cfg.trailId ?? "none"}`,
);
