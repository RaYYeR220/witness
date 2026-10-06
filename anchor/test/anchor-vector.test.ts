import { readFileSync } from "node:fs";
import { fromHex, jcs, verifyEnvelope } from "@witness/verify";
import { describe, expect, it } from "vitest";
import { checkpointHashHex } from "../src/checkpoint.js";

// Sealed by test/vectors/make-anchor-envelope.ts; core/tests/test_anchor_vectors.py checks the same file.
const V = JSON.parse(readFileSync(new URL("../../core/tests/vectors/witness_anchor.json", import.meta.url), "utf8"));

describe("committed witness.anchor fixture", () => {
  it("still verifies as producer-signed and keeps the mirror body shape", () => {
    const key = { kid: V.kid, ed25519Public: fromHex(V.publicKeyHex), x25519Public: null, revokedAtMs: null };
    for (const [i, m] of (V.messages as { envelope: any; data: string }[]).entries()) {
      const chk = verifyEnvelope(m.envelope, V.tag, (kid) => (kid === V.kid ? key : null));
      expect(chk.verdict).toBe("PRODUCER_SIGNED");
      expect(chk.seq).toBe(i + 1);
      expect(jcs(m.envelope)).toBe(m.data);
      const body = m.envelope.body;
      expect(Object.keys(body).sort()).toEqual(["checkpoint", "checkpointHash", "rebased", "seq"]);
      expect(Object.keys(body.rebased).sort()).toEqual(["network", "record", "trail", "tx"]);
      expect(body.checkpointHash).toBe(checkpointHashHex(body.checkpoint));
    }
  });
});
