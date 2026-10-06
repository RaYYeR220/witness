import { cryptoRuntime } from "jose";
import { describe, expect, it } from "vitest";

import * as api from "../src/index.js";

const sources = import.meta.glob("../src/**/*.ts", { query: "?raw", import: "default", eager: true }) as Record<
  string,
  string
>;

describe("browser safety", () => {
  it("the suite runs in a DOM environment", () => {
    expect(typeof window).toBe("object");
    expect(typeof document.createElement).toBe("function");
  });

  it("library sources use no Node built-ins (only the CLI may)", () => {
    const lib = Object.entries(sources).filter(([path]) => !path.endsWith("/cli.ts"));
    expect(lib.length).toBeGreaterThanOrEqual(10);
    for (const [path, text] of lib) {
      const specs = [...text.matchAll(/\bfrom\s+["']([^"']+)["']|\bimport\s*\(\s*["']([^"']+)["']/g)].map(
        (m) => m[1] ?? m[2],
      );
      for (const spec of specs) expect(spec, path).toMatch(/^(\.\/[\w-]+\.js|@noble\/(hashes|curves)\/[\w/]+|jose|canonicalize)$/);
      expect(text, path).not.toMatch(/\bBuffer\b|\bprocess\.|\brequire\(|__dirname|__filename|\bnode:/);
    }
  });

  it("JWE decryption runs on WebCrypto, as it will in the browser", () => {
    expect(cryptoRuntime).toBe("WebCryptoAPI");
  });

  it("the public entry point exposes the documented API", () => {
    for (const name of [
      "blake2b256", "parseBlock", "blockId", "parseMilestonePayload", "milestoneId", "merkleRoot", "auditPath",
      "verifyPath", "jcs", "verifyEnvelope", "sealEnvelope", "decryptBody", "blindToken", "commit",
      "verifyCommitment", "checkpointHash", "buildCheckpoint", "verifyBundle", "snapshotResolver", "parseJson",
    ]) {
      expect(typeof (api as Record<string, unknown>)[name], name).toBe("function");
    }
  });
});
