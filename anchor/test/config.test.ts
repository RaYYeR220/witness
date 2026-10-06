import path from "node:path";
import { describe, expect, it } from "vitest";
import { ConfigError, NETWORKS, explorerLink, loadConfig } from "../src/config.js";

const ADDR = "0xd40892daf5c81e3d67ffe9806575970b973ecf6625eb8a88562afae0d8c940c8";

function issuesOf(env: Record<string, string>): string[] {
  try {
    loadConfig(env, "/srv/anchor");
  } catch (err) {
    expect(err).toBeInstanceOf(ConfigError);
    return (err as ConfigError).issues;
  }
  throw new Error("expected a ConfigError");
}

describe("loadConfig", () => {
  it("uses testnet defaults when nothing is set", () => {
    const cfg = loadConfig({}, "/srv/anchor");
    expect(cfg.network).toBe("testnet");
    expect(cfg.chainId).toBe("2304aa97");
    expect(cfg.didNetwork).toBe("testnet");
    expect(cfg.rpcUrl).toBe("https://api.testnet.iota.cafe");
    expect(cfg.graphqlUrl).toBe("https://graphql.testnet.iota.cafe");
    expect(cfg.packages).toEqual(NETWORKS.testnet.packages);
    expect(cfg.port).toBe(7300);
    expect(cfg.host).toBe("127.0.0.1");
    expect(cfg.secretsDir).toBe(path.resolve("/srv/anchor", "secrets"));
    expect(cfg.keystorePath).toBeNull();
    expect(cfg.address).toBeNull();
    expect(cfg.gasBudget).toBe(50_000_000n);
    expect(cfg.resolveCacheMs).toBe(60_000);
    expect(cfg.identitiesFile).toBe(path.resolve(import.meta.dirname, "..", "..", "deploy", "identity", "testnet.json"));
  });

  it("reads the identities file location from ANCHOR_IDENTITIES_FILE", () => {
    expect(loadConfig({ ANCHOR_IDENTITIES_FILE: "pub/ids.json" }, "/srv/anchor").identitiesFile).toBe(path.resolve("/srv/anchor", "pub/ids.json"));
    expect(loadConfig({ IOTA_NETWORK: "mainnet" }, "/srv/anchor").identitiesFile.endsWith(`identity${path.sep}mainnet.json`)).toBe(true);
  });

  it("switches every network default for mainnet", () => {
    const cfg = loadConfig({ IOTA_NETWORK: "mainnet" }, "/srv/anchor");
    expect(cfg.chainId).toBe("6364aad5");
    expect(cfg.didNetwork).toBeNull();
    expect(cfg.rpcUrl).toBe("https://api.mainnet.iota.cafe");
    expect(cfg.packages.auditTrail).toBe(NETWORKS.mainnet.packages.auditTrail);
    expect(cfg.packages.auditTrailOriginal).not.toBe(cfg.packages.auditTrail);
  });

  it("reads overrides and normalizes ids", () => {
    const cfg = loadConfig(
      {
        IOTA_RPC_URL: "http://localhost:9000/",
        IOTA_AUDIT_TRAIL_PKG_ID: "0x" + "AB".repeat(32),
        ANCHOR_KEYSTORE_PATH: "/keys/iota.keystore",
        ANCHOR_ADDRESS: ADDR.toUpperCase().replace("0X", "0x"),
        SECRETS_DIR: "/data/secrets",
        ANCHOR_PORT: "8080",
        ANCHOR_HOST: "0.0.0.0",
        ANCHOR_ADMIN_TOKEN: "a-long-enough-admin-token",
        ANCHOR_TRAIL_ID: "0x" + "1".repeat(64),
        ANCHOR_GAS_BUDGET: "20000000",
      },
      "/srv/anchor",
    );
    expect(cfg.rpcUrl).toBe("http://localhost:9000");
    expect(cfg.packages.auditTrail).toBe("0x" + "ab".repeat(32));
    expect(cfg.address).toBe(ADDR);
    expect(cfg.secretsDir).toBe(path.resolve("/data/secrets"));
    expect(cfg.port).toBe(8080);
    expect(cfg.host).toBe("0.0.0.0");
    expect(cfg.trailId).toBe("0x" + "1".repeat(64));
    expect(cfg.gasBudget).toBe(20_000_000n);
  });

  it("accepts a keystore alias as ANCHOR_ADDRESS", () => {
    const cfg = loadConfig({ ANCHOR_KEYSTORE_PATH: "/k", ANCHOR_ADDRESS: "veles-testnet" }, "/");
    expect(cfg.address).toBe("veles-testnet");
  });

  it("rejects an unknown network outright", () => {
    expect(issuesOf({ IOTA_NETWORK: "devnet" })).toEqual([expect.stringContaining("IOTA_NETWORK")]);
  });

  it("collects every problem in one error", () => {
    const issues = issuesOf({
      IOTA_RPC_URL: "ftp://nope",
      IOTA_AUDIT_TRAIL_PKG_ID: "0x1234",
      IOTA_TF_COMPONENTS_PKG_ID: "not-an-id",
      ANCHOR_KEYSTORE_PATH: "/keys/iota.keystore",
      ANCHOR_PORT: "70000",
      ANCHOR_TRAIL_ID: "0xzz",
      ANCHOR_GAS_BUDGET: "-5",
      ANCHOR_RESOLVE_CACHE_MS: "soon",
    });
    const joined = issues.join("\n");
    for (const key of [
      "IOTA_RPC_URL",
      "IOTA_AUDIT_TRAIL_PKG_ID",
      "IOTA_TF_COMPONENTS_PKG_ID",
      "ANCHOR_KEYSTORE_PATH and ANCHOR_ADDRESS",
      "ANCHOR_PORT",
      "ANCHOR_TRAIL_ID",
      "ANCHOR_GAS_BUDGET",
      "ANCHOR_RESOLVE_CACHE_MS",
    ]) {
      expect(joined).toContain(key);
    }
    expect(issues).toHaveLength(8);
  });

  it("rejects a malformed address or alias", () => {
    expect(issuesOf({ ANCHOR_KEYSTORE_PATH: "/k", ANCHOR_ADDRESS: "0xabc" })).toEqual([expect.stringContaining("ANCHOR_ADDRESS")]);
    expect(issuesOf({ ANCHOR_KEYSTORE_PATH: "/k", ANCHOR_ADDRESS: "../etc" })).toEqual([expect.stringContaining("ANCHOR_ADDRESS")]);
  });

  it("never echoes the admin token", () => {
    const token = "short-secret";
    let message = "";
    try {
      loadConfig({ ANCHOR_ADMIN_TOKEN: token }, "/");
    } catch (err) {
      message = (err as Error).message;
    }
    expect(message).toContain("ANCHOR_ADMIN_TOKEN");
    expect(message).not.toContain(token);
  });
});

describe("checkpoint settings", () => {
  it("defaults to a read-only service with the documented endpoints and windows", () => {
    const cp = loadConfig({}, "/srv/anchor").checkpoints;
    expect(cp).toEqual({
      loop: false,
      apiUrl: "http://127.0.0.1:7200",
      relayUrl: "http://127.0.0.1:5555",
      relayNode: "iota-hornet",
      every: 60,
      startIndex: 1,
      domain: null,
      tangleNetwork: "private_tangle1",
      policyPath: null,
      statePath: path.resolve("/srv/anchor", "data", "anchor-state.json"),
      identity: "anchor",
      pollMs: 10_000,
      httpTimeoutMs: 10_000,
      allowMissingMsgCount: false,
    });
    expect(loadConfig({ SECRETS_DIR: "/data/secrets" }, "/srv/anchor").checkpoints.statePath).toBe(path.resolve("/data", "data", "anchor-state.json"));
  });

  it("reads the loop settings", () => {
    const cp = loadConfig(
      {
        ANCHOR_LOOP: "on",
        ANCHOR_KEYSTORE_PATH: "/keys/iota.keystore",
        ANCHOR_ADDRESS: ADDR,
        ANCHOR_POLICY_PATH: "deploy/policy.json",
        ANCHOR_API_URL: "http://api:7200/",
        ANCHOR_RELAY_URL: "http://relay:5555",
        ANCHOR_EVERY: "12",
        ANCHOR_START_INDEX: "3601",
        ANCHOR_DOMAIN: "MyDomain",
        ANCHOR_NETWORK_NAME: "private_tangle2",
        ANCHOR_STATE_PATH: "state/a.json",
        ANCHOR_POLL_MS: "2000",
      },
      "/srv/anchor",
    ).checkpoints;
    expect(cp).toMatchObject({
      loop: true,
      apiUrl: "http://api:7200",
      relayUrl: "http://relay:5555",
      every: 12,
      startIndex: 3601,
      domain: "MyDomain",
      tangleNetwork: "private_tangle2",
      policyPath: path.resolve("/srv/anchor", "deploy/policy.json"),
      statePath: path.resolve("/srv/anchor", "state/a.json"),
      pollMs: 2000,
    });
  });

  it("refuses a loop without keystore or policy, and out-of-range windows", () => {
    expect(issuesOf({ ANCHOR_LOOP: "on" })).toEqual([expect.stringContaining("ANCHOR_KEYSTORE_PATH"), expect.stringContaining("ANCHOR_POLICY_PATH")]);
    expect(issuesOf({ ANCHOR_LOOP: "maybe" })).toEqual([expect.stringContaining("ANCHOR_LOOP")]);
    expect(issuesOf({ ANCHOR_EVERY: "0" })).toEqual([expect.stringContaining("ANCHOR_EVERY")]);
    expect(issuesOf({ ANCHOR_EVERY: "10001" })).toEqual([expect.stringContaining("ANCHOR_EVERY")]);
    expect(issuesOf({ ANCHOR_API_URL: "ftp://x" })).toEqual([expect.stringContaining("ANCHOR_API_URL")]);
    expect(issuesOf({ ANCHOR_RELAY_NODE: "http://evil" })).toEqual([expect.stringContaining("ANCHOR_RELAY_NODE")]);
  });
});

describe("explorerLink", () => {
  it("points at the configured network", () => {
    const cfg = loadConfig({}, "/");
    expect(explorerLink(cfg, "txblock", "ABC")).toBe("https://explorer.iota.org/txblock/ABC?network=testnet");
    expect(explorerLink(cfg, "object", "0x1")).toBe("https://explorer.iota.org/object/0x1?network=testnet");
  });
});
