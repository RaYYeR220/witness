// @vitest-environment node
import { describe, expect, it } from "vitest";

import { main } from "../src/cli.js";
import type { CliIO } from "../src/cli.js";
import { bundles } from "./vectors.js";

function memoryIO(files: Record<string, string>) {
  const out: string[] = [];
  const err: string[] = [];
  const io: CliIO = {
    readText: async (path) => {
      if (!Object.hasOwn(files, path)) throw new Error(`ENOENT: no such file '${path}'`);
      return files[path]!;
    },
    stdout: (s) => void out.push(s),
    stderr: (s) => void err.push(s),
  };
  return { io, out, err };
}

/** Files and flags for a vector case, the way an operator would lay them out. */
function caseFiles(name: string) {
  const c = bundles.cases.find((x: any) => x.name === name);
  const files: Record<string, string> = {
    "bundle.json": JSON.stringify(c.bundle),
    "verifier.json": JSON.stringify(c.config),
  };
  const args = ["bundle.json", "--config", "verifier.json"];
  if (c.fetcher !== null) {
    files["record.json"] = JSON.stringify(c.fetcher.record);
    args.push("--anchor-record", "record.json");
  }
  if (c.resolver !== null) {
    files["resolver.json"] = JSON.stringify(bundles.resolvers[c.resolver]);
    args.push("--resolver", "resolver.json");
  }
  return { c, files, args };
}

describe("witness-verify CLI", () => {
  it.each([
    ["valid_anchored", 0],
    ["partial_real_no_anchor", 2],
    ["anchor_unreachable", 2],
    ["envelope_forged", 1],
    ["noncanonical_hex_ms_path", 1],
  ])("%s exits %i and prints the ladder", async (name, code) => {
    const { c, files, args } = caseFiles(name);
    const { io, out } = memoryIO(files);
    expect(await main(args, io)).toBe(code);
    const ladder = JSON.parse(out.join(""));
    expect(ladder.overall).toBe(c.expected.overall);
    expect(ladder.steps.map((s: any) => ({ name: s.name, ok: s.ok }))).toEqual(c.expected.steps);
    expect(ladder.steps.every((s: any) => typeof s.detail === "string")).toBe(true);
  });

  it("flags may come before the bundle path", async () => {
    const { files } = caseFiles("valid_anchored");
    const { io } = memoryIO(files);
    expect(await main(["--config", "verifier.json", "bundle.json"], io)).toBe(2);
  });

  it("reads bundles with Python number semantics", async () => {
    const { files, args } = caseFiles("valid_anchored");
    files["bundle.json"] = files["bundle.json"]!.replace('"v":1', '"v":1.0');
    const { io, out } = memoryIO(files);
    expect(await main(args, io)).toBe(1);
    expect(JSON.parse(out.join("")).steps[0].detail).toBe("not a witness-proof/v1 bundle");
  });

  it.each([
    [[], "missing bundle path"],
    [["bundle.json"], "--config is required"],
    [["bundle.json", "--config"], "--config needs a value"],
    [["bundle.json", "--config", "verifier.json", "--bogus"], "unknown option --bogus"],
    [["a.json", "b.json", "--config", "verifier.json"], "only one bundle path"],
    [["missing.json", "--config", "verifier.json"], "ENOENT"],
  ])("usage error %j exits 3", async (args, message) => {
    const { files } = caseFiles("valid_anchored");
    const { io, out, err } = memoryIO(files);
    expect(await main(args, io)).toBe(3);
    expect(out).toEqual([]);
    expect(err.join("")).toContain(message);
  });

  it("rejects unparseable JSON and a bad verifier config", async () => {
    const { files, args } = caseFiles("valid_anchored");
    let m = memoryIO({ ...files, "bundle.json": "{nope" });
    expect(await main(args, m.io)).toBe(3);
    m = memoryIO({ ...files, "verifier.json": JSON.stringify({ network: "x", threshold: 1 }) });
    expect(await main(args, m.io)).toBe(3);
    expect(m.err.join("")).toContain("trustedCoordinatorKeys");
  });

  it("--help prints usage and exits 0", async () => {
    const { io, out } = memoryIO({});
    expect(await main(["--help"], io)).toBe(0);
    const help = out.join("");
    expect(help).toContain("witness-verify <bundle.json> --config <verifier.json>");
    expect(help).toMatch(/--anchor-record[\s\S]*TRUSTED input/);
    expect(help).toMatch(/--resolver[\s\S]*TRUSTED input/);
    expect(help).toContain("never take them from the bundle's sender");
  });

  it("tolerates a UTF-8 BOM at the start of an input file", async () => {
    const { files, args } = caseFiles("valid_anchored");
    for (const name of Object.keys(files)) files[name] = `\uFEFF${files[name]}`;
    const { io } = memoryIO(files);
    expect(await main(args, io)).toBe(0);
  });
});
