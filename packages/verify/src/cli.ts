#!/usr/bin/env node
/**
 * witness-verify: check a witness-proof/v1 bundle offline and print the ladder.
 * Node-only entry point; the library itself stays browser-safe.
 */

import { realpathSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { isDict, parseJson, verifyBundle } from "./index.js";
import type { Json, VerifierConfig, VerifyOptions } from "./index.js";

export interface CliIO {
  readText(path: string): Promise<string>;
  stdout(text: string): void;
  stderr(text: string): void;
}

const USAGE = `Usage: witness-verify <bundle.json> --config <verifier.json> [--anchor-record <record.json>] [--resolver <resolver.json>]

Verifies a witness-proof/v1 bundle offline and prints the ladder as JSON.

  --config <file>         pinned verifier config:
                          {network, trustedCoordinatorKeys, threshold, rebasedNetwork?, trailId?}
  --anchor-record <file>  on-chain record of the bundle's checkpoint, read from the pinned trail:
                          {checkpointHash} and/or {checkpoint}; null means unavailable
  --resolver <file>       trusted DID documents keyed by DID: {"did:...": {doc, version, keys}}
  -h, --help              show this help

Exit status: 0 VALID, 1 INVALID, 2 PARTIAL, 3 usage or input error.
`;

const EXIT = { VALID: 0, INVALID: 1, PARTIAL: 2 } as const;
const USAGE_ERROR = 3;

class UsageError extends Error {}

interface Args {
  help: boolean;
  bundle?: string;
  config?: string;
  record?: string;
  resolver?: string;
}

const FLAGS: Record<string, "config" | "record" | "resolver"> = {
  "--config": "config",
  "--anchor-record": "record",
  "--resolver": "resolver",
};

function parseArgs(argv: string[]): Args {
  const args: Args = { help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "-h" || a === "--help") args.help = true;
    else if (Object.hasOwn(FLAGS, a)) {
      const value = argv[++i];
      if (value === undefined) throw new UsageError(`${a} needs a value`);
      args[FLAGS[a]!] = value;
    } else if (a.startsWith("-")) throw new UsageError(`unknown option ${a}`);
    else if (args.bundle !== undefined) throw new UsageError("only one bundle path may be given");
    else args.bundle = a;
  }
  if (args.help) return args;
  if (args.bundle === undefined) throw new UsageError("missing bundle path");
  if (args.config === undefined) throw new UsageError("--config is required");
  return args;
}

async function load(io: CliIO, path: string, what: string): Promise<Json> {
  const text = (await io.readText(path)).replace(/^﻿/, "");
  try {
    return parseJson(text);
  } catch (e) {
    throw new Error(`${what} ${path} is not valid JSON (${(e as Error).message})`);
  }
}

const nodeIO: CliIO = {
  readText: (path) => readFile(path, "utf8"),
  stdout: (text) => void process.stdout.write(text),
  stderr: (text) => void process.stderr.write(text),
};

/** Run the CLI with `argv` (without node and script); resolves to the exit status. */
export async function main(argv: string[], io: CliIO = nodeIO): Promise<number> {
  let args: Args;
  try {
    args = parseArgs(argv);
  } catch (e) {
    io.stderr(`witness-verify: ${(e as Error).message}\n\n${USAGE}`);
    return USAGE_ERROR;
  }
  if (args.help) {
    io.stdout(USAGE);
    return 0;
  }
  try {
    const bundle = await load(io, args.bundle!, "bundle");
    const config = await load(io, args.config!, "config");
    if (!isDict(config)) throw new Error(`config ${args.config} must be a JSON object`);
    const options: VerifyOptions = {};
    if (args.record !== undefined) {
      const record = await load(io, args.record, "anchor record");
      options.fetchAnchorRecord = () => record;
    }
    if (args.resolver !== undefined) {
      const docs = await load(io, args.resolver, "resolver");
      if (!isDict(docs)) throw new Error(`resolver ${args.resolver} must map DIDs to documents`);
      options.resolveDid = (did) => (Object.hasOwn(docs, did) ? docs[did] : null);
    }
    const ladder = await verifyBundle(bundle, config as unknown as VerifierConfig, options);
    io.stdout(`${JSON.stringify({ overall: ladder.overall, steps: ladder.steps }, null, 2)}\n`);
    return EXIT[ladder.overall];
  } catch (e) {
    io.stderr(`witness-verify: ${(e as Error).message}\n`);
    return USAGE_ERROR;
  }
}

function invokedDirectly(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (invokedDirectly()) {
  main(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (e: unknown) => {
      process.stderr.write(`witness-verify: ${String(e)}\n`);
      process.exitCode = USAGE_ERROR;
    },
  );
}
