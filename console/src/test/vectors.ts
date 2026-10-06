/**
 * The shared cross-language test vectors (core/tests/vectors), for console
 * tests. Read as raw text and parsed with the verifier's own parser.
 */
import { parseJson, type VerifierConfig, type VerifyOptions } from "@witness/verify";

import bundlesText from "../../../core/tests/vectors/bundles.json?raw";
import rebasedText from "../../../core/tests/vectors/rebased_record.json?raw";
import sealedText from "../../../core/tests/vectors/sealed.json?raw";

/* eslint-disable @typescript-eslint/no-explicit-any */
export const bundles: any = parseJson(bundlesText);
export const sealed: any = JSON.parse(sealedText);
export const rebasedRecord: any = JSON.parse(rebasedText);

export function bundleCase(name: string): any {
  const c = bundles.cases.find((x: any) => x.name === name);
  if (!c) throw new Error(`no bundle vector ${name}`);
  return c;
}

/** A case's bundle text, its pins, and its trusted lookups, wired as the Python reference wires them. */
export function wired(name: string): { text: string; config: VerifierConfig; lookups: Pick<VerifyOptions, "resolveDid" | "fetchAnchorRecord"> } {
  const c = bundleCase(name);
  const docs = c.resolver ? bundles.resolvers[c.resolver] : null;
  return {
    text: JSON.stringify(c.bundle),
    config: c.config,
    lookups: {
      resolveDid: docs ? (did: string) => (Object.hasOwn(docs, did) ? structuredClone(docs[did]) : null) : null,
      fetchAnchorRecord: c.fetcher ? () => structuredClone(c.fetcher.record) : null,
    },
  };
}
