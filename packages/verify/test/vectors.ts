/**
 * Shared cross-language vectors written by the Python reference
 * (core/tests/vectors). Loaded as raw text and parsed with `parseJson`, so
 * float literals such as `7.0` keep the type Python gave them.
 */
import blocksText from "../../../core/tests/vectors/blocks.json?raw";
import bundlesText from "../../../core/tests/vectors/bundles.json?raw";
import conesText from "../../../core/tests/vectors/cones.json?raw";
import envelopesText from "../../../core/tests/vectors/envelopes.json?raw";
import milestonesText from "../../../core/tests/vectors/milestones.json?raw";
import rebasedRecordText from "../../../core/tests/vectors/rebased_record.json?raw";
import sealedText from "../../../core/tests/vectors/sealed.json?raw";

import { JsonNumber, parseJson } from "../src/json.js";

// Vector files are trusted fixtures; `any` keeps the test code readable.
/* eslint-disable @typescript-eslint/no-explicit-any */
type Any = any;

export const raw = { blocksText, bundlesText, conesText, envelopesText, milestonesText, rebasedRecordText, sealedText };
export const blocks: Any[] = parseJson(blocksText) as Any;
export const milestones: Any[] = parseJson(milestonesText) as Any;
export const cones: Any[] = parseJson(conesText) as Any;
export const envelopes: Any = parseJson(envelopesText);
export const sealed: Any = parseJson(sealedText);
export const bundles: Any = parseJson(bundlesText);
export const rebasedRecord: Any = parseJson(rebasedRecordText);

/** Fresh deep copy (JsonNumber kept), so a test can mutate a vector freely. */
export function clone<T>(v: T): T {
  if (Array.isArray(v)) return v.map(clone) as T;
  if (v instanceof JsonNumber || v === null || typeof v !== "object") return v;
  const out: Record<string, unknown> = {};
  for (const [k, x] of Object.entries(v)) {
    Object.defineProperty(out, k, { value: clone(x), enumerable: true, writable: true, configurable: true });
  }
  return out as T;
}
