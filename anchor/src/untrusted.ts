// JSON read from the Tangle or the chain, behind the nesting cap every Witness entry point
// shares (witness_core.nesting.MAX_JSON_DEPTH in Python, PY_JSON_MAX_DEPTH in @witness/verify).

import { PY_JSON_MAX_DEPTH, textTooDeep } from "@witness/verify";

export class JsonTooDeepError extends SyntaxError {
  constructor() {
    super(`JSON nested deeper than ${PY_JSON_MAX_DEPTH} levels`);
    this.name = "JsonTooDeepError";
  }
}

/** `JSON.parse` for untrusted text: brackets nested past the cap (valid JSON or not) throw first. */
export function parseUntrusted(text: string): unknown {
  if (textTooDeep(text)) throw new JsonTooDeepError();
  return JSON.parse(text);
}

/**
 * Deepest value in a resolve reply (`{doc, version, keys}`, the reply itself at depth 0),
 * as witness_core.nesting.MAX_DOC_DEPTH. Anyone can publish a did:iota document; deeper
 * ones are answered as unusable (422) rather than served for clients to walk or copy.
 */
export const MAX_DOC_DEPTH = 64;

/** True when any value inside `value` sits deeper than `limit` (Python `nesting.value_too_deep`). */
export function valueTooDeep(value: unknown, limit: number): boolean {
  const stack: [unknown, number][] = [[value, 0]];
  while (stack.length > 0) {
    const [v, depth] = stack.pop()!;
    if (depth > limit) return true;
    if (Array.isArray(v)) for (const x of v) stack.push([x, depth + 1]);
    else if (v !== null && typeof v === "object") for (const x of Object.values(v)) stack.push([x, depth + 1]);
  }
  return false;
}
