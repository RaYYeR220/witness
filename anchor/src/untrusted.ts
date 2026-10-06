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
