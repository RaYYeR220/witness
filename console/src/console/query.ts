/**
 * The Search screen's one box: whatever id the user has, mapped to the
 * `GET /messages` parameters it means. Every recognised part also comes back
 * as a chip, so the screen can say how it read the input.
 */

import { VERDICTS, type MessageQuery } from "@/api/client";

import { shortDid, shortHex, verdictInfo } from "./format";

export interface Chip {
  key: keyof MessageQuery;
  label: string;
  value: string;
}

export interface ParsedSearch {
  params: MessageQuery;
  chips: Chip[];
  /** Why part of the input could not be used, or null. */
  problem: string | null;
}

const BLOCK_ID = /^0x[0-9a-fA-F]{64}$/;
const MS = /^#?(\d{1,10})$/;
const MS_RANGE = /^#?(\d{1,10})\s*(?:\.\.|-|–)\s*#?(\d{1,10})$/;
const IE = /^[^:\s]+:[0-9a-fA-F]{12}$/;
const DATE = String.raw`\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,3})?)?(?:Z|[+-]\d{2}:?\d{2})?)?`;
const DATE_ONLY = new RegExp(`^${DATE}$`);
const DATE_RANGE = new RegExp(`^(${DATE})?\\s*(?:\\.\\.|–|—)\\s*(${DATE})?$`);
const TAG = /^[a-z][a-z0-9_-]*(?:\.[a-z0-9_-]+)+$/i;
const JSONPATH = /^([A-Za-z0-9_-]{1,64}(?:\.[A-Za-z0-9_-]{1,64}){0,7})=(.{0,200})$/;
const KEYED = /^(tag|kind|ie|iss|issuer|verdict|from|to|ms|block|path|q):(.+)$/i;
const MAX_MS = 0xffffffff;

const VERDICT_BY_NAME = new Map<string, string>(VERDICTS.map((v) => [v.toLowerCase(), v]));

function chipFor(key: keyof MessageQuery, value: string): Chip {
  switch (key) {
    case "block_id":
      return { key, label: "Block", value: shortHex(value, 8, 6) };
    case "ms_from":
      return { key, label: "From milestone", value };
    case "ms_to":
      return { key, label: "To milestone", value };
    case "iss":
      return { key, label: "Issuer", value: shortDid(value) };
    case "ie":
      return { key, label: "IE", value };
    case "tag":
      return { key, label: "Tag", value };
    case "kind":
      return { key, label: "Kind", value };
    case "verdict":
      return { key, label: "Verdict", value: verdictInfo(value).label };
    case "date_from":
      return { key, label: "From", value };
    case "date_to":
      return { key, label: "To", value: DATE_ONLY.test(value) && value.length === 10 ? `${value}, whole day` : value };
    case "jsonpath":
      return { key, label: "Body field", value };
    default:
      return { key, label: "Text", value: `“${value}”` };
  }
}

/** Joins "2026-10-06 to 2026-10-07" into one token before splitting on spaces. */
function joinRanges(text: string): string {
  return text
    .replace(new RegExp(`(${DATE})\\s+(?:to|\\.\\.|–|—)\\s+(${DATE})`, "gi"), "$1..$2")
    .replace(/(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2})/g, "$1T$2");
}

export function parseSearch(input: string): ParsedSearch {
  const params: MessageQuery = {};
  const words: string[] = [];
  let problem: string | null = null;
  const set = <K extends keyof MessageQuery>(k: K, v: MessageQuery[K]) => {
    params[k] = v;
  };

  const milestone = (from: number, to: number) => {
    if (from > MAX_MS || to > MAX_MS) {
      problem = "a milestone index is at most 4294967295";
      return;
    }
    set("ms_from", Math.min(from, to));
    set("ms_to", Math.max(from, to));
  };

  const classify = (token: string): boolean => {
    let m: RegExpExecArray | null;
    if (BLOCK_ID.test(token)) return set("block_id", token.toLowerCase()), true;
    if ((m = MS_RANGE.exec(token))) return milestone(Number(m[1]), Number(m[2])), true;
    if ((m = MS.exec(token))) return milestone(Number(m[1]), Number(m[1])), true;
    if (/^did:/i.test(token)) return set("iss", token), true;
    if (DATE_ONLY.test(token)) return set("date_from", token), set("date_to", token), true;
    if ((m = DATE_RANGE.exec(token)) && (m[1] || m[2])) {
      if (m[1]) set("date_from", m[1]);
      if (m[2]) set("date_to", m[2]);
      return true;
    }
    if (IE.test(token)) return set("ie", token), true;
    const verdict = VERDICT_BY_NAME.get(token.toLowerCase());
    if (verdict) return set("verdict", verdict), true;
    if ((m = JSONPATH.exec(token)) && m[1]!.length) return set("jsonpath", token), true;
    if (TAG.test(token)) return set("tag", token), true;
    return false;
  };

  const keyed = (key: string, value: string) => {
    switch (key.toLowerCase()) {
      case "tag":
        return set("tag", value);
      case "kind":
        return set("kind", value);
      case "ie":
        return set("ie", value);
      case "iss":
      case "issuer":
        return set("iss", value);
      case "verdict": {
        const v = VERDICT_BY_NAME.get(value.toLowerCase());
        if (v) set("verdict", v);
        else problem = `unknown verdict “${value}”`;
        return;
      }
      case "from":
        return set("date_from", value);
      case "to":
        return set("date_to", value);
      case "ms": {
        const r = MS_RANGE.exec(value) ?? MS.exec(value);
        if (r) milestone(Number(r[1]), Number(r[2] ?? r[1]));
        else problem = `“${value}” is not a milestone index`;
        return;
      }
      case "block":
        if (BLOCK_ID.test(value)) set("block_id", value.toLowerCase());
        else problem = "a block id is 0x followed by 64 hex digits";
        return;
      case "path":
        if (JSONPATH.test(value)) set("jsonpath", value);
        else problem = "a body field reads path.to.field=value";
        return;
      case "q":
        words.push(value);
        return;
    }
  };

  const text = joinRanges(input.trim());
  if (text) {
    for (const token of text.split(/\s+/)) {
      const k = KEYED.exec(token);
      if (k && !/^did$/i.test(k[1]!)) keyed(k[1]!, k[2]!);
      else if (!classify(token)) words.push(token);
    }
  }
  if (words.length) set("q", words.join(" ").slice(0, 200));

  const order: (keyof MessageQuery)[] = ["block_id", "ms_from", "ms_to", "iss", "ie", "tag", "kind", "verdict", "date_from", "date_to", "jsonpath", "q"];
  const chips = order.filter((k) => params[k] !== undefined).map((k) => chipFor(k, String(params[k])));
  // a single milestone reads as one chip
  if (params.ms_from !== undefined && params.ms_from === params.ms_to) {
    chips.splice(
      chips.findIndex((c) => c.key === "ms_from"),
      2,
      { key: "ms_from", label: "Milestone", value: String(params.ms_from) },
    );
  }
  if (params.date_from !== undefined && params.date_from === params.date_to && DATE_ONLY.test(params.date_from) && params.date_from.length === 10) {
    chips.splice(
      chips.findIndex((c) => c.key === "date_from"),
      2,
      { key: "date_from", label: "Day", value: params.date_from },
    );
  }
  return { params, chips, problem };
}
