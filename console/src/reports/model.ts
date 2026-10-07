/**
 * A report's hash, computed in the browser: BLAKE2b-256 of the RFC 8785
 * (JCS) form of the report JSON, as served, with @witness/verify's own
 * canonicaliser. And the hash the ledger names: read from the audit.report
 * block's own bytes, which must hash to the block id the explorer gives.
 */

import { canonHash, fromHex, isDict, isEnvelope, parseBlock, parseJson, toHex } from "@witness/verify";

import { bindBundle } from "@/verify/binding";

/** The canonical hash of the `report` member of a `GET /reports/{hash}` answer, from its exact text. */
export function recomputeReportHash(text: string): { hash: string | null; problem: string | null } {
  let doc: unknown;
  try {
    doc = parseJson(text, { constants: true });
  } catch {
    return { hash: null, problem: "the answer is not JSON" };
  }
  if (!isDict(doc) || !Object.hasOwn(doc, "report")) return { hash: null, problem: "the answer carries no report" };
  try {
    return { hash: toHex(canonHash((doc as Record<string, unknown>).report)), problem: null };
  } catch (e) {
    return { hash: null, problem: `the report cannot be canonicalised (${(e as Error).name})` };
  }
}

export interface LedgerCopy {
  /** `reportHash` in the audit.report body, or null. */
  hash: string | null;
  /** The envelope's issuer, as the bytes state it (Verify checks the signature). */
  iss: string | null;
  problem: string | null;
}

/**
 * The report hash an audit.report block names, read from the raw bytes in
 * its proof bundle. The bytes must hash to `blockId` (the bundle is bound to
 * the block asked for), so the explorer cannot swap in another block.
 */
export function ledgerReportHash(bundleText: string, blockId: string): LedgerCopy {
  const none = (problem: string): LedgerCopy => ({ hash: null, iss: null, problem });
  const binding = bindBundle(bundleText, blockId);
  if (binding.kind === "other") return none(`the explorer served the bytes of another block (${binding.servedId})`);
  if (binding.kind === "unreadable") return none("the block's bytes cannot be read");
  try {
    const bundle = parseJson(bundleText) as Record<string, unknown>;
    const raw = fromHex(String((bundle.block as Record<string, unknown>).raw));
    const payload = parseBlock(raw).payload;
    if (!payload || payload.kind !== "tagged_data") return none("the block carries no tagged data");
    const msg = parseJson(new TextDecoder("utf-8", { fatal: true }).decode(payload.data), { constants: true });
    const body = isDict(msg) && isEnvelope(msg) ? msg.body : msg;
    const hash = isDict(body) ? (body as Record<string, unknown>).reportHash : undefined;
    const iss = isDict(msg) ? (msg as Record<string, unknown>).iss : undefined;
    if (typeof hash !== "string") return { hash: null, iss: typeof iss === "string" ? iss : null, problem: "the block's message names no report hash" };
    return { hash: hash.toLowerCase(), iss: typeof iss === "string" ? iss : null, problem: null };
  } catch {
    return none("the block's message is not readable JSON");
  }
}

/** A few totals from the report for the screen; anything not a number is left out. */
export function reportTotals(report: unknown): { label: string; value: number }[] {
  const out: { label: string; value: number }[] = [];
  const at = (...path: string[]) => {
    let cur: unknown = report;
    for (const k of path) cur = isDict(cur) ? (cur as Record<string, unknown>)[k] : undefined;
    return typeof cur === "number" && Number.isFinite(cur) ? cur : null;
  };
  const push = (label: string, v: number | null) => v !== null && out.push({ label, value: v });
  push("Messages", at("messages", "total"));
  push("Confirmed", at("messages", "confirmed"));
  push("Alerts", at("alerts", "total"));
  push("Checkpoints", at("anchors", "total"));
  const proofs = isDict(report) ? (report as Record<string, unknown>).proofs : undefined;
  if (Array.isArray(proofs)) out.push({ label: "Proofs listed", value: proofs.length });
  return out;
}
