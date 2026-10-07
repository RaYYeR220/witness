/**
 * Checking an audit report in the browser.
 *
 * Three hashes are in play: the one the explorer states (`reportHash`), the
 * one the browser computes from the report JSON it was served (BLAKE2b-256
 * of the RFC 8785 form, @witness/verify's canonHash, the same function as
 * core's canon_hash), and the one the audit.report message on the ledger
 * names. Only the browser's own is ever shown as "computed", and a report
 * counts as anchored only when the browser itself has checked the
 * audit.report block: its proof bundle bound to the block id, the five-step
 * ladder run against the console's pins with steps 1 to 4 passing, the
 * message tagged audit.report, and its body naming the browser's hash.
 * Anything less is the explorer's word, and any disagreement is a mismatch.
 */

import { canonHash, fromHex, isDict, isEnvelope, parseBlock, parseJson, toHex, type Ladder, type VerifierConfig } from "@witness/verify";

import type { ReportDoc } from "@/api/client";
import { isBlockId } from "@/console/format";
import { bindBundle } from "@/verify/binding";

export const AUDIT_TAG = "audit.report";

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

export interface AuditMessage {
  /** The tagged-data tag, decoded as UTF-8. */
  tag: string | null;
  /** `reportHash` in the message body, lowercase. */
  hash: string | null;
  /** The envelope's issuer as the bytes state it (step 4 checks its signature). */
  iss: string | null;
  problem: string | null;
}

/**
 * What an audit.report block says, read from the raw bytes of its proof
 * bundle. The bundle must be bound to `blockId` (its bytes hash to it), so
 * the explorer cannot swap in another block. This reads; it does not verify.
 */
export function readAuditMessage(bundleText: string, blockId: string): AuditMessage {
  const none = (problem: string): AuditMessage => ({ tag: null, hash: null, iss: null, problem });
  const binding = bindBundle(bundleText, blockId);
  if (binding.kind === "other") return none(`the explorer served the proof of another block (${binding.servedId})`);
  if (binding.kind === "unreadable") return none("the block's proof cannot be read");
  try {
    const bundle = parseJson(bundleText) as Record<string, unknown>;
    const payload = parseBlock(fromHex(String((bundle.block as Record<string, unknown>).raw))).payload;
    if (!payload || payload.kind !== "tagged_data") return none("the block carries no tagged data");
    const tag = new TextDecoder("utf-8", { fatal: true }).decode(payload.tag);
    const msg = parseJson(new TextDecoder("utf-8", { fatal: true }).decode(payload.data), { constants: true });
    const body = isDict(msg) && isEnvelope(msg) ? msg.body : msg;
    const hash = isDict(body) ? (body as Record<string, unknown>).reportHash : undefined;
    const iss = isDict(msg) ? (msg as Record<string, unknown>).iss : undefined;
    return {
      tag,
      hash: typeof hash === "string" ? hash.toLowerCase() : null,
      iss: typeof iss === "string" ? iss : null,
      problem: typeof hash === "string" ? null : "the block's message names no report hash",
    };
  } catch {
    return none("the block's message is not readable");
  }
}

/** Whether the pins can verify a block at all: a network, coordinator keys and a threshold they can meet. */
export function pinsUsable(cfg: Pick<VerifierConfig, "network" | "trustedCoordinatorKeys" | "threshold">): boolean {
  const keys = [...(cfg.trustedCoordinatorKeys ?? [])];
  return Boolean(cfg.network) && keys.length > 0 && Number.isInteger(cfg.threshold) && cfg.threshold >= 1 && cfg.threshold <= keys.length;
}

/**
 * verified      the browser checked the audit.report block and every hash agrees
 * mismatch      something disagrees or fails: never shown as anchored
 * unchecked     the explorer says anchored, the browser could not check it
 * not-anchored  the explorer says no audit.report was accepted
 */
export type ReportState = "verified" | "mismatch" | "unchecked" | "not-anchored";

export interface ReportCheck {
  state: ReportState;
  explorerHash: string;
  /** Computed here from the served JSON; null when it cannot be. */
  browserHash: string | null;
  /** What the audit.report body names, read from bytes bound to its block id; null when not read. */
  ledgerHash: string | null;
  iss: string | null;
  ladder: Ladder | null;
  /** The pinned report signer the block's (step 4 checked) issuer matched, once verified. */
  signer: string | null;
  /** Step 5: the block's milestone is in a checkpoint on IOTA Rebased (null: not run). */
  rebased: boolean | null;
  /** Why it is a mismatch, or why it could not be checked. */
  reasons: string[];
}

export interface CheckDeps {
  /** The pins the ladder runs with (only checked for usability here). */
  config: Pick<VerifierConfig, "network" | "trustedCoordinatorKeys" | "threshold">;
  /** `GET /proofs/{blockId}` as text. */
  bundle: (blockId: string) => Promise<string>;
  /** Runs the five-step ladder on the bundle text with the pinned config; null when it could not run. */
  verify: (bundleText: string) => Promise<Ladder | null>;
  /** The DID pinned as the one that signs audit.report messages; null: none pinned, so never verified. */
  reportSigner: string | null;
}

export async function checkReport(doc: ReportDoc, deps: CheckDeps): Promise<ReportCheck> {
  const r = doc.result;
  const explorerHash = String(r.reportHash).toLowerCase();
  const mine = recomputeReportHash(doc.text);
  const out: ReportCheck = {
    state: "unchecked",
    explorerHash,
    browserHash: mine.hash,
    ledgerHash: null,
    iss: null,
    ladder: null,
    signer: null,
    rebased: null,
    reasons: [],
  };
  const bad: string[] = [];
  if (mine.hash === null) bad.push(`your browser cannot compute the report's hash: ${mine.problem}`);
  else if (mine.hash !== explorerHash) bad.push("the report the explorer served does not hash to the reportHash it states");
  const finish = (state: ReportState, reasons: string[]): ReportCheck => {
    if (bad.length) return { ...out, state: "mismatch", reasons: [...bad, ...(state === "mismatch" ? reasons : [])] };
    return { ...out, state, reasons };
  };

  if (!r.anchored) return finish("not-anchored", []);
  const blockId = r.blockId;
  if (!isBlockId(blockId)) return finish("unchecked", ["the explorer names no audit.report block"]);
  if (!pinsUsable(deps.config)) return finish("unchecked", ["this console pins no coordinator keys to check the block with"]);

  let text: string;
  try {
    text = await deps.bundle(blockId);
  } catch (e) {
    return finish("unchecked", [`the audit.report block's proof could not be read (${(e as Error).message})`]);
  }
  const msg = readAuditMessage(text, blockId);
  if (msg.problem && msg.tag === null) return finish("mismatch", [msg.problem]);
  out.iss = msg.iss;
  out.ledgerHash = msg.hash;

  const ladder = await deps.verify(text);
  out.ladder = ladder;
  if (!ladder) return finish("unchecked", ["the checks could not run on the audit.report block"]);
  const steps = ladder.steps;
  out.rebased = steps[4]?.ok ?? null;
  const failed = steps.filter((s) => s.ok === false);
  if (failed.length) return finish("mismatch", failed.map((s) => `check ${steps.indexOf(s) + 1} failed on the audit.report block: ${s.detail}`));
  if (msg.tag !== AUDIT_TAG) return finish("mismatch", [`the block is tagged ${JSON.stringify(msg.tag)}, not ${AUDIT_TAG}`]);
  if (msg.hash === null) return finish("mismatch", [msg.problem ?? "the block's message names no report hash"]);
  if (mine.hash !== null && msg.hash !== mine.hash) return finish("mismatch", ["the audit.report on the ledger names another hash than the report served"]);
  // Check 4 proves who signed it; the pin says who may: only the pinned report signer anchors a report.
  if (deps.reportSigner && msg.iss !== deps.reportSigner) {
    return finish("mismatch", [`the audit.report was signed by ${msg.iss ?? "no one"}, not by the report signer pinned in this console`]);
  }
  const open = steps.slice(0, 4).filter((s) => s.ok !== true);
  if (open.length) return finish("unchecked", open.map((s) => `check ${steps.indexOf(s) + 1} could not be evaluated: ${s.detail}`));
  if (!deps.reportSigner) return finish("unchecked", ["this console pins no report signer, so it cannot tell whose audit.report counts"]);
  out.signer = deps.reportSigner;
  return finish("verified", []);
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
