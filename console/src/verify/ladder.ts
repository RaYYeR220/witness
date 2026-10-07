/**
 * The five-check ladder as reactive state.
 *
 * `runLadder` calls `verifyBundleText` from @witness/verify and writes each
 * step into the state from the library's `onStep` callback, in ladder order,
 * the moment the library decides it. Nothing here decides a verdict: a step
 * reads "pass" only because the library returned `ok: true` for it.
 *
 * It verifies against the console's pinned config (verify/pinned.ts) unless a
 * caller passes another one on purpose, like the landing page's sample, which
 * is checked against the pins of the test vectors it comes from.
 */

import { reactive } from "vue";
import {
  STEP_NAMES,
  verifyBundleText,
  type Ladder,
  type Overall,
  type StepName,
  type StepResult,
  type VerifierConfig,
  type VerifyOptions,
} from "@witness/verify";

import { pinnedConfig } from "./pinned";

/** waiting: not reached yet; running: being computed; unknown: the library could not evaluate it (ok null). */
export type StepStatus = "waiting" | "running" | "pass" | "fail" | "unknown";

export interface StepView {
  name: StepName;
  /** 1-based position on the ladder. */
  n: number;
  title: string;
  status: StepStatus;
  /** The library's own detail string for this step ("" until decided). */
  detail: string;
}

export interface LadderState {
  steps: StepView[];
  overall: Overall | null;
  running: boolean;
  /** Time spent inside the verifier, without any pacing pauses. */
  computeMs: number | null;
  /** 1-based number of the first failed step, or null. */
  failedAt: number | null;
  error: string | null;
  /** Bumped on every run; a newer run supersedes an older one. */
  run: number;
}

export const STEP_TITLES: Record<StepName, string> = {
  block_hash: "Block hash",
  inclusion: "Milestone inclusion",
  milestone_signatures: "Milestone signatures",
  envelope: "Sender signature",
  anchor: "Public anchor",
};

function blankSteps(): StepView[] {
  return STEP_NAMES.map((name, i) => ({ name, n: i + 1, title: STEP_TITLES[name], status: "waiting", detail: "" }));
}

export function createLadder(): LadderState {
  return reactive({
    steps: blankSteps(),
    overall: null,
    running: false,
    computeMs: null,
    failedAt: null,
    error: null,
    run: 0,
  }) as LadderState;
}

/** Back to five waiting steps; also cancels a run in progress. */
export function resetLadder(state: LadderState): void {
  state.run += 1;
  state.steps = blankSteps();
  state.overall = null;
  state.running = false;
  state.computeMs = null;
  state.failedAt = null;
  state.error = null;
}

export function statusOf(ok: boolean | null): StepStatus {
  return ok === true ? "pass" : ok === false ? "fail" : "unknown";
}

export interface RunOptions extends Pick<VerifyOptions, "resolveDid" | "fetchAnchorRecord"> {
  /** The pins to verify against. Default: the console's pinned config. */
  config?: VerifierConfig;
  /** Pause after each decided step, in ms, so people can watch the ladder climb. 0 = no pause. */
  pace?: number;
  /** Called after each step is written into the state; awaited when it returns a promise. */
  onStep?: (step: StepView, state: LadderState) => unknown;
}

class Superseded extends Error {}

const now = () => (typeof performance !== "undefined" ? performance.now() : Date.now());
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * Verify `input` (bundle text or bytes) and stream every step
 * into `state`. Resolves with the library's ladder, or with null when a newer
 * run (or `resetLadder`) took over before this one finished.
 */
export async function runLadder(state: LadderState, input: string | Uint8Array, options: RunOptions = {}): Promise<Ladder | null> {
  const cfg = options.config ?? pinnedConfig();
  resetLadder(state);
  const run = state.run;
  const pace = Math.max(0, options.pace ?? 0);
  state.running = true;
  state.steps[0]!.status = "running";
  let spent = 0;
  let resumed = now();

  const onStep = async (step: Readonly<StepResult>) => {
    if (state.run !== run) throw new Superseded();
    spent += now() - resumed;
    const i = STEP_NAMES.indexOf(step.name);
    const view = state.steps[i]!;
    view.status = statusOf(step.ok);
    view.detail = step.detail;
    if (step.ok === false && state.failedAt === null) state.failedAt = view.n;
    const next = state.steps[i + 1];
    if (next) next.status = "running";
    await options.onStep?.(view, state);
    if (pace > 0) await sleep(pace);
    if (state.run !== run) throw new Superseded();
    resumed = now();
  };

  try {
    const ladder = await verifyBundleText(input, cfg, {
      resolveDid: options.resolveDid,
      fetchAnchorRecord: options.fetchAnchorRecord,
      onStep,
    });
    if (state.run !== run) return null;
    spent += now() - resumed;
    state.overall = ladder.overall;
    state.computeMs = spent;
    state.running = false;
    return ladder;
  } catch (e) {
    if (e instanceof Superseded || state.run !== run) return null;
    state.running = false;
    state.error = e instanceof Error ? e.message : String(e);
    for (const s of state.steps) if (s.status === "waiting" || s.status === "running") s.status = "unknown";
    return null;
  }
}

/** The library's detail with every 32-byte hex value shortened, for display next to a step. */
export function stepNote(detail: string): string {
  return detail.replace(/0x[0-9a-f]{64}/g, (h) => short(h));
}

const short = (h: string) => (h.length > 14 ? `${h.slice(0, 6)}…${h.slice(-4)}` : h);
const firstHex = (s: string) => /0x[0-9a-f]{64}/.exec(s)?.[0] ?? null;

/**
 * A short value for a decided step, taken from the library's detail string
 * (the full detail stays available next to it).
 */
export function stepValue(step: Pick<StepView, "name" | "status" | "detail">): string {
  const { name, status, detail } = step;
  if (status === "waiting" || status === "running") return "";
  if (status === "unknown") return "not evaluated";
  switch (name) {
    case "block_hash": {
      const h = firstHex(detail);
      return h ? `${status === "fail" ? "hash " : ""}${short(h)}` : status === "pass" ? "matches" : "does not parse";
    }
    case "inclusion": {
      const h = firstHex(detail);
      return status === "pass" && h ? `root ${short(h)}` : "path broken";
    }
    case "milestone_signatures": {
      const m = /(\d+) valid signature\(s\) by pinned keys, threshold (\d+)/.exec(detail);
      return m ? `${m[1]} valid, ${m[2]} needed` : status === "pass" ? "valid" : "rejected";
    }
    case "envelope": {
      if (status === "pass") {
        const kid = /#[\w-]+$/.exec(detail)?.[0];
        // a did:key fragment is the whole multibase key: shortened like the hashes (the full detail is next to it)
        return kid ? `Ed25519, key ${kid.length > 16 ? `${kid.slice(0, 8)}…${kid.slice(-4)}` : kid}` : "Ed25519";
      }
      return /^FORGED/.test(detail) ? "signature rejected" : (detail.split(":")[0] ?? "rejected").toLowerCase();
    }
    case "anchor": {
      const h = firstHex(detail);
      return status === "pass" && h ? `checkpoint ${short(h)}` : "record differs";
    }
  }
}
