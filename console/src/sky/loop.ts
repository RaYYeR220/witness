/**
 * When the sky needs another animation frame. Kept pure so it can be tested:
 * the stage calls it after every frame and stops the loop when it says no.
 */

export interface TraceTiming {
  /** Hops of the trace path. */
  hops: number;
  /** Hops' worth of time since the trace started (elapsed ms / HOP_MS); Infinity when motion is reduced. */
  elapsedHops: number;
  /** The trace ends in a trust message, so a plumb line must reach the ladder first. */
  toLadder: boolean;
  /** The plumb line has arrived and the ladder run has started. */
  plumbFired: boolean;
}

export interface LoopState {
  onScreen: boolean;
  hidden: boolean;
  /** prefers-reduced-motion: no twinkle, no idle motion. */
  still: boolean;
  /** Scroll progress through the descent. */
  p: number;
  /** Opacity of the sky layer at p (0 once the descent is past the stars). */
  skyAlpha: number;
  trace: TraceTiming | null;
}

/** Past this the sky has faded into the star's bytes and nothing in it moves. */
export const SKY_LIVE_UNTIL = 0.46;

/** True while a trace is still drawing something the viewer can see. */
export function traceAnimating(s: Pick<LoopState, "skyAlpha" | "trace">): boolean {
  const t = s.trace;
  if (!t || s.skyAlpha <= 0.02) return false;
  return t.elapsedHops < t.hops || (t.toLadder && !t.plumbFired);
}

export function needsFrame(s: LoopState): boolean {
  if (!s.onScreen || s.hidden) return false;
  if (traceAnimating(s)) return true;
  // the idle sky twinkles and follows the cursor while it is on screen
  return !s.still && s.skyAlpha > 0.02 && s.p < SKY_LIVE_UNTIL;
}
