/**
 * Verification state for the landing page's sample and its forged twin.
 *
 * `results` holds one full ladder per trust message, computed once in the
 * browser when the page loads; the sky and the descent read their verdicts
 * from here. `hero` is the ladder you watch climb when you trace a star: it is
 * a fresh, paced run of the same library call, not a replay of `results`.
 */

import { defineStore } from "pinia";
import { reactive, ref } from "vue";

import { createLadder, resetLadder, runLadder } from "@/verify/ladder";
import { bundleText, sampleRun, type Which } from "@/verify/sample";

export const useVerificationStore = defineStore("verification", () => {
  const results = reactive({ sample: createLadder(), forged: createLadder() });
  const hero = createLadder();
  /** Which trust message the hero ladder is checking (null: a plain block or nothing traced). */
  const heroSubject = ref<Which | null>(null);
  /** The trust message the descent dives into. Tracing one in the sky makes it the subject. */
  const subject = ref<Which>("sample");
  let booted: Promise<void> | null = null;

  /**
   * One run per bundle, one after the other, so their timings are comparable.
   * An untimed run goes first: the very first verification in a page pays for
   * JIT warm-up, which would otherwise land on whichever bundle runs first.
   */
  function computeAll(): Promise<void> {
    booted ??= (async () => {
      await runLadder(createLadder(), bundleText("sample"), sampleRun("sample"));
      for (const w of ["sample", "forged"] as const) await runLadder(results[w], bundleText(w), sampleRun(w));
    })();
    return booted;
  }

  function verifyInHero(which: Which, pace: number) {
    heroSubject.value = which;
    subject.value = which;
    return runLadder(hero, bundleText(which), { ...sampleRun(which), pace });
  }

  function clearHero() {
    heroSubject.value = null;
    resetLadder(hero);
  }

  return { results, hero, heroSubject, subject, computeAll, verifyInHero, clearHero };
});
