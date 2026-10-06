<script setup lang="ts">
import { computed } from "vue";

import StepMark from "@/components/StepMark.vue";
import { stepNote, stepValue, type LadderState } from "@/verify/ladder";

/**
 * The five checks as the browser decides them, step by step. Every status and
 * value comes from @witness/verify's own step results (via `runLadder`); this
 * component only says in words what each step compares.
 */
const props = defineProps<{ state: LadderState; anchorPinned: boolean }>();

const GLOSS: Record<string, string> = {
  block_hash: "BLAKE2b-256 of the raw bytes must equal the block id.",
  inclusion: "A Merkle path from the block id must reach the inclusion root the milestone commits to.",
  milestone_signatures: "Enough coordinator keys pinned in this console must have signed that milestone.",
  envelope: "The sender's Ed25519 signature must check against the key its DID document lists at that time.",
  anchor: "The milestone must sit in a checkpoint recorded on IOTA Rebased, read from the chain by this browser.",
};

const STATUS_WORD: Record<string, string> = {
  waiting: "not run yet",
  running: "running",
  pass: "passed",
  fail: "failed",
  unknown: "not checked",
};

const overall = computed(() => props.state.overall);
const failed = computed(() => props.state.steps.find((s) => s.status === "fail") ?? null);
const unknown = computed(() => props.state.steps.filter((s) => s.status === "unknown"));

const summary = computed(() => {
  const s = props.state;
  if (s.error) return `The verifier stopped: ${s.error}`;
  if (s.running) return "Checking in your browser…";
  if (overall.value === "VALID") return "All five checks passed in your browser.";
  if (overall.value === "INVALID" && failed.value) return `Check ${failed.value.n}, ${failed.value.title.toLowerCase()}, failed: ${stepNote(failed.value.detail)}.`;
  if (overall.value === "PARTIAL") {
    const names = unknown.value.map((x) => `${x.n}`).join(" and ");
    return `Nothing failed, but check ${names} could not be evaluated. Partial is not a pass.`;
  }
  return "";
});
</script>

<template>
  <section class="ladder" aria-labelledby="ladder-h" :aria-busy="state.running">
    <h2 id="ladder-h" class="sr-only">The five checks, run in your browser</h2>
    <ol class="steps">
      <li v-for="s in state.steps" :key="s.name" class="step" :data-s="s.status" :data-step="s.name">
        <span class="mk"><StepMark :status="s.status" /></span>
        <span class="n" aria-hidden="true">{{ s.n }}</span>
        <div class="body">
          <p class="title">
            <span class="t">{{ s.title }}</span>
            <span class="sr-only">: {{ STATUS_WORD[s.status] }}.</span>
            <span class="val" aria-hidden="true">{{ stepValue(s) }}</span>
          </p>
          <p class="gloss">{{ GLOSS[s.name] }}</p>
          <p v-if="s.detail" class="detail mono">{{ s.detail }}</p>
          <p v-if="s.name === 'anchor' && s.status === 'unknown' && !anchorPinned" class="detail why">
            This console pins no complete Rebased anchor (trail, RPC and package), so it cannot read the record.
          </p>
          <p v-else-if="s.name === 'anchor' && s.status === 'unknown' && s.detail === 'bundle carries no anchor'" class="detail why">
            Its milestone is newer than the last checkpoint written to IOTA Rebased. Run the checks again once the next checkpoint is anchored.
          </p>
        </div>
      </li>
    </ol>
    <p class="overall" :data-o="state.error ? 'ERROR' : (overall ?? 'RUNNING')" role="status" aria-live="polite">
      <b v-if="overall && !state.running">{{ overall === "VALID" ? "Valid." : overall === "INVALID" ? "Invalid." : "Partial." }}</b>
      {{ summary }}
      <span v-if="state.computeMs !== null && !state.running" class="ms">{{ Math.max(1, Math.round(state.computeMs)) }} ms, lookups of the issuer's keys and the anchor record included</span>
    </p>
  </section>
</template>

<style scoped>
.steps {
  list-style: none;
  margin: 0;
  padding: 0;
}
.step {
  position: relative;
  display: grid;
  grid-template-columns: 22px 22px minmax(0, 1fr);
  padding: 10px 0 12px;
}
.step:not(:last-child)::before {
  content: "";
  position: absolute;
  left: 5px;
  top: 26px;
  bottom: -8px;
  width: 1px;
  background: var(--hair);
  transition: background var(--t-step);
}
.step[data-s="pass"]:not(:last-child)::before {
  background: rgba(var(--rgb-aurora), 0.55);
}
.mk {
  position: relative;
  top: 6px;
}
.n {
  font-size: 14px;
  line-height: 22px;
  color: var(--fog-400);
  font-variant-numeric: tabular-nums;
}
.body {
  min-width: 0;
}
.title {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: 16px;
  margin: 0;
}
.t {
  font-size: 17px;
  line-height: 22px;
  color: var(--fog-50);
  transition: color var(--t-step);
}
.step[data-s="waiting"] .t,
.step[data-s="running"] .t {
  color: var(--fog-400);
}
.step[data-s="fail"] .t,
.step[data-s="fail"] .val {
  color: var(--fail);
}
.val {
  font: 400 12px/22px var(--mono);
  color: var(--fog-400);
  text-align: right;
  white-space: nowrap;
}
.gloss {
  margin: 2px 0 0;
  font-size: 13.5px;
  line-height: 20px;
  color: var(--fog-400);
}
.detail {
  margin: 6px 0 0;
  padding: 6px 10px;
  border-left: 1px solid var(--hair-strong);
  font-size: 11.5px;
  line-height: 17px;
  color: var(--fog-200);
  overflow-wrap: anywhere;
}
.step[data-s="fail"] .detail {
  border-color: var(--fail);
  background: var(--nova-wash);
  color: var(--fog-50);
}
.step[data-s="unknown"] .detail {
  border-left-style: dashed;
}
.detail.why {
  font-family: var(--sans);
  font-size: 12.5px;
  color: var(--fog-400);
}
.step[data-s="running"] .t::after {
  content: " …";
  color: var(--ember);
}
.overall {
  margin: 14px 0 0;
  padding: 14px 0 0 44px;
  border-top: 1px solid var(--hair);
  font-size: 15px;
  line-height: 22px;
  color: var(--fog-200);
}
.overall b {
  font-weight: 500;
  color: var(--fog-50);
}
.overall[data-o="VALID"] b {
  color: var(--pass);
}
.overall[data-o="INVALID"] b,
.overall[data-o="ERROR"] {
  color: var(--fail);
}
.ms {
  display: block;
  font-size: 12.5px;
  color: var(--fog-400);
}
@media (max-width: 760px) {
  .title {
    flex-direction: column;
    gap: 0;
  }
  .val {
    text-align: left;
  }
  .overall {
    padding-left: 0;
  }
}
</style>
