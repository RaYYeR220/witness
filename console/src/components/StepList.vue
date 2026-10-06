<script setup lang="ts">
import { ref } from "vue";

import { stepNote, stepValue, type StepView } from "@/verify/ladder";

import StepMark from "./StepMark.vue";

/**
 * The five checks as a thin vertical line of marks. Values and failure text
 * come straight from the library's step details; `glosses` say in plain words
 * what each step compares.
 */
const props = withDefaults(
  defineProps<{
    steps: StepView[];
    glosses: string[];
    /** One row of five marks, for narrow screens. */
    compact?: boolean;
    /** Show the gloss under every decided step instead of on hover. */
    open?: boolean;
  }>(),
  { compact: false, open: false },
);

const first = ref<HTMLElement | null>(null);
defineExpose({ firstMark: first });

function label(s: StepView) {
  const state =
    s.status === "pass"
      ? "passed"
      : s.status === "fail"
        ? "failed"
        : s.status === "unknown"
          ? "not evaluated"
          : s.status === "running"
            ? "running"
            : "not run yet";
  return `Check ${s.n}, ${s.title}: ${state}. ${s.status === "fail" || s.status === "unknown" ? stepNote(s.detail) : (props.glosses[s.n - 1] ?? "")}`;
}
</script>

<template>
  <ol v-if="!compact" class="steps">
    <li
      v-for="s in steps"
      :key="s.name"
      class="step"
      :data-s="s.status"
      :class="{ 'show-gloss': open && s.status !== 'waiting' }"
      tabindex="0"
      :aria-label="label(s)"
    >
      <span :ref="s.n === 1 ? (el) => (first = el as HTMLElement) : undefined" class="mk"><StepMark :status="s.status" /></span>
      <span class="nm"><i>{{ s.n }}</i>{{ s.title }}</span>
      <span class="vl" :class="{ plain: s.name === 'milestone_signatures' || s.name === 'envelope' || s.status === 'unknown' }">{{
        stepValue(s)
      }}</span>
      <span class="gl">{{ s.status === "fail" || s.status === "unknown" ? stepNote(s.detail) : glosses[s.n - 1] }}</span>
    </li>
  </ol>
  <ol v-else class="row" aria-label="Five checks">
    <li v-for="s in steps" :key="s.name" :data-s="s.status" :aria-label="label(s)">
      <span :ref="s.n === 1 ? (el) => (first = el as HTMLElement) : undefined" class="mk"><StepMark :status="s.status" /></span>
      <i>{{ s.n }}</i>
    </li>
  </ol>
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
  grid-template-columns: 22px minmax(0, 1fr) auto;
  column-gap: 0;
  align-items: baseline;
  min-height: 30px;
  padding: 5px 0;
  outline-offset: 2px;
}
/* the thread between marks: lit once the step above it has passed */
.step:not(:last-child)::before {
  content: "";
  position: absolute;
  left: 5px;
  top: 19px;
  height: calc(100% - 8px);
  width: 1px;
  background: var(--hair);
  transition: background var(--t-step);
}
.step[data-s="pass"]:not(:last-child)::before {
  background: rgba(var(--rgb-aurora), 0.55);
}
.mk {
  position: relative;
  top: 1px;
  width: 11px;
  height: 11px;
}
.nm {
  color: var(--fog-50);
  font-size: 14px;
  line-height: 20px;
  transition: color var(--t-step);
}
.nm i {
  font-style: normal;
  color: var(--fog-400);
  font-variant-numeric: tabular-nums;
  margin-right: 10px;
}
.step[data-s="waiting"] .nm,
.step[data-s="running"] .nm,
.step[data-s="unknown"] .nm {
  color: var(--fog-400);
}
.vl {
  padding-left: 16px;
  font: 400 12px/20px var(--mono);
  color: var(--fog-400);
  text-align: right;
  white-space: nowrap;
}
.vl.plain {
  font: 400 13px/20px var(--sans);
}
.step[data-s="fail"] .vl,
.step[data-s="fail"] .nm {
  color: var(--fail);
}
.gl {
  grid-column: 2 / 4;
  font-size: 12.5px;
  line-height: 18px;
  color: var(--fog-400);
  max-height: 0;
  overflow: hidden;
  opacity: 0;
  overflow-wrap: anywhere;
  transition:
    max-height var(--t-step),
    opacity var(--t-step);
}
.step:hover .gl,
.step:focus-visible .gl,
.step.show-gloss .gl,
.step[data-s="fail"] .gl {
  max-height: 60px;
  opacity: 1;
}
.step[data-s="fail"] .gl {
  color: var(--fog-200);
}

.row {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  gap: 14px;
  align-items: center;
}
.row li {
  display: flex;
  align-items: center;
  gap: 5px;
}
.row i {
  font-style: normal;
  font-size: 12px;
  color: var(--fog-400);
  font-variant-numeric: tabular-nums;
}
.row li[data-s="fail"] i {
  color: var(--fail);
}
</style>
