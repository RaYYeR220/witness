<script setup lang="ts">
import { computed } from "vue";

import type { Lifecycle } from "@/api/client";

import { clock, LIFECYCLE, LIFECYCLE_BAD, statusLabel, utc } from "./format";

/**
 * What the explorer saw happen to the block: RECEIVED, SUBMITTED, SOLID,
 * CONFIRMED, CONTENT_VERIFIED (or where it went wrong), with when. The
 * brief's two node checks themselves sit above the ladder (TangleChecks).
 */
const props = defineProps<{ lifecycle: Lifecycle | null; lifecycleError: string | null }>();

const stages = computed(() => {
  const t = props.lifecycle?.transitions ?? [];
  const firstAt = (s: string) => t.find((x) => x.status === s)?.atMs ?? null;
  const path = LIFECYCLE.map((s) => ({ status: s as string, atMs: firstAt(s), bad: false }));
  const extra = t.filter((x) => LIFECYCLE_BAD.has(x.status)).map((x) => ({ status: x.status, atMs: x.atMs, bad: true }));
  if (!extra.length) return path;
  // a bad outcome replaces what would have come after the last stage reached
  const reached = path.filter((p) => p.atMs !== null);
  return [...reached, ...extra];
});
</script>

<template>
  <section class="node" aria-labelledby="life-h">
    <h2 id="life-h">What the explorer saw</h2>
    <p v-if="lifecycleError" class="muted">{{ lifecycleError }}</p>
    <p v-else-if="lifecycle && !lifecycle.transitions.length" class="muted">
      No submission was recorded for this block: it reached the Tangle without passing through the Messages API, so the explorer only saw it
      in a milestone.
    </p>
    <ol v-else-if="lifecycle" class="life">
      <li v-for="s in stages" :key="s.status" :data-reached="s.atMs !== null" :data-bad="s.bad">
        <span class="dot" aria-hidden="true"></span>
        <span class="st">{{ statusLabel(s.status) }}</span>
        <time v-if="s.atMs !== null" :title="utc(s.atMs)">{{ clock(s.atMs) }}</time>
        <span v-else class="muted">not reached</span>
      </li>
    </ol>

  </section>
</template>

<style scoped>
h2 {
  margin: 0 0 12px;
  font: 400 15px var(--sans);
  color: var(--fog-400);
}
.life {
  list-style: none;
  margin: 0;
  padding: 0;
}
.life li {
  position: relative;
  display: grid;
  grid-template-columns: 18px minmax(0, 1fr) auto;
  align-items: baseline;
  padding: 5px 0;
  font-size: 14px;
  color: var(--fog-400);
}
.life li:not(:last-child)::before {
  content: "";
  position: absolute;
  left: 3.5px;
  top: 17px;
  bottom: -7px;
  width: 1px;
  background: var(--hair);
}
.dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  border: 1px solid var(--fog-400);
  align-self: center;
}
.life li[data-reached="true"] {
  color: var(--fog-200);
}
/* the explorer's record: neutral, not green */
.life li[data-reached="true"] .dot {
  background: var(--fog-200);
  border-color: var(--fog-200);
}
.life li[data-reached="true"]:not(:last-child)::before {
  background: var(--hair-strong);
}
.life li[data-bad="true"] {
  color: var(--fail);
}
.life li[data-bad="true"] .dot {
  background: var(--fail);
  border-color: var(--fail);
}
.life time {
  font-size: 12.5px;
  color: var(--fog-400);
  font-variant-numeric: tabular-nums;
}
.muted {
  color: var(--fog-400);
}
</style>
