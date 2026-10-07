<script setup lang="ts">
import { computed } from "vue";

import { RECORDED_NOTE, verdictInfo } from "./format";
import VerdictMark from "./VerdictMark.vue";

/** The verdict the indexer recorded, as mark + words. `quiet` drops the outline for dense rows. */
const props = withDefaults(defineProps<{ verdict: string | null | undefined; quiet?: boolean }>(), { quiet: false });
const info = computed(() => verdictInfo(props.verdict));
const title = computed(() => [info.value.gloss, RECORDED_NOTE].filter(Boolean).join(" "));
</script>

<template>
  <span class="vb" :class="{ quiet }" :data-f="info.family" :title="title">
    <VerdictMark :family="info.family" />
    <span class="lbl">{{ info.label }}</span>
  </span>
</template>

<style scoped>
.vb {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  height: 26px;
  padding: 0 11px 0 9px;
  border: 1px solid rgba(var(--rgb-fog-50), 0.22);
  border-radius: var(--r-pill);
  font-size: 13px;
  line-height: 1;
  color: var(--fog-50);
  white-space: nowrap;
}
.vb[data-f="rejected"] {
  border-color: rgba(var(--rgb-nova), 0.5);
  color: var(--fail);
}
.vb[data-f="unsigned"],
.vb[data-f="unknown"] {
  color: var(--fog-200);
}
.vb.quiet {
  height: auto;
  padding: 0;
  border: 0;
}
</style>
