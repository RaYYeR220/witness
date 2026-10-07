<script setup lang="ts">
import { computed } from "vue";

import { severityLabel } from "./severity";

/**
 * A severity as a diamond plus its word (the same diamond Live uses for
 * alerts): critical is filled, high an outline, medium a quieter outline, low
 * and info a dotted one. Colour only repeats what the shape and word say.
 */
const props = withDefaults(defineProps<{ severity: string | null | undefined; bare?: boolean }>(), { bare: false });
const level = computed(() => {
  const s = props.severity ?? "";
  return ["critical", "high", "medium"].includes(s) ? s : "low";
});
</script>

<template>
  <span class="sev" :data-l="level" :class="{ bare }">
    <span class="dia" aria-hidden="true"></span>
    <span class="lbl">{{ severityLabel(severity) }}</span>
  </span>
</template>

<style scoped>
.sev {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
  color: var(--fog-200);
  white-space: nowrap;
}
.dia {
  flex: none;
  width: 7px;
  height: 7px;
  margin: 0 1px;
  transform: rotate(45deg);
  border: 1px dotted var(--fog-400);
}
.sev[data-l="critical"] {
  color: var(--fail);
}
.sev[data-l="critical"] .dia {
  border: 1px solid var(--fail);
  background: var(--fail);
}
.sev[data-l="high"] {
  color: var(--fail);
}
.sev[data-l="high"] .dia {
  border: 1.2px solid var(--fail);
}
.sev[data-l="medium"] .dia {
  border: 1px solid var(--fog-200);
}
.sev[data-l="low"] {
  color: var(--fog-400);
}
.bare .lbl {
  position: absolute;
  width: 1px;
  height: 1px;
  overflow: hidden;
  clip-path: inset(50%);
  white-space: nowrap;
}
</style>
