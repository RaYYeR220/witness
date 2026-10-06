<script setup lang="ts">
import type { VerdictFamily } from "./format";

/**
 * A verdict as a shape first, a colour second: signed is a filled seal,
 * unsigned an open ring, rejected a broken ring with a cross, no verdict a
 * dotted ring. Same drawing language as the ladder's StepMark.
 */
defineProps<{ family: VerdictFamily }>();
</script>

<template>
  <svg class="vm" :data-f="family" viewBox="-6 -6 12 12" aria-hidden="true">
    <circle v-if="family === 'signed'" r="4.2" class="seal" />
    <g v-else-if="family === 'rejected'" class="broken">
      <path d="M -1.4 -4.3 A 4.5 4.5 0 0 1 4.3 -1.3" />
      <path d="M 3.7 2.5 A 4.5 4.5 0 0 1 -2.3 3.9" />
      <path d="M -3.9 2.2 A 4.5 4.5 0 0 1 -4.2 -1.6" />
      <path d="M -1.8 -1.8 L 1.8 1.8 M 1.8 -1.8 L -1.8 1.8" />
    </g>
    <circle v-else-if="family === 'unsigned'" r="3.9" class="ring" />
    <circle v-else r="4" class="dotted" />
  </svg>
</template>

<style scoped>
.vm {
  display: block;
  flex: none;
  width: 11px;
  height: 11px;
  overflow: visible;
}
.seal {
  fill: var(--pass);
}
.broken path {
  fill: none;
  stroke: var(--fail);
  stroke-width: 1.3;
  stroke-linecap: round;
}
.ring {
  fill: none;
  stroke: var(--fog-200);
  stroke-width: 1.2;
}
.dotted {
  fill: none;
  stroke: var(--fog-400);
  stroke-width: 1.1;
  stroke-dasharray: 1.2 2;
}
</style>
