<script setup lang="ts">
import type { StepStatus } from "@/verify/ladder";

/** A verdict as a shape first, a colour second: seal, broken ring, dotted ring, empty ring. */
defineProps<{ status: StepStatus }>();
</script>

<template>
  <svg class="mark" :data-s="status" viewBox="-6 -6 12 12" aria-hidden="true">
    <circle v-if="status === 'pass'" r="4.2" class="seal" />
    <g v-else-if="status === 'fail'" class="broken">
      <path d="M -1.4 -4.3 A 4.5 4.5 0 0 1 4.3 -1.3" />
      <path d="M 3.7 2.5 A 4.5 4.5 0 0 1 -2.3 3.9" />
      <path d="M -3.9 2.2 A 4.5 4.5 0 0 1 -4.2 -1.6" />
      <path d="M -1.8 -1.8 L 1.8 1.8 M 1.8 -1.8 L -1.8 1.8" />
    </g>
    <circle v-else-if="status === 'unknown'" r="4" class="dotted" />
    <circle v-else-if="status === 'running'" r="3.6" class="running" />
    <circle v-else r="3.2" class="wait" />
  </svg>
</template>

<style scoped>
.mark {
  display: block;
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
.dotted {
  fill: none;
  stroke: var(--fog-400);
  stroke-width: 1.1;
  stroke-dasharray: 1.2 2;
}
.running {
  fill: none;
  stroke: var(--ember);
  stroke-width: 1.3;
  animation: breathe 0.9s ease-in-out infinite alternate;
}
.wait {
  fill: var(--void);
  stroke: rgba(var(--rgb-fog-400), 0.7);
  stroke-width: 1;
}
@keyframes breathe {
  from {
    opacity: 0.35;
  }
  to {
    opacity: 1;
  }
}
</style>
