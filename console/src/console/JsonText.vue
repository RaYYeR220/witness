<script setup lang="ts">
import { computed } from "vue";

/**
 * Untrusted JSON (alert evidence, incident detail, a report) shown as text:
 * indented, never interpreted, never turned into links or markup. Very long
 * values are cut with a note of how much was left out.
 */
const props = withDefaults(defineProps<{ value: unknown; max?: number }>(), { max: 20_000 });

const text = computed(() => {
  let t: string;
  try {
    t = JSON.stringify(props.value, null, 1) ?? String(props.value);
  } catch {
    t = String(props.value);
  }
  return t.length > props.max ? `${t.slice(0, props.max)}\n… ${t.length - props.max} more characters` : t;
});
</script>

<template>
  <pre class="json mono" tabindex="0">{{ text }}</pre>
</template>

<style scoped>
.json {
  margin: 0;
  max-height: 320px;
  overflow: auto;
  padding: 10px 12px;
  border-left: 1px solid var(--hair-strong);
  background: rgba(var(--rgb-fog-50), 0.02);
  color: var(--fog-200);
  font-size: 12px;
  line-height: 18px;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
</style>
