<script setup lang="ts">
import { computed } from "vue";
import { useRoute } from "vue-router";

import ConsoleShell from "@/components/ConsoleShell.vue";

const route = useRoute();
const title = computed(() => String(route.meta.title ?? "Console"));
const blurb = computed(() => String(route.meta.blurb ?? ""));
const param = computed(() => {
  const v = route.params.blockId ?? route.params.id;
  return typeof v === "string" ? v : null;
});
</script>

<template>
  <ConsoleShell>
    <section class="soon" aria-labelledby="soon-h">
      <h1 id="soon-h">{{ title }}</h1>
      <p v-if="param" class="param mono">{{ param }}</p>
      <p class="blurb">{{ blurb }}</p>
      <p class="note">
        This screen is not built yet. The verifier it will use already runs in your browser on the
        <RouterLink to="/">landing page</RouterLink>.
      </p>
    </section>
  </ConsoleShell>
</template>

<style scoped>
.soon {
  max-width: 640px;
}
h1 {
  margin: 0;
  font: 400 var(--fs-h2) / 1 var(--serif);
  letter-spacing: -0.012em;
  color: var(--fog-50);
}
.param {
  margin: 14px 0 0;
  color: var(--fog-200);
  overflow-wrap: anywhere;
}
.blurb {
  margin: 18px 0 0;
  max-width: 52ch;
  font-size: var(--fs-lead);
  line-height: 27px;
}
.note {
  margin: 28px 0 0;
  padding-top: 18px;
  border-top: 1px solid var(--hair);
  max-width: 56ch;
  font-size: var(--fs-small);
  line-height: 20px;
  color: var(--fog-400);
}
.note a {
  color: var(--fog-200);
  text-decoration-color: var(--ember);
  text-underline-offset: 4px;
}
</style>
