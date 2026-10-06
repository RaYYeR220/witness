<script setup lang="ts">
import { REPO_URL } from "@/links";
</script>

<template>
  <main class="landing">
    <h1>Witness</h1>
    <p>Don&rsquo;t trust the dashboard. Verify the Tangle.</p>
    <p><RouterLink to="/live">Console</RouterLink> &middot; <a :href="REPO_URL" rel="noopener">Source</a></p>
  </main>
</template>

<style scoped>
.landing {
  max-width: var(--content);
  margin: 0 auto;
  padding: 120px var(--gut);
}
h1 {
  margin: 0;
  font: 400 var(--fs-h1) / 1 var(--serif);
  color: var(--fog-50);
}
</style>
