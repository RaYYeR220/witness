<script setup lang="ts">
import { REPO_URL } from "@/links";
</script>

<template>
  <footer class="foot">
    <div class="inner">
      <span class="wordmark">Witness</span>
      <span>Built on Eclipse aeriOS and IOTA</span>
      <a :href="REPO_URL" rel="noopener">Source on GitHub</a>
      <span>Apache-2.0</span>
    </div>
  </footer>
</template>

<style scoped>
.foot {
  border-top: 1px solid var(--hair);
  padding: 28px var(--gut) 40px;
}
.inner {
  max-width: var(--content);
  margin: 0 auto;
  display: flex;
  flex-wrap: wrap;
  gap: 12px 32px;
  align-items: baseline;
  font-size: var(--fs-small);
  color: var(--fog-400);
}
.wordmark {
  margin-right: auto;
  font: 400 21px/1 var(--serif);
  color: var(--fog-200);
}
a {
  text-decoration: none;
  transition: color var(--t-quick);
}
a:hover {
  color: var(--fog-50);
}
@media (max-width: 760px) {
  .wordmark {
    flex-basis: 100%;
  }
}
</style>
