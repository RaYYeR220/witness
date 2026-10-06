<script setup lang="ts">
import { REPO_URL } from "@/links";

/** The landing page's top line: wordmark left, three ways out on the right. */
const emit = defineEmits<{ how: [] }>();
</script>

<template>
  <header class="nav">
    <RouterLink class="wordmark" to="/" aria-label="Witness, home">Witness</RouterLink>
    <nav aria-label="Primary">
      <a class="how" href="#how" @click.prevent="emit('how')">How it works</a>
      <RouterLink to="/live">Console</RouterLink>
      <a :href="REPO_URL" rel="noopener">Source</a>
    </nav>
  </header>
</template>

<style scoped>
.nav {
  position: absolute;
  z-index: 10;
  top: 0;
  left: 0;
  right: 0;
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  max-width: calc(var(--content) + 2 * var(--gut));
  margin: 0 auto;
  padding: 30px var(--gut) 0;
}
.wordmark {
  font: 400 27px/1 var(--serif);
  letter-spacing: 0.005em;
  color: var(--fog-50);
  text-decoration: none;
}
nav {
  display: flex;
  gap: 28px;
}
nav a {
  font-size: 14px;
  color: var(--fog-400);
  text-decoration: none;
  transition: color var(--t-quick);
}
nav a:hover {
  color: var(--fog-50);
}
@media (max-width: 760px) {
  .nav {
    padding-top: 22px;
  }
  nav {
    gap: 18px;
  }
  .how {
    display: none;
  }
}
</style>
