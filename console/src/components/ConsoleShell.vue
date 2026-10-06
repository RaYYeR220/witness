<script setup lang="ts">
import { REPO_URL } from "@/links";
import { CONSOLE_TABS } from "@/screens";

/** The console's frame: wordmark, the screens, and room for the screen itself. */
</script>

<template>
  <div class="shell">
    <header class="bar">
      <RouterLink class="wordmark" to="/">Witness</RouterLink>
      <nav class="tabs" aria-label="Console">
        <RouterLink v-for="t in CONSOLE_TABS" :key="t.path" :to="t.path">{{ t.title }}</RouterLink>
      </nav>
      <a class="source" :href="REPO_URL" rel="noopener">Source</a>
    </header>
    <main class="screen">
      <slot />
    </main>
  </div>
</template>

<style scoped>
.shell {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}
.bar {
  display: flex;
  align-items: center;
  gap: 32px;
  min-height: 60px;
  padding: 0 28px;
  border-bottom: 1px solid var(--hair);
}
.wordmark {
  font: 400 23px/1 var(--serif);
  color: var(--fog-50);
  text-decoration: none;
}
.tabs {
  display: flex;
  gap: 22px;
  overflow-x: auto;
  scrollbar-width: none;
  min-width: 0;
}
.tabs a {
  flex: none;
  padding: 20px 0 19px;
  border-bottom: 1px solid transparent;
  font-size: 14px;
  color: var(--fog-400);
  text-decoration: none;
  transition: color var(--t-quick);
}
.tabs a:hover {
  color: var(--fog-50);
}
.tabs a.router-link-active {
  color: var(--fog-50);
  border-color: var(--ember);
}
.source {
  margin-left: auto;
  font-size: 14px;
  color: var(--fog-400);
  text-decoration: none;
}
.source:hover {
  color: var(--fog-50);
}
.screen {
  flex: 1;
  padding: 56px 28px;
}
@media (max-width: 760px) {
  .bar {
    flex-wrap: wrap;
    gap: 0 20px;
    padding: 14px var(--gut) 0;
  }
  .tabs {
    order: 3;
    flex-basis: 100%;
  }
  .tabs a {
    padding: 12px 0 11px;
  }
  .screen {
    padding: 40px var(--gut);
  }
}
</style>
