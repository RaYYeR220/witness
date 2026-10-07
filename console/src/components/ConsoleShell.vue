<script setup lang="ts">
import { computed, ref } from "vue";
import { useRouter } from "vue-router";

import { useHealth } from "@/console/health";
import { REPO_URL } from "@/links";
import { CONSOLE_TABS } from "@/screens";

/**
 * The console's frame: wordmark, the screens, where the data comes from and
 * whether it answers, and room for the screen itself.
 */
const { health, mode } = useHealth();
const router = useRouter();
const quick = ref("");

const status = computed(() => {
  const h = health.value;
  if (mode === "replay") {
    return { tone: h?.ok === false ? "bad" : "replay", label: "Replay", note: h?.note ?? "recorded snapshot" };
  }
  if (!h) return { tone: "wait", label: "Live", note: "checking the API" };
  if (!h.ok) return { tone: "bad", label: "Live", note: h.note ?? "the API does not answer" };
  return { tone: "ok", label: "Live", note: [h.network, h.version ? `api ${h.version}` : null].filter(Boolean).join(" · ") };
});

function go() {
  const q = quick.value.trim();
  if (!q) return;
  void router.push({ name: "search", query: { q } });
  quick.value = "";
}
</script>

<template>
  <div class="shell">
    <a class="skip-link" href="#screen">Skip to content</a>
    <header class="bar">
      <RouterLink class="wordmark" to="/">Witness</RouterLink>
      <nav class="tabs" aria-label="Console">
        <RouterLink v-for="t in CONSOLE_TABS" :key="t.path" :to="t.link ?? t.path">{{ t.title }}</RouterLink>
      </nav>
      <form class="quick" role="search" @submit.prevent="go">
        <label class="sr-only" for="quick-q">Find a block, milestone, DID or IE</label>
        <input id="quick-q" v-model="quick" type="search" placeholder="Block id, milestone, DID or IE" autocomplete="off" spellcheck="false" />
      </form>
      <p class="status" :data-tone="status.tone" role="status" :title="status.note">
        <span class="dot" aria-hidden="true"></span>
        <span class="lbl">{{ status.label }}</span>
        <span class="note">{{ status.note }}</span>
      </p>
      <a class="source" :href="REPO_URL" rel="noopener">Source</a>
    </header>
    <main id="screen" class="screen" tabindex="-1">
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
  position: sticky;
  top: 0;
  z-index: 20;
  display: flex;
  align-items: center;
  gap: 28px;
  min-height: 60px;
  padding: 0 28px;
  border-bottom: 1px solid var(--hair);
  background: var(--void);
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
.quick {
  margin-left: auto;
  flex: 0 1 300px;
  min-width: 160px;
}
.quick input {
  width: 100%;
  height: 34px;
  padding: 0 16px;
  border-radius: var(--r-pill);
  border: 1px solid var(--hair);
  background: transparent;
  color: var(--fog-50);
  font: 400 14px var(--sans);
}
.quick input::placeholder {
  color: var(--fog-400);
}
.quick input:focus-visible {
  outline: none;
  border-color: var(--ember);
}
.status {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: 0;
  max-width: 300px;
  min-width: 0;
  font-size: 13px;
  color: var(--fog-200);
  white-space: nowrap;
}
.status .lbl {
  color: var(--fog-50);
}
.status .note {
  overflow: hidden;
  text-overflow: ellipsis;
  color: var(--fog-400);
}
.dot {
  flex: none;
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--fog-400);
}
.status[data-tone="ok"] .dot {
  background: var(--pass);
  box-shadow: 0 0 0 3px rgba(var(--rgb-aurora), 0.14);
}
.status[data-tone="replay"] .dot {
  background: transparent;
  border: 1.2px solid var(--fog-200);
}
.status[data-tone="bad"] .dot {
  background: var(--fail);
}
.status[data-tone="bad"] .note {
  color: var(--fail);
}
.status[data-tone="wait"] .dot {
  animation: pulse 1s ease-in-out infinite alternate;
}
@keyframes pulse {
  from {
    opacity: 0.3;
  }
  to {
    opacity: 1;
  }
}
.source {
  font-size: 14px;
  color: var(--fog-400);
  text-decoration: none;
}
.source:hover {
  color: var(--fog-50);
}
.screen {
  flex: 1;
  width: 100%;
  max-width: 1440px;
  margin: 0 auto;
  padding: 40px 28px 72px;
  outline: none;
}
@media (max-width: 1180px) {
  .quick {
    display: none;
  }
  .status {
    margin-left: auto;
  }
}
@media (max-width: 760px) {
  .bar {
    flex-wrap: wrap;
    gap: 0 16px;
    padding: 12px var(--gut) 0;
  }
  .status {
    max-width: none;
    flex: 1;
    justify-content: flex-end;
  }
  .status .note {
    max-width: 150px;
  }
  .source {
    display: none;
  }
  .tabs {
    order: 3;
    flex-basis: 100%;
    margin: 4px calc(-1 * var(--gut)) 0;
    padding: 0 var(--gut);
  }
  .tabs a {
    padding: 12px 0 11px;
  }
  .screen {
    padding: 28px var(--gut) 56px;
  }
}
</style>
