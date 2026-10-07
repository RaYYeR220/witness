<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";

import type { IeSummary } from "@/api/client";
import ConsoleShell from "@/components/ConsoleShell.vue";
import WitnessLineage from "@/components/WitnessLineage.vue";
import { useData } from "@/console/data";
import { score2 } from "@/console/format";

/**
 * Lineage: one Infrastructure Element's trust score as the ledger holds it,
 * next to Orion's current value. `/ie` opens the most recently active IE; the
 * picker switches between every IE the ledger has messages about. The chart
 * itself is WitnessLineage, the same component the Portal embeds.
 */
const route = useRoute();
const router = useRouter();
const data = useData();

const id = computed(() => (typeof route.params.id === "string" && route.params.id ? route.params.id : null));
const ies = ref<IeSummary[]>([]);
const iesError = ref<string | null>(null);
const iesLoaded = ref(false);

onMounted(async () => {
  try {
    ies.value = await data.ies();
  } catch (e) {
    iesError.value = e instanceof Error ? e.message : String(e);
  } finally {
    iesLoaded.value = true;
  }
});

// `/ie` alone: open the most recently active IE (only while still on /ie, not while leaving it)
watch([id, iesLoaded], ([current, loaded]) => {
  if (route.name === "lineage" && !current && loaded && ies.value[0]) void router.replace({ name: "lineage", params: { id: ies.value[0].ieId } });
});

const known = computed(() => (id.value && !ies.value.some((i) => i.ieId === id.value) ? [{ ieId: id.value } as IeSummary, ...ies.value] : ies.value));

function pick(ev: Event) {
  const v = (ev.target as HTMLSelectElement).value;
  if (v && v !== id.value) void router.push({ name: "lineage", params: { id: v } });
}

const verifyHref = (blockId: string) => router.resolve({ name: "verify", params: { blockId } }).href;
const navigate = (blockId: string) => void router.push({ name: "verify", params: { blockId } });
const incidentHref = (n: number) => router.resolve({ name: "integrity", query: { incident: String(n) } }).href;
const optionLabel = (i: IeSummary) =>
  i.count === undefined ? i.ieId : `${i.ieId}: ${i.count} ${i.count === 1 ? "message" : "messages"}${i.latestScore !== null ? `, last score ${score2(i.latestScore)}` : ""}`;
</script>

<template>
  <ConsoleShell>
    <div class="lineage">
      <header class="x-head">
        <div class="titles">
          <p class="x-kicker"><RouterLink to="/live">Live</RouterLink> <span aria-hidden="true">/</span> Lineage</p>
          <h1 class="x-title">Lineage</h1>
          <p class="x-lede">
            The trust score of one aeriOS Infrastructure Element as the ledger holds it, next to what Orion, the context broker aeriOS acts on, reports
            now. Each score opens in Verify, where your browser checks it.
          </p>
        </div>
        <div v-if="known.length" class="pick">
          <label for="ie-pick">Infrastructure Element</label>
          <select id="ie-pick" :value="id ?? ''" @change="pick">
            <option v-for="i in known" :key="i.ieId" :value="i.ieId">{{ optionLabel(i) }}</option>
          </select>
        </div>
      </header>

      <p v-if="id" class="which mono">{{ id }}</p>
      <WitnessLineage v-if="id" :key="id" class="body" :ie-id="id" :data="data" :verify-href="verifyHref" :navigate="navigate" :incident-href="incidentHref" />
      <p v-else-if="iesError" class="x-quiet x-err">Could not list the IEs: {{ iesError }}</p>
      <p v-else-if="iesLoaded" class="x-quiet">The ledger holds no message about any Infrastructure Element yet.</p>
      <p v-else class="x-quiet">Listing the IEs…</p>
    </div>
  </ConsoleShell>
</template>

<style scoped>
.titles {
  min-width: 0;
}
.pick {
  display: flex;
  flex-direction: column;
  gap: 6px;
  min-width: 0;
  max-width: 100%;
}
.pick label {
  font-size: 13px;
  color: var(--fog-400);
}
.pick select {
  max-width: 100%;
  height: 40px;
  padding: 0 14px;
  border-radius: var(--r-pill);
  border: 1px solid var(--hair-strong);
  background: var(--void-raised);
  color: var(--fog-50);
  font: 400 14px var(--sans);
}
.pick select:focus-visible {
  outline: none;
  border-color: var(--ember);
}
.which {
  margin: 22px 0 18px;
  font-size: 14px;
  color: var(--fog-50);
  overflow-wrap: anywhere;
}
</style>
