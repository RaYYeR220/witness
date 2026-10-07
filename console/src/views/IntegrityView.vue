<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";

import type { Alert, Incident, Scorecard } from "@/api/client";
import ConsoleShell from "@/components/ConsoleShell.vue";
import { useData } from "@/console/data";
import { isBlockId, shortHex, utc } from "@/console/format";
import JsonText from "@/console/JsonText.vue";
import SeverityTag from "@/console/SeverityTag.vue";
import { RULES, SEVERITIES, severityLabel } from "@/console/severity";
import IncidentDetail from "@/integrity/IncidentDetail.vue";
import { alertReason, statusLine } from "@/integrity/model";
import ScorecardCard from "@/integrity/ScorecardCard.vue";

/**
 * Integrity: the evaluation scorecard (when one is published), the incidents
 * the correlation engine opened with one in detail, and the alerts the rules
 * raised, filterable by severity and rule. Filters and the open incident live
 * in the URL. Evidence is untrusted and shown as text.
 */
const route = useRoute();
const router = useRouter();
const data = useData();

// ---------------------------------------------------------------- scorecard
const card = ref<Scorecard | null>(null);
const cardError = ref<string | null>(null);
const cardLoading = ref(true);

// ---------------------------------------------------------------- incidents
const incidents = ref<Incident[]>([]);
const incError = ref<string | null>(null);
const incLoaded = ref(false);

onMounted(() => {
  data
    .scorecard()
    .then((c) => (card.value = c))
    .catch((e: Error) => (cardError.value = `The published scorecard could not be read: ${e.message}`))
    .finally(() => (cardLoading.value = false));
  data
    .incidents({ limit: 200 })
    .then((items) => (incidents.value = items))
    .catch((e: Error) => (incError.value = e.message))
    .finally(() => (incLoaded.value = true));
});

const asked = computed(() => {
  const n = Number(route.query.incident);
  return Number.isSafeInteger(n) && n > 0 ? n : null;
});
/** The incident in the URL, else the newest open one, else the newest. */
const selected = computed(() => asked.value ?? (incidents.value.find((i) => i.status === "open") ?? incidents.value[0])?.id ?? null);
const openCount = computed(() => incidents.value.filter((i) => i.status === "open").length);

// ---------------------------------------------------------------- alerts
const severity = computed(() => {
  const s = route.query.severity;
  return typeof s === "string" && (SEVERITIES as readonly string[]).includes(s) ? s : "";
});
const rule = computed(() => {
  const r = route.query.rule;
  return typeof r === "string" && /^[A-Z][A-Z0-9_]{0,63}$/.test(r) ? r : "";
});
/** Alerts asked for: 50 first, then 200, then the API's maximum of 500. */
const STEPS = [50, 200, 500];
const limit = ref(STEPS[0]!);
const alerts = ref<Alert[]>([]);
const alertsBusy = ref(false);
const alertsError = ref<string | null>(null);
let generation = 0;

async function loadAlerts() {
  const g = ++generation;
  alertsBusy.value = true;
  alertsError.value = null;
  try {
    const items = await data.alerts({ severity: severity.value || undefined, rule: rule.value || undefined, limit: limit.value });
    if (g === generation) alerts.value = items;
  } catch (e) {
    if (g === generation) alertsError.value = (e as Error).message;
  } finally {
    if (g === generation) alertsBusy.value = false;
  }
}
watch([severity, rule, limit], () => void loadAlerts(), { immediate: true });

function filter(patch: Record<string, string>) {
  const query: Record<string, string> = {};
  for (const [k, v] of Object.entries({ ...route.query, ...patch })) if (typeof v === "string" && v) query[k] = v;
  limit.value = STEPS[0]!;
  void router.replace({ query });
}

const rules = computed(() => [...new Set([...Object.keys(RULES), ...alerts.value.map((a) => a.rule), rule.value].filter((r) => r))].sort());
const nextLimit = computed(() => STEPS.find((n) => n > limit.value) ?? null);
const canMore = computed(() => alerts.value.length >= limit.value && nextLimit.value !== null);
const incidentTo = (id: number) => ({ name: "integrity", query: { ...route.query, incident: String(id) } });
</script>

<template>
  <ConsoleShell>
    <div class="integrity">
      <header class="x-head">
        <div>
          <h1 class="x-title">Integrity</h1>
          <p class="x-lede">
            What the integrity rules caught, the incidents the correlation engine grouped it into, and how detection held up when this stack was
            attacked on purpose. Every block named here opens in Verify, where your browser checks it.
          </p>
        </div>
      </header>

      <ScorecardCard class="x-sec" :card="card" :error="cardError" :loading="cardLoading" :source="data.scorecardSource" />

      <section class="x-sec" aria-labelledby="incs-h">
        <div class="x-sec-head">
          <h2 id="incs-h" class="x-sec-title">Incidents</h2>
          <p class="x-sec-note">{{ incidents.length }} in all, {{ openCount }} open; newest first</p>
        </div>
        <p v-if="incError" class="x-quiet x-err">Could not list incidents: {{ incError }}</p>
        <p v-else-if="incLoaded && !incidents.length" class="x-quiet">No incident so far. Alerts that do not add up to one are listed below.</p>
        <div v-else class="incs">
          <ol class="inc-list" aria-label="Incidents">
            <li v-for="i in incidents" :key="i.id">
              <RouterLink :to="incidentTo(i.id)" class="inc-row" :aria-current="i.id === selected ? 'true' : undefined" replace>
                <span class="row1">
                  <SeverityTag :severity="i.severity" />
                  <span class="st" :data-tone="statusLine(i).tone">{{ statusLine(i).label }}</span>
                  <span class="num">{{ i.id }}</span>
                </span>
                <span class="ttl">{{ i.title }}</span>
                <span class="meta">opened {{ utc(i.openedAtMs) }}<template v-if="i.ieId">, {{ i.ieId }}</template></span>
              </RouterLink>
            </li>
          </ol>
          <div class="inc-pane">
            <IncidentDetail v-if="selected !== null" :id="selected" :data="data" />
          </div>
        </div>
      </section>

      <section class="x-sec" aria-labelledby="alerts-h">
        <div class="x-sec-head">
          <h2 id="alerts-h" class="x-sec-title">Alerts</h2>
          <p class="x-sec-note" aria-live="polite">{{ alertsBusy ? "Reading…" : `${alerts.length} shown, newest first` }}</p>
        </div>
        <div class="filters">
          <div class="sev" role="group" aria-label="Severity">
            <button type="button" class="chip" :aria-pressed="severity === ''" @click="filter({ severity: '' })">All</button>
            <button v-for="s in SEVERITIES" :key="s" type="button" class="chip" :aria-pressed="severity === s" @click="filter({ severity: s })">
              {{ severityLabel(s) }}
            </button>
          </div>
          <label class="rule">
            <span>Rule</span>
            <select :value="rule" @change="filter({ rule: ($event.target as HTMLSelectElement).value })">
              <option value="">All rules</option>
              <option v-for="r in rules" :key="r" :value="r">{{ r }}</option>
            </select>
          </label>
        </div>
        <p v-if="rule && RULES[rule]" class="x-sec-note rule-gloss">{{ rule }}: {{ RULES[rule] }}</p>
        <p v-if="alertsError" class="x-quiet x-err">Could not list alerts: {{ alertsError }}</p>
        <p v-else-if="!alertsBusy && !alerts.length" class="x-quiet">No alert matches.</p>
        <ol v-else class="alerts" :aria-busy="alertsBusy">
          <li v-for="a in alerts" :key="a.id" class="alert">
            <SeverityTag :severity="a.severity" class="a-sev" />
            <span class="a-what">
              <b :title="RULES[a.rule]">{{ a.rule }}</b>
              <span v-if="alertReason(a)" class="a-reason">{{ alertReason(a) }}</span>
            </span>
            <span class="a-blk">
              <RouterLink v-if="isBlockId(a.blockId)" class="x-link mono" :to="{ name: 'verify', params: { blockId: a.blockId } }"
                >{{ shortHex(a.blockId) }}<span class="sr-only">, verify</span></RouterLink
              >
              <span v-else class="x-muted">no block</span>
            </span>
            <span class="a-ie">
              <RouterLink v-if="a.ieId" class="x-link mono" :to="{ name: 'lineage', params: { id: a.ieId } }">{{ a.ieId }}</RouterLink>
            </span>
            <time class="a-at">{{ utc(a.atMs) }}</time>
            <details class="a-ev">
              <summary>Evidence</summary>
              <JsonText :value="a.evidence" />
            </details>
          </li>
        </ol>
        <button v-if="canMore && nextLimit" type="button" class="btn more" :disabled="alertsBusy" @click="limit = nextLimit">Show up to {{ nextLimit }}</button>
      </section>
    </div>
  </ConsoleShell>
</template>

<style scoped>
.incs {
  display: grid;
  grid-template-columns: minmax(0, 400px) minmax(0, 1fr);
  gap: 40px;
  align-items: start;
}
.inc-list {
  margin: 0;
  padding: 0;
  list-style: none;
  border-top: 1px solid var(--hair);
}
.inc-row {
  display: grid;
  gap: 4px;
  padding: 12px 12px 12px 14px;
  border-bottom: 1px solid var(--hair);
  border-left: 2px solid transparent;
  color: inherit;
  text-decoration: none;
  transition: background var(--t-quick);
}
.inc-row:hover {
  background: rgba(var(--rgb-fog-50), 0.03);
}
.inc-row[aria-current="true"] {
  border-left-color: var(--ember);
  background: rgba(var(--rgb-fog-50), 0.035);
}
.row1 {
  display: flex;
  align-items: center;
  gap: 12px;
}
.st {
  font-size: 12px;
  padding: 0 8px;
  border-radius: var(--r-pill);
  border: 1px solid var(--hair-strong);
  color: var(--fog-200);
}
.st[data-tone="open"] {
  border-color: rgba(var(--rgb-nova), 0.5);
  color: var(--fail);
}
.st[data-tone="closed"] {
  border-color: var(--hair-strong);
  color: var(--fog-200);
}
.row1 .num {
  margin-left: auto;
  font-size: 12.5px;
  color: var(--fog-400);
}
.row1 .num::before {
  content: "#";
}
.ttl {
  font-size: 14px;
  color: var(--fog-50);
  overflow-wrap: anywhere;
}
.meta {
  font-size: 12.5px;
  color: var(--fog-400);
  overflow-wrap: anywhere;
}
.inc-pane {
  min-width: 0;
  padding-left: 40px;
  border-left: 1px solid var(--hair);
}
.filters {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 12px 24px;
}
.sev {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.chip {
  height: 32px;
  padding: 0 14px;
  border-radius: var(--r-pill);
  border: 1px solid var(--hair-strong);
  background: none;
  color: var(--fog-200);
  font-size: 13px;
  cursor: pointer;
}
.chip:hover {
  border-color: var(--fog-200);
}
.chip[aria-pressed="true"] {
  border-color: var(--fog-50);
  background: var(--fog-50);
  color: var(--void);
}
.rule {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 13px;
  color: var(--fog-400);
}
.rule select {
  height: 34px;
  padding: 0 12px;
  border-radius: var(--r-pill);
  border: 1px solid var(--hair-strong);
  background: var(--void-raised);
  color: var(--fog-50);
  font: 400 13px var(--sans);
}
.rule-gloss {
  margin-top: 10px;
}
.alerts {
  margin: 14px 0 0;
  padding: 0;
  list-style: none;
  border-top: 1px solid var(--hair-strong);
}
.alert {
  display: grid;
  grid-template-columns: 96px minmax(0, 1fr) 128px minmax(0, 210px) 186px;
  gap: 4px 16px;
  align-items: baseline;
  padding: 11px 0;
  border-bottom: 1px solid var(--hair);
  font-size: 13.5px;
}
.a-what b {
  font-weight: 500;
  color: var(--fog-50);
}
.a-reason {
  display: block;
  font-size: 12.5px;
  color: var(--fog-400);
  overflow-wrap: anywhere;
}
.a-ie {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.a-at {
  font-size: 12.5px;
  color: var(--fog-400);
  text-align: right;
  white-space: nowrap;
  font-variant-numeric: tabular-nums;
}
.a-ev {
  grid-column: 2 / -1;
}
.a-ev summary {
  cursor: pointer;
  font-size: 12.5px;
  color: var(--fog-400);
}
.a-ev[open] summary {
  margin-bottom: 6px;
}
.more {
  height: 38px;
  margin-top: 16px;
  font-size: 14px;
}
@media (max-width: 1180px) {
  .incs {
    grid-template-columns: minmax(0, 1fr);
    gap: 28px;
  }
  .inc-pane {
    padding-left: 0;
    border-left: 0;
  }
  .alert {
    grid-template-columns: 96px minmax(0, 1fr) 128px 186px;
  }
  .a-ie {
    display: none;
  }
}
@media (max-width: 760px) {
  .alert {
    grid-template-columns: minmax(0, 1fr) auto;
  }
  .a-sev {
    grid-column: 1;
  }
  .a-at {
    grid-column: 2;
    grid-row: 1;
  }
  .a-what,
  .a-blk,
  .a-ev {
    grid-column: 1 / -1;
  }
  .rule {
    width: 100%;
  }
  .rule select {
    flex: 1;
    min-width: 0;
  }
}
</style>
