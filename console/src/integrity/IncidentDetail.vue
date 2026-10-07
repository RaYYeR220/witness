<script setup lang="ts">
import { computed, ref, shallowRef, watch } from "vue";

import { DataError, type Alert, type IncidentDetail, type IncidentEvent, type WitnessData } from "@/api/client";
import { isBlockId, score2, shortHex, utc, verdictInfo } from "@/console/format";
import JsonText from "@/console/JsonText.vue";
import SeverityTag from "@/console/SeverityTag.vue";
import { RULES } from "@/console/severity";
import VerdictMark from "@/console/VerdictMark.vue";

import { alertReason, eventSummary, keyLabel, roleLabel, statusLine, TRUST, trustOf, type TrustLevel } from "./model";

/**
 * One incident: why it opened, how it stands or closed, and its timeline,
 * each event with the trust level the correlation engine gave it and a link
 * to verify its block. Events and alerts arrive a page at a time, with the
 * API's cursors.
 */
const props = withDefaults(defineProps<{ id: number; data: Pick<WitnessData, "incident">; pageSize?: number }>(), { pageSize: 50 });

const head = shallowRef<IncidentDetail | null>(null);
const events = shallowRef<IncidentEvent[]>([]);
const alerts = shallowRef<Alert[]>([]);
const nextEvents = ref<string | null>(null);
const nextAlerts = ref<number | null>(null);
const loading = ref(false);
const more = ref<"events" | "alerts" | null>(null);
const error = ref<string | null>(null);
let generation = 0;

async function load() {
  const g = ++generation;
  loading.value = true;
  error.value = null;
  head.value = null;
  events.value = [];
  alerts.value = [];
  try {
    const d = await props.data.incident(props.id, { limit: props.pageSize });
    if (g !== generation) return;
    if (d.id !== props.id) throw new DataError(`the explorer answered with incident ${d.id}`, null);
    head.value = d;
    events.value = d.events;
    alerts.value = d.alerts;
    nextEvents.value = d.nextEventsCursor;
    nextAlerts.value = d.nextAlertsAfter;
  } catch (e) {
    if (g === generation) error.value = e instanceof DataError && e.status === 404 ? `There is no incident ${props.id}.` : `Could not read incident ${props.id}: ${(e as Error).message}`;
  } finally {
    if (g === generation) loading.value = false;
  }
}

async function loadMore(kind: "events" | "alerts") {
  if (more.value) return;
  const g = generation;
  more.value = kind;
  try {
    const page =
      kind === "events"
        ? await props.data.incident(props.id, { limit: props.pageSize, eventsAfter: nextEvents.value ?? undefined })
        : await props.data.incident(props.id, { limit: props.pageSize, alertsAfter: nextAlerts.value ?? undefined });
    if (g !== generation) return;
    if (kind === "events") {
      events.value = [...events.value, ...page.events];
      nextEvents.value = page.nextEventsCursor;
    } else {
      alerts.value = [...alerts.value, ...page.alerts];
      nextAlerts.value = page.nextAlertsAfter;
    }
  } catch (e) {
    if (g === generation) error.value = `Could not read more: ${(e as Error).message}`;
  } finally {
    more.value = null;
  }
}

watch(() => props.id, () => void load(), { immediate: true });

const status = computed(() => (head.value ? statusLine(head.value) : null));
/** The event that opened it: the trigger, else the first event. */
const opener = computed(() => events.value.find((e) => e.role === "trigger") ?? events.value[0] ?? null);
const FAMILY: Record<TrustLevel, "signed" | "unsigned" | "rejected" | "unknown"> = { proven: "signed", relayed: "unsigned", untrusted: "rejected", unknown: "unknown" };
</script>

<template>
  <article class="inc" :aria-busy="loading" aria-labelledby="inc-h">
    <p v-if="loading" class="x-quiet">Reading incident {{ id }}…</p>
    <p v-else-if="error && !head" class="x-quiet x-err" role="alert">{{ error }}</p>
    <template v-if="head && status">
      <header>
        <p class="inc-kick">
          <SeverityTag :severity="head.severity" /> <span class="inc-n">Incident {{ head.id }}</span>
          <span class="inc-status" :data-tone="status.tone">{{ status.label }}</span>
        </p>
        <h3 id="inc-h" class="inc-title">{{ head.title }}</h3>
        <p class="inc-line">{{ status.text }}</p>
      </header>

      <dl class="x-kv inc-facts">
        <div>
          <dt>Why it opened</dt>
          <dd>
            <template v-if="opener">
              {{ eventSummary(opener) }}, {{ TRUST[trustOf(opener)].label.toLowerCase() }}, at {{ utc(opener.atMs) }}<template v-if="isBlockId(opener.blockId)"
                >, block
                <RouterLink class="x-link mono" :to="{ name: 'verify', params: { blockId: opener.blockId } }">{{ shortHex(opener.blockId) }}</RouterLink></template
              >.
            </template>
            <template v-else>No event of this incident is on record.</template>
          </dd>
        </div>
        <div v-if="head.status === 'closed:recovered' && isBlockId(head.closedBy)">
          <dt>Closed by</dt>
          <dd>
            the proven trust score in block
            <RouterLink class="x-link mono" :to="{ name: 'verify', params: { blockId: head.closedBy } }">{{ shortHex(head.closedBy) }}</RouterLink>
          </dd>
        </div>
        <div>
          <dt>Correlated on</dt>
          <dd>{{ head.keys.length ? head.keys.map(keyLabel).join(", ") : "nothing recorded" }}</dd>
        </div>
        <div v-if="head.baselineScore !== null || head.lowScore !== null">
          <dt>Trust score</dt>
          <dd>
            <template v-if="head.baselineScore !== null">{{ score2(head.baselineScore) }} before the incident (the recovery target)</template
            ><template v-if="head.baselineScore !== null && head.lowScore !== null">; </template
            ><template v-if="head.lowScore !== null">lowest proven score since: {{ score2(head.lowScore) }}</template>
          </dd>
        </div>
        <div v-if="head.ieId">
          <dt>IE</dt>
          <dd>
            <RouterLink class="x-link mono" :to="{ name: 'lineage', params: { id: head.ieId } }">{{ head.ieId }}</RouterLink>
          </dd>
        </div>
      </dl>

      <section class="inc-sec" aria-labelledby="inc-tl-h">
        <h4 id="inc-tl-h" class="inc-h">Timeline <span class="x-muted">{{ events.length }} of {{ head.eventsTotal }}</span></h4>
        <ol class="tl">
          <li v-for="e in events" :key="`${e.blockId}-${e.role}-${e.atMs}`" class="ev" :data-trust="trustOf(e)">
            <span class="ev-mark" :title="TRUST[trustOf(e)].gloss"><VerdictMark :family="FAMILY[trustOf(e)]" /></span>
            <div class="ev-body">
              <p class="ev-top">
                <span class="ev-role">{{ roleLabel(e.role) }}</span>
                <span class="ev-trust" :data-trust="trustOf(e)">{{ TRUST[trustOf(e)].label }}</span>
                <time class="ev-at">{{ utc(e.atMs) }}</time>
              </p>
              <p class="ev-what">
                {{ eventSummary(e) }}<template v-if="e.verdict">, recorded {{ verdictInfo(e.verdict).label.toLowerCase() }}</template
                ><template v-if="e.status">, {{ e.status.toLowerCase().replaceAll("_", " ") }}</template
                ><template v-if="e.msIndex !== null">, milestone {{ e.msIndex }}</template>.
              </p>
              <p class="ev-blk">
                <RouterLink v-if="isBlockId(e.blockId) && e.indexed" class="x-link mono" :to="{ name: 'verify', params: { blockId: e.blockId } }"
                  >{{ shortHex(e.blockId, 8, 6) }}<span class="sr-only">, verify this block</span></RouterLink
                >
                <span v-else class="mono x-muted" :title="e.blockId">{{ shortHex(e.blockId, 8, 6) }} (not in the explorer's records)</span>
              </p>
              <details class="ev-detail">
                <summary>What the engine saw</summary>
                <p class="ev-gloss">{{ TRUST[trustOf(e)].gloss }}</p>
                <JsonText :value="e.detail" />
              </details>
            </div>
          </li>
        </ol>
        <button v-if="nextEvents" type="button" class="btn more" :disabled="more !== null" @click="loadMore('events')">
          {{ more === "events" ? "Loading…" : `Show more events (${events.length} of ${head.eventsTotal})` }}
        </button>
      </section>

      <section class="inc-sec" aria-labelledby="inc-al-h">
        <h4 id="inc-al-h" class="inc-h">Alerts that joined it <span class="x-muted">{{ alerts.length }} of {{ head.alertsTotal }}</span></h4>
        <p v-if="!alerts.length" class="x-quiet">None.</p>
        <ul v-else class="al">
          <li v-for="a in alerts" :key="a.id">
            <SeverityTag :severity="a.severity" />
            <span class="al-what">
              <b :title="RULES[a.rule]">{{ a.rule }}</b>
              <template v-if="isBlockId(a.blockId)">
                on <RouterLink class="x-link mono" :to="{ name: 'verify', params: { blockId: a.blockId } }">{{ shortHex(a.blockId) }}</RouterLink>
              </template>
              <span v-if="alertReason(a)" class="al-reason">{{ alertReason(a) }}</span>
            </span>
            <time class="al-at">{{ utc(a.atMs) }}</time>
          </li>
        </ul>
        <button v-if="nextAlerts !== null" type="button" class="btn more" :disabled="more !== null" @click="loadMore('alerts')">
          {{ more === "alerts" ? "Loading…" : `Show more alerts (${alerts.length} of ${head.alertsTotal})` }}
        </button>
      </section>
      <p v-if="error" class="x-note" data-tone="bad" role="alert">{{ error }}</p>
    </template>
  </article>
</template>

<style scoped>
.inc-kick {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px 14px;
  margin: 0;
  font-size: 13px;
  color: var(--fog-400);
}
.inc-n {
  color: var(--fog-200);
}
.inc-status {
  padding: 1px 10px;
  border-radius: var(--r-pill);
  border: 1px solid var(--hair-strong);
  color: var(--fog-200);
}
.inc-status[data-tone="open"] {
  border-color: rgba(var(--rgb-nova), 0.55);
  color: var(--fail);
}
.inc-status[data-tone="closed"] {
  border-color: rgba(var(--rgb-aurora), 0.45);
  color: var(--pass);
}
.inc-title {
  margin: 10px 0 0;
  font: 400 26px/1.15 var(--serif);
  color: var(--fog-50);
  overflow-wrap: anywhere;
}
.inc-line {
  margin: 8px 0 0;
  font-size: 14px;
  color: var(--fog-200);
}
.inc-facts {
  margin-top: 18px;
  padding: 14px 0;
  border-top: 1px solid var(--hair);
  border-bottom: 1px solid var(--hair);
}
.inc-sec {
  margin-top: 24px;
}
.inc-h {
  margin: 0 0 10px;
  font: 400 15px/1.3 var(--sans);
  color: var(--fog-50);
}
.inc-h .x-muted {
  margin-left: 6px;
  font-size: 13px;
}
.tl {
  margin: 0;
  padding: 0;
  list-style: none;
}
.ev {
  position: relative;
  display: grid;
  grid-template-columns: 18px minmax(0, 1fr);
  gap: 12px;
  padding: 0 0 16px;
}
.ev::before {
  content: "";
  position: absolute;
  left: 5px;
  top: 16px;
  bottom: 0;
  border-left: 1px solid var(--hair-strong);
}
.ev:last-child::before {
  display: none;
}
.ev-mark {
  display: flex;
  padding-top: 5px;
}
.ev-top {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: 4px 12px;
  margin: 0;
}
.ev-role {
  font-size: 14px;
  color: var(--fog-50);
}
.ev-trust {
  font-size: 12px;
  padding: 0 8px;
  border-radius: var(--r-pill);
  border: 1px solid var(--hair-strong);
  color: var(--fog-200);
}
.ev-trust[data-trust="proven"] {
  border-color: rgba(var(--rgb-aurora), 0.45);
  color: var(--pass);
}
.ev-trust[data-trust="untrusted"] {
  border-color: rgba(var(--rgb-nova), 0.5);
  color: var(--fail);
}
.ev-at {
  margin-left: auto;
  font-size: 12.5px;
  color: var(--fog-400);
  font-variant-numeric: tabular-nums;
}
.ev-what {
  margin: 4px 0 0;
  font-size: 13.5px;
  color: var(--fog-200);
}
.ev-blk {
  margin: 2px 0 0;
}
.ev-detail {
  margin-top: 6px;
}
.ev-detail summary {
  cursor: pointer;
  font-size: 12.5px;
  color: var(--fog-400);
}
.ev-gloss {
  margin: 6px 0;
  font-size: 12.5px;
  color: var(--fog-400);
}
.al {
  margin: 0;
  padding: 0;
  list-style: none;
}
.al li {
  display: grid;
  grid-template-columns: 92px minmax(0, 1fr) auto;
  gap: 4px 12px;
  align-items: baseline;
  padding: 9px 0;
  border-bottom: 1px solid var(--hair);
  font-size: 13.5px;
}
.al-what b {
  font-weight: 500;
  color: var(--fog-50);
}
.al-reason {
  display: block;
  font-size: 12.5px;
  color: var(--fog-400);
  overflow-wrap: anywhere;
}
.al-at {
  font-size: 12.5px;
  color: var(--fog-400);
  white-space: nowrap;
}
.more {
  height: 36px;
  margin-top: 8px;
  font-size: 14px;
}
@media (max-width: 760px) {
  .al li {
    grid-template-columns: 84px minmax(0, 1fr);
  }
  .al-at {
    grid-column: 2;
  }
  .ev-at {
    margin-left: 0;
    flex-basis: 100%;
  }
}
</style>
