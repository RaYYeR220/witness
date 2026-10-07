<script setup lang="ts">
import { computed, ref, shallowRef, watch } from "vue";

import { DataError, LiveAdapter, type Lineage, type WitnessData } from "@/api/client";
import { isoOf, RECORDED_NOTE, score2, shortHex, utc, verdictInfo } from "@/console/format";
import SeverityTag from "@/console/SeverityTag.vue";
import VerdictMark from "@/console/VerdictMark.vue";
import LineageChart from "@/lineage/LineageChart.vue";
import { orionView, overlaysOf, seriesOf, type Overlay } from "@/lineage/model";

/**
 * The trust score lineage of one aeriOS Infrastructure Element: every score
 * the ledger holds for it, the latest one it vouches for, what Orion (the
 * context broker aeriOS acts on) says now, and the alerts and incidents about
 * the IE on the same time axis.
 *
 * Standalone: no router, no store. The console passes its data source and
 * link builders; an embedding page (the aeriOS Management Portal) passes only
 * `apiBase` and `ieId`, and optionally `verifyHref` to link each score to a
 * Witness console's Verify screen.
 */
type Source = Pick<WitnessData, "lineage" | "alerts" | "incidents">;

const props = withDefaults(
  defineProps<{
    ieId: string;
    /** Base URL of a witness-api, used when no `data` is given. */
    apiBase?: string;
    data?: Source;
    /** Where a message is verified; without it scores are not links. */
    verifyHref?: (blockId: string) => string;
    /** Follows a Verify link in place (a router) instead of loading the page. */
    navigate?: (blockId: string) => void;
    /** Where an incident is shown; without it incidents are not links. */
    incidentHref?: (id: number) => string;
    /** Newest entries drawn (the API's default and maximum is 1000 / 10000). */
    limit?: number;
  }>(),
  { apiBase: "/api", data: undefined, verifyHref: undefined, navigate: undefined, incidentHref: undefined, limit: 1000 },
);
const emit = defineEmits<{ select: [blockId: string] }>();

const source = computed<Source>(() => props.data ?? new LiveAdapter(props.apiBase));
const lineage = shallowRef<Lineage | null>(null);
const overlays = shallowRef<Overlay[]>([]);
const overlayNote = ref<string | null>(null);
const loading = ref(false);
const error = ref<string | null>(null);
const showAll = ref(false);
let generation = 0;

async function load() {
  const g = ++generation;
  const ie = props.ieId;
  loading.value = true;
  error.value = null;
  overlayNote.value = null;
  lineage.value = null;
  overlays.value = [];
  showAll.value = false;
  const src = source.value;
  const [lin, alerts, incidents] = await Promise.allSettled([src.lineage(ie, { limit: props.limit }), src.alerts({ ie, limit: 200 }), src.incidents({ ie })]);
  if (g !== generation) return;
  loading.value = false;
  if (lin.status === "rejected") {
    const e = lin.reason;
    error.value = e instanceof DataError && e.status === 404 ? `The ledger holds no messages about ${ie}.` : `Could not read the lineage: ${e instanceof Error ? e.message : String(e)}`;
    return;
  }
  if (lin.value.ieId !== ie) {
    error.value = `The explorer answered with the lineage of another IE (${lin.value.ieId}); it is not shown.`;
    return;
  }
  lineage.value = lin.value;
  overlays.value = overlaysOf(alerts.status === "fulfilled" ? alerts.value : [], incidents.status === "fulfilled" ? incidents.value : []);
  if (alerts.status === "rejected" || incidents.status === "rejected") overlayNote.value = "Alerts or incidents could not be read; the chart shows the scores only.";
}

watch(() => [props.ieId, source.value], () => void load(), { immediate: true });

const points = computed(() => (lineage.value ? seriesOf(lineage.value.entries) : []));
const orion = computed(() => (lineage.value ? orionView(lineage.value) : null));
const ledger = computed(() => lineage.value?.ledger ?? null);
const newestFirst = computed(() => [...(lineage.value?.entries ?? [])].reverse());
const ROWS = 12;
const rows = computed(() => (showAll.value ? newestFirst.value : newestFirst.value.slice(0, ROWS)));
const events = computed(() => [...overlays.value].reverse());
const chartLabel = computed(() => {
  const l = lineage.value;
  if (!l) return "";
  const parts = [`${points.value.length} trust scores of ${l.ieId} over time`];
  if (ledger.value) parts.push(`the ledger vouches for ${score2(ledger.value.score)} now`);
  parts.push(orion.value?.value !== null && orion.value?.value !== undefined ? `Orion reports ${score2(orion.value.value)}` : (orion.value?.headline ?? ""));
  const inc = overlays.value.filter((o) => o.kind === "incident").length;
  const al = overlays.value.length - inc;
  if (al || inc) parts.push(`${al} alerts and ${inc} incidents marked`);
  return `${parts.join("; ")}. The table below lists every score.`;
});

function follow(ev: MouseEvent, blockId: string) {
  if (!props.navigate || ev.defaultPrevented || ev.button !== 0 || ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey) return;
  ev.preventDefault();
  props.navigate(blockId);
}

function select(blockId: string) {
  emit("select", blockId);
  if (props.navigate) props.navigate(blockId);
  else if (props.verifyHref) window.location.assign(props.verifyHref(blockId));
}
</script>

<template>
  <section class="witness-lineage" :aria-busy="loading">
    <p v-if="loading" class="wl-quiet">Reading the lineage of {{ ieId }}…</p>
    <p v-else-if="error" class="wl-quiet wl-err" role="alert">{{ error }}</p>
    <template v-else-if="lineage && orion">
      <div class="wl-now">
        <div class="wl-cell">
          <p class="wl-lab">Latest score the ledger vouches for, per the explorer</p>
          <p v-if="ledger" class="wl-big">{{ score2(ledger.score) }}</p>
          <p v-else class="wl-state">No score yet</p>
          <p v-if="ledger" class="wl-sub">
            {{ verdictInfo(ledger.verdict).label.toLowerCase() }}, milestone {{ ledger.msIndex ?? "?" }}, {{ utc(ledger.atMs) }}.
            <a v-if="verifyHref" class="wl-link" :href="verifyHref(ledger.blockId)" @click="follow($event, ledger.blockId)">Verify it</a>
          </p>
          <p v-else class="wl-sub">No proven score for this IE: none producer-signed without an UNSIGNED or SHADOW alert.</p>
        </div>
        <div class="wl-cell wl-orion" :data-kind="orion.kind">
          <p class="wl-lab">Orion says now</p>
          <p v-if="orion.value !== null" class="wl-big">{{ score2(orion.value) }}</p>
          <p v-else class="wl-state">{{ orion.headline }}</p>
          <span v-if="orion.showDrift" class="drift-badge" :data-drift="orion.drift ? 'yes' : 'no'">{{ orion.drift ? "Drift" : "No drift" }}</span>
          <p class="wl-sub">{{ orion.detail }}</p>
        </div>
        <div class="wl-cell">
          <p class="wl-lab">On the ledger</p>
          <p class="wl-big">{{ lineage.total }}</p>
          <p class="wl-sub">
            {{ lineage.total === 1 ? "message" : "messages" }} about this IE<template v-if="lineage.entries.length < lineage.total"
              >; the newest {{ lineage.entries.length }} are drawn</template
            >.
          </p>
        </div>
      </div>

      <div class="wl-chart">
        <p v-if="!points.length" class="wl-quiet">No message about this IE carries a score.</p>
        <LineageChart v-else :points="points" :orion="orion" :overlays="overlays" :latest-block-id="ledger?.blockId ?? null" :label="chartLabel" @select="select" />
        <ul class="wl-legend" aria-label="Legend" :title="RECORDED_NOTE">
          <li><VerdictMark family="signed" />Signed, as recorded</li>
          <li><VerdictMark family="unsigned" />Unsigned legacy, as recorded</li>
          <li><VerdictMark family="rejected" />Rejected, as recorded (not on the line)</li>
          <li v-if="orion.value !== null"><span class="lg-orion" aria-hidden="true"></span>Orion now</li>
          <li><span class="lg-band" aria-hidden="true"></span>Incident</li>
          <li><span class="lg-dia" aria-hidden="true"></span>Alert</li>
        </ul>
        <p v-if="overlayNote" class="wl-sub">{{ overlayNote }}</p>
      </div>

      <div class="wl-cols">
        <section class="wl-entries" aria-labelledby="wl-entries-h">
          <h3 id="wl-entries-h" class="wl-h">Every score, newest first</h3>
          <table class="wl-tbl">
            <caption class="wl-sr">Messages about {{ lineage.ieId }}, newest first</caption>
            <thead>
              <tr>
                <th scope="col">Time (UTC)</th>
                <th scope="col" class="wl-num">Score</th>
                <th scope="col">Verdict recorded</th>
                <th scope="col" class="wl-num">Milestone</th>
                <th scope="col">Block</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="e in rows" :key="e.blockId" :data-f="verdictInfo(e.verdict).family">
                <td class="wl-nowrap">{{ utc(e.atMs) }}</td>
                <td class="wl-num wl-score">{{ e.score === null ? "–" : score2(e.score) }}</td>
                <td>
                  <span class="wl-v" :title="RECORDED_NOTE"
                    ><VerdictMark :family="verdictInfo(e.verdict).family" />{{ verdictInfo(e.verdict).label }}<span class="wl-sr">, recorded</span></span
                  >
                </td>
                <td class="wl-num">{{ e.msIndex ?? "pending" }}</td>
                <td>
                  <a v-if="verifyHref" class="wl-link wl-mono" :href="verifyHref(e.blockId)" @click="follow($event, e.blockId)"
                    >{{ shortHex(e.blockId, 8, 6) }}<span class="wl-sr">, verify</span></a
                  >
                  <span v-else class="wl-mono" :title="e.blockId">{{ shortHex(e.blockId, 8, 6) }}</span>
                </td>
              </tr>
            </tbody>
          </table>
          <button v-if="newestFirst.length > ROWS" type="button" class="wl-more" :aria-expanded="showAll" @click="showAll = !showAll">
            {{ showAll ? `Show the newest ${ROWS}` : `Show all ${newestFirst.length}` }}
          </button>
        </section>

        <section class="wl-events" aria-labelledby="wl-events-h">
          <h3 id="wl-events-h" class="wl-h">Alerts and incidents on this IE</h3>
          <p v-if="!events.length" class="wl-quiet">None recorded.</p>
          <ol v-else class="wl-evlist">
            <li v-for="o in events" :key="o.key" :data-kind="o.kind">
              <SeverityTag :severity="o.severity" />
              <span class="wl-evwhat">
                <template v-if="o.kind === 'incident'">
                  <a v-if="incidentHref" class="wl-link" :href="incidentHref(o.id)">Incident {{ o.id }}</a><template v-else>Incident {{ o.id }}</template
                  >: {{ o.label }}
                </template>
                <template v-else>
                  <b>{{ o.label }}</b>
                  <template v-if="o.blockId">
                    on
                    <a v-if="verifyHref" class="wl-link wl-mono" :href="verifyHref(o.blockId)" @click="follow($event, o.blockId!)">{{ shortHex(o.blockId) }}</a>
                    <span v-else class="wl-mono">{{ shortHex(o.blockId) }}</span>
                  </template>
                </template>
              </span>
              <time class="wl-evat" :datetime="isoOf(o.startMs) ?? undefined">{{ utc(o.startMs) }}</time>
            </li>
          </ol>
        </section>
      </div>
    </template>
  </section>
</template>

<style scoped>
.witness-lineage {
  color: var(--fog-200);
  font-family: var(--sans);
}
.wl-quiet {
  margin: 0;
  padding: 18px 0;
  color: var(--fog-400);
}
.wl-err {
  color: var(--fail);
}
.wl-now {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  border: 1px solid var(--hair);
  border-radius: var(--r-cell);
}
.wl-cell {
  padding: 16px 20px 18px;
  min-width: 0;
}
.wl-cell + .wl-cell {
  border-left: 1px solid var(--hair);
}
.wl-lab {
  margin: 0 0 8px;
  font-size: 13px;
  color: var(--fog-400);
}
.wl-big {
  margin: 0;
  font: 400 46px/1 var(--serif);
  letter-spacing: -0.01em;
  color: var(--fog-50);
  font-variant-numeric: tabular-nums;
}
.wl-state {
  margin: 0;
  font: 400 24px/1.15 var(--serif);
  color: var(--fog-50);
}
.wl-orion[data-kind="unreachable"] .wl-state {
  color: var(--ember);
}
.wl-sub {
  margin: 10px 0 0;
  font-size: 13px;
  line-height: 19px;
  color: var(--fog-400);
}
.drift-badge {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  margin-top: 10px;
  height: 24px;
  padding: 0 11px;
  border-radius: var(--r-pill);
  border: 1px solid var(--hair-strong);
  font-size: 12.5px;
  font-weight: 500;
  letter-spacing: 0.03em;
  color: var(--fog-200);
}
.drift-badge::before {
  content: "";
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: currentColor;
}
.drift-badge[data-drift="yes"] {
  border-color: rgba(var(--rgb-nova), 0.6);
  color: var(--fail);
}
.drift-badge[data-drift="yes"]::before {
  background: none;
  border: 1.4px solid currentColor;
}
.wl-link {
  color: var(--fog-50);
  text-decoration: underline;
  text-decoration-color: rgba(var(--rgb-ember), 0.6);
  text-underline-offset: 4px;
}
.wl-mono {
  font-family: var(--mono);
  font-size: 12px;
}
.wl-chart {
  margin-top: 26px;
}
.wl-legend {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 20px;
  margin: 12px 0 0;
  padding: 0;
  list-style: none;
  font-size: 12.5px;
  color: var(--fog-400);
}
.wl-legend li {
  display: inline-flex;
  align-items: center;
  gap: 8px;
}
.lg-orion {
  width: 18px;
  border-top: 1.4px dashed var(--fog-50);
}
.lg-band {
  width: 14px;
  height: 10px;
  background: rgba(var(--rgb-nova), 0.14);
  border-left: 1px solid rgba(var(--rgb-nova), 0.6);
}
.lg-dia {
  width: 7px;
  height: 7px;
  margin: 0 2px;
  transform: rotate(45deg);
  border: 1.2px solid var(--fail);
}
.wl-cols {
  display: grid;
  grid-template-columns: minmax(0, 1.5fr) minmax(0, 1fr);
  gap: 48px;
  margin-top: 36px;
}
.wl-h {
  margin: 0 0 12px;
  font: 400 22px/1.15 var(--serif);
  color: var(--fog-50);
}
.wl-tbl {
  width: 100%;
  border-collapse: collapse;
  font-size: 13.5px;
}
.wl-tbl th {
  padding: 0 14px 10px 0;
  text-align: left;
  font-weight: 400;
  font-size: 12.5px;
  color: var(--fog-400);
  border-bottom: 1px solid var(--hair-strong);
  white-space: nowrap;
}
.wl-tbl td {
  padding: 10px 14px 10px 0;
  border-bottom: 1px solid var(--hair);
  vertical-align: baseline;
}
.wl-num {
  text-align: right;
  font-variant-numeric: tabular-nums;
}
.wl-nowrap {
  white-space: nowrap;
}
.wl-score {
  font: 400 19px/1 var(--serif);
  color: var(--fog-50);
}
.wl-v {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  white-space: nowrap;
}
tr[data-f="rejected"] .wl-v {
  color: var(--fail);
}
.wl-more {
  margin-top: 12px;
  padding: 0;
  border: 0;
  background: none;
  cursor: pointer;
  font: inherit;
  font-size: 14px;
  color: var(--fog-200);
  text-decoration: underline;
  text-decoration-color: rgba(var(--rgb-fog-200), 0.35);
  text-underline-offset: 5px;
}
.wl-evlist {
  margin: 0;
  padding: 0;
  list-style: none;
}
.wl-evlist li {
  display: grid;
  grid-template-columns: 92px minmax(0, 1fr);
  gap: 2px 12px;
  padding: 10px 0;
  border-bottom: 1px solid var(--hair);
  font-size: 13.5px;
}
.wl-evwhat {
  min-width: 0;
  overflow-wrap: anywhere;
}
.wl-evwhat b {
  font-weight: 500;
  color: var(--fog-50);
}
.wl-evat {
  grid-column: 2;
  font-size: 12.5px;
  color: var(--fog-400);
}
.wl-sr {
  position: absolute;
  width: 1px;
  height: 1px;
  overflow: hidden;
  clip: rect(0 0 0 0);
  clip-path: inset(50%);
  white-space: nowrap;
}
@media (max-width: 980px) {
  .wl-cols {
    grid-template-columns: minmax(0, 1fr);
    gap: 32px;
  }
}
@media (max-width: 760px) {
  .wl-now {
    grid-template-columns: minmax(0, 1fr);
  }
  .wl-cell + .wl-cell {
    border-left: 0;
    border-top: 1px solid var(--hair);
  }
  .wl-big {
    font-size: 38px;
  }
  .wl-tbl th:nth-child(4),
  .wl-tbl td:nth-child(4) {
    display: none;
  }
  .wl-tbl td:first-child {
    white-space: normal;
    font-size: 12.5px;
  }
}
</style>
