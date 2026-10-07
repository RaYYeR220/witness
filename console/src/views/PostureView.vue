<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, shallowRef } from "vue";

import type { Posture, Stats } from "@/api/client";
import ConsoleShell from "@/components/ConsoleShell.vue";
import { useData } from "@/console/data";
import { ago, utc } from "@/console/format";
import JsonText from "@/console/JsonText.vue";
import SeverityTag from "@/console/SeverityTag.vue";
import { severityRank } from "@/console/severity";

/**
 * Posture: the last security scan of the node this explorer watches, as the
 * API cached it. Each finding comes with what the scan observed and how to
 * fix it. Scans run on the server, started by the operator with a token;
 * this console only reads the result. Next to it, the explorer's own
 * components as `GET /stats` reports them.
 */
const data = useData();

const posture = shallowRef<Posture | null>(null);
const error = ref<string | null>(null);
const stats = shallowRef<Stats | null>(null);
const statsError = ref<string | null>(null);
const now = ref(Date.now());
let tick: ReturnType<typeof setInterval> | null = null;

onMounted(async () => {
  tick = setInterval(() => (now.value = Date.now()), 15_000);
  data
    .stats()
    .then((s) => (stats.value = s))
    .catch((e: Error) => (statsError.value = e.message));
  try {
    posture.value = await data.posture();
  } catch (e) {
    error.value = (e as Error).message;
  }
});
onBeforeUnmount(() => tick && clearInterval(tick));

const findings = computed(() => [...(posture.value?.findings ?? [])].sort((a, b) => severityRank(a.severity) - severityRank(b.severity)));
const summary = computed(() =>
  Object.entries(posture.value?.summary ?? {})
    .filter(([, n]) => typeof n === "number")
    .sort(([a], [b]) => severityRank(a) - severityRank(b)),
);

const GOOD = new Set(["ok", "on", "file", "running"]);
const BAD = new Set(["unreachable", "error", "stalled", "mismatch", "unverifiable", "failed", "degraded"]);
const services = computed(() => Object.entries(stats.value?.services ?? {}).sort(([a], [b]) => a.localeCompare(b)));
const tone = (v: string) => (GOOD.has(v) ? "ok" : BAD.has(v) ? "bad" : "other");
</script>

<template>
  <ConsoleShell>
    <div class="posture">
      <header class="x-head">
        <div>
          <h1 class="x-title">Posture</h1>
          <p class="x-lede">
            The last security scan of the IOTA node this explorer watches: what it found, the evidence, and how to fix each finding. The scan runs
            on the server, started by the operator; this console only shows its result and cannot start one.
          </p>
        </div>
      </header>

      <p v-if="error" class="x-quiet x-err">Could not read the last scan: {{ error }}</p>
      <p v-else-if="!posture" class="x-quiet">Reading the last scan…</p>
      <template v-else>
        <section class="x-sec scan" aria-labelledby="scan-h">
          <h2 id="scan-h" class="sr-only">The last scan</h2>
          <div class="when">
            <p class="lab">Last scan</p>
            <p v-if="posture.scannedAtMs !== null" class="big">{{ ago(posture.scannedAtMs, now) }}</p>
            <p v-else class="big">None yet</p>
            <p class="x-sec-note">
              <template v-if="posture.scannedAtMs !== null">{{ utc(posture.scannedAtMs) }}, {{ posture.active ? "with active probes" : "passive" }}</template>
              <template v-else>No scan has run on this server yet.</template>
            </p>
          </div>
          <dl v-if="summary.length" class="counts">
            <div v-for="[s, n] in summary" :key="s">
              <dt><SeverityTag :severity="s" /></dt>
              <dd>{{ n }}</dd>
            </div>
          </dl>
          <p class="how x-sec-note">
            Scans run server-side by the operator (<span class="mono">POST /posture/scan</span> with the operator's token). Passive by default:
            only reads, never a write or a login; active probes run only against the operator's own node.
          </p>
        </section>

        <section class="x-sec" aria-labelledby="find-h">
          <div class="x-sec-head">
            <h2 id="find-h" class="x-sec-title">Findings</h2>
            <p v-if="findings.length" class="x-sec-note">most severe first</p>
          </div>
          <p v-if="posture.scannedAtMs === null" class="x-quiet">Findings appear here once the operator has run a scan.</p>
          <p v-else-if="!findings.length" class="x-note" data-tone="ok"><b>Nothing to fix.</b> The last scan found no weakness.</p>
          <ol v-else class="finds">
            <li v-for="f in findings" :key="f.id" class="find">
              <div class="f-head">
                <SeverityTag :severity="f.severity" />
                <h3 class="f-title">{{ f.title }}</h3>
                <span class="mono x-muted f-id">{{ f.id }}</span>
              </div>
              <div class="f-body">
                <div>
                  <p class="lab">How to fix it</p>
                  <p class="fix">{{ f.fix }}</p>
                </div>
                <div>
                  <p class="lab">What the scan saw</p>
                  <JsonText :value="f.evidence" />
                </div>
              </div>
            </li>
          </ol>
        </section>
      </template>

      <section class="x-sec" aria-labelledby="svc-h">
        <div class="x-sec-head">
          <h2 id="svc-h" class="x-sec-title">The explorer's own components</h2>
          <p class="x-sec-note">as <span class="mono">GET /stats</span> reports them</p>
        </div>
        <p v-if="statsError" class="x-quiet x-err">Could not read the component statuses: {{ statsError }}</p>
        <p v-else-if="!stats" class="x-quiet">Reading…</p>
        <template v-else>
          <p v-if="!services.length" class="x-quiet">This API version does not report component statuses.</p>
          <ul v-else class="svcs">
            <li v-for="[name, v] in services" :key="name" :data-tone="tone(v)">
              <span class="dot" aria-hidden="true"></span>
              <span class="sn">{{ name }}</span>
              <span class="sv">{{ v }}</span>
            </li>
          </ul>
          <dl class="x-kv sys">
            <div>
              <dt>Validator</dt>
              <dd>
                {{ stats.validator.configured ? (stats.validator.running ? "running in the API" : "configured, not running in the API") : "not configured" }}<template
                  v-if="stats.validator.pending"
                  >, {{ stats.validator.pending }} pending</template
                >
              </dd>
            </div>
            <div>
              <dt>Node route</dt>
              <dd>
                <template v-if="!stats.nodeRoute.enabled">not mounted on the node</template>
                <template v-else>
                  <span class="mono">{{ stats.nodeRoute.route }}</span>
                  {{ stats.nodeRoute.registered ? "registered on the node" : `not registered${stats.nodeRoute.error ? ` (${stats.nodeRoute.error})` : ""}` }}
                </template>
              </dd>
            </div>
            <div v-if="typeof stats.counts.cursor === 'number'">
              <dt>Indexed up to</dt>
              <dd>milestone {{ stats.counts.cursor }}</dd>
            </div>
          </dl>
        </template>
      </section>
    </div>
  </ConsoleShell>
</template>

<style scoped>
.scan {
  display: grid;
  grid-template-columns: minmax(0, 260px) minmax(0, 1fr);
  gap: 18px 40px;
  align-items: end;
}
.lab {
  margin: 0 0 6px;
  font-size: 13px;
  color: var(--fog-400);
}
.big {
  margin: 0 0 6px;
  font: 400 40px/1 var(--serif);
  color: var(--fog-50);
}
.counts {
  display: flex;
  flex-wrap: wrap;
  gap: 12px 36px;
  margin: 0;
}
.counts dd {
  margin: 4px 0 0;
  font: 400 32px/1 var(--serif);
  color: var(--fog-50);
}
.how {
  grid-column: 1 / -1;
  max-width: 80ch;
  padding-top: 14px;
  border-top: 1px solid var(--hair);
}
.finds {
  margin: 0;
  padding: 0;
  list-style: none;
}
.find {
  padding: 16px 0 20px;
  border-bottom: 1px solid var(--hair);
}
.f-head {
  display: flex;
  align-items: baseline;
  flex-wrap: wrap;
  gap: 6px 16px;
}
.f-title {
  margin: 0;
  font: 400 22px/1.2 var(--serif);
  color: var(--fog-50);
}
.f-id {
  margin-left: auto;
}
.f-body {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 24px;
  margin-top: 12px;
}
.fix {
  margin: 0;
  padding-left: 12px;
  border-left: 2px solid var(--ember);
  color: var(--fog-50);
}
.svcs {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 0 32px;
  margin: 0;
  padding: 0;
  list-style: none;
}
.svcs li {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 9px 0;
  border-bottom: 1px solid var(--hair);
  font-size: 14px;
}
.dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  border: 1.2px dashed var(--fog-400);
}
/* the API's own word about its components: not green */
.svcs li[data-tone="ok"] .dot {
  border: 0;
  background: var(--fog-200);
}
.svcs li[data-tone="bad"] .dot {
  border: 1.4px solid var(--fail);
}
.sn {
  color: var(--fog-200);
}
.sv {
  margin-left: auto;
  font-size: 13px;
  color: var(--fog-400);
}
.svcs li[data-tone="bad"] .sv {
  color: var(--fail);
}
.sys {
  margin-top: 18px;
}
@media (max-width: 760px) {
  .scan {
    grid-template-columns: minmax(0, 1fr);
    align-items: start;
  }
  .f-body {
    grid-template-columns: minmax(0, 1fr);
  }
  .f-id {
    margin-left: 0;
    flex-basis: 100%;
  }
}
</style>
