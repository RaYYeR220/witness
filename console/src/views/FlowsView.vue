<script setup lang="ts">
import { computed, ref, shallowRef, watch } from "vue";
import { useRoute, useRouter } from "vue-router";

import { DataError, FLOW_BYS, isFlowBy, type Alert, type Flow, type FlowBy, type FlowSummary } from "@/api/client";
import ConsoleShell from "@/components/ConsoleShell.vue";
import { useData } from "@/console/data";
import { isBlockId, RECORDED_NOTE, shortDid, shortHex, utc, verdictInfo } from "@/console/format";
import VerdictMark from "@/console/VerdictMark.vue";
import { chainAlerts, FLOW_TITLES, LINK_TEXT, linkStates, newestFirst } from "@/flows/model";
import { alertReason } from "@/integrity/model";

/**
 * Flows: IoT flow traceability. Messages grouped by producer (a hash chain:
 * each envelope names the producer's previous message), correlation id, IE or
 * service component. A producer's chain shows, message by message, whether it
 * follows the one before it; gaps and forks are flagged with the CHAIN_GAP /
 * CHAIN_FORK alerts raised on them. Every message opens in Verify. The flow
 * and its chain are the explorer's index; Verify checks each message itself.
 */
const route = useRoute();
const router = useRouter();
const data = useData();

const by = computed<FlowBy>(() => (isFlowBy(route.query.by) ? route.query.by : "issuer"));
const askedKey = computed(() => (typeof route.query.key === "string" && route.query.key ? route.query.key : null));

const list = ref<FlowSummary[]>([]);
const listError = ref<string | null>(null);
const listLoaded = ref(false);
const flow = shallowRef<Flow | null>(null);
const flowError = ref<string | null>(null);
const limit = ref(100);
const alerts = shallowRef<Map<string, Alert[]>>(new Map());
let gen = 0;
let fgen = 0;

async function loadList() {
  const g = ++gen;
  listLoaded.value = false;
  listError.value = null;
  list.value = [];
  try {
    const items = await data.flows(by.value);
    if (g === gen) list.value = items;
  } catch (e) {
    if (g === gen) listError.value = (e as Error).message;
  } finally {
    if (g === gen) listLoaded.value = true;
  }
}

const key = computed(() => askedKey.value ?? list.value[0]?.key ?? null);

async function loadFlow() {
  const g = ++fgen;
  flow.value = null;
  flowError.value = null;
  const k = key.value;
  if (!k) return;
  try {
    const f = await data.flow(by.value, k, { limit: limit.value });
    if (g !== fgen) return;
    if (f.key !== k || f.by !== by.value) throw new DataError("the explorer answered with another flow", null);
    flow.value = f;
  } catch (e) {
    if (g === fgen) flowError.value = e instanceof DataError && e.status === 404 ? `No ${FLOW_TITLES[by.value].key.toLowerCase()} flow ${k}.` : (e as Error).message;
  }
}

watch(by, () => {
  limit.value = 100;
  void loadList();
}, { immediate: true });
watch([key, by, limit], () => void loadFlow(), { immediate: true });

// the chain alerts, once: they flag gaps and forks wherever they are
void Promise.allSettled([data.alerts({ rule: "CHAIN_GAP", limit: 500 }), data.alerts({ rule: "CHAIN_FORK", limit: 500 })]).then((r) => {
  alerts.value = chainAlerts(r.flatMap((x) => (x.status === "fulfilled" ? x.value : [])));
});

const states = computed(() => (flow.value && flow.value.by === "issuer" ? linkStates(flow.value) : null));
const rows = computed(() => (flow.value ? newestFirst(flow.value.items) : []));
const chain = computed(() => flow.value?.chain ?? null);

function pick(b: FlowBy) {
  void router.replace({ query: { by: b } });
}
const keyTo = (k: string) => ({ name: "flows", query: { by: by.value, key: k } });
const label = (k: string) => (by.value === "issuer" ? shortDid(k) : k);
</script>

<template>
  <ConsoleShell>
    <div class="flows">
      <header class="x-head">
        <div>
          <h1 class="x-title">Flows</h1>
          <p class="x-lede">
            IoT flow traceability. A producer's messages form a hash chain: each signed envelope names the producer's previous message. Follow a
            chain, or every message sharing a correlation id, IE or service component; gaps and forks are flagged, and every message opens in
            Verify.
          </p>
        </div>
      </header>

      <div class="groups x-sec" role="group" aria-label="Group messages by">
        <button v-for="b in FLOW_BYS" :key="b" type="button" class="chip" :aria-pressed="by === b" @click="pick(b)">{{ FLOW_TITLES[b].tab }}</button>
      </div>
      <p class="x-sec-note gloss">{{ FLOW_TITLES[by].gloss }}</p>

      <p v-if="!listLoaded" class="x-quiet">Listing the flows…</p>
      <p v-else-if="listError" class="x-quiet x-err">Could not list the flows: {{ listError }}</p>
      <p v-else-if="!list.length" class="x-quiet">No message carries a {{ FLOW_TITLES[by].key.toLowerCase() }} yet.</p>
      <div v-else class="cols">
        <nav class="list" :aria-label="`${FLOW_TITLES[by].tab} flows`">
          <ol>
            <li v-for="f in list.slice(0, 60)" :key="f.key">
              <RouterLink class="row" :to="keyTo(f.key)" :aria-current="f.key === key ? 'true' : undefined" replace :title="f.key">
                <span class="k mono">{{ label(f.key) }}</span>
                <span class="n">{{ f.count }} {{ f.count === 1 ? "message" : "messages" }}</span>
                <span class="x-muted when">last {{ utc(f.lastAtMs) }}</span>
              </RouterLink>
            </li>
          </ol>
          <p v-if="list.length > 60" class="x-sec-note">The 60 most recently active of {{ list.length }}.</p>
        </nav>

        <section class="detail" aria-labelledby="flow-h" :aria-busy="!flow && !flowError">
          <p v-if="flowError" class="x-quiet x-err">{{ flowError }}</p>
          <p v-else-if="!flow" class="x-quiet">Reading the flow…</p>
          <template v-else>
            <p class="x-kicker">{{ FLOW_TITLES[by].key }}</p>
            <h2 id="flow-h" class="key mono">{{ flow.key }}</h2>
            <p class="x-sec-note">
              {{ flow.total }} {{ flow.total === 1 ? "message" : "messages" }}<template v-if="flow.items.length < flow.total">, the newest {{ flow.items.length }} shown</template
              >, newest first; as the explorer indexed them.
            </p>
            <dl v-if="chain" class="chain" aria-label="Hash chain over the whole flow">
              <div>
                <dt>Linked by prev</dt>
                <dd>{{ chain.links }}</dd>
              </div>
              <div :data-bad="chain.gaps.length > 0">
                <dt>Gaps</dt>
                <dd>{{ chain.gaps.length }}</dd>
              </div>
              <div :data-bad="chain.forks.length > 0">
                <dt>Forks</dt>
                <dd>{{ chain.forks.length }}</dd>
              </div>
            </dl>

            <ol class="tl">
              <li v-for="m in rows" :key="m.blockId" class="msg" :data-link="states?.get(m.blockId) ?? 'na'">
                <span class="mk"><VerdictMark :family="verdictInfo(m.verdict).family" /></span>
                <div class="body">
                  <p class="top">
                    <span class="tag">{{ m.tag ?? "untagged" }}</span>
                    <span class="vd" :title="RECORDED_NOTE">{{ verdictInfo(m.verdict).label }}, as recorded</span>
                    <time class="at">{{ utc(m.atMs) }}</time>
                  </p>
                  <p class="meta">
                    <RouterLink v-if="isBlockId(m.blockId)" class="x-link mono" :to="{ name: 'verify', params: { blockId: m.blockId } }"
                      >{{ shortHex(m.blockId, 8, 6) }}<span class="sr-only">, verify</span></RouterLink
                    >
                    <template v-if="m.seq !== null"> · seq {{ m.seq }}</template>
                    <template v-if="m.msIndex !== null"> · milestone {{ m.msIndex }}</template>
                    <template v-if="by !== 'issuer' && m.iss"> · <span class="mono">{{ shortDid(m.iss) }}</span></template>
                    <template v-if="by !== 'ie' && m.ieId">
                      · <RouterLink class="x-link mono" :to="{ name: 'lineage', params: { id: m.ieId } }">{{ m.ieId }}</RouterLink>
                    </template>
                  </p>
                  <p v-if="states" class="link" :data-link="states.get(m.blockId)">
                    {{ LINK_TEXT[states.get(m.blockId) ?? "none"] }}<template v-if="m.prev"> (prev <span class="mono">{{ shortHex(m.prev) }}</span>)</template>
                  </p>
                  <p v-for="a in alerts.get(m.blockId.toLowerCase()) ?? []" :key="a.id" class="alert">
                    <RouterLink class="x-link" :to="{ name: 'integrity', query: { rule: a.rule } }">{{ a.rule }}</RouterLink> alert:
                    {{ alertReason(a) ?? "raised on this block" }}
                  </p>
                </div>
              </li>
            </ol>
            <button v-if="flow.items.length < flow.total && limit < 1000" type="button" class="btn more" @click="limit = 1000">
              Show up to 1000
            </button>
          </template>
        </section>
      </div>
    </div>
  </ConsoleShell>
</template>

<style scoped>
.groups {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.gloss {
  margin-top: 10px;
}
.chip {
  height: 34px;
  padding: 0 15px;
  border-radius: var(--r-pill);
  border: 1px solid var(--hair-strong);
  background: none;
  color: var(--fog-200);
  font-size: 13.5px;
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
.cols {
  display: grid;
  grid-template-columns: minmax(0, 380px) minmax(0, 1fr);
  gap: 40px;
  align-items: start;
  margin-top: 24px;
}
.list ol {
  margin: 0;
  padding: 0;
  list-style: none;
  border-top: 1px solid var(--hair);
}
.row {
  display: grid;
  gap: 2px;
  padding: 11px 12px 11px 14px;
  border-bottom: 1px solid var(--hair);
  border-left: 2px solid transparent;
  color: inherit;
  text-decoration: none;
}
.row:hover {
  background: rgba(var(--rgb-fog-50), 0.03);
}
.row[aria-current="true"] {
  border-left-color: var(--ember);
  background: rgba(var(--rgb-fog-50), 0.035);
}
.row .k {
  color: var(--fog-50);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.row .n {
  font-size: 13.5px;
  color: var(--fog-200);
}
.when {
  font-size: 12.5px;
}
.detail {
  min-width: 0;
  padding-left: 40px;
  border-left: 1px solid var(--hair);
}
.key {
  margin: 0 0 6px;
  font-size: 14px;
  color: var(--fog-50);
  overflow-wrap: anywhere;
}
.chain {
  display: flex;
  flex-wrap: wrap;
  gap: 12px 36px;
  margin: 16px 0 6px;
}
.chain dt {
  font-size: 12.5px;
  color: var(--fog-400);
}
.chain dd {
  margin: 2px 0 0;
  font: 400 30px/1 var(--serif);
  color: var(--fog-50);
}
.chain div[data-bad="true"] dd {
  color: var(--fail);
}
.tl {
  margin: 18px 0 0;
  padding: 0;
  list-style: none;
  border-top: 1px solid var(--hair-strong);
}
.msg {
  display: grid;
  grid-template-columns: 14px minmax(0, 1fr);
  gap: 12px;
  padding: 11px 0;
  border-bottom: 1px solid var(--hair);
}
.msg[data-link="gap"],
.msg[data-link="fork"] {
  background: var(--nova-wash);
}
.mk {
  display: flex;
  padding-top: 6px;
}
.top {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: 2px 14px;
  margin: 0;
}
.tag {
  color: var(--fog-50);
}
.vd {
  font-size: 13px;
  color: var(--fog-400);
}
.at {
  margin-left: auto;
  font-size: 12.5px;
  color: var(--fog-400);
  font-variant-numeric: tabular-nums;
}
.meta {
  margin: 3px 0 0;
  font-size: 13px;
  color: var(--fog-400);
  overflow-wrap: anywhere;
}
.link {
  margin: 3px 0 0;
  font-size: 13px;
  color: var(--fog-200);
}
.link[data-link="gap"],
.link[data-link="fork"] {
  color: var(--fail);
}
.alert {
  margin: 3px 0 0;
  font-size: 12.5px;
  color: var(--fog-200);
}
.more {
  height: 36px;
  margin-top: 14px;
  font-size: 14px;
}
@media (max-width: 1080px) {
  .cols {
    grid-template-columns: minmax(0, 1fr);
    gap: 28px;
  }
  .detail {
    padding-left: 0;
    border-left: 0;
  }
  .list ol {
    max-height: 340px;
    overflow: auto;
  }
}
@media (max-width: 760px) {
  .at {
    margin-left: 0;
    flex-basis: 100%;
  }
}
</style>
