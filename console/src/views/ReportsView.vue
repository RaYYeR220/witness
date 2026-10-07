<script setup lang="ts">
import { computed, onMounted, ref, shallowRef, watch } from "vue";
import { useRoute } from "vue-router";

import { isReportHash, type ReportDoc, type ReportSummary } from "@/api/client";
import ConsoleShell from "@/components/ConsoleShell.vue";
import { useData } from "@/console/data";
import { isBlockId, shortDid, shortHex, utc } from "@/console/format";
import JsonText from "@/console/JsonText.vue";
import { ledgerReportHash, recomputeReportHash, reportTotals, type LedgerCopy } from "@/reports/model";

/**
 * Reports: signed audit reports, newest first, and whether the ledger
 * vouches for each one. For the open report the browser recomputes its hash
 * from the JSON as served and reads the hash the audit.report block names
 * from that block's own bytes; the three must agree. The HTML page opens on
 * its own (the API serves it with a strict CSP); it is never put into this
 * page.
 */
const route = useRoute();
const data = useData();

const items = ref<ReportSummary[]>([]);
const next = ref<string | null>(null);
const listError = ref<string | null>(null);
const loaded = ref(false);
const more = ref(false);

onMounted(async () => {
  try {
    const page = await data.reports({ limit: 50 });
    items.value = page.items;
    next.value = page.nextCursor;
  } catch (e) {
    listError.value = (e as Error).message;
  } finally {
    loaded.value = true;
  }
});

async function loadMore() {
  if (!next.value || more.value) return;
  more.value = true;
  try {
    const page = await data.reports({ limit: 50, cursor: next.value });
    items.value = [...items.value, ...page.items];
    next.value = page.nextCursor;
  } catch (e) {
    listError.value = (e as Error).message;
  } finally {
    more.value = false;
  }
}

const asked = computed(() => (typeof route.query.report === "string" && isReportHash(route.query.report) ? route.query.report : null));
const selected = computed(() => asked.value ?? items.value[0]?.reportHash ?? null);

const doc = shallowRef<ReportDoc | null>(null);
const docError = ref<string | null>(null);
const mine = ref<{ hash: string | null; problem: string | null } | null>(null);
const ledger = ref<LedgerCopy | null>(null);
const ledgerBusy = ref(false);
let generation = 0;

async function open(hash: string) {
  const g = ++generation;
  doc.value = null;
  docError.value = null;
  mine.value = null;
  ledger.value = null;
  try {
    const d = await data.report(hash);
    if (g !== generation) return;
    if (d.result.reportHash !== hash) throw new Error(`the explorer answered with report ${shortHex(d.result.reportHash, 10, 8)}`);
    doc.value = d;
    mine.value = recomputeReportHash(d.text);
    const block = d.result.blockId;
    if (d.result.anchored && isBlockId(block)) {
      ledgerBusy.value = true;
      try {
        const text = await data.bundle(block);
        if (g === generation) ledger.value = ledgerReportHash(text, block);
      } catch (e) {
        if (g === generation) ledger.value = { hash: null, iss: null, problem: `its proof could not be read (${(e as Error).message})` };
      } finally {
        if (g === generation) ledgerBusy.value = false;
      }
    }
  } catch (e) {
    if (g === generation) docError.value = (e as Error).message;
  }
}

watch(selected, (h) => h && void open(h), { immediate: true });

const result = computed(() => doc.value?.result ?? null);
const agree = computed(() => {
  const r = result.value;
  if (!r || !mine.value?.hash) return null;
  return mine.value.hash === r.reportHash.toLowerCase();
});
const ledgerAgree = computed(() => (ledger.value?.hash && mine.value?.hash ? ledger.value.hash === mine.value.hash : null));
const totals = computed(() => reportTotals(result.value?.report));
const htmlUrl = computed(() => (result.value ? data.reportHtmlUrl(result.value.reportHash) : null));
const scope = (r: ReportSummary) =>
  `${r.ie ?? "every IE"}, ${r.msFrom !== null || r.msTo !== null ? `milestones ${r.msFrom ?? "first"}–${r.msTo ?? "last"}` : "all milestones"}`;

function download() {
  if (!doc.value) return;
  const url = URL.createObjectURL(new Blob([doc.value.text], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = `witness-report-${doc.value.result.reportHash.slice(2, 14)}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
</script>

<template>
  <ConsoleShell>
    <div class="reports">
      <header class="x-head">
        <div>
          <h1 class="x-title">Reports</h1>
          <p class="x-lede">
            Signed audit reports over a period: message totals by verdict, alerts, checkpoints and an index of proofs. Each report's hash is posted to
            the Tangle in a signed audit.report message, so the ledger vouches for exactly one version of it. Your browser recomputes the hash.
          </p>
        </div>
      </header>

      <p v-if="!loaded" class="x-quiet">Listing the reports…</p>
      <p v-else-if="listError && !items.length" class="x-quiet x-err">Could not list the reports: {{ listError }}</p>
      <section v-else-if="!items.length" class="x-sec empty" aria-labelledby="none-h">
        <h2 id="none-h" class="x-sec-title">No report yet</h2>
        <p class="x-sec-note">
          Reports are built by the operator on the server (<span class="mono">POST /reports</span>, with a token); this console lists them and checks
          them, and cannot write one. Once one exists it appears here with whether the ledger vouches for it.
        </p>
      </section>
      <div v-else class="cols x-sec">
        <section aria-labelledby="list-h">
          <h2 id="list-h" class="x-sec-title list-h">Audit reports</h2>
          <ol class="list">
            <li v-for="r in items" :key="r.reportHash">
              <RouterLink
                class="row"
                :to="{ name: 'reports', query: { report: r.reportHash } }"
                :aria-current="r.reportHash === selected ? 'true' : undefined"
                replace
              >
                <span class="anch" :data-a="r.anchored ? 'yes' : 'no'">{{ r.anchored ? "Anchored" : "NOT anchored" }}</span>
                <span class="mono h">{{ shortHex(r.reportHash, 10, 8) }}</span>
                <span class="sc">{{ scope(r) }}</span>
                <span class="x-muted when">generated {{ utc(r.generatedAtMs) }}</span>
              </RouterLink>
            </li>
          </ol>
          <button v-if="next" type="button" class="btn more" :disabled="more" @click="loadMore">{{ more ? "Loading…" : "Show older reports" }}</button>
        </section>

        <section class="detail" aria-labelledby="rep-h" :aria-busy="!doc && !docError">
          <p v-if="docError" class="x-quiet x-err">Could not read the report: {{ docError }}</p>
          <p v-else-if="!result" class="x-quiet">Reading the report…</p>
          <template v-else>
            <p class="anch big" :data-a="result.anchored ? 'yes' : 'no'">{{ result.anchored ? "Anchored on the Tangle" : "NOT anchored" }}</p>
            <h2 id="rep-h" class="title">Report <span class="mono">{{ shortHex(result.reportHash, 10, 8) }}</span></h2>
            <p class="x-sec-note">{{ scope(result) }}; generated {{ utc(result.generatedAtMs) }}<template v-if="result.iss">, signed by {{ shortDid(result.iss) }}</template>.</p>
            <p v-if="!result.anchored" class="x-note" data-tone="bad">
              <b>Nothing on the ledger vouches for this report yet.</b> It is stored, but its audit.report message was not accepted, so anyone could
              have changed it since.
            </p>

            <dl class="x-kv hashes">
              <div>
                <dt>The explorer says</dt>
                <dd class="mono">{{ result.reportHash }}</dd>
              </div>
              <div>
                <dt>Your browser computes</dt>
                <dd>
                  <span v-if="mine?.hash" class="mono">{{ mine.hash }}</span>
                  <span v-else class="x-err">{{ mine?.problem }}</span>
                  <span v-if="agree !== null" class="x-cmp" :data-c="agree ? 'same' : 'differs'">{{ agree ? "same" : "differs" }}</span>
                </dd>
              </div>
              <div v-if="result.anchored">
                <dt>The ledger names</dt>
                <dd>
                  <template v-if="ledgerBusy">reading the audit.report block…</template>
                  <template v-else-if="ledger?.hash">
                    <span class="mono">{{ ledger.hash }}</span>
                    <span v-if="ledgerAgree !== null" class="x-cmp" :data-c="ledgerAgree ? 'same' : 'differs'">{{ ledgerAgree ? "same" : "differs" }}</span>
                  </template>
                  <template v-else-if="ledger">{{ ledger.problem }}</template>
                  <template v-else>no audit.report block is named</template>
                  <span v-if="isBlockId(result.blockId)" class="blk">
                    in block
                    <RouterLink class="x-link mono" :to="{ name: 'verify', params: { blockId: result.blockId } }">{{ shortHex(result.blockId, 8, 6) }}</RouterLink
                    >: read from the block's own bytes; open it to run the five checks on it.
                  </span>
                </dd>
              </div>
            </dl>
            <p v-if="agree === true && ledgerAgree === true" class="x-note" data-tone="ok">
              <b>All three agree.</b> The report as served is the one the ledger vouches for.
            </p>
            <p v-else-if="agree === false || ledgerAgree === false" class="x-note" data-tone="bad">
              <b>They do not agree.</b> The report as served is not the one {{ ledgerAgree === false ? "the ledger names" : "the explorer names" }}.
            </p>

            <dl v-if="totals.length" class="totals">
              <div v-for="t in totals" :key="t.label">
                <dt>{{ t.label }}</dt>
                <dd>{{ t.value }}</dd>
              </div>
            </dl>

            <div class="actions">
              <a v-if="htmlUrl" class="btn" :href="htmlUrl" target="_blank" rel="noopener noreferrer">Open the HTML page</a>
              <button type="button" class="btn btn--ghost" @click="download">Download the JSON</button>
            </div>
            <details class="json">
              <summary>The report JSON, as served</summary>
              <JsonText :value="result.report" :max="60000" />
            </details>
          </template>
        </section>
      </div>
    </div>
  </ConsoleShell>
</template>

<style scoped>
.empty {
  max-width: 720px;
}
.empty .x-sec-note {
  margin-top: 10px;
  font-size: 14px;
  line-height: 22px;
}
.cols {
  display: grid;
  grid-template-columns: minmax(0, 380px) minmax(0, 1fr);
  gap: 44px;
  align-items: start;
}
.list-h {
  margin-bottom: 14px;
}
.list {
  margin: 0;
  padding: 0;
  list-style: none;
  border-top: 1px solid var(--hair);
}
.row {
  display: grid;
  gap: 3px;
  padding: 12px 12px 12px 14px;
  border-bottom: 1px solid var(--hair);
  border-left: 2px solid transparent;
  color: inherit;
  text-decoration: none;
}
.row[aria-current="true"] {
  border-left-color: var(--ember);
  background: rgba(var(--rgb-fog-50), 0.035);
}
.row .h {
  color: var(--fog-50);
}
.sc {
  font-size: 13.5px;
  color: var(--fog-200);
}
.when {
  font-size: 12.5px;
}
.anch {
  justify-self: start;
  padding: 0 9px;
  border-radius: var(--r-pill);
  border: 1px solid rgba(var(--rgb-nova), 0.55);
  font-size: 12px;
  color: var(--fail);
}
.anch[data-a="yes"] {
  border-color: rgba(var(--rgb-aurora), 0.45);
  color: var(--pass);
}
.anch.big {
  display: inline-block;
  margin: 0;
  font-size: 13px;
}
.detail {
  min-width: 0;
  padding-left: 44px;
  border-left: 1px solid var(--hair);
}
.title {
  margin: 10px 0 6px;
  font: 400 30px/1.1 var(--serif);
  color: var(--fog-50);
}
.title .mono {
  font-size: 0.6em;
}
.hashes {
  margin-top: 20px;
  padding: 14px 0;
  border-top: 1px solid var(--hair);
  border-bottom: 1px solid var(--hair);
}
.hashes .x-cmp {
  margin-left: 10px;
}
.blk {
  display: block;
  margin-top: 4px;
  font-size: 12.5px;
  color: var(--fog-400);
}
.totals {
  display: flex;
  flex-wrap: wrap;
  gap: 12px 36px;
  margin: 20px 0 0;
}
.totals dt {
  font-size: 12.5px;
  color: var(--fog-400);
}
.totals dd {
  margin: 2px 0 0;
  font: 400 26px/1 var(--serif);
  color: var(--fog-50);
}
.actions {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin-top: 22px;
}
.actions .btn {
  height: 40px;
  font-size: 14px;
}
.json {
  margin-top: 18px;
}
.json summary {
  cursor: pointer;
  margin-bottom: 8px;
  font-size: 14px;
  color: var(--fog-200);
}
.more {
  height: 36px;
  margin-top: 12px;
  font-size: 14px;
}
@media (max-width: 1080px) {
  .cols {
    grid-template-columns: minmax(0, 1fr);
    gap: 32px;
  }
  .detail {
    padding-left: 0;
    border-left: 0;
  }
}
</style>
