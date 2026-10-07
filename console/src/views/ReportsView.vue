<script setup lang="ts">
import { computed, onMounted, ref, shallowRef, watch } from "vue";
import { useRoute } from "vue-router";

import { isReportHash, type ReportDoc, type ReportSummary } from "@/api/client";
import ConsoleShell from "@/components/ConsoleShell.vue";
import { useData, useLookups } from "@/console/data";
import { isBlockId, shortDid, shortHex, utc } from "@/console/format";
import JsonText from "@/console/JsonText.vue";
import LadderPanel from "@/console/LadderPanel.vue";
import { checkReport, reportTotals, type ReportCheck } from "@/reports/model";
import { createLadder, resetLadder, runLadder } from "@/verify/ladder";
import { anchorPinned, PINNED, pinnedConfig } from "@/verify/pinned";

/**
 * Reports: signed audit reports, newest first. The list says what the
 * explorer claims. For the open report the browser checks it: the hash of
 * the JSON as served, computed here; the audit.report block named as its
 * anchor, verified with the five checks against the console's pins; and the
 * hash that block's message names. Only when all of that holds is the report
 * shown as anchored; otherwise it is the explorer's word, or a mismatch. The
 * HTML page is a rendering the explorer serves, opened on its own.
 */
const route = useRoute();
const data = useData();
const lookups = useLookups();

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
const check = shallowRef<ReportCheck | null>(null);
const ladder = createLadder();
const anchorOk = anchorPinned();
let generation = 0;

async function open(hash: string) {
  const g = ++generation;
  doc.value = null;
  docError.value = null;
  check.value = null;
  resetLadder(ladder);
  try {
    const d = await data.report(hash);
    if (g !== generation) return;
    if (d.result.reportHash !== hash) throw new Error(`the explorer answered with report ${shortHex(d.result.reportHash, 10, 8)}`);
    doc.value = d;
    const cfg = pinnedConfig();
    const result = await checkReport(d, {
      config: cfg,
      bundle: (blockId) => data.bundle(blockId),
      verify: (text) => runLadder(ladder, text, { config: cfg, resolveDid: lookups.resolveDid, fetchAnchorRecord: lookups.fetchAnchorRecord }),
      reportSigner: PINNED.reportSigner,
    });
    if (g === generation) check.value = result;
  } catch (e) {
    if (g === generation) docError.value = (e as Error).message;
  }
}

watch(selected, (h) => h && void open(h), { immediate: true });

const result = computed(() => doc.value?.result ?? null);
const state = computed(() => check.value?.state ?? "checking");
/** Shown from the browser's own parse of the text served, the one it hashed; nothing until then. */
const totals = computed(() => reportTotals(check.value?.report));
const htmlUrl = computed(() => (result.value ? data.reportHtmlUrl(result.value.reportHash) : null));
const scope = (r: ReportSummary) =>
  `${r.ie ?? "every IE"}, ${r.msFrom !== null || r.msTo !== null ? `milestones ${r.msFrom ?? "first"}–${r.msTo ?? "last"}` : "all milestones"}`;

const HEADLINE: Record<string, string> = {
  checking: "Checking in your browser…",
  verified: "Anchored, checked in your browser",
  mismatch: "Does not match",
  unchecked: "Anchored per the explorer (not checked in your browser)",
  "not-anchored": "NOT anchored",
};

/**
 * How one hash compares with the browser's own: green only when the whole
 * check holds, red where it differs, neutral otherwise.
 */
function mark(h: string | null | undefined): { c: "same" | "differs" | "unknown"; text: string } | null {
  const c = check.value;
  if (!c || !h || c.browserHash === null) return null;
  if (h !== c.browserHash) return { c: "differs", text: "does not match" };
  return c.state === "verified" ? { c: "same", text: "matches" } : { c: "unknown", text: "equal" };
}

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
                <span class="anch" :data-a="r.anchored ? 'claimed' : 'no'">{{ r.anchored ? "Anchored, per the explorer" : "NOT anchored" }}</span>
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
            <p class="anch big" :data-a="state" role="status">{{ HEADLINE[state] }}</p>
            <h2 id="rep-h" class="title">Report <span class="mono">{{ shortHex(result.reportHash, 10, 8) }}</span></h2>
            <p class="x-sec-note">
              {{ scope(result) }}; generated {{ utc(result.generatedAtMs) }}<template v-if="result.iss">, signed by {{ shortDid(result.iss) }}</template
              >, as the explorer lists it.
            </p>

            <p v-if="state === 'verified'" class="x-note" data-tone="ok">
              <b>The ledger vouches for this report.</b> Its audit.report block passed checks 1 to 4 in your browser (its bytes, its milestone, the
              pinned coordinators' signatures and its sender's signature), names the hash your browser computed from the report served, and is
              signed by <span class="mono">{{ shortDid(check?.signer) }}</span>, the report signer pinned in this console (checked in your browser).
              <template v-if="check?.rebased === true">Its milestone is also in a checkpoint on IOTA Rebased.</template>
              <template v-else>Its milestone is not in a checkpoint on IOTA Rebased yet.</template>
            </p>
            <div v-else-if="state === 'mismatch'" class="x-note" data-tone="bad" role="alert">
              <b>Does not match.</b> The report as served is not shown as anchored:
              <ul class="why">
                <li v-for="r in check?.reasons" :key="r">{{ r }}</li>
              </ul>
            </div>
            <div v-else-if="state === 'unchecked'" class="x-note">
              <b>Not checked in your browser.</b> The explorer says this report is anchored; that is its word only:
              <ul class="why">
                <li v-for="r in check?.reasons" :key="r">{{ r }}</li>
              </ul>
            </div>
            <p v-else-if="state === 'not-anchored'" class="x-note" data-tone="bad">
              <b>Nothing on the ledger vouches for this report.</b> The explorer stored it, but no audit.report message for it was accepted, so it
              could have changed since.
            </p>

            <dl class="x-kv hashes">
              <div>
                <dt>The explorer states</dt>
                <dd>
                  <span class="mono">{{ result.reportHash }}</span>
                  <span v-if="mark(check?.explorerHash)" class="x-cmp" :data-c="mark(check?.explorerHash)!.c">{{ mark(check?.explorerHash)!.text }}</span>
                </dd>
              </div>
              <div>
                <dt>Your browser computes</dt>
                <dd>
                  <span v-if="check?.browserHash" class="mono">{{ check.browserHash }}</span>
                  <span v-else-if="check" class="x-err">cannot be computed from the report served</span>
                  <span v-else class="x-muted">computing…</span>
                  <span class="how">BLAKE2b-256 of the report's canonical JSON (RFC 8785), from the JSON this page received</span>
                </dd>
              </div>
              <div v-if="result.anchored">
                <dt>The audit.report names</dt>
                <dd>
                  <template v-if="check?.ledgerHash">
                    <span class="mono">{{ check.ledgerHash }}</span>
                    <span v-if="mark(check.ledgerHash)" class="x-cmp" :data-c="mark(check.ledgerHash)!.c">{{ mark(check.ledgerHash)!.text }}</span>
                  </template>
                  <span v-else-if="check" class="x-muted">not read</span>
                  <span v-else class="x-muted">reading the block…</span>
                  <span v-if="isBlockId(result.blockId)" class="how">
                    read from the bytes of block
                    <RouterLink class="x-link mono" :to="{ name: 'verify', params: { blockId: result.blockId } }">{{ shortHex(result.blockId, 8, 6) }}</RouterLink
                    >, which must hash to its id</span
                  >
                </dd>
              </div>
            </dl>

            <details v-if="result.anchored && isBlockId(result.blockId)" class="ladder">
              <summary>The five checks on the audit.report block, in your browser</summary>
              <LadderPanel :state="ladder" :anchor-pinned="anchorOk" />
            </details>

            <dl v-if="totals.length" class="totals">
              <div v-for="t in totals" :key="t.label">
                <dt>{{ t.label }}</dt>
                <dd>{{ t.value }}</dd>
              </div>
            </dl>

            <div class="actions">
              <a v-if="htmlUrl" class="btn" :href="htmlUrl" target="_blank" rel="noopener noreferrer">Open the HTML rendering</a>
              <button type="button" class="btn btn--ghost" @click="download">Download the JSON as served</button>
            </div>
            <p class="x-sec-note render-note">
              The HTML page is the explorer's rendering of the stored report, opened on its own. It is not what your browser checked; the hashes above
              are.
            </p>
            <details v-if="check && check.report !== undefined" class="json">
              <summary>The report JSON, as your browser parsed and hashed it</summary>
              <JsonText :value="check.report" :max="60000" />
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
.anch[data-a="claimed"],
.anch[data-a="unchecked"],
.anch[data-a="checking"] {
  border-color: var(--hair-strong);
  color: var(--fog-200);
}
.anch[data-a="verified"] {
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
.hashes .x-cmp[data-c="unknown"]::before {
  border-style: solid;
}
.how {
  display: block;
  margin-top: 3px;
  font-size: 12.5px;
  color: var(--fog-400);
}
.why {
  margin: 6px 0 0;
  padding-left: 18px;
}
.ladder {
  margin-top: 18px;
}
.ladder summary {
  cursor: pointer;
  margin-bottom: 8px;
  font-size: 14px;
  color: var(--fog-200);
}
.render-note {
  margin-top: 10px;
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
