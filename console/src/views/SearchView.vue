<script setup lang="ts">
import { ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";

import type { MessageSummary } from "@/api/client";
import ConsoleShell from "@/components/ConsoleShell.vue";
import { useData } from "@/console/data";
import { RECORDED_NOTE, shortDid, shortHex, utc, verdictInfo } from "@/console/format";
import LookupPanel from "@/console/LookupPanel.vue";
import { parseSearch, type ParsedSearch } from "@/console/query";
import VerdictMark from "@/console/VerdictMark.vue";

/**
 * Search: one box for whatever id you have (block id, milestone index or
 * range, DID, IE id, tag, date or date range, verdict, free text), mapped to
 * `GET /messages` and shown back as chips. Results page with the API's cursor.
 * The query lives in the URL, so a search can be linked.
 */
const data = useData();
const route = useRoute();
const router = useRouter();

const text = ref(typeof route.query.q === "string" ? route.query.q : "");
const parsed = ref<ParsedSearch>(parseSearch(text.value));
const items = ref<MessageSummary[]>([]);
const next = ref<string | null>(null);
const busy = ref(false);
const more = ref(false);
const error = ref<string | null>(null);
const searched = ref(false);
/** Bumped by every search; an answer to an older one is dropped. */
let generation = 0;

const EXAMPLES = ["trust.score", "FORGED", "2026-10-06 to 2026-10-07", "ms:1280..1300", "event=scale"];

async function run(q: string) {
  const g = ++generation;
  parsed.value = parseSearch(q);
  error.value = parsed.value.problem;
  items.value = [];
  next.value = null;
  searched.value = true;
  busy.value = true;
  try {
    const page = await data.messages({ ...parsed.value.params, limit: 50 });
    if (g !== generation) return;
    items.value = page.items;
    next.value = page.nextCursor;
  } catch (e) {
    if (g === generation) error.value = e instanceof Error ? e.message : String(e);
  } finally {
    if (g === generation) busy.value = false;
  }
}

async function loadMore() {
  if (!next.value || more.value) return;
  const g = generation;
  more.value = true;
  try {
    const page = await data.messages({ ...parsed.value.params, cursor: next.value, limit: 50 });
    if (g !== generation) return;
    items.value = [...items.value, ...page.items];
    next.value = page.nextCursor;
  } catch (e) {
    if (g === generation) error.value = e instanceof Error ? e.message : String(e);
  } finally {
    more.value = false;
  }
}

function submit() {
  void router.replace({ query: text.value.trim() ? { q: text.value.trim() } : {} });
}

function example(q: string) {
  text.value = q;
  submit();
}

watch(
  () => route.query.q,
  (q) => {
    const value = typeof q === "string" ? q : "";
    text.value = value;
    void run(value);
  },
  { immediate: true },
);
</script>

<template>
  <ConsoleShell>
    <div class="search">
      <div class="main">
        <header>
          <h1>Search</h1>
          <p class="lede">A block id, a milestone, a DID, an IE, a tag, a day or a range of them. Combine as many as you like.</p>
        </header>
        <form class="box" role="search" @submit.prevent="submit">
          <label class="sr-only" for="sq">Search stored messages</label>
          <input
            id="sq"
            v-model="text"
            type="search"
            autocomplete="off"
            spellcheck="false"
            placeholder="0x972a…, 1284, did:iota:…, MyDomain:fa163e5e25ef, trust.score, 2026-10-06"
          />
          <button class="btn btn--solid" type="submit">Search</button>
        </form>
        <div class="read" aria-live="polite">
          <template v-if="parsed.chips.length">
            <span class="as">Reading this as</span>
            <span v-for="c in parsed.chips" :key="c.key" class="chip">
              <span class="k">{{ c.label }}</span> <span class="v">{{ c.value }}</span>
            </span>
          </template>
          <template v-else>
            <span class="as">Try</span>
            <button v-for="e in EXAMPLES" :key="e" type="button" class="chip ex" @click="example(e)">{{ e }}</button>
          </template>
        </div>
        <p v-if="error" class="err" role="alert">{{ error }}</p>

        <div class="results" :aria-busy="busy">
          <p v-if="busy" class="quiet">Searching…</p>
          <p v-else-if="searched && !items.length && !error" class="quiet">No stored message matches.</p>
          <table v-if="items.length">
            <caption class="sr-only">Matching messages, newest first</caption>
            <thead>
              <tr>
                <th scope="col">Verdict recorded</th>
                <th scope="col">Date</th>
                <th scope="col">Tag</th>
                <th scope="col">IE</th>
                <th scope="col">Issuer</th>
                <th scope="col" class="num">Milestone</th>
                <th scope="col">Block</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="m in items" :key="m.blockId" :data-f="verdictInfo(m.verdict).family">
                <td class="vd">
                  <span class="cell-v" :title="RECORDED_NOTE"
                    ><VerdictMark :family="verdictInfo(m.verdict).family" />{{ verdictInfo(m.verdict).label }}<span class="sr-only">, recorded</span></span
                  >
                </td>
                <td class="dt">{{ utc(m.dateMs) }}</td>
                <td>{{ m.tag ?? "" }}<span v-if="m.encrypted" class="sealed">sealed</span></td>
                <td class="mono">{{ m.ieId ?? "" }}</td>
                <td class="mono" :title="m.iss ?? undefined">{{ shortDid(m.iss) }}</td>
                <td class="num">{{ m.msIndex ?? "pending" }}</td>
                <td>
                  <RouterLink class="mono blk" :to="{ name: 'verify', params: { blockId: m.blockId } }">
                    {{ shortHex(m.blockId, 8, 6) }}<span class="sr-only">, verify</span>
                  </RouterLink>
                </td>
              </tr>
            </tbody>
          </table>
          <div v-if="next" class="pager">
            <button class="btn" type="button" :disabled="more" @click="loadMore">{{ more ? "Loading…" : "Show older messages" }}</button>
          </div>
          <p v-if="items.length" class="count">{{ items.length }} shown{{ next ? ", more available" : "" }}.</p>
        </div>
      </div>
      <aside class="side">
        <LookupPanel />
      </aside>
    </div>
  </ConsoleShell>
</template>

<style scoped>
.search {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 400px;
  gap: 56px;
}
h1 {
  margin: 0;
  font: 400 var(--fs-h2) / 1 var(--serif);
  letter-spacing: -0.012em;
  color: var(--fog-50);
}
.lede {
  margin: 12px 0 0;
  max-width: 62ch;
  color: var(--fog-200);
}
.box {
  display: flex;
  gap: 10px;
  margin-top: 24px;
}
.box input {
  flex: 1;
  min-width: 0;
  height: 48px;
  padding: 0 20px;
  border-radius: var(--r-pill);
  border: 1px solid var(--hair-strong);
  background: var(--void-raised);
  color: var(--fog-50);
  font: 400 15px var(--sans);
}
.box input::placeholder {
  color: var(--fog-400);
}
.box input:focus-visible {
  outline: none;
  border-color: var(--ember);
}
.box .btn {
  height: 48px;
}
.read {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  min-height: 30px;
  margin-top: 14px;
}
.as {
  font-size: 13px;
  color: var(--fog-400);
  margin-right: 2px;
}
.chip {
  display: inline-flex;
  gap: 6px;
  align-items: baseline;
  padding: 4px 11px;
  border-radius: var(--r-pill);
  border: 1px solid var(--hair-strong);
  font-size: 13px;
  color: var(--fog-50);
  background: none;
}
.chip .k {
  color: var(--fog-400);
}
.chip .v {
  font-family: var(--mono);
  font-size: 12px;
}
.chip.ex {
  cursor: pointer;
  font-family: var(--mono);
  font-size: 12px;
  color: var(--fog-200);
}
.chip.ex:hover {
  border-color: var(--ember);
  color: var(--fog-50);
}
.err {
  margin: 14px 0 0;
  color: var(--fail);
}
.results {
  margin-top: 26px;
}
.quiet {
  margin: 0;
  padding: 18px 0;
  color: var(--fog-400);
}
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13.5px;
}
th {
  padding: 0 12px 10px 0;
  text-align: left;
  font-weight: 400;
  font-size: 12.5px;
  color: var(--fog-400);
  border-bottom: 1px solid var(--hair-strong);
  white-space: nowrap;
}
td {
  padding: 12px 12px 12px 0;
  border-bottom: 1px solid var(--hair);
  color: var(--fog-200);
  vertical-align: baseline;
  max-width: 220px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
tbody tr:hover td {
  background: rgba(var(--rgb-fog-50), 0.025);
}
.num {
  text-align: right;
  font-variant-numeric: tabular-nums;
}
.cell-v {
  display: inline-flex;
  align-items: center;
  gap: 9px;
  color: var(--fog-50);
}
tr[data-f="rejected"] .cell-v {
  color: var(--fail);
}
tr[data-f="unsigned"] .cell-v {
  color: var(--fog-200);
}
.dt {
  font-variant-numeric: tabular-nums;
}
.sealed {
  margin-left: 8px;
  font-size: 11.5px;
  padding: 1px 7px;
  border-radius: var(--r-pill);
  border: 1px solid var(--hair-strong);
}
.blk {
  color: var(--fog-50);
  text-decoration: underline;
  text-decoration-color: rgba(var(--rgb-ember), 0.6);
  text-underline-offset: 4px;
}
.pager {
  margin-top: 18px;
}
.count {
  margin: 12px 0 0;
  font-size: 13px;
  color: var(--fog-400);
}
.side {
  padding-top: 6px;
  border-left: 1px solid var(--hair);
  padding-left: 36px;
}

@media (max-width: 1180px) {
  .search {
    grid-template-columns: minmax(0, 1fr);
    gap: 40px;
  }
  .side {
    border-left: 0;
    padding-left: 0;
    border-top: 1px solid var(--hair);
    padding-top: 28px;
  }
}
@media (max-width: 760px) {
  .box {
    flex-direction: column;
  }
  .box input {
    flex: none;
  }
  table,
  thead,
  tbody,
  tr,
  td {
    display: block;
  }
  thead {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip-path: inset(50%);
  }
  tbody tr {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    gap: 4px 12px;
    padding: 12px 0;
    border-bottom: 1px solid var(--hair);
  }
  td {
    padding: 0;
    border: 0;
    max-width: none;
  }
  td.num {
    text-align: right;
  }
}
</style>
