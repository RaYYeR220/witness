<script setup lang="ts">
import { computed, markRaw, onMounted, reactive, ref, shallowRef } from "vue";

import type { AnchorCheckpoint } from "@/api/client";
import { recheckAnchor, selfConsistent, type Recheck } from "@/anchors/recheck";
import ConsoleShell from "@/components/ConsoleShell.vue";
import { useData } from "@/console/data";
import { explorerAddress, explorerObject, explorerTx } from "@/console/explorer";
import { shortHex, utc } from "@/console/format";
import { PINNED } from "@/verify/pinned";

/**
 * Anchors: the checkpoints that commit milestone windows to the Audit Trail
 * on IOTA Rebased, newest first, each linked to its transaction and chained
 * to the one before. Any anchored checkpoint can be re-checked here: the
 * browser reads its record from the pinned RPC and compares it field by
 * field with what the explorer shows.
 */
const data = useData();

const items = shallowRef<AnchorCheckpoint[]>([]);
const error = ref<string | null>(null);
const loaded = ref(false);
/**
 * Re-check results keyed by the checkpoint object the explorer listed, never by a field of
 * it: two rows claiming one `seq` cannot share (or steal) each other's result.
 */
const checks = reactive(new WeakMap<AnchorCheckpoint, Recheck | "running">());

onMounted(async () => {
  try {
    items.value = await data.anchors(100);
  } catch (e) {
    error.value = (e as Error).message;
  } finally {
    loaded.value = true;
  }
});

async function recheck(a: AnchorCheckpoint) {
  if (checks.get(a) === "running") return;
  checks.set(a, "running");
  const r = await recheckAnchor(a, PINNED);
  // kept raw, so `r.for` stays the very object it was asked about
  if (r.for === a) checks.set(a, markRaw(r));
}

const running = (a: AnchorCheckpoint) => checks.get(a) === "running";
const result = (a: AnchorCheckpoint): Recheck | null => {
  const r = checks.get(a);
  return r && r !== "running" && r.for === a ? r : null;
};

/**
 * How each checkpoint links to the one before it (newest first in `items`):
 * two of the explorer's answers held against each other, so at best
 * "consistent", never shown as checked.
 */
function chain(i: number): { tone: "consistent" | "differs" | "unknown"; text: string } {
  const a = items.value[i]!;
  const prev = (a.checkpoint as Record<string, unknown> | null)?.prev;
  const older = items.value[i + 1];
  if (prev === null || prev === undefined) return a.seq === 1 ? { tone: "consistent", text: "the first checkpoint" } : { tone: "unknown", text: "names no previous checkpoint" };
  if (!older) return { tone: "unknown", text: `follows ${shortHex(String(prev), 8, 6)}` };
  return String(prev).toLowerCase() === (older.checkpointHash ?? "").toLowerCase()
    ? { tone: "consistent", text: `follows checkpoint ${older.seq}` }
    : { tone: "differs", text: `names ${shortHex(String(prev), 8, 6)}, not checkpoint ${older.seq}` };
}

const msgCount = (a: AnchorCheckpoint) => {
  const n = (a.checkpoint as Record<string, unknown> | null)?.msgCount;
  return typeof n === "number" ? n : null;
};

/**
 * The explorer's status, in its own words and its own vocabulary: whatever the API
 * sends, it never becomes one of the browser's states below.
 */
const API_STATUS: Record<string, string> = {
  anchored: "Anchored, per the explorer",
  pending: "Pending, per the explorer",
  failed: "Failed, per the explorer",
  mismatch: "Mismatch, per the explorer",
  other: "A status this console does not know",
};
const apiStatus = (a: AnchorCheckpoint) => (Object.hasOwn(API_STATUS, a.status) && a.status !== "other" ? a.status : "other");

/** What the browser found, if it re-checked: the only source of green. */
function checked(a: AnchorCheckpoint): { c: "agrees" | "differs" | "partial"; text: string } | null {
  const r = result(a);
  if (!r) return null;
  if (r.verdict === true) return { c: "agrees", text: "Checked on IOTA Rebased in your browser" };
  if (r.verdict === false) return { c: "differs", text: "Does not match the chain" };
  return { c: "partial", text: "Not fully checked" };
}

/** The values shown for a checkpoint: the chain's once the browser has read the record. */
function shownValues(a: AnchorCheckpoint) {
  const c = result(a)?.chain;
  if (c) return { from: c.fromMilestone, to: c.toMilestone, msRoot: c.msRoot, hash: c.checkpointHash, msgCount: c.msgCount, fromChain: true };
  return { from: a.fromMilestone, to: a.toMilestone, msRoot: a.msRoot, hash: a.checkpointHash, msgCount: msgCount(a), fromChain: false };
}
const pinsComplete = Boolean(PINNED.rebasedRpc && PINNED.trailId && PINNED.auditTrailPackage);
const otherNetwork = computed(() => items.value.find((a) => a.network && PINNED.rebasedNetwork && a.network !== PINNED.rebasedNetwork)?.network ?? null);
</script>

<template>
  <ConsoleShell>
    <div class="anchors">
      <header class="x-head">
        <div>
          <h1 class="x-title">Anchors</h1>
          <p class="x-lede">
            Every checkpoint commits a window of milestones (the root of their ids, how many messages they hold and the writer policy in force) to an
            Audit Trail on IOTA Rebased. Your browser can read any record straight from the chain and hold it against what the explorer shows.
          </p>
        </div>
      </header>

      <section class="x-sec" aria-labelledby="trail-h">
        <h2 id="trail-h" class="x-sec-title">The trail this console trusts</h2>
        <dl class="x-kv trail">
          <div>
            <dt>Audit Trail</dt>
            <dd>
              <a v-if="explorerObject(PINNED.trailId)" class="x-link mono" :href="explorerObject(PINNED.trailId)!" rel="noopener noreferrer" target="_blank">{{
                PINNED.trailId
              }}</a>
              <span v-else>none pinned</span>
            </dd>
          </div>
          <div>
            <dt>Network</dt>
            <dd>IOTA Rebased {{ PINNED.rebasedNetwork ?? "(none pinned)" }}, read at <span class="mono">{{ PINNED.rebasedRpc ?? "no RPC pinned" }}</span></dd>
          </div>
          <div>
            <dt>Package</dt>
            <dd class="mono">{{ PINNED.auditTrailPackage ? shortHex(PINNED.auditTrailPackage, 10, 8) : "none pinned" }}</dd>
          </div>
          <div>
            <dt>Writer</dt>
            <dd>
              <a v-if="explorerAddress(PINNED.anchorWriter)" class="x-link mono" :href="explorerAddress(PINNED.anchorWriter)!" rel="noopener noreferrer" target="_blank">{{
                shortHex(PINNED.anchorWriter, 10, 8)
              }}</a>
              <span v-else>any address</span>
            </dd>
          </div>
        </dl>
        <p class="x-sec-note pins-note">Built into the console (src/config/verifier.json), like the keys Verify checks with. The explorer cannot change them.</p>
        <p v-if="otherNetwork" class="x-note" data-tone="bad">
          The explorer says a checkpoint was written to <span class="mono">{{ otherNetwork }}</span>, not to the pinned
          <span class="mono">{{ PINNED.rebasedNetwork }}</span>.
        </p>
      </section>

      <section class="x-sec" aria-labelledby="cps-h">
        <div class="x-sec-head">
          <h2 id="cps-h" class="x-sec-title">Checkpoints</h2>
          <p class="x-sec-note">{{ items.length }} recorded, newest first</p>
        </div>
        <p v-if="!loaded" class="x-quiet">Reading the checkpoints…</p>
        <p v-else-if="error" class="x-quiet x-err">Could not list the checkpoints: {{ error }}</p>
        <p v-else-if="!items.length" class="x-quiet">No checkpoint yet. The anchor service commits a window once enough milestones have passed.</p>
        <ol v-else class="cps">
          <li v-for="(a, i) in items" :key="i" class="cp" :data-status="apiStatus(a)" :data-check="checked(a)?.c ?? 'none'">
            <div class="rail">
              <span class="seq">{{ a.seq }}</span>
              <span class="dot" aria-hidden="true"></span>
            </div>
            <div class="body">
              <p class="top">
                <span class="st" :data-status="apiStatus(a)">{{ API_STATUS[apiStatus(a)] }}</span>
                <span v-if="checked(a)" class="chk" :data-check="checked(a)!.c">{{ checked(a)!.text }}</span>
                <span class="x-muted">{{ utc(a.createdAtMs) }}</span>
              </p>
              <h3 class="win">Milestones {{ shownValues(a).from ?? "?" }}–{{ shownValues(a).to ?? "?" }}</h3>
              <p class="src x-sec-note">
                {{ shownValues(a).fromChain ? "As the record on IOTA Rebased holds it, read by your browser." : "As the explorer shows it." }}
              </p>
              <dl class="x-kv">
                <div>
                  <dt>Messages</dt>
                  <dd>{{ shownValues(a).msgCount ?? "not stated" }}</dd>
                </div>
                <div>
                  <dt>Milestone root</dt>
                  <dd class="mono">{{ shownValues(a).msRoot ?? "none" }}</dd>
                </div>
                <div>
                  <dt>Checkpoint hash</dt>
                  <dd class="mono">
                    {{ shownValues(a).hash ?? "none" }}
                    <span v-if="selfConsistent(a) === false" class="x-cmp" data-c="differs">the explorer's own document does not hash to it</span>
                  </dd>
                </div>
                <div>
                  <dt>On IOTA Rebased</dt>
                  <dd>
                    <template v-if="a.record !== null">record {{ a.record }}</template><template v-else>no record yet</template>
                    <template v-if="explorerTx(a.tx)">
                      ·
                      <a class="x-link" :href="explorerTx(a.tx)!" rel="noopener noreferrer" target="_blank">transaction <span class="mono">{{ shortHex(a.tx, 6, 6) }}</span></a>
                    </template>
                  </dd>
                </div>
                <div>
                  <dt>Chain</dt>
                  <dd class="chain">
                    <span class="x-cmp" :data-c="chain(i).tone">{{ chain(i).text }}</span>
                  </dd>
                </div>
              </dl>

              <div class="re">
                <button
                  type="button"
                  class="btn"
                  :disabled="!pinsComplete || a.record === null || running(a)"
                  @click="recheck(a)"
                >
                  {{ running(a) ? "Reading the chain…" : result(a) ? "Re-check again" : "Re-check from your browser" }}
                </button>
                <span v-if="!pinsComplete" class="x-sec-note">This console pins no trail to read.</span>
              </div>
              <div v-if="result(a)" class="res" role="status">
                <p class="verdict" :data-v="String(result(a)!.verdict)">
                  <template v-if="result(a)!.verdict === true"
                    ><b>The chain agrees.</b> Record {{ a.record }} of the pinned trail holds this checkpoint, read by your browser in {{ result(a)!.ms }} ms.</template
                  >
                  <template v-else-if="result(a)!.verdict === false"
                    ><b>The chain disagrees.</b> {{ result(a)!.problem ?? "What the explorer shows is not what record " + a.record + " holds." }}</template
                  >
                  <template v-else><b>Not fully checked.</b> {{ result(a)!.problem }}</template>
                </p>
                <table v-if="result(a)!.rows.length" class="x-tbl cmp">
                  <thead>
                    <tr>
                      <th scope="col">Field</th>
                      <th scope="col">The explorer shows</th>
                      <th scope="col">The chain holds</th>
                      <th scope="col"><span class="sr-only">Agreement</span></th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="r in result(a)!.rows" :key="r.what" :data-c="r.c">
                      <th scope="row">{{ r.what }}</th>
                      <td class="mono" data-label="The explorer shows" :title="r.explorer ?? undefined">{{ r.explorer === null ? "–" : r.explorer.length > 24 ? shortHex(r.explorer, 10, 8) : r.explorer }}</td>
                      <td class="mono" data-label="The chain holds" :title="r.chain ?? undefined">{{ r.chain === null ? "–" : r.chain.length > 24 ? shortHex(r.chain, 10, 8) : r.chain }}</td>
                      <td>
                        <span class="x-cmp" :data-c="r.c">{{ r.c === "same" ? "same" : r.c === "differs" ? "differs" : "not stated" }}</span>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </li>
        </ol>
      </section>
    </div>
  </ConsoleShell>
</template>

<style scoped>
.trail {
  margin-top: 16px;
}
.pins-note {
  margin-top: 12px;
}
.cps {
  margin: 0;
  padding: 0;
  list-style: none;
}
.cp {
  display: grid;
  grid-template-columns: 56px minmax(0, 1fr);
  gap: 16px;
}
.rail {
  position: relative;
  display: flex;
  flex-direction: column;
  align-items: center;
  padding-top: 4px;
}
.rail::after {
  content: "";
  position: absolute;
  top: 46px;
  bottom: 0;
  border-left: 1px solid var(--hair-strong);
}
.cp:last-child .rail::after {
  display: none;
}
.seq {
  font: 400 26px/1 var(--serif);
  color: var(--fog-50);
}
.dot {
  width: 9px;
  height: 9px;
  margin-top: 8px;
  border-radius: 50%;
  border: 1.2px dashed var(--fog-400);
}
.cp[data-status="anchored"] .dot {
  border: 1.2px solid var(--fog-200);
}
.cp[data-check="agrees"] .dot {
  border: 0;
  background: var(--pass);
}
.cp[data-check="differs"] .dot,
.cp[data-check="none"][data-status="mismatch"] .dot,
.cp[data-check="none"][data-status="failed"] .dot {
  border: 1.4px solid var(--fail);
}
.body {
  min-width: 0;
  padding-bottom: 34px;
  border-bottom: 1px solid var(--hair);
  margin-bottom: 26px;
}
.cp:last-child .body {
  border-bottom: 0;
}
.top {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 12px;
  align-items: center;
  margin: 0;
  font-size: 13px;
}
.st {
  padding: 1px 10px;
  border-radius: var(--r-pill);
  border: 1px solid var(--hair-strong);
  color: var(--fog-200);
}
.chk {
  padding: 1px 10px;
  border-radius: var(--r-pill);
  border: 1px solid var(--hair-strong);
  color: var(--fog-200);
}
.chk[data-check="agrees"] {
  border-color: rgba(var(--rgb-aurora), 0.45);
  color: var(--pass);
}
.chk[data-check="differs"] {
  border-color: rgba(var(--rgb-nova), 0.55);
  color: var(--fail);
}
.st[data-status="mismatch"],
.st[data-status="failed"] {
  border-color: rgba(var(--rgb-nova), 0.55);
  color: var(--fail);
}
.src {
  margin: 0 0 12px;
}
.win {
  margin: 8px 0 4px;
  font: 400 28px/1.1 var(--serif);
  color: var(--fog-50);
}
.re {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 12px 16px;
  margin-top: 18px;
}
.re .btn {
  height: 38px;
  font-size: 14px;
}
.res {
  margin-top: 14px;
}
.verdict {
  margin: 0 0 12px;
  padding: 10px 14px;
  border-left: 2px solid var(--fog-400);
  font-size: 14px;
  color: var(--fog-200);
}
.verdict b {
  font-weight: 500;
  color: var(--fog-50);
}
.verdict[data-v="true"] {
  border-color: var(--pass);
}
.verdict[data-v="true"] b {
  color: var(--pass);
}
.verdict[data-v="false"] {
  border-color: var(--fail);
  background: var(--nova-wash);
}
.verdict[data-v="false"] b {
  color: var(--fail);
}
.cmp th[scope="row"] {
  padding: 11px 14px 11px 0;
  vertical-align: baseline;
  font-weight: 400;
  text-align: left;
  color: var(--fog-200);
  border-bottom: 1px solid var(--hair);
  white-space: nowrap;
}
.cmp tr[data-c="differs"] td.mono {
  color: var(--fail);
}
@media (max-width: 760px) {
  .cp {
    grid-template-columns: 34px minmax(0, 1fr);
    gap: 10px;
  }
  .seq {
    font-size: 22px;
  }
  .win {
    font-size: 23px;
  }
  .cmp,
  .cmp tbody,
  .cmp tr,
  .cmp th,
  .cmp td {
    display: block;
  }
  .cmp thead {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip-path: inset(50%);
  }
  .cmp tr {
    padding: 8px 0;
    border-bottom: 1px solid var(--hair);
  }
  .cmp th[scope="row"],
  .cmp td {
    padding: 1px 0;
    border: 0;
    white-space: normal;
  }
  .cmp td[data-label]::before {
    content: attr(data-label) ": ";
    font-family: var(--sans);
    color: var(--fog-400);
  }
}
</style>
