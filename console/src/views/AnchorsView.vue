<script setup lang="ts">
import { computed, onMounted, reactive, ref, shallowRef } from "vue";

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
const checks = reactive(new Map<number, Recheck | "running">());

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
  if (checks.get(a.seq) === "running") return;
  checks.set(a.seq, "running");
  checks.set(a.seq, await recheckAnchor(a, PINNED));
}

const result = (seq: number) => {
  const r = checks.get(seq);
  return r && r !== "running" ? r : null;
};

/** How each checkpoint links to the one before it (newest first in `items`). */
function chain(i: number): { tone: "same" | "differs" | "unknown"; text: string } {
  const a = items.value[i]!;
  const prev = (a.checkpoint as Record<string, unknown> | null)?.prev;
  const older = items.value[i + 1];
  if (prev === null || prev === undefined) return a.seq === 1 ? { tone: "same", text: "the first checkpoint" } : { tone: "unknown", text: "names no previous checkpoint" };
  if (!older) return { tone: "unknown", text: `follows ${shortHex(String(prev), 8, 6)}` };
  return String(prev).toLowerCase() === (older.checkpointHash ?? "").toLowerCase()
    ? { tone: "same", text: `follows checkpoint ${older.seq}` }
    : { tone: "differs", text: `names ${shortHex(String(prev), 8, 6)}, not checkpoint ${older.seq}` };
}

const msgCount = (a: AnchorCheckpoint) => {
  const n = (a.checkpoint as Record<string, unknown> | null)?.msgCount;
  return typeof n === "number" ? n : null;
};

const STATUS: Record<string, string> = { anchored: "Anchored", pending: "Pending", failed: "Failed", mismatch: "Mismatch" };
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
          <li v-for="(a, i) in items" :key="a.seq" class="cp" :data-status="a.status">
            <div class="rail">
              <span class="seq">{{ a.seq }}</span>
              <span class="dot" aria-hidden="true"></span>
            </div>
            <div class="body">
              <p class="top">
                <span class="st" :data-status="a.status">{{ STATUS[a.status] ?? a.status }}</span>
                <span class="x-muted">{{ utc(a.createdAtMs) }}</span>
              </p>
              <h3 class="win">Milestones {{ a.fromMilestone }}–{{ a.toMilestone }}</h3>
              <dl class="x-kv">
                <div>
                  <dt>Messages</dt>
                  <dd>{{ msgCount(a) ?? "not stated" }}</dd>
                </div>
                <div>
                  <dt>Milestone root</dt>
                  <dd class="mono">{{ a.msRoot ?? "none" }}</dd>
                </div>
                <div>
                  <dt>Checkpoint hash</dt>
                  <dd class="mono">
                    {{ a.checkpointHash ?? "none" }}
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
                  :disabled="!pinsComplete || a.record === null || checks.get(a.seq) === 'running'"
                  @click="recheck(a)"
                >
                  {{ checks.get(a.seq) === "running" ? "Reading the chain…" : result(a.seq) ? "Re-check again" : "Re-check from your browser" }}
                </button>
                <span v-if="!pinsComplete" class="x-sec-note">This console pins no trail to read.</span>
              </div>
              <div v-if="result(a.seq)" class="res" role="status">
                <p class="verdict" :data-v="String(result(a.seq)!.verdict)">
                  <template v-if="result(a.seq)!.verdict === true"
                    ><b>The chain agrees.</b> Record {{ a.record }} of the pinned trail holds this checkpoint, read by your browser in {{ result(a.seq)!.ms }} ms.</template
                  >
                  <template v-else-if="result(a.seq)!.verdict === false"
                    ><b>The chain disagrees.</b> {{ result(a.seq)!.problem ?? "What the explorer shows is not what record " + a.record + " holds." }}</template
                  >
                  <template v-else><b>Not checked.</b> {{ result(a.seq)!.problem }}</template>
                </p>
                <table v-if="result(a.seq)!.rows.length" class="x-tbl cmp">
                  <thead>
                    <tr>
                      <th scope="col">Field</th>
                      <th scope="col">The explorer shows</th>
                      <th scope="col">The chain holds</th>
                      <th scope="col"><span class="sr-only">Agreement</span></th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="r in result(a.seq)!.rows" :key="r.what" :data-c="r.c">
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
  border: 0;
  background: var(--pass);
}
.cp[data-status="mismatch"] .dot,
.cp[data-status="failed"] .dot {
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
  gap: 12px;
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
.st[data-status="anchored"] {
  border-color: rgba(var(--rgb-aurora), 0.45);
  color: var(--pass);
}
.st[data-status="mismatch"],
.st[data-status="failed"] {
  border-color: rgba(var(--rgb-nova), 0.55);
  color: var(--fail);
}
.win {
  margin: 8px 0 14px;
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
