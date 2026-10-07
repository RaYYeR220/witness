<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";

import { DataError, type Checks, type NodeCheck, type RecheckResult } from "@/api/client";

import { useData } from "./data";
import { statusLabel, utc } from "./format";

/**
 * The challenge brief's two checks on the Tangle, as the explorer's HORNET
 * node answered them: (c) the block is solid on the Tangle, (d) its content
 * there is byte for byte what the Messages API received. These are the
 * explorer's recorded results (GET /messages/{id}/lifecycle), labelled as
 * such; "Re-check on the node" asks the server to run them again now
 * (POST /messages/{id}/verify). The five checks below are the browser's own.
 */
const props = defineProps<{ blockId: string; recorded: Checks | null; recordedError: string | null }>();
const emit = defineEmits<{ rechecked: [] }>();

const data = useData();
const fresh = ref<Checks | null>(null);
const busy = ref(false);
const note = ref<string | null>(null);
const waitS = ref(0);
let timer: ReturnType<typeof setInterval> | null = null;
let asked = 0;
onBeforeUnmount(() => timer && clearInterval(timer));

// the same component serves the next block when the route changes: forget this one's answers
watch(
  () => props.blockId,
  () => {
    asked += 1;
    fresh.value = null;
    note.value = null;
    busy.value = false;
    waitS.value = 0;
    if (timer) clearInterval(timer);
    timer = null;
  },
);

const current = computed(() => fresh.value ?? props.recorded ?? null);

const METADATA = "GET /api/core/v2/blocks/{blockId}/metadata";
const BLOCK = "GET /api/core/v2/blocks/{blockId}";
/** The route the explorer says it asked, when it names one; else the brief's. */
const via = (c: NodeCheck | undefined, fallback: string) => (typeof c?.via === "string" && /^GET \/[\w/{}.-]{1,120}$/.test(c.via) ? c.via : fallback);

function solidLine(c: NodeCheck | undefined): { tone: "yes" | "no" | "open"; text: string } {
  if (!c || c.ok === null || c.ok === undefined) return { tone: "open", text: "Not checked yet." };
  if (c.ok === false) return { tone: "no", text: `No${c.detail ? `: ${c.detail}` : ""}.` };
  const parts = ["Yes, solid"];
  if (c.referencedByMilestoneIndex) parts.push(`referenced by milestone ${c.referencedByMilestoneIndex}`);
  if (c.ledgerInclusionState) parts.push(c.ledgerInclusionState);
  return { tone: "yes", text: `${parts.join(", ")}.` };
}

function contentLine(c: NodeCheck | undefined): { tone: "yes" | "no" | "open"; text: string } {
  if (!c || (c.ok === null && !c.result)) return { tone: "open", text: c?.detail ? `Not checked: ${c.detail}.` : "Not checked yet." };
  if (c.result === "MATCH" || (c.ok === true && !c.result)) return { tone: "yes", text: "Match: the bytes on the Tangle are the bytes the Messages API received." };
  if (c.result === "NOT_FOUND") return { tone: "no", text: "Not found on the Tangle." };
  return { tone: "no", text: `${c.result ? statusLabel(c.result) : "No"}: the Tangle holds other bytes than were received.` };
}

function countdown(s: number) {
  waitS.value = s;
  if (timer) clearInterval(timer);
  timer = setInterval(() => {
    waitS.value = Math.max(0, waitS.value - 1);
    if (waitS.value === 0 && timer) clearInterval(timer);
  }, 1000);
}

async function recheck() {
  const ask = ++asked;
  busy.value = true;
  note.value = null;
  try {
    const r: RecheckResult = await data.recheck(props.blockId);
    if (ask !== asked) return; // the screen moved on to another block
    fresh.value = r.checks;
    note.value = r.cached
      ? "The node answered about this block moments ago, so these are its stored answers (cached); it was not asked again."
      : r.timedOut
        ? "The node did not settle the block in time; these are its latest answers."
        : `Asked the node just now: ${r.calls.length} ${r.calls.length === 1 ? "call" : "calls"}, ${Math.max(0, r.finishedAtMs - r.startedAtMs)} ms.`;
    emit("rechecked");
  } catch (e) {
    if (ask !== asked) return;
    if (e instanceof DataError && e.status === 429) {
      const s = e.retryAfterS ?? 10;
      note.value = `Too many checks are running on the server. Try again in ${s} s.`;
      countdown(s);
    } else if (e instanceof DataError && e.status === 401) {
      note.value = "This server only re-checks with a token, which the public console does not hold.";
    } else if (e instanceof DataError && e.status === 503) {
      note.value = data.mode === "replay" ? "This is a recorded snapshot: there is no node to ask." : "The server has no node configured to ask.";
    } else {
      note.value = e instanceof Error ? e.message : String(e);
    }
  } finally {
    if (ask === asked) busy.value = false;
  }
}

const rows = computed(() => {
  const c = current.value;
  return [
    { id: "c", name: "Solid on the Tangle", via: via(c?.solid, METADATA), line: solidLine(c?.solid), at: c?.solid.checkedAtMs ?? null },
    { id: "d", name: "Same content as on the Tangle", via: via(c?.content, BLOCK), line: contentLine(c?.content), at: c?.content.checkedAtMs ?? null },
  ];
});
</script>

<template>
  <section class="tangle" aria-labelledby="tangle-h">
    <div class="head">
      <h2 id="tangle-h">On the Tangle, as the explorer's node answered</h2>
      <button class="btn" type="button" :disabled="busy || waitS > 0" @click="recheck">
        {{ busy ? "Asking the node…" : waitS > 0 ? `Re-check on the node (${waitS} s)` : "Re-check on the node" }}
      </button>
    </div>
    <p v-if="recordedError && !current" class="muted">{{ recordedError }}</p>
    <ol class="tc">
      <li v-for="r in rows" :key="r.id" :data-check="r.id" :data-tone="r.line.tone">
        <p class="name"><span class="lab">({{ r.id }})</span> {{ r.name }}</p>
        <p class="via">via HORNET <span class="mono">{{ r.via }}</span></p>
        <p class="res">{{ r.line.text }}</p>
        <p class="when">{{ r.at ? `checked by the explorer at ${utc(r.at)}` : "not checked by the explorer yet" }}</p>
      </li>
    </ol>
    <p v-if="note" class="note" role="status">{{ note }}</p>
    <p class="fine">
      The explorer asks its HORNET node and records the answers: that is its word, not a check made in your browser. The five checks below are
      yours.
    </p>
  </section>
</template>

<style scoped>
.tangle {
  margin-top: 28px;
}
.head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 10px 16px;
}
h2 {
  margin: 0;
  font: 400 22px/1.15 var(--serif);
  color: var(--fog-50);
}
.head .btn {
  height: 36px;
  font-size: 14px;
}
.tc {
  display: grid;
  grid-template-columns: 1fr 1fr;
  margin: 12px 0 0;
  padding: 0;
  list-style: none;
  border: 1px solid var(--hair);
  border-radius: var(--r-cell);
}
.tc li {
  padding: 14px 18px 16px;
  min-width: 0;
}
.tc li + li {
  border-left: 1px solid var(--hair);
}
.name {
  margin: 0;
  font-size: 15px;
  color: var(--fog-50);
}
.lab {
  color: var(--fog-400);
}
.via {
  margin: 4px 0 0;
  font-size: 12.5px;
  color: var(--fog-400);
  overflow-wrap: anywhere;
}
.via .mono {
  font-size: 11.5px;
}
.res {
  margin: 10px 0 0;
  font-size: 14px;
  color: var(--fog-200);
}
li[data-tone="no"] .res {
  color: var(--fail);
}
li[data-tone="open"] .res {
  color: var(--fog-400);
}
.when {
  margin: 4px 0 0;
  font-size: 12.5px;
  color: var(--fog-400);
}
.note {
  margin: 10px 0 0;
  font-size: 13.5px;
  line-height: 19px;
  color: var(--fog-200);
}
.fine {
  margin: 8px 0 0;
  font-size: 12.5px;
  line-height: 18px;
  color: var(--fog-400);
}
.muted {
  margin: 8px 0 0;
  color: var(--fog-400);
}
@media (max-width: 760px) {
  .tc {
    grid-template-columns: 1fr;
  }
  .tc li + li {
    border-left: 0;
    border-top: 1px solid var(--hair);
  }
}
</style>
