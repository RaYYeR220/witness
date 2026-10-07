<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";

import { DataError, type Checks, type Lifecycle, type RecheckResult } from "@/api/client";

import { useData } from "./data";
import { clock, LIFECYCLE, LIFECYCLE_BAD, statusLabel, utc } from "./format";

/**
 * What the explorer saw happen to the block (RECEIVED … CONTENT_VERIFIED) and
 * the brief's node checks: (c) valid and solid per the node's metadata, (d)
 * the bytes on the Tangle equal what was received. These are the server's
 * answers, shown as such; "Re-check on the node" asks it to run them again.
 */
const props = defineProps<{ blockId: string; lifecycle: Lifecycle | null; lifecycleError: string | null }>();
const emit = defineEmits<{ rechecked: [] }>();

const data = useData();
const checks = ref<Checks | null>(null);
const last = ref<RecheckResult | null>(null);
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
    checks.value = null;
    last.value = null;
    note.value = null;
    busy.value = false;
    waitS.value = 0;
    if (timer) clearInterval(timer);
    timer = null;
  },
);

const current = computed(() => checks.value ?? props.lifecycle?.checks ?? null);

const stages = computed(() => {
  const t = props.lifecycle?.transitions ?? [];
  const firstAt = (s: string) => t.find((x) => x.status === s)?.atMs ?? null;
  const path = LIFECYCLE.map((s) => ({ status: s as string, atMs: firstAt(s), bad: false }));
  const extra = t.filter((x) => LIFECYCLE_BAD.has(x.status)).map((x) => ({ status: x.status, atMs: x.atMs, bad: true }));
  if (!extra.length) return path;
  // a bad outcome replaces what would have come after the last stage reached
  const reached = path.filter((p) => p.atMs !== null);
  return [...reached, ...extra];
});

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
    const r = await data.recheck(props.blockId);
    if (ask !== asked) return; // the screen moved on to another block
    last.value = r;
    checks.value = r.checks;
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

const yesNo = (ok: boolean | null | undefined) => (ok === true ? "yes" : ok === false ? "no" : "not checked yet");
</script>

<template>
  <section class="node" aria-labelledby="life-h">
    <h2 id="life-h">What the explorer saw</h2>
    <p v-if="lifecycleError" class="muted">{{ lifecycleError }}</p>
    <p v-else-if="lifecycle && !lifecycle.transitions.length" class="muted">
      No submission was recorded for this block: it reached the Tangle without passing through the Messages API, so the explorer only saw it
      in a milestone.
    </p>
    <ol v-else-if="lifecycle" class="life">
      <li v-for="s in stages" :key="s.status" :data-reached="s.atMs !== null" :data-bad="s.bad">
        <span class="dot" aria-hidden="true"></span>
        <span class="st">{{ statusLabel(s.status) }}</span>
        <time v-if="s.atMs !== null" :title="utc(s.atMs)">{{ clock(s.atMs) }}</time>
        <span v-else class="muted">not reached</span>
      </li>
    </ol>

    <dl v-if="current" class="checks">
      <div :data-ok="current.solid.ok">
        <dt>(c) Valid and solid, per the node</dt>
        <dd>
          {{ yesNo(current.solid.ok) }}<template v-if="current.solid.referencedByMilestoneIndex">, milestone {{ current.solid.referencedByMilestoneIndex }}</template
          ><template v-if="current.solid.ledgerInclusionState">, {{ current.solid.ledgerInclusionState }}</template>
          <span v-if="current.solid.checkedAtMs" class="muted"> · {{ utc(current.solid.checkedAtMs) }}</span>
        </dd>
      </div>
      <div :data-ok="current.content.ok">
        <dt>(d) Bytes on the Tangle equal what was received</dt>
        <dd>
          {{ current.content.result ? statusLabel(current.content.result) : yesNo(current.content.ok) }}
          <span v-if="current.content.checkedAtMs" class="muted"> · {{ utc(current.content.checkedAtMs) }}</span>
        </dd>
      </div>
    </dl>

    <div class="re">
      <button class="btn" type="button" :disabled="busy || waitS > 0" @click="recheck">
        {{ busy ? "Asking the node…" : waitS > 0 ? `Re-check on the node (${waitS} s)` : "Re-check on the node" }}
      </button>
      <p v-if="note" class="note" role="status">{{ note }}</p>
      <p class="fine">The server asks its node and reports back. That is the server's word; the five checks above are yours.</p>
    </div>
  </section>
</template>

<style scoped>
h2 {
  margin: 0 0 12px;
  font: 400 15px var(--sans);
  color: var(--fog-400);
}
.life {
  list-style: none;
  margin: 0;
  padding: 0;
}
.life li {
  position: relative;
  display: grid;
  grid-template-columns: 18px minmax(0, 1fr) auto;
  align-items: baseline;
  padding: 5px 0;
  font-size: 14px;
  color: var(--fog-400);
}
.life li:not(:last-child)::before {
  content: "";
  position: absolute;
  left: 3.5px;
  top: 17px;
  bottom: -7px;
  width: 1px;
  background: var(--hair);
}
.dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  border: 1px solid var(--fog-400);
  align-self: center;
}
.life li[data-reached="true"] {
  color: var(--fog-200);
}
.life li[data-reached="true"] .dot {
  background: var(--pass);
  border-color: var(--pass);
}
.life li[data-reached="true"]:not(:last-child)::before {
  background: rgba(var(--rgb-aurora), 0.45);
}
.life li[data-bad="true"] {
  color: var(--fail);
}
.life li[data-bad="true"] .dot {
  background: var(--fail);
  border-color: var(--fail);
}
.life time {
  font-size: 12.5px;
  color: var(--fog-400);
  font-variant-numeric: tabular-nums;
}
.checks {
  margin: 16px 0 0;
  display: grid;
  gap: 10px;
}
.checks dt {
  font-size: 12.5px;
  color: var(--fog-400);
}
.checks dd {
  margin: 2px 0 0;
  font-size: 14px;
  color: var(--fog-200);
}
.checks div[data-ok="false"] dd {
  color: var(--fail);
}
.re {
  margin-top: 16px;
}
.re .btn {
  height: 38px;
  font-size: 14px;
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
  color: var(--fog-400);
}
</style>
