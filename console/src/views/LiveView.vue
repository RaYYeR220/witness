<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from "vue";

import ConsoleShell from "@/components/ConsoleShell.vue";
import { useData } from "@/console/data";
import { useLiveFeed } from "@/console/feed";
import { ago, clock, isoOf, RECORDED_NOTE, shortDid, shortHex, statusLabel, utc, verdictInfo } from "@/console/format";
import VerdictMark from "@/console/VerdictMark.vue";

/**
 * Live: trust messages as milestones confirm them, with milestones, alerts,
 * anchors and incidents in between. Each message row leads to Verify, where
 * the browser checks it.
 */
const data = useData();
const feed = useLiveFeed(data);
const { visible, held, paused, conn, counts, lastMilestone, lastAnchor, showMilestones, loading, loadError, lifecycleOf } = feed;

const now = ref(Date.now());
let tick: ReturnType<typeof setInterval> | null = null;
onMounted(() => (tick = setInterval(() => (now.value = Date.now()), 5000)));
onBeforeUnmount(() => tick && clearInterval(tick));

/** The connection in words, announced when it changes; nothing per event goes in here. */
const connLine = computed(() => {
  if (paused.value) return "Paused, new events are held";
  if (data.mode === "replay" && conn.status === "open") return "Playing back the events recorded with this snapshot";
  switch (conn.status) {
    case "open":
      return conn.lastId !== null ? "Connected" : "Connected, waiting for the next event";
    case "connecting":
      return "Connecting to the event stream";
    case "retrying":
      return `Reconnecting in ${Math.ceil((conn.retryInMs ?? 0) / 1000)} s${conn.reason ? ` (${conn.reason})` : ""}`;
    default:
      return "Stream closed";
  }
});

const toggle = () => (paused.value ? feed.resume() : feed.pause());
const score = (s: number | null) => (s === null ? "" : s.toFixed(2));
</script>

<template>
  <ConsoleShell>
    <div class="live">
      <header class="head">
        <div class="titles">
          <h1>Live</h1>
          <p class="lede">
            Trust messages as milestones confirm them, each with the verdict the indexer recorded. Open one to check it yourself, in your browser.
          </p>
        </div>
        <div class="controls">
          <p class="conn" :data-s="conn.status">
            <span class="pulse" aria-hidden="true"></span>
            <span role="status" aria-live="polite">{{ connLine }}</span>
            <!-- changes with every event: shown, not announced -->
            <span v-if="paused" class="held" aria-hidden="true">({{ held.length }})</span>
            <span v-else-if="conn.status === 'open' && conn.lastId !== null && data.mode === 'live'" aria-hidden="true"
              >, resuming after event {{ conn.lastId }} if the line drops</span
            >
          </p>
          <label class="check">
            <input v-model="showMilestones" type="checkbox" />
            <span>Milestones</span>
          </label>
          <button type="button" class="btn" :class="{ 'btn--solid': paused }" :aria-pressed="paused" @click="toggle">
            {{ paused ? `Resume${held.length ? ` (${held.length})` : ""}` : "Pause" }}
          </button>
        </div>
      </header>

      <div class="cols">
        <section class="feed" aria-labelledby="feed-h">
          <h2 id="feed-h" class="sr-only">Feed, newest first</h2>
          <p v-if="loadError" class="empty bad">Could not list recent messages: {{ loadError }}</p>
          <p v-else-if="!loading && !visible.length" class="empty">
            Nothing yet. New trust messages appear here the moment a milestone confirms them.
          </p>
          <TransitionGroup tag="ol" name="row" class="rows">
            <li v-for="r in visible" :key="r.key" :data-kind="r.kind">
              <RouterLink v-if="r.kind === 'message'" class="msg" :to="{ name: 'verify', params: { blockId: r.blockId } }" :data-f="verdictInfo(r.verdict).family">
                <span class="mk"><VerdictMark :family="verdictInfo(r.verdict).family" /></span>
                <span class="vd" :title="RECORDED_NOTE">{{ verdictInfo(r.verdict).label }}<span class="rec">recorded</span></span>
                <span class="what">
                  <span class="tag">{{ r.tag ?? "untagged" }}</span>
                  <span v-if="r.score !== null" class="score">{{ score(r.score) }}</span>
                  <span v-if="r.encrypted" class="sealed">sealed</span>
                </span>
                <span class="ie mono" :title="r.ieId ?? undefined">{{ r.ieId ?? "no IE" }}</span>
                <span class="iss mono" :title="r.iss ?? undefined">{{ r.iss ? shortDid(r.iss) : "unsigned" }}</span>
                <span class="ms">{{ r.msIndex !== null ? `ms ${r.msIndex}` : "pending" }}</span>
                <time class="at" :datetime="isoOf(r.atMs) ?? undefined" :title="utc(r.atMs)">
                  <span class="clk">{{ clock(r.atMs) }}</span><span class="ago">{{ ago(r.atMs, now) }}</span>
                </time>
                <span v-if="lifecycleOf(r.blockId)" class="sr-only"
                  >, lifecycle as the explorer recorded it: {{ lifecycleOf(r.blockId)!.filter((s) => s.reached).map((s) => statusLabel(s.status)).join(", ") }}</span
                >
                <span v-if="lifecycleOf(r.blockId)" class="lc" aria-hidden="true">
                  <span
                    v-for="s in lifecycleOf(r.blockId)!"
                    :key="s.status"
                    class="lc-step"
                    :data-r="s.reached"
                    :data-bad="s.bad"
                    :title="s.atMs ? `${statusLabel(s.status)} at ${utc(s.atMs)}` : statusLabel(s.status)"
                    >{{ statusLabel(s.status).toLowerCase() }}</span
                  >
                </span>
                <span class="sr-only">, the explorer's recorded verdict; open to check block {{ r.blockId }} in your browser</span>
              </RouterLink>

              <div v-else-if="r.kind === 'milestone'" class="ms-row">
                <span class="diamond" aria-hidden="true"></span>
                <span>Milestone <b>{{ r.index }}</b></span>
                <span class="muted">{{ r.blocks ?? "?" }} {{ r.blocks === 1 ? "block" : "blocks" }}{{ r.messages !== null ? `, ${r.messages} new ${r.messages === 1 ? "message" : "messages"}` : "" }}</span>
                <time class="at" :title="utc(r.atMs)">{{ clock(r.atMs) }}</time>
              </div>

              <div v-else-if="r.kind === 'alert'" class="note-row alert" :data-sev="r.severity">
                <span class="mk"><VerdictMark family="rejected" /></span>
                <span>
                  <b>{{ r.rule }}</b> <span class="muted">{{ r.severity }}</span>
                  <template v-if="r.blockId">
                    on
                    <RouterLink class="mono" :to="{ name: 'verify', params: { blockId: r.blockId } }">{{ shortHex(r.blockId) }}</RouterLink>
                  </template>
                  <span v-if="r.ieId" class="mono muted"> {{ r.ieId }}</span>
                </span>
                <time class="at" :title="utc(r.atMs)">{{ clock(r.atMs) }}</time>
              </div>

              <div v-else-if="r.kind === 'anchor'" class="note-row anchor">
                <span class="mk"><VerdictMark family="signed" /></span>
                <span>
                  Checkpoint <b>{{ r.seq ?? "" }}</b> anchored on IOTA Rebased{{ r.network ? ` ${r.network}` : "" }}:
                  milestones {{ r.from }}–{{ r.to }}<template v-if="r.record !== null">, record {{ r.record }}</template>
                </span>
                <time class="at" :title="utc(r.atMs)">{{ clock(r.atMs) }}</time>
              </div>

              <div v-else-if="r.kind === 'incident'" class="note-row incident">
                <span class="mk"><VerdictMark family="unknown" /></span>
                <span>
                  Incident {{ r.change }}: <b>{{ r.title }}</b> <span v-if="r.severity" class="muted">{{ r.severity }}</span>
                </span>
                <time class="at" :title="utc(r.atMs)">{{ clock(r.atMs) }}</time>
              </div>
            </li>
          </TransitionGroup>
          <p v-if="loading" class="empty">Listing recent messages…</p>
        </section>

        <aside class="rail" aria-label="This session">
          <h2>New since you opened this page, as recorded</h2>
          <dl class="tally">
            <div><dt><VerdictMark family="signed" />Signed</dt><dd>{{ counts.signed }}</dd></div>
            <div><dt><VerdictMark family="unsigned" />Unsigned</dt><dd>{{ counts.unsigned }}</dd></div>
            <div><dt><VerdictMark family="rejected" />Rejected</dt><dd>{{ counts.rejected }}</dd></div>
            <div><dt><span class="diamond" aria-hidden="true"></span>Alerts</dt><dd>{{ counts.alerts }}</dd></div>
          </dl>
          <dl class="facts">
            <div>
              <dt>Last milestone</dt>
              <dd>{{ lastMilestone ? `${lastMilestone.index}, ${ago(lastMilestone.atMs, now)}` : "none yet" }}</dd>
            </div>
            <div>
              <dt>Last anchor</dt>
              <dd>{{ lastAnchor ? `milestones ${lastAnchor.from}–${lastAnchor.to}` : "none yet" }}</dd>
            </div>
          </dl>
          <p class="aside-note">
            Verdicts here are what the indexer recorded. The checks that matter run in your browser when you open a message, against keys
            built into this console.
          </p>
        </aside>
      </div>
    </div>
  </ConsoleShell>
</template>

<style scoped>
.head {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 24px 40px;
  flex-wrap: wrap;
  padding-bottom: 24px;
  border-bottom: 1px solid var(--hair);
}
h1 {
  margin: 0;
  font: 400 var(--fs-h2) / 1 var(--serif);
  letter-spacing: -0.012em;
  color: var(--fog-50);
}
.lede {
  margin: 12px 0 0;
  max-width: 60ch;
  font-size: var(--fs-body);
  color: var(--fog-200);
}
.controls {
  display: flex;
  align-items: center;
  gap: 20px;
  flex-wrap: wrap;
}
.conn {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  margin: 0;
  font-size: 13px;
  color: var(--fog-400);
}
.conn .held {
  margin-left: 0.35em;
}
.pulse {
  margin-right: 9px;
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--fog-400);
}
.conn[data-s="open"] .pulse {
  background: var(--pass);
  animation: breathe 2.4s ease-in-out infinite;
}
.conn[data-s="retrying"] {
  color: var(--ember);
}
.conn[data-s="retrying"] .pulse {
  background: var(--ember);
}
@keyframes breathe {
  0%,
  100% {
    box-shadow: 0 0 0 0 rgba(var(--rgb-aurora), 0.35);
  }
  50% {
    box-shadow: 0 0 0 5px rgba(var(--rgb-aurora), 0);
  }
}
.check {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  font-size: 14px;
  color: var(--fog-200);
  cursor: pointer;
}
.check input {
  accent-color: var(--ember);
  width: 15px;
  height: 15px;
  margin: 0;
}

.cols {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 272px;
  gap: 48px;
  margin-top: 8px;
}

.rows {
  list-style: none;
  margin: 0;
  padding: 0;
}
.rows > li {
  border-bottom: 1px solid var(--hair);
}
.msg {
  display: grid;
  grid-template-columns: 14px 148px minmax(120px, 1fr) minmax(0, 190px) minmax(0, 220px) 78px 116px;
  align-items: baseline;
  column-gap: 14px;
  padding: 15px 10px 14px 6px;
  color: inherit;
  text-decoration: none;
  transition: background var(--t-quick);
}
.msg:hover {
  background: rgba(var(--rgb-fog-50), 0.03);
}
.msg:focus-visible {
  outline-offset: -2px;
}
.mk {
  align-self: center;
  display: flex;
}
.vd {
  font-size: 14px;
  color: var(--fog-50);
}
.rec {
  display: block;
  font-size: 11.5px;
  line-height: 1.3;
  color: var(--fog-400);
}
.msg[data-f="rejected"] .vd {
  color: var(--fail);
}
.msg[data-f="unsigned"] .vd,
.msg[data-f="unknown"] .vd {
  color: var(--fog-200);
}
.what {
  display: flex;
  align-items: baseline;
  gap: 12px;
  min-width: 0;
}
.tag {
  font-size: 14px;
  color: var(--fog-200);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.score {
  font: 400 22px/1 var(--serif);
  color: var(--fog-50);
}
.lc {
  grid-column: 3 / -1;
  display: flex;
  flex-wrap: wrap;
  gap: 2px 0;
  font-size: 12px;
  color: var(--fog-400);
}
.lc-step + .lc-step::before {
  content: "→";
  margin: 0 7px;
  color: var(--hair-strong);
}
/* the explorer's record: reached steps are plain, not green */
.lc-step[data-r="true"] {
  color: var(--fog-200);
}
.lc-step[data-bad="true"] {
  color: var(--fail);
}
.sealed {
  font-size: 12px;
  padding: 1px 8px;
  border-radius: var(--r-pill);
  border: 1px solid var(--hair-strong);
  color: var(--fog-200);
}
.ie,
.iss {
  color: var(--fog-200);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.ms {
  font-size: 13px;
  color: var(--fog-400);
  font-variant-numeric: tabular-nums;
}
.at {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
  font-size: 13px;
  color: var(--fog-400);
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}
.clk {
  color: var(--fog-200);
}

.ms-row,
.note-row {
  display: grid;
  grid-template-columns: 14px minmax(0, 1fr) auto;
  align-items: baseline;
  column-gap: 14px;
  padding: 10px 10px 10px 6px;
  font-size: 13.5px;
  color: var(--fog-400);
}
.ms-row {
  grid-template-columns: 14px auto minmax(0, 1fr) auto;
}
.ms-row b,
.note-row b {
  font-weight: 500;
  color: var(--fog-200);
}
.diamond {
  display: inline-block;
  align-self: center;
  width: 7px;
  height: 7px;
  margin-left: 2px;
  border: 1px solid var(--fog-400);
  transform: rotate(45deg);
}
.note-row .mk {
  align-self: start;
  margin-top: 5px;
}
.note-row.alert {
  color: var(--fog-200);
  background: var(--nova-wash);
}
.note-row.alert b {
  color: var(--fail);
}
.note-row a {
  color: var(--fog-50);
  text-underline-offset: 3px;
}
.muted {
  color: var(--fog-400);
}

.empty {
  margin: 0;
  padding: 28px 6px;
  color: var(--fog-400);
}
.empty.bad {
  color: var(--fail);
}

.row-enter-active {
  transition:
    opacity 420ms var(--ease-out),
    transform 420ms var(--ease-out),
    background 1.6s ease;
}
.row-enter-from {
  opacity: 0;
  transform: translateY(-6px);
  background: rgba(var(--rgb-ember), 0.08);
}
.row-leave-active {
  display: none;
}

.rail {
  padding-top: 18px;
}
.rail h2 {
  margin: 0 0 14px;
  font: 400 15px/20px var(--sans);
  color: var(--fog-400);
}
.tally,
.facts {
  margin: 0;
  display: grid;
  gap: 2px;
}
.tally div,
.facts div {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  padding: 8px 0;
  border-bottom: 1px solid var(--hair);
}
.tally dt {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 14px;
  color: var(--fog-200);
}
.tally dd {
  margin: 0;
  font: 400 24px/1 var(--serif);
  color: var(--fog-50);
  font-variant-numeric: tabular-nums;
}
.facts {
  margin-top: 22px;
}
.facts dt {
  font-size: 13px;
  color: var(--fog-400);
}
.facts dd {
  margin: 0;
  font-size: 13px;
  color: var(--fog-200);
  text-align: right;
}
.aside-note {
  margin: 22px 0 0;
  font-size: 13px;
  line-height: 20px;
  color: var(--fog-400);
}

@media (max-width: 1240px) {
  .msg {
    grid-template-columns: 14px 132px minmax(100px, 1fr) minmax(0, 170px) 74px 76px;
  }
  .iss {
    display: none;
  }
  .ago {
    display: none;
  }
}
@media (max-width: 980px) {
  .cols {
    grid-template-columns: minmax(0, 1fr);
    gap: 24px;
  }
  .rail {
    order: -1;
    padding-top: 0;
  }
  .rail h2,
  .facts,
  .aside-note {
    display: none;
  }
  .tally {
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 12px;
  }
  .tally div {
    flex-direction: column;
    align-items: flex-start;
    gap: 4px;
    border: 0;
  }
}
@media (max-width: 760px) {
  .controls {
    width: 100%;
    justify-content: space-between;
  }
  .conn {
    flex-basis: 100%;
  }
  .msg {
    grid-template-columns: 14px minmax(0, 1fr) auto;
    grid-template-areas:
      "mk vd at"
      ". what what"
      ". ie ie"
      ". lc lc";
    row-gap: 4px;
    padding: 13px 4px;
  }
  .msg .mk {
    grid-area: mk;
  }
  .msg .vd {
    grid-area: vd;
  }
  .msg .at {
    grid-area: at;
  }
  .msg .what {
    grid-area: what;
  }
  .msg .ie {
    grid-area: ie;
  }
  .msg .lc {
    grid-area: lc;
  }
  .msg .ms {
    display: none;
  }
  .ms-row .muted {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .tally dd {
    font-size: 20px;
  }
  .tally dt {
    font-size: 12.5px;
    gap: 6px;
  }
}
</style>
