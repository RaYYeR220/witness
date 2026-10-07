<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from "vue";

import { score2, utc, verdictInfo } from "@/console/format";

import { makeScale, nearest, onLine, type OrionView, type Overlay, type SeriesPoint } from "./model";

/**
 * The trust score history of one IE as an SVG chart drawn here (no chart
 * library): the ledger's scores over time, Orion's current value as a dashed
 * line, incidents as bands and alerts as diamonds on the time axis. Pointing
 * at the chart reads the nearest score; clicking it selects that message.
 * Screen readers and keyboards get the same data from the table next to it.
 */
const props = defineProps<{
  points: SeriesPoint[];
  orion: OrionView;
  overlays: Overlay[];
  /** The score the ledger vouches for now, ringed. */
  latestBlockId: string | null;
  label: string;
}>();
const emit = defineEmits<{ select: [blockId: string] }>();

const wrap = ref<HTMLElement | null>(null);
const width = ref(720);
let ro: ResizeObserver | null = null;
onMounted(() => {
  const el = wrap.value;
  if (!el) return;
  if (el.clientWidth) width.value = el.clientWidth;
  if (typeof ResizeObserver === "undefined") return;
  ro = new ResizeObserver((entries) => {
    const w = entries[0]?.contentRect.width;
    if (w) width.value = Math.max(280, Math.round(w));
  });
  ro.observe(el);
});
onBeforeUnmount(() => ro?.disconnect());

const narrow = computed(() => width.value < 560);
const height = computed(() => (narrow.value ? 220 : 270));
const orionValue = computed(() => props.orion.value);
const box = computed(() => ({
  left: 40,
  right: width.value - (orionValue.value !== null ? (narrow.value ? 58 : 74) : 10),
  top: 16,
  bottom: height.value - 42,
}));
const scale = computed(() =>
  makeScale(props.points, box.value, { values: [orionValue.value], times: props.overlays.map((o) => o.startMs) }, narrow.value ? 3 : 6),
);
const X = (ms: number) => scale.value.x(ms);
const yLabel = (t: number) => String(Number(t.toFixed(2)));
const Y = (s: number) => scale.value.y(s);

const line = computed(() =>
  props.points
    .filter(onLine)
    .map((p, i) => `${i ? "L" : "M"}${X(p.atMs).toFixed(1)},${Y(p.score).toFixed(1)}`)
    .join(" "),
);

/** Incident bands and alert marks that fall inside the time axis. */
const bands = computed(() => {
  const s = scale.value;
  return props.overlays
    .filter((o) => o.kind === "incident" && o.startMs <= s.t1 && (o.endMs ?? s.t1) >= s.t0)
    .map((o) => {
      const x0 = Math.max(box.value.left, X(o.startMs));
      const x1 = Math.min(box.value.right, X(o.endMs ?? s.t1));
      return { o, x: x0, w: Math.max(2, x1 - x0) };
    });
});
const marks = computed(() => {
  const s = scale.value;
  return props.overlays.filter((o) => o.kind === "alert" && o.startMs >= s.t0 && o.startMs <= s.t1).map((o) => ({ o, x: X(o.startMs) }));
});

const hover = ref<SeriesPoint | null>(null);
function pick(ev: MouseEvent): SeriesPoint | null {
  const svg = ev.currentTarget as SVGSVGElement;
  const r = svg.getBoundingClientRect();
  if (!r.width) return null;
  const px = (ev.clientX - r.left) * (width.value / r.width);
  const s = scale.value;
  const ms = s.t0 + ((px - box.value.left) / (box.value.right - box.value.left)) * (s.t1 - s.t0);
  return nearest(props.points, ms);
}
const onMove = (ev: MouseEvent) => (hover.value = pick(ev));
function onClick(ev: MouseEvent) {
  const p = pick(ev) ?? hover.value;
  if (p) emit("select", p.blockId);
}
const readoutLeft = computed(() => {
  if (!hover.value) return 0;
  return Math.min(Math.max(X(hover.value.atMs) - 90, 0), width.value - 190);
});
</script>

<template>
  <div ref="wrap" class="chart">
    <svg
      class="plot"
      :width="width"
      :height="height"
      :viewBox="`0 0 ${width} ${height}`"
      role="img"
      :aria-label="label"
      :data-hover="hover ? 'yes' : 'no'"
      @mousemove="onMove"
      @mouseleave="hover = null"
      @click="onClick"
    >
      <g class="grid">
        <g v-for="t in scale.yTicks" :key="`y${t}`">
          <line :x1="box.left" :x2="box.right" :y1="Y(t)" :y2="Y(t)" />
          <text :x="box.left - 8" :y="Y(t) + 4" text-anchor="end">{{ yLabel(t) }}</text>
        </g>
        <g v-for="t in scale.xTicks" :key="`x${t.at}`">
          <line class="tick" :x1="X(t.at)" :x2="X(t.at)" :y1="box.bottom" :y2="box.bottom + 4" />
          <text :x="X(t.at)" :y="box.bottom + 32" text-anchor="middle">{{ t.label }}</text>
        </g>
      </g>

      <g class="bands">
        <g v-for="b in bands" :key="b.o.key" class="band" :data-sev="b.o.severity">
          <rect :x="b.x" :y="box.top" :width="b.w" :height="box.bottom - box.top" />
          <line :x1="b.x" :x2="b.x" :y1="box.top" :y2="box.bottom" />
          <text v-if="b.w > 60" :x="b.x + 6" :y="box.top + 12">incident {{ b.o.id }}</text>
        </g>
      </g>

      <path v-if="line" class="line" :d="line" />

      <g v-if="orionValue !== null" class="orion-mark" :data-drift="orion.drift ? 'yes' : 'no'">
        <line :x1="box.left" :x2="box.right" :y1="Y(orionValue)" :y2="Y(orionValue)" />
        <text :x="box.right + 8" :y="Y(orionValue) - 3">Orion</text>
        <text class="v" :x="box.right + 8" :y="Y(orionValue) + 12">{{ score2(orionValue) }}</text>
      </g>

      <g class="points">
        <g v-for="p in points" :key="p.blockId" class="pt" :data-f="p.family" :transform="`translate(${X(p.atMs).toFixed(1)},${Y(p.score).toFixed(1)})`">
          <circle v-if="p.blockId === latestBlockId" class="latest" r="7" />
          <circle v-if="p.family === 'signed'" r="3.2" class="seal" />
          <circle v-else-if="p.family === 'unsigned'" r="3" class="ring" />
          <path v-else-if="p.family === 'rejected'" class="cross" d="M-3.4,-3.4L3.4,3.4M3.4,-3.4L-3.4,3.4" />
          <circle v-else r="3" class="dotted" />
        </g>
      </g>

      <g class="marks">
        <rect
          v-for="m in marks"
          :key="m.o.key"
          class="mark"
          :data-sev="m.o.severity"
          :x="m.x - 3.5"
          :y="box.bottom + 8"
          width="7"
          height="7"
          :transform="`rotate(45 ${m.x} ${box.bottom + 11.5})`"
        />
      </g>

      <line v-if="hover" class="guide" :x1="X(hover.atMs)" :x2="X(hover.atMs)" :y1="box.top" :y2="box.bottom" />
    </svg>
    <div v-if="hover" class="readout" :style="{ left: `${readoutLeft}px` }" aria-hidden="true">
      <b>{{ score2(hover.score) }}</b> <span>{{ verdictInfo(hover.verdict).label }}</span>
      <span class="when">{{ utc(hover.atMs) }}<template v-if="hover.msIndex !== null">, ms {{ hover.msIndex }}</template></span>
      <span class="go">Click to verify this message</span>
    </div>
  </div>
</template>

<style scoped>
.chart {
  position: relative;
  width: 100%;
  min-width: 0;
}
.plot {
  display: block;
  max-width: 100%;
  cursor: crosshair;
  font-family: var(--sans);
}
.grid line {
  stroke: var(--hair);
  stroke-width: 1;
}
.grid .tick {
  stroke: var(--hair-strong);
}
.grid text {
  fill: var(--fog-400);
  font-size: 11px;
  font-variant-numeric: tabular-nums;
}
.band rect {
  fill: rgba(var(--rgb-nova), 0.07);
}
.band line {
  stroke: rgba(var(--rgb-nova), 0.55);
  stroke-width: 1;
}
.band[data-sev="medium"] rect,
.band[data-sev="low"] rect {
  fill: rgba(var(--rgb-fog-200), 0.06);
}
.band[data-sev="medium"] line,
.band[data-sev="low"] line {
  stroke: var(--hair-strong);
}
.band text {
  fill: var(--fog-200);
  font-size: 11px;
}
.line {
  fill: none;
  stroke: var(--fog-200);
  stroke-width: 1.3;
  stroke-linejoin: round;
  opacity: 0.75;
}
.orion-mark line {
  stroke: var(--fog-50);
  stroke-width: 1.2;
  stroke-dasharray: 5 4;
}
.orion-mark text {
  fill: var(--fog-400);
  font-size: 11px;
}
.orion-mark text.v {
  fill: var(--fog-50);
  font-size: 13px;
  font-variant-numeric: tabular-nums;
}
.orion-mark[data-drift="yes"] line {
  stroke: var(--fail);
}
.orion-mark[data-drift="yes"] text.v {
  fill: var(--fail);
}
.seal {
  fill: var(--pass);
}
.ring {
  fill: var(--void);
  stroke: var(--fog-200);
  stroke-width: 1.2;
}
.cross {
  stroke: var(--fail);
  stroke-width: 1.5;
  stroke-linecap: round;
}
.dotted {
  fill: none;
  stroke: var(--fog-400);
  stroke-dasharray: 1.2 2;
}
.latest {
  fill: none;
  stroke: var(--fog-50);
  stroke-width: 1.1;
}
.mark {
  fill: none;
  stroke: var(--fog-400);
  stroke-width: 1;
}
.mark[data-sev="critical"] {
  fill: var(--fail);
  stroke: var(--fail);
}
.mark[data-sev="high"] {
  stroke: var(--fail);
}
.mark[data-sev="medium"] {
  stroke: var(--fog-200);
}
.guide {
  stroke: var(--ember);
  stroke-width: 1;
  opacity: 0.7;
}
.readout {
  position: absolute;
  top: 0;
  width: 190px;
  padding: 8px 10px;
  border: 1px solid var(--hair-strong);
  border-radius: var(--r-cell);
  background: var(--void-raised);
  font-size: 12.5px;
  line-height: 17px;
  color: var(--fog-200);
  pointer-events: none;
}
.readout b {
  font: 400 20px/1 var(--serif);
  color: var(--fog-50);
}
.readout .when,
.readout .go {
  display: block;
  color: var(--fog-400);
}
.readout .go {
  margin-top: 4px;
  color: var(--ember);
}
</style>
