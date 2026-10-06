<script setup lang="ts">
/**
 * Flip a byte of the sample block and watch the library re-run the ladder on
 * the edited bundle. The hash, the bit portrait and every step come from
 * @witness/verify computing over the bytes as they are now.
 */
import { blake2b256, toHex } from "@witness/verify";
import { computed, nextTick, onBeforeUnmount, onMounted, reactive, ref, shallowRef, watch } from "vue";

import StepList from "@/components/StepList.vue";
import { mulberry32 } from "@/sky/model";
import { createLadder, runLadder } from "@/verify/ladder";
import {
  blockFields,
  bundleText,
  claimedId,
  fieldOf,
  rawBytes,
  readTrustMessage,
  scoreDigitIndex,
  sampleRun,
  shortHex,
} from "@/verify/sample";

import { bundleFacts, glosses, SAMPLE_NOTE } from "./facts";

const facts = bundleFacts("sample");
const gloss = glosses(facts);
const original = rawBytes("sample");
const fields = blockFields(original);
const envelope = fields.find((f) => f.name === "signed envelope");
const claimed = claimedId("sample");

const bytes = shallowRef(new Uint8Array(original));
const flipped = reactive(new Set<number>());
const ladder = createLadder();
const hash = computed(() => toHex(blake2b256(bytes.value)));
const changedBits = ref<boolean[]>([]);
const readout = ref("");
const cursor = ref(0);
const hovered = ref(-1);
const dirty = computed(() => flipped.size > 0);

const mq = typeof matchMedia === "function" ? matchMedia("(max-width: 760px)") : null;
const cols = ref(mq?.matches ? 16 : 32);
const rows = computed(() => {
  const out: number[][] = [];
  for (let i = 0; i < bytes.value.length; i += cols.value) out.push([...Array(Math.min(cols.value, bytes.value.length - i)).keys()].map((k) => i + k));
  return out;
});

const DEFAULT = "Point at a byte to read it. Click it to flip its lowest bit.";
const hx = (v: number) => v.toString(16).padStart(2, "0");
const printable = (v: number) => (v >= 32 && v < 127 ? String.fromCharCode(v) : null);

function describeByte(i: number) {
  const v = bytes.value[i]!;
  const f = fieldOf(fields, i);
  const ch = printable(v);
  return `Byte ${i} is 0x${hx(v)}${ch ? ` (${ch})` : ""}, part of the ${f?.name ?? "block"}.`;
}

function bitDiff(a: string, b: string) {
  const x = a.slice(2);
  const y = b.slice(2);
  const out: boolean[] = [];
  let n = 0;
  for (let k = 0; k < 256; k++) {
    const nib = k >> 2;
    const sh = 3 - (k & 3);
    const d = ((parseInt(x[nib]!, 16) >> sh) & 1) !== ((parseInt(y[nib]!, 16) >> sh) & 1);
    out.push(d);
    if (d) n++;
  }
  return { bits: out, n };
}

async function recompute() {
  await runLadder(ladder, bundleText("sample", bytes.value), sampleRun("sample"));
}

function flip(i: number) {
  const next = new Uint8Array(bytes.value);
  const before = next[i]!;
  next[i] = before ^ 1;
  if (next[i] === original[i]) flipped.delete(i);
  else flipped.add(i);
  const old = hash.value;
  bytes.value = next;
  const d = bitDiff(old, hash.value);
  changedBits.value = d.bits;
  flashUntil = performance.now() + 1200;
  let text = `Byte ${i}: 0x${hx(before)} to 0x${hx(next[i]!)}. `;
  const msg = readTrustMessage(next);
  if (msg.scoreText !== null && msg.scoreText !== facts.scoreText) text += `The message now claims a score of ${msg.scoreText}. `;
  text += `${d.n} of 256 hash bits changed.`;
  readout.value = text;
  cursor.value = i;
  void recompute();
  drawPortrait();
}

const rnd = mulberry32(0x0c1e7);
let firstFlip = true;
function flipSuggested() {
  const i = firstFlip ? scoreDigitIndex(bytes.value, fields) : Math.floor(rnd() * bytes.value.length);
  firstFlip = false;
  flip(i);
}

function restore() {
  bytes.value = new Uint8Array(original);
  flipped.clear();
  firstFlip = true;
  changedBits.value = [];
  readout.value = `Original bytes restored. ${DEFAULT}`;
  void recompute();
  drawPortrait();
}

// ---------------------------------------------------------------- the grid, keyboard first
const dump = ref<HTMLElement | null>(null);
function cellEl(i: number) {
  return dump.value?.querySelector<HTMLElement>(`[data-i="${i}"]`) ?? null;
}
function onKey(e: KeyboardEvent, i: number) {
  const d: Record<string, number> = { ArrowLeft: -1, ArrowRight: 1, ArrowUp: -cols.value, ArrowDown: cols.value };
  const step = d[e.key];
  if (step !== undefined) {
    e.preventDefault();
    const j = Math.max(0, Math.min(bytes.value.length - 1, i + step));
    cursor.value = j;
    readout.value = describeByte(j);
    void nextTick(() => cellEl(j)?.focus());
  } else if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    flip(i);
  }
}
function onOver(i: number) {
  hovered.value = i;
  readout.value = describeByte(i);
}
function onOut() {
  hovered.value = -1;
}

// ---------------------------------------------------------------- the hash, bit by bit
const portrait = ref<HTMLCanvasElement | null>(null);
let flashUntil = 0;
let flashRaf = 0;
const reduced = typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;
function drawPortrait() {
  cancelAnimationFrame(flashRaf);
  flashRaf = 0;
  const cv = portrait.value;
  if (!cv) return;
  const ps = mq?.matches ? 6 : 7;
  const size = ps * 16;
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  if (cv.width !== Math.round(size * dpr)) {
    cv.width = Math.round(size * dpr);
    cv.height = Math.round(size * dpr);
    cv.style.width = `${size}px`;
    cv.style.height = `${size}px`;
  }
  const cx = cv.getContext("2d");
  if (!cx) return;
  cx.setTransform(dpr, 0, 0, dpr, 0, 0);
  cx.clearRect(0, 0, size, size);
  const h = hash.value.slice(2);
  const flash = !reduced && performance.now() < flashUntil;
  for (let k = 0; k < 256; k++) {
    const on = (parseInt(h[k >> 2]!, 16) >> (3 - (k & 3))) & 1;
    const x = (k % 16) * ps + ps / 2;
    const y = Math.floor(k / 16) * ps + ps / 2;
    if (flash && changedBits.value[k]) {
      cx.fillStyle = "#FF5A6E";
      cx.beginPath();
      cx.arc(x, y, ps * 0.36, 0, Math.PI * 2);
      cx.fill();
      continue;
    }
    cx.fillStyle = on ? "#EEF6F3" : "rgba(238,246,243,.13)";
    cx.beginPath();
    cx.arc(x, y, on ? ps * 0.34 : ps * 0.16, 0, Math.PI * 2);
    cx.fill();
  }
  if (flash) flashRaf = requestAnimationFrame(drawPortrait);
}

const hexLines = computed(() => {
  const h = hash.value.slice(2);
  const c = claimed.slice(2);
  const lines: { ch: string; diff: boolean }[][] = [];
  for (let l = 0; l < 4; l++) lines.push([...h.slice(l * 16, l * 16 + 16)].map((ch, k) => ({ ch, diff: ch !== c[l * 16 + k] })));
  return lines;
});
const matches = computed(() => hash.value === claimed);

const verdict = computed(() => {
  if (ladder.running || !ladder.overall) return { b: "", bad: false, t: "Checking in your browser…" };
  const ms = Math.max(1, Math.round(ladder.computeMs ?? 0));
  if (ladder.overall === "VALID") return { b: "Verified.", bad: false, t: `All five checks pass on ${dirty.value ? "these" : "the original"} bytes, ${ms} ms.` };
  const failing = ladder.steps.filter((s) => s.status === "fail").map((s) => s.n);
  const holding = ladder.steps.filter((s) => s.status === "pass").map((s) => s.n);
  const list = (xs: number[]) => (xs.length > 1 ? `${xs.slice(0, -1).join(", ")} and ${xs[xs.length - 1]}` : `${xs[0]}`);
  let t = `${failing.length === 1 ? "Check" : "Checks"} ${list(failing)} now fail${failing.length === 1 ? "s" : ""}.`;
  if (holding.length && failing.includes(1))
    t += ` ${holding.length === 1 ? "Check" : "Checks"} ${list(holding)} still vouch for the id ${shortHex(claimed)}, but these bytes no longer hash to it.`;
  return { b: `Broken at check ${ladder.failedAt}.`, bad: true, t };
});

function onMq() {
  cols.value = mq?.matches ? 16 : 32;
  drawPortrait();
}

onMounted(async () => {
  readout.value = DEFAULT;
  mq?.addEventListener("change", onMq);
  drawPortrait();
  await recompute();
});
onBeforeUnmount(() => {
  mq?.removeEventListener("change", onMq);
  cancelAnimationFrame(flashRaf);
});
watch(hash, () => drawPortrait());
</script>

<template>
  <section id="flip" class="flip" aria-labelledby="flip-h">
    <div class="inner">
      <header class="head">
        <h2 id="flip-h">Flip one byte.</h2>
        <p>
          The {{ original.length }} raw bytes of the sample block. Your browser hashes them with BLAKE2b-256 and re-runs all five checks after
          every change. Click a byte to flip its lowest bit.
        </p>
      </header>

      <div class="body">
        <div class="plate">
          <div ref="dump" class="dump" role="grid" :aria-label="`Raw bytes of the sample block, ${cols} per row. Arrow keys move, Enter flips the lowest bit.`" :style="{ '--cols': cols }" @pointerleave="onOut">
            <div v-for="(row, r) in rows" :key="r" class="row" role="row">
              <span
                v-for="i in row"
                :key="i"
                :data-i="i"
                role="gridcell"
                :tabindex="i === cursor ? 0 : -1"
                :class="{ env: envelope && i >= envelope.from && i < envelope.to, x: flipped.has(i), hot: i === hovered }"
                :aria-label="`Byte ${i}, 0x${hx(bytes[i]!)}${flipped.has(i) ? ', flipped' : ''}`"
                @pointerover="onOver(i)"
                @click="flip(i)"
                @keydown="onKey($event, i)"
                @focus="readout = describeByte(i)"
                >{{ hx(bytes[i]!) }}</span
              >
            </div>
          </div>
        </div>
        <div class="controls">
          <p class="readout" aria-live="polite">{{ readout }}</p>
          <div class="actions">
            <button class="btn" type="button" @click="flipSuggested">Flip a byte</button>
            <button class="btn btn--ghost" type="button" :disabled="!dirty" @click="restore">Restore</button>
          </div>
        </div>

        <div class="result">
          <div class="hash-row">
            <canvas ref="portrait" role="img" :aria-label="`The 256 bits of the computed hash ${shortHex(hash)}${matches ? ', equal to the block id' : ', no longer equal to the block id'}`"></canvas>
            <div>
              <p class="hex mono" aria-hidden="true">
                <span v-for="(line, l) in hexLines" :key="l" class="line"><i v-for="(c, k) in line" :key="k" :class="{ d: c.diff }">{{ c.ch }}</i></span>
              </p>
              <p class="cmp">
                <template v-if="matches"><b>Equals the block id.</b> BLAKE2b-256 of the bytes on the left, computed here.</template>
                <template v-else><b class="bad">Not the block id</b> {{ shortHex(claimed) }} any more.</template>
              </p>
            </div>
          </div>
          <StepList :steps="ladder.steps" :glosses="gloss" :open="dirty" />
          <p class="verdict" aria-live="polite">
            <b v-if="verdict.b" :class="{ bad: verdict.bad }">{{ verdict.b }}</b> {{ verdict.t }}
          </p>
          <p class="sample-note">{{ SAMPLE_NOTE }}</p>
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.flip {
  position: relative;
  background: var(--void);
  padding: var(--sp-10) var(--gut) 128px;
}
.inner {
  max-width: var(--content);
  margin: 0 auto;
}
.head {
  max-width: 620px;
}
h2 {
  margin: 0;
  font: 400 var(--fs-h2) / 1 var(--serif);
  letter-spacing: -0.012em;
  color: var(--fog-50);
}
.head p {
  margin: 18px 0 0;
  max-width: 52ch;
  font-size: 16px;
  line-height: 26px;
}
.body {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  grid-template-areas:
    "plate result"
    "controls result";
  grid-template-rows: auto 1fr;
  column-gap: 72px;
  margin-top: 52px;
  align-items: start;
}
.plate {
  grid-area: plate;
}
.controls {
  grid-area: controls;
}
.dump {
  font: 400 11px/20px var(--mono);
  user-select: none;
}
.row {
  display: grid;
  grid-template-columns: repeat(var(--cols), 20px);
}
.dump span {
  text-align: center;
  color: rgba(var(--rgb-fog-200), 0.62);
  border-radius: var(--r-cell);
  cursor: pointer;
  transition:
    color 120ms,
    background 120ms;
}
.dump span.env {
  color: rgba(var(--rgb-fog-50), 0.82);
}
.dump span.hot,
.dump span:focus-visible {
  background: var(--fog-50);
  color: var(--void);
  outline: none;
}
.dump span.x {
  color: var(--nova);
  background: var(--nova-wash);
}
.dump span.x.hot,
.dump span.x:focus-visible {
  background: var(--nova);
  color: var(--void);
}
.readout {
  margin: 16px 0 0;
  min-height: 40px;
  max-width: 640px;
  font-size: 13.5px;
  line-height: 20px;
  color: var(--fog-400);
}
.actions {
  display: flex;
  gap: 8px;
  margin-top: 8px;
}
.result {
  grid-area: result;
  min-width: 0;
  max-width: 420px;
}
.hash-row {
  display: flex;
  gap: 22px;
  align-items: flex-start;
  margin: 2px 0 30px;
}
.hash-row canvas {
  flex: none;
  display: block;
}
.hex {
  margin: 0;
  font-size: 13px;
  line-height: 21px;
  letter-spacing: 0.04em;
  color: var(--fog-50);
}
.hex .line {
  display: block;
}
.hex i {
  font-style: normal;
}
.hex i.d {
  color: var(--nova);
}
.cmp {
  margin: 10px 0 0;
  max-width: 32ch;
  font-size: 13px;
  line-height: 19px;
  color: var(--fog-400);
}
.cmp b,
.verdict b {
  font-weight: 500;
  color: var(--fog-50);
}
.cmp b.bad,
.verdict b.bad {
  color: var(--fail);
}
.sample-note {
  margin: 8px 0 0 22px;
  max-width: 46ch;
  font-size: var(--fs-micro);
  line-height: 17px;
  color: var(--fog-400);
}
.verdict {
  margin: 14px 0 0 22px;
  min-height: 38px;
  font-size: 13px;
  line-height: 19px;
  color: var(--fog-400);
}

@media (max-width: 1100px) {
  .body {
    grid-template-columns: minmax(0, 1fr);
    grid-template-areas:
      "result"
      "controls"
      "plate";
    grid-template-rows: auto;
    row-gap: 20px;
  }
  .controls {
    margin-bottom: 8px;
  }
  .readout {
    margin-top: 0;
  }
}
@media (max-width: 760px) {
  .flip {
    padding: 96px var(--gut) 80px;
  }
  .row {
    grid-template-columns: repeat(var(--cols), minmax(0, 1fr));
  }
  .dump {
    font-size: 11px;
    line-height: 22px;
  }
}
</style>
