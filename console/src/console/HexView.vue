<script setup lang="ts">
import { computed, ref } from "vue";

import { blockFields, fieldOf, type ByteField } from "@/verify/sample";

/**
 * The block's raw bytes as a hex dump, 16 per line, with the TIP-24 field
 * each byte belongs to (read from the block's own length prefixes). Point at
 * a byte, or focus the dump and use the arrow keys, to read its field.
 */
const props = defineProps<{ raw: Uint8Array }>();

const PER = 16;
const fields = computed(() => blockFields(props.raw));
const lines = computed(() => {
  const out: { off: number; bytes: number[] }[] = [];
  for (let o = 0; o < props.raw.length; o += PER) out.push({ off: o, bytes: [...props.raw.subarray(o, o + PER)] });
  return out;
});
const at = ref<number | null>(null);
const field = computed<ByteField | null>(() => (at.value === null ? null : fieldOf(fields.value, at.value)));
const envelope = computed(() => fields.value.find((f) => f.name === "signed envelope") ?? null);

const hex2 = (b: number) => b.toString(16).padStart(2, "0");
const off = (o: number) => o.toString(16).padStart(4, "0");
const ascii = (b: number) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "·");
const inField = (i: number) => field.value !== null && i >= field.value.from && i < field.value.to;
const inEnvelope = (i: number) => envelope.value !== null && i >= envelope.value.from && i < envelope.value.to;

function key(e: KeyboardEvent) {
  const n = props.raw.length;
  const cur = at.value ?? 0;
  const step = { ArrowRight: 1, ArrowLeft: -1, ArrowDown: PER, ArrowUp: -PER }[e.key];
  if (step === undefined) return;
  e.preventDefault();
  at.value = Math.min(n - 1, Math.max(0, at.value === null ? 0 : cur + step));
}
</script>

<template>
  <section class="hex" aria-labelledby="hex-h">
    <div class="head">
      <h2 id="hex-h">Raw block</h2>
      <p class="status" aria-live="polite">
        <template v-if="field && at !== null">
          byte <span class="mono">{{ at }}</span> = <span class="mono">0x{{ hex2(raw[at]!) }}</span>, {{ field.name }}
          <span class="muted">(bytes {{ field.from }}–{{ field.to - 1 }})</span>
        </template>
        <template v-else>{{ raw.length }} bytes as the Tangle stores them. Point at a byte to read its field.</template>
      </p>
    </div>
    <div
      class="dump"
      tabindex="0"
      role="group"
      :aria-label="`Hex dump of the ${raw.length}-byte block; arrow keys move between bytes`"
      @keydown="key"
      @mouseleave="at = null"
      @blur="at = null"
    >
      <div v-for="l in lines" :key="l.off" class="line">
        <span class="off" aria-hidden="true">{{ off(l.off) }}</span>
        <span class="bytes" aria-hidden="true"
          ><span
            v-for="(b, j) in l.bytes"
            :key="j"
            class="b"
            :class="{ env: inEnvelope(l.off + j), hl: inField(l.off + j), cur: at === l.off + j }"
            @mouseenter="at = l.off + j"
            >{{ hex2(b) }}</span
          ></span
        >
        <span class="asc" aria-hidden="true"
          ><span v-for="(b, j) in l.bytes" :key="j" :class="{ env: inEnvelope(l.off + j), hl: inField(l.off + j) }">{{ ascii(b) }}</span></span
        >
      </div>
    </div>
  </section>
</template>

<style scoped>
.head {
  display: flex;
  align-items: baseline;
  gap: 16px;
  flex-wrap: wrap;
  margin-bottom: 12px;
}
h2 {
  margin: 0;
  font: 400 15px var(--sans);
  color: var(--fog-400);
}
.status {
  margin: 0;
  font-size: 13.5px;
  color: var(--fog-400);
}
.status .mono {
  color: var(--fog-50);
}
.muted {
  color: var(--fog-400);
}
.dump {
  font: 400 11.5px/19px var(--mono);
  color: var(--fog-400);
  overflow-x: auto;
  outline-offset: 4px;
}
.line {
  display: flex;
  gap: 18px;
  white-space: pre;
}
.off {
  color: rgba(var(--rgb-fog-400), 0.6);
}
.bytes {
  display: inline-flex;
  gap: 0.6ch;
}
.b {
  border-radius: 2px;
  transition:
    color var(--t-quick),
    background var(--t-quick);
}
.env {
  color: var(--fog-200);
}
.hl {
  color: var(--void);
  background: rgba(var(--rgb-aurora), 0.75);
}
.b.cur {
  background: var(--ember);
  color: var(--void);
}
.asc {
  color: rgba(var(--rgb-fog-400), 0.7);
}
.asc .env {
  color: var(--fog-200);
}
.asc .hl {
  color: var(--void);
  background: rgba(var(--rgb-aurora), 0.5);
}
@media (max-width: 760px) {
  .asc {
    display: none;
  }
  .line {
    gap: 10px;
  }
  .dump {
    font-size: 10.5px;
  }
}
</style>
