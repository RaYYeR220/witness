<script setup lang="ts">
import type { Scorecard } from "@/api/client";

/**
 * The evaluation scorecard: witness-chaos runs every attack class against the
 * stack and scores what the explorer caught. Shown exactly as the published
 * scorecard.json states it; without one, the card says it is not there yet.
 */
defineProps<{ card: Scorecard | null; error: string | null; loading: boolean }>();

const pct = (r: number) => `${Math.round(r * 1000) / 10}%`;
const secs = (ms: number | null) => (ms === null ? "–" : `${(ms / 1000).toFixed(1)} s`);
</script>

<template>
  <section class="card" aria-labelledby="sc-h" :data-state="card ? 'card' : 'none'">
    <h2 id="sc-h" class="sc-h">Detection under attack</h2>
    <p v-if="loading" class="x-quiet">Looking for the evaluation scorecard…</p>
    <template v-else-if="card">
      <p class="headline">{{ card.headline }}</p>
      <dl class="nums">
        <div>
          <dt>Detected</dt>
          <dd>{{ pct(card.detection_rate) }}</dd>
        </div>
        <div>
          <dt>Attacks</dt>
          <dd>{{ card.detected }}/{{ card.attacks }}</dd>
        </div>
        <div>
          <dt>Insertion to detection, p50 / p95</dt>
          <dd>{{ secs(card.latency_p50_ms) }} / {{ secs(card.latency_p95_ms) }}</dd>
        </div>
        <div v-if="card.traps">
          <dt>False positives on genuine traffic</dt>
          <dd>{{ card.traps.false_positives }}/{{ card.traps.messages }}</dd>
        </div>
        <div v-if="card.controls">
          <dt>Positive controls</dt>
          <dd>{{ card.controls.passed }}/{{ card.controls.trials }}</dd>
        </div>
      </dl>
      <details class="classes">
        <summary>Per attack class</summary>
        <table class="x-tbl">
          <thead>
            <tr>
              <th scope="col">Class</th>
              <th scope="col">Expected</th>
              <th scope="col" class="num">Detected</th>
              <th scope="col" class="num">p50</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="c in card.classes" :key="c.id">
              <td>
                <span class="mono">{{ c.id }}</span> {{ c.name }}
              </td>
              <td class="mono">{{ c.expected }}</td>
              <td class="num">{{ c.detected }}/{{ c.trials }}</td>
              <td class="num">{{ secs(c.latency_p50_ms) }}</td>
            </tr>
          </tbody>
        </table>
      </details>
    </template>
    <template v-else>
      <p class="placeholder">The scorecard appears after the evaluation run.</p>
      <p class="x-sec-note">
        witness-chaos attacks this stack with every class in its answer key (forgeries, replays, writes around the relay, tampered records…) and
        scores what was caught and how fast. <template v-if="error">{{ error }}</template
        ><template v-else>No scorecard is published with this deployment yet, so there are no numbers to show.</template>
      </p>
    </template>
  </section>
</template>

<style scoped>
.card {
  padding: 18px 22px 20px;
  border: 1px solid var(--hair);
  border-radius: var(--r-cell);
}
.card[data-state="none"] {
  border-style: dashed;
}
.sc-h {
  margin: 0;
  font-size: 13px;
  font-weight: 400;
  color: var(--fog-400);
}
.headline {
  margin: 8px 0 0;
  font: 400 30px/1.1 var(--serif);
  color: var(--fog-50);
}
.placeholder {
  margin: 8px 0 8px;
  font: 400 24px/1.15 var(--serif);
  color: var(--fog-50);
}
.nums {
  display: flex;
  flex-wrap: wrap;
  gap: 12px 36px;
  margin: 16px 0 0;
}
.nums dt {
  font-size: 12.5px;
  color: var(--fog-400);
}
.nums dd {
  margin: 2px 0 0;
  font: 400 24px/1 var(--serif);
  color: var(--fog-50);
  font-variant-numeric: tabular-nums;
}
.classes {
  margin-top: 16px;
}
.classes summary {
  cursor: pointer;
  margin-bottom: 10px;
  font-size: 14px;
  color: var(--fog-200);
}
</style>
