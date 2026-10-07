<script setup lang="ts">
import { fromHex, isDict, parseBlock, parseJson, toHex, type VerifierConfig } from "@witness/verify";
import { computed, onBeforeUnmount, ref, watch } from "vue";
import { useRoute } from "vue-router";

import { DataError, type Lifecycle, type Message } from "@/api/client";
import ConsoleShell from "@/components/ConsoleShell.vue";
import { useData, useLookups } from "@/console/data";
import { scoreOf, shortDid, shortHex, utc, verdictInfo } from "@/console/format";
import HexView from "@/console/HexView.vue";
import LadderPanel from "@/console/LadderPanel.vue";
import MessageBody from "@/console/MessageBody.vue";
import NodeChecks from "@/console/NodeChecks.vue";
import TangleChecks from "@/console/TangleChecks.vue";
import VerdictBadge from "@/console/VerdictBadge.vue";
import { bindBundle, type Binding } from "@/verify/binding";
import { createLadder, resetLadder, runLadder } from "@/verify/ladder";
import { anchorPinned, PINNED, pinnedConfig } from "@/verify/pinned";
import { readTrustMessage } from "@/verify/sample";

/**
 * Verify: one message, what the indexer recorded about it, and the five
 * checks run again here, in the browser, from the proof bundle's bytes
 * against the pins built into this console. The two verdicts are shown side
 * by side and may differ; only the browser's is computed in front of you.
 */
const route = useRoute();
const data = useData();
const lookups = useLookups();

const blockId = computed(() => String(route.params.blockId ?? "").toLowerCase());
const msg = ref<Message | null>(null);
const msgError = ref<string | null>(null);
const life = ref<Lifecycle | null>(null);
const lifeError = ref<string | null>(null);
const bundleText = ref<string | null>(null);
const bundleError = ref<string | null>(null);
/** Whether the served bundle is about the requested block at all. */
const binding = ref<Binding | null>(null);
const foreign = computed(() => binding.value?.kind === "other");
const apiPins = ref<VerifierConfig | null>(null);
/** The last milestone an anchored checkpoint covers; undefined until asked. */
const lastAnchored = ref<number | null | undefined>(undefined);
const ladder = createLadder();
const anchorOk = anchorPinned();
let generation = 0;

interface BundleView {
  raw: Uint8Array | null;
  msIndex: number | null;
  leafIndex: number | null;
  leafCount: number | null;
  record: number | null;
  anchorFrom: number | null;
  anchorTo: number | null;
}

/** Facts read from the bundle for display only; the ladder parses it on its own. */
const bundle = computed<BundleView | null>(() => {
  // a bundle about another block shows nothing of that block here
  if (!bundleText.value || foreign.value) return null;
  try {
    const b = parseJson(bundleText.value) as Record<string, unknown>;
    const block = b.block as Record<string, unknown> | undefined;
    const ms = b.milestone as Record<string, unknown> | undefined;
    const inc = b.inclusion as Record<string, unknown> | undefined;
    const anchor = isDict(b.anchor) ? (b.anchor as Record<string, unknown>) : null;
    const cp = anchor && isDict(anchor.checkpoint) ? (anchor.checkpoint as Record<string, Record<string, unknown>>) : null;
    const reb = anchor && isDict(anchor.rebased) ? (anchor.rebased as Record<string, unknown>) : null;
    const num = (v: unknown) => (typeof v === "number" ? v : null);
    let raw: Uint8Array | null = null;
    try {
      raw = typeof block?.raw === "string" ? fromHex(block.raw) : null;
    } catch {
      raw = null;
    }
    return {
      raw,
      msIndex: num(ms?.index),
      leafIndex: num(inc?.leafIndex),
      leafCount: num(inc?.leafCount),
      record: num(reb?.record),
      anchorFrom: num(cp?.from?.index),
      anchorTo: num(cp?.to?.index),
    };
  } catch {
    return null;
  }
});

const trust = computed(() => (bundle.value?.raw ? readTrustMessage(bundle.value.raw) : null));
/** The score exactly as written in the envelope (the bundle's bytes first, else the stored body). */
const scoreExact = computed(() => {
  if (trust.value?.scoreText) return trust.value.scoreText;
  const s = msg.value && !msg.value.encrypted ? scoreOf(msg.value.json) : null;
  return s === null ? null : String(s);
});
/** Two decimals for the headline; the exact literal is shown next to it when they differ. */
const score = computed(() => {
  const s = scoreExact.value;
  if (s === null) return null;
  const n = Number(s);
  return s.length > 5 && Number.isFinite(n) ? n.toFixed(2) : s;
});

/**
 * The message as its bytes carry it: the tagged data decoded as JSON. The
 * API's stored `json` is only the body (none for a sealed message), so the
 * envelope, signature and ciphertext come from the raw bytes.
 */
const decoded = computed<unknown>(() => {
  const fromBlock = bundle.value?.raw ? taggedData(bundle.value.raw) : null;
  const bytes = fromBlock ?? (msg.value?.dataHex ? safeHex(msg.value.dataHex) : null);
  if (bytes) {
    try {
      return parseJson(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    } catch {
      /* not JSON: fall back to what the API stored */
    }
  }
  return msg.value?.json ?? null;
});

function taggedData(raw: Uint8Array): Uint8Array | null {
  try {
    const p = parseBlock(raw).payload;
    return p && p.kind === "tagged_data" ? p.data : null;
  } catch {
    return null;
  }
}

function safeHex(h: string): Uint8Array | null {
  try {
    return fromHex(h);
  } catch {
    return null;
  }
}
// What the block's own bytes say comes first; the explorer's index only fills gaps.
const ie = computed(() => trust.value?.entity ?? msg.value?.ieId ?? null);
/** An IE id the lineage route takes (the API's own pattern: no slash, no space). */
const ieLinkable = computed(() => typeof ie.value === "string" && /^[^/\s]{1,256}$/.test(ie.value));
const iss = computed(() => trust.value?.issuer ?? msg.value?.iss ?? null);
const tag = computed(() => trust.value?.tag ?? msg.value?.tag ?? null);
/** Where the explorer's record names something else than the bytes do. */
const recordDiffers = computed(() => {
  const t = trust.value;
  const m = msg.value;
  if (!t || !m) return [];
  const out: string[] = [];
  if (t.tag !== null && m.tag !== null && t.tag !== m.tag) out.push(`tag ${m.tag}`);
  if (t.entity !== null && m.ieId !== null && t.entity !== m.ieId) out.push(`IE ${m.ieId}`);
  if (t.issuer !== null && m.iss !== null && t.issuer !== m.iss) out.push(`issuer ${shortDid(m.iss)}`);
  return out;
});

function reduced() {
  return typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;
}

async function verify() {
  if (!bundleText.value || foreign.value) return;
  const g = generation;
  await runLadder(ladder, bundleText.value, {
    resolveDid: lookups.resolveDid,
    fetchAnchorRecord: lookups.fetchAnchorRecord,
    pace: reduced() ? 0 : 240,
  });
  if (g === generation && notAnchoredYet.value && lastAnchored.value === undefined) {
    lastAnchored.value = await data.lastAnchoredMilestone().catch(() => null);
  }
}

const pendingNote = computed(() => {
  const n = lastAnchored.value;
  const ms = bundle.value?.msIndex;
  const where =
    n === undefined
      ? "its milestone is newer than the last checkpoint"
      : n === null
        ? "no checkpoint has been anchored on IOTA Rebased so far"
        : `the last checkpoint covers up to milestone ${n}${ms !== null && ms !== undefined ? `, this block is in milestone ${ms}` : ""}`;
  return `${where}; checks 1–4 passed. Run the checks again once the next checkpoint is anchored.`;
});

/** Checks 1 to 4 passed and the bundle has no anchor: the block's milestone is newer than the last checkpoint. */
const notAnchoredYet = computed(() => {
  const st = ladder.steps;
  return (
    !foreign.value &&
    !ladder.running &&
    ladder.overall === "PARTIAL" &&
    st.slice(0, 4).every((x) => x.status === "pass") &&
    st[4]?.status === "unknown" &&
    st[4]?.detail === "bundle carries no anchor"
  );
});

const why = (e: unknown, what: string) => {
  if (e instanceof DataError && e.status === 404) return `${what}: not found.`;
  return `${what}: ${e instanceof Error ? e.message : String(e)}`;
};

async function load(id: string) {
  const g = ++generation;
  msg.value = null;
  life.value = null;
  bundleText.value = null;
  binding.value = null;
  lastAnchored.value = undefined;
  msgError.value = lifeError.value = bundleError.value = null;
  resetLadder(ladder);
  const [m, l, b] = await Promise.allSettled([data.message(id), data.lifecycle(id), data.bundle(id)]);
  if (g !== generation) return;
  const same = (other: unknown) => typeof other === "string" && other.toLowerCase() === id;
  if (m.status === "fulfilled" && same(m.value.blockId)) msg.value = m.value;
  else if (m.status === "fulfilled") msgError.value = `The explorer answered with another message (${shortHex(String(m.value.blockId), 8, 6)}); it is not shown.`;
  else msgError.value = why(m.reason, "The explorer has no message with this id");
  if (l.status === "fulfilled" && same(l.value.blockId)) life.value = l.value;
  else if (l.status === "fulfilled") lifeError.value = "The explorer answered with the lifecycle of another block; it is not shown.";
  else lifeError.value = why(l.reason, "No lifecycle recorded");
  if (b.status === "fulfilled") {
    bundleText.value = b.value;
    binding.value = bindBundle(b.value, id);
    void verify();
  } else {
    bundleError.value =
      b.reason instanceof DataError && b.reason.status === 404
        ? "No proof bundle yet: the block is not in a milestone the explorer has indexed. Once a milestone confirms it, the checks can run."
        : why(b.reason, "The proof bundle could not be fetched");
  }
}

watch(blockId, (id) => void load(id), { immediate: true });
onBeforeUnmount(() => {
  generation += 1;
  resetLadder(ladder);
});

void data
  .verifierConfig()
  .then((c) => (apiPins.value = c))
  .catch(() => undefined);

const pinsDiffer = computed(() => {
  const a = apiPins.value;
  if (!a) return null;
  const keys = (k: Iterable<string | Uint8Array>) => [...k].map((x) => (typeof x === "string" ? x.toLowerCase() : toHex(x))).sort().join(",");
  const diffs: string[] = [];
  if (a.network !== PINNED.network) diffs.push("network");
  if (keys(a.trustedCoordinatorKeys) !== keys(PINNED.trustedCoordinatorKeys)) diffs.push("coordinator keys");
  if (a.threshold !== PINNED.threshold) diffs.push("threshold");
  if ((a.rebasedNetwork ?? null) !== PINNED.rebasedNetwork) diffs.push("Rebased network");
  if ((a.trailId ?? null) !== PINNED.trailId) diffs.push("anchor trail");
  return diffs;
});

/** The browser's verdict: the ladder's, except that a proof of another block is no proof of this one. */
const browserOverall = computed(() => (foreign.value ? "INVALID" : ladder.overall));

const family = computed(() => verdictInfo(msg.value?.verdict).family);
const comparison = computed(() => {
  const o = browserOverall.value;
  const v = msg.value?.verdict;
  if (foreign.value || !o || ladder.running || !v) return null;
  if (family.value === "signed" && o === "INVALID") {
    return { tone: "bad", text: `They disagree. The indexer recorded a valid signature; check ${ladder.failedAt} failed in your browser. Your result comes from the bytes in front of you.` };
  }
  if (family.value === "rejected" && o === "VALID") {
    if (v === "REPLAY" || v === "UNAUTHORIZED_WRITER") {
      return {
        tone: "note",
        text: `Both hold. The bytes, the milestone, the signature and the anchor are genuine, yet the indexer judged it ${verdictInfo(v).label.toLowerCase()}: a question of context (earlier messages, the writer policy) the five checks do not cover.`,
      };
    }
    // The indexer keeps the issuer of a MALFORMED message only when the signature checked out
    // and the body broke its tag's schema; a broken envelope has no recorded issuer.
    if (v === "MALFORMED" && msg.value?.iss) {
      return {
        tone: "note",
        text: "Both hold. The bytes, the milestone, the signature and the anchor are genuine, yet the indexer judged it malformed: the signed body breaks its tag's schema, which the five checks do not cover.",
      };
    }
    return { tone: "bad", text: `They disagree. The indexer recorded ${verdictInfo(v).label.toLowerCase()}; every check passed in your browser.` };
  }
  if (v === "UNSIGNED_LEGACY" && o === "PARTIAL") {
    return { tone: "note", text: "An unsigned message can be proven included and anchored, but there is no signature to check: partial by design." };
  }
  return null;
});

/** After a re-check on the node, the lifecycle the explorer recorded has moved on too. */
async function refreshLifecycle() {
  const id = blockId.value;
  try {
    const l = await data.lifecycle(id);
    if (id === blockId.value && l.blockId.toLowerCase() === id) life.value = l;
  } catch {
    /* the earlier answer stays */
  }
}

function download() {
  if (!bundleText.value) return;
  const url = URL.createObjectURL(new Blob([bundleText.value], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = `witness-proof-${blockId.value.slice(2, 14)}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const keyList = PINNED.trustedCoordinatorKeys.map((k) => shortHex(k, 6, 4)).join(", ");
const cfg = pinnedConfig();
</script>

<template>
  <ConsoleShell>
    <div class="verify">
      <div class="main">
        <header class="head">
          <p class="kicker">
            <RouterLink to="/live">Live</RouterLink> <span aria-hidden="true">/</span> Verify
            <span v-if="msg?.encrypted" class="sealed">sealed</span>
          </p>
          <h1 v-if="score !== null" class="title">
            <span class="score">{{ score }}</span>
            <span class="for"
              >trust score for
              <RouterLink v-if="ieLinkable" class="mono ie-link" :to="{ name: 'lineage', params: { id: ie } }" title="Its score history">{{ ie }}</RouterLink
              ><span v-else class="mono">{{ ie }}</span
              ><span v-if="scoreExact !== score" class="exact">exactly <span class="mono">{{ scoreExact }}</span></span></span
            >
          </h1>
          <h1 v-else class="title">
            <span class="tagname">{{ tag ?? "Message" }}</span>
            <span v-if="ie" class="for mono">{{ ie }}</span>
          </h1>
          <dl class="meta">
            <div>
              <dt>Block</dt>
              <dd class="mono" :title="blockId">{{ shortHex(blockId, 8, 6) }}</dd>
            </div>
            <div>
              <dt>Milestone</dt>
              <dd>
                {{ msg?.msIndex ?? bundle?.msIndex ?? "not yet" }}<template v-if="bundle?.leafCount">, leaf {{ (bundle.leafIndex ?? 0) + 1 }} of {{ bundle.leafCount }}</template>
              </dd>
            </div>
            <div>
              <dt>Issued</dt>
              <dd>{{ msg?.issuedAtMs ? utc(msg.issuedAtMs) : utc(msg?.dateMs) || "unknown" }}</dd>
            </div>
            <div>
              <dt>Sender</dt>
              <dd class="mono" :title="iss ?? undefined">{{ iss ? shortDid(iss) : "unsigned" }}</dd>
            </div>
          </dl>
          <p v-if="recordDiffers.length" class="warn">
            Read from the block's bytes. The explorer's record names {{ recordDiffers.join(", ") }} instead.
          </p>
          <p v-if="msgError" class="warn">{{ msgError }}</p>
        </header>

        <section class="verdicts" aria-label="Two verdicts">
          <div class="vbox">
            <p class="vlabel">Recorded by the indexer</p>
            <VerdictBadge :verdict="msg?.verdict" />
            <p class="vfine">What the explorer decided when it stored the message. A record, not a proof.</p>
          </div>
          <div class="vbox mine" :data-o="ladder.running ? 'RUNNING' : (browserOverall ?? 'NONE')">
            <p class="vlabel">Checked in your browser</p>
            <span class="overall-chip">
              <span class="ring" aria-hidden="true"></span>
              {{ ladder.running ? "Checking…" : (browserOverall ?? (bundleError ? "Not run" : "Waiting")) }}
            </span>
            <p class="vfine">Computed here from the bundle's bytes against keys built into this console. It can differ from the record.</p>
          </div>
        </section>
        <p v-if="binding?.kind === 'other'" class="compare foreign" data-tone="bad" role="alert">
          <b>The explorer served a proof for another block</b> (<span class="mono">{{ shortHex(binding.servedId, 10, 8) }}</span>), not for
          <span class="mono">{{ shortHex(blockId, 10, 8) }}</span>. A proof of another block proves nothing about this one, so the checks were not run on
          it and this block counts as invalid here.
        </p>
        <p v-if="comparison" class="compare" :data-tone="comparison.tone" role="note">{{ comparison.text }}</p>
        <p v-if="notAnchoredYet" class="compare pending" data-tone="note" role="note"><b>Not anchored yet:</b> {{ pendingNote }}</p>

        <TangleChecks :block-id="blockId" :recorded="life?.checks ?? null" :recorded-error="lifeError" @rechecked="refreshLifecycle" />

        <section class="checks" aria-labelledby="checks-h">
          <div class="checks-head">
            <h2 id="checks-h">The five checks, in your browser</h2>
            <div class="actions">
              <button class="btn" type="button" :disabled="!bundleText || foreign || ladder.running" @click="verify">Run the checks again</button>
              <button class="btn btn--ghost" type="button" :disabled="!bundleText" @click="download">Download bundle</button>
            </div>
          </div>
          <p v-if="bundleError" class="warn">{{ bundleError }}</p>
          <p v-else-if="foreign" class="warn">Not run: the bundle is about another block.</p>
          <LadderPanel v-else :state="ladder" :anchor-pinned="anchorOk" />

          <details class="pins">
            <summary>What your browser trusts for these checks</summary>
            <dl>
              <div>
                <dt>Tangle network</dt>
                <dd class="mono">{{ cfg.network }}</dd>
              </div>
              <div>
                <dt>Coordinator keys</dt>
                <dd class="mono">{{ keyList }}, {{ cfg.threshold }} of {{ PINNED.trustedCoordinatorKeys.length }} must sign</dd>
              </div>
              <div>
                <dt>Anchor trail</dt>
                <dd class="mono">{{ PINNED.trailId ? `${shortHex(PINNED.trailId, 8, 6)} on ${PINNED.rebasedNetwork}` : "none pinned" }}</dd>
              </div>
              <div>
                <dt>Anchor writer</dt>
                <dd class="mono">{{ PINNED.anchorWriter ? shortHex(PINNED.anchorWriter, 8, 6) : "any" }}</dd>
              </div>
              <div>
                <dt>Issuer keys from</dt>
                <dd>
                  {{ lookups.didSource }}.
                  <span class="assume">Check 4 trusts that answer: issuer keys come from the anchor service operated with this explorer, not from an
                  independent read of the chain.</span>
                </dd>
              </div>
              <div>
                <dt>Anchor record from</dt>
                <dd>{{ lookups.anchorSource }}</dd>
              </div>
            </dl>
            <p class="fine">
              These pins are built into the console (src/config/verifier.json). The API also publishes the pins it uses (all of the above but the
              RPC, the package and the writer);
              <template v-if="pinsDiffer === null">it did not answer, which changes nothing here.</template>
              <template v-else-if="!pinsDiffer.length">they are the same.</template>
              <b v-else class="bad">they differ ({{ pinsDiffer.join(", ") }}).</b>
              Either way they are never used to verify.
            </p>
          </details>
        </section>

        <HexView v-if="bundle?.raw" class="hexwrap" :raw="bundle.raw" />
      </div>

      <aside class="rail">
        <MessageBody v-if="msg || bundle" :json="decoded" />
        <p v-else-if="!msgError" class="muted">Loading the message…</p>
        <NodeChecks :lifecycle="life" :lifecycle-error="lifeError" />
      </aside>
    </div>
  </ConsoleShell>
</template>

<style scoped>
.verify {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 360px;
  gap: 48px;
}
.kicker {
  margin: 0 0 14px;
  font-size: 13px;
  color: var(--fog-400);
}
.kicker a {
  color: var(--fog-400);
}
.kicker a:hover {
  color: var(--fog-50);
}
.sealed {
  margin-left: 10px;
  padding: 1px 8px;
  border-radius: var(--r-pill);
  border: 1px dashed var(--hair-strong);
  color: var(--fog-200);
}
.title {
  display: flex;
  align-items: baseline;
  flex-wrap: wrap;
  gap: 6px 18px;
  margin: 0;
  font-weight: 400;
}
.score {
  font: 400 86px/0.9 var(--serif);
  letter-spacing: -0.02em;
  color: var(--fog-50);
}
.tagname {
  font: 400 var(--fs-h2) / 1 var(--serif);
  color: var(--fog-50);
  overflow-wrap: anywhere;
}
.for {
  font-size: 16px;
  color: var(--fog-400);
}
.exact {
  display: block;
  margin-top: 4px;
  font-size: 13px;
}
.ie-link {
  text-decoration: underline;
  text-decoration-color: rgba(var(--rgb-ember), 0.6);
  text-underline-offset: 4px;
}
.for .mono,
.for.mono {
  font-size: 13px;
  color: var(--fog-200);
}
.meta {
  display: grid;
  grid-template-columns: repeat(4, auto);
  justify-content: start;
  gap: 6px 44px;
  margin: 22px 0 0;
}
.meta dt {
  font-size: 13px;
  color: var(--fog-400);
}
.meta dd {
  margin: 3px 0 0;
  font-size: 14.5px;
  color: var(--fog-200);
  white-space: nowrap;
}
.meta dd.mono {
  font-size: 12.5px;
}
.warn {
  margin: 14px 0 0;
  font-size: 14px;
  color: var(--ember);
}

.verdicts {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0;
  margin-top: 28px;
  border: 1px solid var(--hair);
  border-radius: var(--r-cell);
}
.vbox {
  padding: 16px 20px 18px;
}
.vbox + .vbox {
  border-left: 1px solid var(--hair);
}
.vlabel {
  margin: 0 0 10px;
  font-size: 13px;
  color: var(--fog-400);
}
.vfine {
  margin: 10px 0 0;
  font-size: 12.5px;
  line-height: 18px;
  color: var(--fog-400);
}
.overall-chip {
  display: inline-flex;
  align-items: center;
  gap: 9px;
  height: 26px;
  padding: 0 12px 0 10px;
  border-radius: var(--r-pill);
  border: 1px solid rgba(var(--rgb-fog-50), 0.22);
  font-size: 13px;
  font-weight: 500;
  letter-spacing: 0.04em;
  color: var(--fog-200);
}
.ring {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  border: 1.2px dashed var(--fog-400);
}
.mine[data-o="RUNNING"] .ring {
  border: 1.3px solid var(--ember);
  animation: spin 1.2s linear infinite;
  border-top-color: transparent;
}
.mine[data-o="VALID"] .overall-chip {
  color: var(--pass);
  border-color: rgba(var(--rgb-aurora), 0.5);
}
.mine[data-o="VALID"] .ring {
  border: 0;
  background: var(--pass);
}
.mine[data-o="INVALID"] .overall-chip {
  color: var(--fail);
  border-color: rgba(var(--rgb-nova), 0.55);
}
.mine[data-o="INVALID"] .ring {
  border: 1.3px solid var(--fail);
}
.mine[data-o="PARTIAL"] .overall-chip {
  color: var(--fog-50);
}
@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}
.compare {
  margin: 12px 0 0;
  padding: 10px 14px;
  border-left: 2px solid var(--ember);
  font-size: 14px;
  line-height: 21px;
  color: var(--fog-200);
}
.compare.pending b {
  font-weight: 500;
  color: var(--fog-50);
}
.compare.foreign b {
  font-weight: 500;
  color: var(--fail);
}
.compare[data-tone="bad"] {
  border-color: var(--fail);
  background: var(--nova-wash);
  color: var(--fog-50);
}

.checks {
  margin-top: 32px;
}
.checks-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  flex-wrap: wrap;
  margin-bottom: 8px;
}
.checks h2 {
  margin: 0;
  font: 400 26px/1.1 var(--serif);
  color: var(--fog-50);
}
.actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}
.actions .btn {
  height: 38px;
  font-size: 14px;
}
.pins {
  margin-top: 18px;
  padding-top: 14px;
  border-top: 1px solid var(--hair);
}
.pins summary {
  cursor: pointer;
  font-size: 14px;
  color: var(--fog-200);
}
.pins dl {
  display: grid;
  grid-template-columns: max-content minmax(0, 1fr);
  gap: 8px 20px;
  margin: 14px 0 0;
}
.pins dl div {
  display: contents;
}
.pins dt {
  font-size: 13px;
  color: var(--fog-400);
}
.pins dd {
  margin: 0;
  font-size: 13px;
  color: var(--fog-200);
  overflow-wrap: anywhere;
}
.pins dd.mono {
  font-size: 12px;
}
.assume {
  display: block;
  margin-top: 4px;
  color: var(--fog-400);
}
.fine {
  margin: 12px 0 0;
  font-size: 12.5px;
  line-height: 18px;
  color: var(--fog-400);
}
.bad {
  font-weight: 500;
  color: var(--fail);
}
.hexwrap {
  margin-top: 36px;
  padding-top: 20px;
  border-top: 1px solid var(--hair);
}
.rail {
  display: flex;
  flex-direction: column;
  gap: 32px;
  padding-left: 32px;
  border-left: 1px solid var(--hair);
}
.rail > * + * {
  padding-top: 26px;
  border-top: 1px solid var(--hair);
}
.muted {
  color: var(--fog-400);
}

@media (max-width: 1180px) {
  .verify {
    grid-template-columns: minmax(0, 1fr);
    gap: 36px;
  }
  .rail {
    padding-left: 0;
    border-left: 0;
    padding-top: 28px;
    border-top: 1px solid var(--hair);
  }
}
@media (max-width: 760px) {
  .score {
    font-size: 64px;
  }
  .meta {
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 12px 20px;
  }
  .meta dd {
    white-space: normal;
    overflow-wrap: anywhere;
  }
  .meta div:last-child {
    grid-column: 1 / -1;
  }
  .verdicts {
    grid-template-columns: 1fr;
  }
  .vbox + .vbox {
    border-left: 0;
    border-top: 1px solid var(--hair);
  }
  .pins dl {
    grid-template-columns: 1fr;
    gap: 2px;
  }
  .pins dd {
    margin-bottom: 8px;
  }
}
</style>
