<script setup lang="ts">
import { blindToken, fromHex } from "@witness/verify";
import { computed, ref } from "vue";

import { DataError, localCanonHash, type BlindMatch, type LookupResult } from "@/api/client";

import { useData } from "./data";
import { shortDid, shortHex, utc } from "./format";
import VerdictBadge from "./VerdictBadge.vue";

/**
 * "Was this exact message stored?" Paste any JSON: the explorer matches its
 * canonical form (RFC 8785) against every stored body. The canonical hash is
 * computed here too, so the answer can be compared with what this browser
 * makes of the same text. Sealed messages are found by blind token; a token
 * can be derived here from a search key that never leaves this tab.
 */
const data = useData();

const doc = ref("");
const busy = ref(false);
const result = ref<LookupResult | null>(null);
const local = ref<{ hash: string; bodyHash: string | null } | null>(null);
const error = ref<string | null>(null);

async function lookup() {
  error.value = null;
  result.value = null;
  local.value = localCanonHash(doc.value);
  if (!local.value) {
    error.value = "This is not JSON that can be canonicalised (RFC 8785).";
    return;
  }
  busy.value = true;
  try {
    result.value = await data.lookup(doc.value);
  } catch (e) {
    error.value = e instanceof DataError ? e.message : String(e);
  } finally {
    busy.value = false;
  }
}

const agrees = computed(() => !!(result.value && local.value && result.value.canonHash === local.value.hash));

// ---- blind tokens

const tokens = ref("");
const keyHex = ref("");
const keyKind = ref<"ie" | "tag">("ie");
const keyValue = ref("");
const keyError = ref<string | null>(null);
const blindBusy = ref(false);
const blind = ref<BlindMatch[] | null>(null);
const blindError = ref<string | null>(null);

function derive() {
  keyError.value = null;
  try {
    const key = fromHex(keyHex.value.trim().startsWith("0x") ? keyHex.value.trim() : `0x${keyHex.value.trim()}`);
    if (!keyValue.value.trim()) throw new Error("name the IE or tag to look for");
    const t = blindToken(key, keyKind.value, keyValue.value.trim());
    tokens.value = [...tokens.value.split(/\s+/).filter(Boolean), t].join("\n");
  } catch (e) {
    keyError.value = e instanceof Error ? e.message : String(e);
  }
  // the key is only needed for this one computation
  keyHex.value = "";
}

async function lookupBlind() {
  blindError.value = null;
  blind.value = null;
  const list = [...new Set(tokens.value.split(/\s+/).filter(Boolean))];
  if (!list.length) {
    blindError.value = "Add at least one token.";
    return;
  }
  if (list.length > 64) {
    blindError.value = "At most 64 tokens at a time.";
    return;
  }
  blindBusy.value = true;
  try {
    blind.value = await data.lookupBlind(list);
  } catch (e) {
    blindError.value = e instanceof Error ? e.message : String(e);
  } finally {
    blindBusy.value = false;
  }
}
</script>

<template>
  <section class="lookup" aria-labelledby="lk-h">
    <h2 id="lk-h">Was this exact message stored?</h2>
    <p class="hint">Paste any JSON. Key order and whitespace do not matter: both sides compare the canonical form.</p>
    <form @submit.prevent="lookup">
      <label class="sr-only" for="lk-doc">JSON document</label>
      <textarea
        id="lk-doc"
        v-model="doc"
        rows="6"
        spellcheck="false"
        placeholder='{"id": "MyDomain:fa163e5e25ef", "score": 0.91}'
      ></textarea>
      <div class="row">
        <button class="btn" type="submit" :disabled="busy || !doc.trim()">{{ busy ? "Looking up…" : "Look up" }}</button>
      </div>
    </form>
    <p v-if="error" class="err" role="alert">{{ error }}</p>
    <div v-if="result" class="answer" role="status">
      <p class="verdict" :data-hit="result.matches.length > 0">
        <template v-if="result.matches.length">
          <b>Stored.</b> This exact message was inserted
          {{ result.matches.length === 1 ? "once" : `${result.matches.length} times` }}.
        </template>
        <template v-else><b>Not stored.</b> No message with this canonical form was inserted.</template>
      </p>
      <dl class="hashes">
        <div>
          <dt>Canonical hash, this browser</dt>
          <dd class="mono">{{ local?.hash }}</dd>
        </div>
        <div>
          <dt>Canonical hash, the explorer</dt>
          <dd class="mono" :class="{ bad: !agrees }">
            {{ result.canonHash }} <span class="tick">{{ agrees ? "same" : "differs" }}</span>
          </dd>
        </div>
        <div v-if="result.bodyCanonHash">
          <dt>Envelope body, matched as well</dt>
          <dd class="mono">{{ result.bodyCanonHash }}</dd>
        </div>
      </dl>
      <ul v-if="result.matches.length" class="hits">
        <li v-for="m in result.matches" :key="m.blockId">
          <RouterLink :to="{ name: 'verify', params: { blockId: m.blockId } }">
            <VerdictBadge :verdict="m.verdict" quiet />
            <span class="mono">{{ shortHex(m.blockId, 10, 6) }}</span>
            <span class="muted">{{ m.msIndex !== null ? `milestone ${m.msIndex}` : "not confirmed yet" }}, {{ utc(m.dateMs, false) }}</span>
          </RouterLink>
        </li>
      </ul>
    </div>

    <details class="blind">
      <summary>Sealed messages: find them by blind token</summary>
      <p class="hint">
        Encrypted messages carry tokens <span class="mono">HMAC-SHA256(search key, "ie:"+id | "tag:"+tag)</span>. Paste tokens, or derive one
        here: the key is used in this tab for one computation and never sent.
      </p>
      <form class="derive" @submit.prevent="derive">
        <label>
          <span>Search key (hex)</span>
          <input v-model="keyHex" type="password" autocomplete="off" spellcheck="false" placeholder="0x…" />
        </label>
        <label>
          <span>Kind</span>
          <select v-model="keyKind">
            <option value="ie">IE</option>
            <option value="tag">Tag</option>
          </select>
        </label>
        <label>
          <span>Value</span>
          <input v-model="keyValue" type="text" spellcheck="false" placeholder="MyDomain:fa163e5e25ef" />
        </label>
        <button class="btn btn--ghost" type="submit" :disabled="!keyHex || !keyValue">Add token</button>
      </form>
      <p v-if="keyError" class="err">{{ keyError }}</p>
      <form @submit.prevent="lookupBlind">
        <label class="sr-only" for="lk-tokens">Blind tokens, one per line</label>
        <textarea id="lk-tokens" v-model="tokens" rows="3" spellcheck="false" placeholder="One token per line"></textarea>
        <div class="row">
          <button class="btn" type="submit" :disabled="blindBusy || !tokens.trim()">{{ blindBusy ? "Looking up…" : "Find sealed messages" }}</button>
        </div>
      </form>
      <p v-if="blindError" class="err" role="alert">{{ blindError }}</p>
      <p v-if="blind && !blind.length" class="muted" role="status">No sealed message carries these tokens.</p>
      <ul v-if="blind?.length" class="hits" role="status">
        <li v-for="m in blind" :key="m.token + m.blockId">
          <RouterLink :to="{ name: 'verify', params: { blockId: m.blockId } }">
            <VerdictBadge :verdict="m.verdict" quiet />
            <span class="mono">{{ shortHex(m.blockId, 10, 6) }}</span>
            <span class="muted">{{ m.tag }}{{ m.iss ? `, ${shortDid(m.iss)}` : "" }}</span>
          </RouterLink>
        </li>
      </ul>
    </details>
  </section>
</template>

<style scoped>
h2 {
  margin: 0;
  font: 400 var(--fs-h4) / 1.2 var(--serif);
  font-size: 26px;
  color: var(--fog-50);
}
.hint {
  margin: 8px 0 14px;
  font-size: 13.5px;
  line-height: 20px;
  color: var(--fog-400);
}
textarea,
input,
select {
  width: 100%;
  padding: 10px 12px;
  border: 1px solid var(--hair-strong);
  border-radius: var(--r-cell);
  background: var(--void-raised);
  color: var(--fog-50);
  font: 400 12.5px/1.55 var(--mono);
  resize: vertical;
}
select {
  font-family: var(--sans);
  font-size: 14px;
}
textarea:focus-visible,
input:focus-visible,
select:focus-visible {
  outline: none;
  border-color: var(--ember);
}
.row {
  display: flex;
  justify-content: flex-end;
  margin-top: 10px;
}
.err {
  margin: 12px 0 0;
  font-size: 14px;
  color: var(--fail);
}
.answer {
  margin-top: 18px;
  padding-top: 16px;
  border-top: 1px solid var(--hair);
}
.verdict {
  margin: 0 0 12px;
  font-size: 15px;
  color: var(--fog-200);
}
.verdict b {
  font-weight: 500;
  color: var(--fog-50);
}
.verdict[data-hit="true"] b {
  color: var(--pass);
}
.hashes {
  margin: 0;
  display: grid;
  gap: 10px;
}
.hashes dt {
  font-size: 12.5px;
  color: var(--fog-400);
}
.hashes dd {
  margin: 2px 0 0;
  color: var(--fog-200);
  overflow-wrap: anywhere;
}
.hashes dd.bad {
  color: var(--fail);
}
.tick {
  margin-left: 6px;
  font-family: var(--sans);
  color: var(--pass);
}
.bad .tick {
  color: var(--fail);
}
.hits {
  list-style: none;
  margin: 14px 0 0;
  padding: 0;
}
.hits a {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px 12px;
  padding: 9px 0;
  border-top: 1px solid var(--hair);
  color: var(--fog-200);
  text-decoration: none;
  font-size: 13.5px;
}
.hits a:hover .mono {
  color: var(--fog-50);
  text-decoration: underline;
  text-decoration-color: var(--ember);
}
.muted {
  color: var(--fog-400);
}
.blind {
  margin-top: 28px;
  padding-top: 16px;
  border-top: 1px solid var(--hair);
}
.blind summary {
  cursor: pointer;
  font-size: 15px;
  color: var(--fog-50);
}
.blind summary::marker {
  color: var(--fog-400);
}
.derive {
  display: grid;
  grid-template-columns: minmax(0, 1.2fr) 90px minmax(0, 1fr) auto;
  gap: 10px;
  align-items: end;
  margin-bottom: 12px;
}
.derive label span {
  display: block;
  margin-bottom: 4px;
  font-size: 12.5px;
  color: var(--fog-400);
}
.derive .btn {
  height: 40px;
}
@media (max-width: 1100px) {
  .derive {
    grid-template-columns: 1fr 1fr;
  }
}
</style>
