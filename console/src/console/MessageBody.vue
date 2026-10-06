<script setup lang="ts">
import { decryptBody, isDict, NotARecipient, type X25519PrivateJwk } from "@witness/verify";
import { computed, ref, watch } from "vue";

import { shortDid } from "./format";

/**
 * The message's decoded JSON. A sealed envelope (`enc`, a JWE) shows as
 * ciphertext; "Unlock with a local key file" reads an X25519 private JWK from
 * a file the user picks and decrypts in this tab with @witness/verify. The key
 * lives in a local variable for that one call: it is never stored, never put
 * in a store or in the URL, and never sent anywhere.
 */
const props = defineProps<{ json: unknown }>();

const env = computed(() => (isDict(props.json) ? (props.json as Record<string, unknown>) : null));
const enc = computed(() => (env.value && isDict(env.value.enc) ? (env.value.enc as Record<string, unknown>) : null));
const recipients = computed<string[]>(() => {
  const list = enc.value?.recipients;
  if (!Array.isArray(list)) return [];
  return list
    .map((r) => (isDict(r) && isDict((r as Record<string, unknown>).header) ? ((r as { header: { kid?: unknown } }).header.kid as unknown) : null))
    .filter((k): k is string => typeof k === "string");
});
const cipherBytes = computed(() => {
  const c = enc.value?.ciphertext;
  return typeof c === "string" ? Math.floor((c.length * 3) / 4) : null;
});

/** The envelope without the long base64 parts, for the readable view. */
const shown = computed(() => {
  const j = props.json;
  if (!env.value) return JSON.stringify(j, null, 2);
  const copy: Record<string, unknown> = { ...env.value };
  if (enc.value) copy.enc = { "…": `JWE, ${recipients.value.length} recipient${recipients.value.length === 1 ? "" : "s"}, ${cipherBytes.value ?? "?"} bytes of ciphertext` };
  return JSON.stringify(copy, null, 2);
});

const plain = ref<Record<string, unknown> | null>(null);
const unlockedFor = ref<string | null>(null);
const problem = ref<string | null>(null);
const busy = ref(false);
const picker = ref<HTMLInputElement | null>(null);

watch(
  () => props.json,
  () => lock(),
);

function lock() {
  plain.value = null;
  unlockedFor.value = null;
  problem.value = null;
}

function readFile(file: File): Promise<string> {
  if (typeof file.text === "function") return file.text();
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result));
    r.onerror = () => reject(r.error);
    r.readAsText(file);
  });
}

async function unlock(e: Event) {
  const input = e.target as HTMLInputElement;
  const file = input.files?.[0];
  input.value = ""; // the file handle goes too
  if (!file || !enc.value) return;
  problem.value = null;
  busy.value = true;
  let jwk: (X25519PrivateJwk & { kid?: unknown }) | null = null;
  try {
    try {
      jwk = JSON.parse(await readFile(file)) as X25519PrivateJwk & { kid?: unknown };
    } catch {
      problem.value = "That file is not a JSON key (an X25519 private JWK).";
      return;
    }
    const kids = typeof jwk.kid === "string" && recipients.value.includes(jwk.kid) ? [jwk.kid] : recipients.value;
    for (const kid of kids) {
      try {
        plain.value = await decryptBody(enc.value, kid, jwk);
        unlockedFor.value = kid;
        return;
      } catch (err) {
        if (err instanceof TypeError) {
          problem.value = "That file is not an X25519 private key (kty OKP, crv X25519, d).";
          return;
        }
        if (err instanceof NotARecipient) continue;
        // a wrong key for this recipient: try the next one
      }
    }
    problem.value =
      typeof jwk.kid === "string" && !recipients.value.includes(jwk.kid)
        ? `This message is not addressed to ${shortDid(jwk.kid)}.`
        : "This key does not open the message: it is not one of its recipients' keys.";
  } finally {
    jwk = null; // drop the key as soon as the attempt is over
    busy.value = false;
  }
}
</script>

<template>
  <section class="body" aria-labelledby="body-h">
    <div class="head">
      <h2 id="body-h">Decoded message</h2>
      <span v-if="enc && !plain" class="badge" data-k="cipher">Ciphertext</span>
      <span v-if="plain" class="badge" data-k="plain">Decrypted in this tab</span>
    </div>

    <template v-if="enc">
      <p class="note">
        The body is encrypted to {{ recipients.length }} recipient{{ recipients.length === 1 ? "" : "s" }}. The signature covers the ciphertext, so
        the checks hold without decrypting.
      </p>
      <ul class="rcpt">
        <li v-for="k in recipients" :key="k" class="mono" :title="k">{{ shortDid(k) }}</li>
      </ul>
      <div v-if="!plain" class="unlock">
        <input ref="picker" class="sr-only" type="file" accept=".json,.jwk,application/json" tabindex="-1" aria-hidden="true" @change="unlock" />
        <button class="btn" type="button" :disabled="busy" @click="picker?.click()">{{ busy ? "Decrypting…" : "Unlock with a local key file" }}</button>
        <p class="fine">The key file is read and used in this tab only. It is never stored or sent.</p>
      </div>
      <p v-if="problem" class="err" role="alert">{{ problem }}</p>
      <div v-if="plain" class="plain">
        <p class="fine">Opened with <span class="mono">{{ shortDid(unlockedFor) }}</span>. Closing this page forgets it.</p>
        <pre class="json mono" data-plain>{{ JSON.stringify(plain, null, 2) }}</pre>
        <button class="text-action" type="button" @click="lock">Lock again</button>
      </div>
    </template>

    <pre class="json mono" :class="{ dim: !!plain }">{{ shown }}</pre>
  </section>
</template>

<style scoped>
.head {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 10px;
}
h2 {
  margin: 0;
  font: 400 15px var(--sans);
  color: var(--fog-400);
}
.badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  height: 22px;
  padding: 0 10px;
  border-radius: var(--r-pill);
  border: 1px dashed var(--hair-strong);
  font-size: 12px;
  color: var(--fog-200);
}
.badge[data-k="plain"] {
  border-style: solid;
  border-color: rgba(var(--rgb-ember), 0.6);
  color: var(--ember);
}
.note,
.fine {
  margin: 0 0 10px;
  font-size: 13px;
  line-height: 19px;
  color: var(--fog-400);
}
.rcpt {
  list-style: none;
  margin: 0 0 12px;
  padding: 0;
  color: var(--fog-200);
}
.unlock {
  margin: 4px 0 14px;
}
.unlock .btn {
  height: 38px;
  font-size: 14px;
}
.unlock .fine {
  margin-top: 8px;
}
.err {
  margin: 0 0 12px;
  font-size: 13.5px;
  color: var(--fail);
}
.plain {
  margin-bottom: 14px;
  padding: 12px 14px;
  border: 1px solid rgba(var(--rgb-ember), 0.35);
  border-radius: var(--r-cell);
}
.json {
  margin: 0;
  max-height: 420px;
  overflow: auto;
  font-size: 11.5px;
  line-height: 18px;
  color: var(--fog-200);
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.plain .json {
  margin-bottom: 8px;
  color: var(--fog-50);
}
.json.dim {
  opacity: 0.6;
}
</style>
