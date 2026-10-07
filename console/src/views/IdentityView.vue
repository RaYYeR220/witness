<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, shallowRef } from "vue";

import type { AnchorCheckpoint, Identity } from "@/api/client";
import ConsoleShell from "@/components/ConsoleShell.vue";
import { useData, useLookups } from "@/console/data";
import { didObjectId, explorerAddress, explorerObject, explorerTx } from "@/console/explorer";
import { shortDid, shortHex, utc } from "@/console/format";
import VerdictMark from "@/console/VerdictMark.vue";
import { ForeignDocument, fragment, keyStatus, readIdentities, tagsFor, type ComponentIdentity, type KeyState, type KeyStatus } from "@/identity/model";
import { PINNED } from "@/verify/pinned";

/**
 * Identity & policy: the did:iota identities of the domain and its
 * components as the anchor service publishes them, each key's status read
 * from the trusted DID resolver (in force, or revoked and when), and the
 * writer policy: which identities may write which tag. The policy hash is
 * held against the one the newest checkpoint committed to.
 */
const data = useData();
const lookups = useLookups();

const identity = shallowRef<Identity | null>(null);
const error = ref<string | null>(null);
const loaded = ref(false);
const latest = shallowRef<AnchorCheckpoint | null>(null);
/** Key status per DID: "pending" while asking, null when the resolver did not answer, "foreign" when it answered for another DID. */
const status = reactive(new Map<string, KeyStatus | null | "pending" | "foreign">());
let alive = true;
onBeforeUnmount(() => (alive = false));

const current = computed(() => readIdentities(identity.value?.anchor.identities ?? []));
const previous = computed(() => readIdentities(identity.value?.anchor.previous ?? []));
const policy = computed(() => identity.value?.policy ?? null);
const names = computed(() => new Map(current.value.map((i) => [i.did, i.name])));
const network = PINNED.rebasedNetwork;
const networkDiffers = computed(() => {
  const n = identity.value?.anchor.network;
  return n && network && n !== network ? n : null;
});

async function resolveAll(ids: ComponentIdentity[]) {
  for (const i of ids) status.set(i.did, "pending");
  const queue = [...ids];
  const worker = async () => {
    for (let next = queue.shift(); next && alive; next = queue.shift()) {
      try {
        const resolved = await lookups.resolveDid(next.did);
        status.set(next.did, resolved === null ? null : keyStatus(resolved, next.did, next.keys));
      } catch (e) {
        status.set(next.did, e instanceof ForeignDocument ? "foreign" : null);
      }
    }
  };
  await Promise.all([worker(), worker()]);
}

onMounted(async () => {
  data
    .anchors(1)
    .then((a) => (latest.value = a[0] ?? null))
    .catch(() => undefined);
  try {
    identity.value = await data.identity();
  } catch (e) {
    error.value = (e as Error).message;
  } finally {
    loaded.value = true;
  }
  if (alive) void resolveAll(current.value);
});

const committed = computed(() => {
  const cp = latest.value?.checkpoint;
  const h = cp && typeof cp === "object" ? (cp as Record<string, unknown>).policyHash : undefined;
  return typeof h === "string" ? h : null;
});

function keyLine(did: string, kid: string): { tone: "ok" | "bad" | "wait" | "none"; text: string } {
  const s = status.get(did);
  if (s === undefined || s === "pending") return { tone: "wait", text: "checking…" };
  if (s === null) return { tone: "none", text: "resolver did not answer" };
  if (s === "foreign") return { tone: "bad", text: "resolver answered for another DID" };
  return stateLine(s.byKid.get(kid) ?? { kind: "absent" });
}

function stateLine(st: KeyState): { tone: "ok" | "bad" | "wait" | "none"; text: string } {
  if (st.kind === "active") return { tone: "ok", text: "in force" };
  if (st.kind === "revoked") return { tone: "bad", text: `revoked ${utc(st.atMs)}` };
  return { tone: "none", text: "not in the DID document" };
}

const FAMILY = { ok: "signed", bad: "rejected", wait: "unknown", none: "unknown" } as const;

function writerLabel(did: string): string {
  if (did === "*") return "anyone";
  return names.value.get(did) ?? shortDid(did);
}

const ruleRows = computed(() => (policy.value ? Object.entries(policy.value.tags).sort(([a], [b]) => a.localeCompare(b)) : []));
</script>

<template>
  <ConsoleShell>
    <div class="identity">
      <header class="x-head">
        <div>
          <h1 class="x-title">Identity & policy</h1>
          <p class="x-lede">
            The did:iota identities that sign for this aeriOS domain, their keys, and the writer policy that says who may write which tag. Each one
            lives on IOTA Rebased{{ network ? ` ${network}` : "" }}; follow the links to see it there.
          </p>
        </div>
      </header>

      <p v-if="!loaded" class="x-quiet">Reading the identities…</p>
      <p v-else-if="error" class="x-quiet x-err">Could not read the identities: {{ error }}</p>
      <template v-else-if="identity">
        <p v-if="identity.anchor.status === 'unreachable'" class="x-note" data-tone="bad">
          The anchor service that publishes the identities did not answer, so they cannot be listed now. The writer policy below is the explorer's own.
        </p>
        <p v-else-if="identity.anchor.status === 'not_configured'" class="x-note">This explorer is not connected to an anchor service, so it publishes no identities.</p>
        <p v-if="networkDiffers" class="x-note">
          The anchor service names the network <span class="mono">{{ networkDiffers }}</span>; links use <span class="mono">{{ network }}</span>, the
          network pinned in this console.
        </p>

        <section v-if="current.length" class="x-sec" aria-labelledby="ids-h">
          <div class="x-sec-head">
            <h2 id="ids-h" class="x-sec-title">Component identities</h2>
            <p class="x-sec-note">Key status from {{ lookups.didSource }}.</p>
          </div>
          <ul class="cards">
            <li v-for="i in current" :key="i.did" class="card">
              <p class="name">{{ i.name }}</p>
              <p class="did mono">{{ i.did }}</p>
              <dl class="x-kv">
                <div>
                  <dt>Controlled by</dt>
                  <dd>
                    <template v-if="i.controller?.kind === 'address'">
                      address
                      <a v-if="explorerAddress(i.controller.address)" class="x-link mono" :href="explorerAddress(i.controller.address)!" rel="noopener noreferrer" target="_blank">{{
                        shortHex(i.controller.address, 8, 6)
                      }}</a>
                      <span v-else class="mono">{{ shortHex(i.controller.address, 8, 6) }}</span>
                    </template>
                    <template v-else-if="i.controller?.kind === 'identity'">
                      {{ names.get(i.controller.did) ? `the ${names.get(i.controller.did)} DID` : "the DID" }}
                      <span class="mono">{{ shortDid(i.controller.did) }}</span>
                    </template>
                    <template v-else>not published</template>
                  </dd>
                </div>
                <div>
                  <dt>On IOTA Rebased</dt>
                  <dd>
                    <a v-if="explorerObject(i.objectId ?? didObjectId(i.did))" class="x-link" :href="explorerObject(i.objectId ?? didObjectId(i.did))!" rel="noopener noreferrer" target="_blank"
                      >Identity object</a
                    >
                    <template v-if="explorerTx(i.createdTx)">
                      ·
                      <a class="x-link" :href="explorerTx(i.createdTx)!" rel="noopener noreferrer" target="_blank">created{{ i.createdAt ? ` ${i.createdAt.slice(0, 10)}` : "" }}</a>
                    </template>
                    <span v-else-if="i.createdAt" class="x-muted">, created {{ i.createdAt.slice(0, 10) }}</span>
                  </dd>
                </div>
                <div v-if="policy">
                  <dt>May write</dt>
                  <dd>{{ tagsFor(i.did, policy).join(", ") || "no tag of its own" }}</dd>
                </div>
              </dl>
              <table class="keys">
                <caption class="sr-only">Keys of {{ i.name }}</caption>
                <thead>
                  <tr>
                    <th scope="col">Key</th>
                    <th scope="col">Type</th>
                    <th scope="col">Public key</th>
                    <th scope="col">Status</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="k in i.keys" :key="k.kid">
                    <td class="mono" :title="k.kid">{{ fragment(k.kid) }}</td>
                    <td :title="k.relationships.join(', ')">{{ k.type }}</td>
                    <td class="mono" :title="k.publicKeyHex ?? undefined">{{ k.publicKeyHex ? shortHex(k.publicKeyHex, 6, 4) : "–" }}</td>
                    <td class="st" :data-tone="keyLine(i.did, k.kid).tone">
                      <VerdictMark :family="FAMILY[keyLine(i.did, k.kid).tone]" /> {{ keyLine(i.did, k.kid).text }}
                    </td>
                  </tr>
                  <template v-if="status.get(i.did) && status.get(i.did) !== 'pending' && status.get(i.did) !== 'foreign'">
                    <tr v-for="o in (status.get(i.did) as KeyStatus).others" :key="o.kid" class="other">
                      <td class="mono" :title="o.kid">{{ fragment(o.kid) }}</td>
                      <td colspan="2" class="x-muted">known to the resolver only</td>
                      <td class="st" :data-tone="stateLine(o.state).tone"><VerdictMark :family="FAMILY[stateLine(o.state).tone]" /> {{ stateLine(o.state).text }}</td>
                    </tr>
                  </template>
                </tbody>
              </table>
              <p v-if="(status.get(i.did) as KeyStatus | undefined)?.historyComplete === false" class="fine">
                Part of this DID's history could not be read, so a revocation time may be an early bound.
              </p>
            </li>
          </ul>
        </section>

        <section class="x-sec" aria-labelledby="pol-h">
          <div class="x-sec-head">
            <h2 id="pol-h" class="x-sec-title">Writer policy</h2>
            <p v-if="policy" class="x-sec-note">version {{ policy.version }}</p>
          </div>
          <p v-if="!policy" class="x-quiet">This explorer runs without a writer policy: every signed writer is accepted for every tag.</p>
          <template v-else>
            <p class="hashline">
              Policy hash <span class="mono" :title="policy.hash">{{ shortHex(policy.hash, 10, 8) }}</span>.
              <template v-if="committed">
                The newest checkpoint (record {{ latest?.record ?? "?" }}) commits to
                <span class="x-cmp" :data-c="committed === policy.hash ? 'consistent' : 'differs'">{{
                  committed === policy.hash ? "the same hash" : `another hash, ${shortHex(committed, 10, 8)}`
                }}</span
                >.
              </template>
              <template v-else>Every checkpoint commits to it; none is anchored yet to compare with.</template>
              <span class="x-sec-note">Both are the explorer's answers; Anchors re-reads the checkpoint itself from IOTA Rebased.</span>
            </p>
            <table class="x-tbl x-cards rules">
              <caption class="sr-only">Who may write each tag</caption>
              <thead>
                <tr>
                  <th scope="col">Tag</th>
                  <th scope="col">Allowed writers</th>
                  <th scope="col">Signature</th>
                  <th scope="col">Unsigned legacy</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="[tag, r] in ruleRows" :key="tag">
                  <td class="mono tag">{{ tag }}</td>
                  <td>
                    <span v-for="w in r.allowed" :key="w" class="writer" :title="w">{{ writerLabel(w) }}</span>
                  </td>
                  <td>{{ r.requireSignature ? "required" : "optional" }}</td>
                  <td>{{ r.legacyGrace ? "accepted" : "rejected" }}</td>
                </tr>
                <tr class="default">
                  <td>any other tag</td>
                  <td>
                    <span v-for="w in policy.default.allowed" :key="w" class="writer" :title="w">{{ writerLabel(w) }}</span>
                  </td>
                  <td>{{ policy.default.requireSignature ? "required" : "optional" }}</td>
                  <td>{{ policy.default.legacyGrace ? "accepted" : "rejected" }}</td>
                </tr>
              </tbody>
            </table>
          </template>
        </section>

        <section v-if="previous.length" class="x-sec" aria-labelledby="prev-h">
          <div class="x-sec-head">
            <h2 id="prev-h" class="x-sec-title">Retired identities</h2>
            <p class="x-sec-note">replaced, no longer allowed to write</p>
          </div>
          <details class="prev">
            <summary>Show the {{ previous.length }} retired identities</summary>
            <ul class="prev-list">
              <li v-for="p in previous" :key="p.did">
                <span class="pn">{{ p.name }}</span>
                <span class="mono pd">{{ p.did }}</span>
                <span class="x-muted">retired {{ p.retiredAt?.slice(0, 10) ?? "" }}{{ p.reason ? `: ${p.reason}` : "" }}</span>
              </li>
            </ul>
          </details>
        </section>
      </template>
    </div>
  </ConsoleShell>
</template>

<style scoped>
.cards {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 18px;
  margin: 0;
  padding: 0;
  list-style: none;
}
.card {
  padding: 18px 20px 16px;
  border: 1px solid var(--hair);
  border-radius: var(--r-cell);
  min-width: 0;
}
.name {
  margin: 0;
  font: 400 24px/1.1 var(--serif);
  color: var(--fog-50);
}
.did {
  margin: 6px 0 14px;
  color: var(--fog-200);
  overflow-wrap: anywhere;
}
.keys {
  width: 100%;
  margin-top: 14px;
  border-collapse: collapse;
  font-size: 13px;
}
.keys th {
  padding: 0 10px 6px 0;
  text-align: left;
  font-weight: 400;
  font-size: 12px;
  color: var(--fog-400);
  border-bottom: 1px solid var(--hair-strong);
}
.keys td {
  padding: 7px 10px 7px 0;
  border-bottom: 1px solid var(--hair);
  color: var(--fog-200);
}
.st {
  white-space: nowrap;
}
.st :deep(.vm) {
  display: inline-block;
  margin-right: 6px;
  vertical-align: -1px;
}
.st[data-tone="ok"] {
  color: var(--pass);
}
.st[data-tone="bad"] {
  color: var(--fail);
}
.st[data-tone="none"],
.st[data-tone="wait"] {
  color: var(--fog-400);
}
.fine {
  margin: 10px 0 0;
  font-size: 12.5px;
  color: var(--fog-400);
}
.hashline {
  margin: 0 0 16px;
  font-size: 14px;
  color: var(--fog-200);
}
.tag {
  color: var(--fog-50);
}
.writer {
  display: inline-block;
  margin: 2px 6px 2px 0;
  padding: 1px 9px;
  border-radius: var(--r-pill);
  border: 1px solid var(--hair-strong);
  font-size: 12.5px;
  color: var(--fog-200);
}
.default td {
  color: var(--fog-400);
}
.prev summary {
  cursor: pointer;
  color: var(--fog-200);
}
.prev-list {
  margin: 14px 0 0;
  padding: 0;
  list-style: none;
}
.prev-list li {
  display: grid;
  grid-template-columns: 150px minmax(0, 1fr);
  gap: 2px 16px;
  padding: 9px 0;
  border-bottom: 1px solid var(--hair);
  font-size: 13px;
}
.prev-list .x-muted {
  grid-column: 2;
}
.pn {
  color: var(--fog-50);
}
.pd {
  overflow-wrap: anywhere;
}
@media (max-width: 1080px) {
  .cards {
    grid-template-columns: minmax(0, 1fr);
  }
}
@media (max-width: 760px) {
  .keys th:nth-child(3),
  .keys td:nth-child(3) {
    display: none;
  }
  .prev-list li {
    grid-template-columns: minmax(0, 1fr);
  }
  .prev-list .x-muted {
    grid-column: 1;
  }
}
</style>
