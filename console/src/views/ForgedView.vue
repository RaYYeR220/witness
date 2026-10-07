<script setup lang="ts">
import { fromHex, isDict, parseJson } from "@witness/verify";
import { computed, onBeforeUnmount, onMounted } from "vue";

import ConsoleShell from "@/components/ConsoleShell.vue";
import { useLookups } from "@/console/data";
import { explorerObject } from "@/console/explorer";
import { shortDid, shortHex } from "@/console/format";
import LadderPanel from "@/console/LadderPanel.vue";
import demo from "@/fixtures/forged-milestone.json";
import { createLadder, resetLadder, runLadder } from "@/verify/ladder";
import { anchorPinned, PINNED } from "@/verify/pinned";
import { readTrustMessage } from "@/verify/sample";

/**
 * A forged proof to try: a bundle made offline (make-fixture.mjs), not a
 * message of this explorer. Its milestone is signed with IOTA's public sample
 * coordinator keys, the keys this console pins, and its anchor names a record
 * of the pinned trail. The five checks run on it exactly as on Verify: the
 * issuer is a did:key (decoded, nothing looked up) and step 5 reads the record
 * from IOTA Rebased.
 */
const lookups = useLookups();
const ladder = createLadder();
const anchorOk = anchorPinned();

const facts = (() => {
  const b = parseJson(demo.bundle) as Record<string, unknown>;
  const block = b.block as { id: string; raw: string };
  const ms = b.milestone as { index: number };
  const anchor = isDict(b.anchor) ? (b.anchor as Record<string, Record<string, unknown>>) : null;
  const trust = readTrustMessage(fromHex(block.raw));
  return {
    blockId: block.id,
    msIndex: ms.index,
    record: typeof anchor?.rebased?.record === "number" ? anchor.rebased.record : null,
    issuer: trust?.issuer ?? null,
    score: trust?.scoreText ?? null,
    entity: trust?.entity ?? null,
  };
})();

const trailLink = explorerObject(PINNED.trailId);
const verdict = computed(() => (ladder.running ? null : ladder.overall));

function reduced() {
  return typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;
}

async function verify() {
  await runLadder(ladder, demo.bundle, {
    resolveDid: lookups.resolveDid,
    fetchAnchorRecord: lookups.fetchAnchorRecord,
    pace: reduced() ? 0 : 240,
  });
}

function download() {
  const url = URL.createObjectURL(new Blob([demo.bundle], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = "witness-forged-milestone.json";
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

onMounted(() => void verify());
onBeforeUnmount(() => resetLadder(ladder));
</script>

<template>
  <ConsoleShell>
    <div class="forged">
      <header class="x-head">
        <div>
          <p class="x-kicker"><RouterLink to="/live">Live</RouterLink> <span aria-hidden="true">/</span> Verify <span aria-hidden="true">/</span> A forged proof</p>
          <h1 class="x-title">A forged milestone</h1>
          <p class="x-lede">
            This proof was made offline, not taken from the explorer. A trust score of {{ facts.score ?? "?" }} for
            <span class="mono">{{ facts.entity ?? "an entity" }}</span>, signed by a did:key, sits in a milestone {{ facts.msIndex }} that was signed
            with IOTA's public sample coordinator keys: the keys the organisers' private Tangle uses, and so the keys this console pins. Anyone can
            sign such a milestone. The bundle then claims record {{ facts.record ?? "?" }} of the anchor trail this console trusts.
          </p>
        </div>
      </header>

      <dl class="x-kv facts">
        <div>
          <dt>Block</dt>
          <dd class="mono" :title="facts.blockId">{{ shortHex(facts.blockId, 8, 6) }}</dd>
        </div>
        <div>
          <dt>Milestone</dt>
          <dd>{{ facts.msIndex }}, signed with the sample keys</dd>
        </div>
        <div>
          <dt>Sender</dt>
          <dd class="mono" :title="facts.issuer ?? undefined">{{ facts.issuer ? shortDid(facts.issuer) : "unsigned" }}</dd>
        </div>
        <div>
          <dt>Claims</dt>
          <dd>
            record {{ facts.record }} of
            <a v-if="trailLink" class="x-link mono" :href="trailLink" rel="noopener noreferrer" target="_blank">{{ shortHex(PINNED.trailId ?? "", 8, 6) }}</a>
            <span v-else>the pinned trail</span>
            on IOTA Rebased {{ PINNED.rebasedNetwork }}
          </dd>
        </div>
      </dl>

      <section class="x-sec" aria-labelledby="forged-checks-h">
        <div class="x-sec-head">
          <h2 id="forged-checks-h" class="x-sec-title">The five checks, in your browser</h2>
          <div class="actions">
            <button class="btn" type="button" :disabled="ladder.running" @click="verify">Run the checks again</button>
            <button class="btn btn--ghost" type="button" @click="download">Download bundle</button>
          </div>
        </div>
        <LadderPanel :state="ladder" :anchor-pinned="anchorOk" />
        <p v-if="verdict === 'INVALID' && ladder.failedAt === 5" class="x-note" data-tone="bad" role="note">
          <b>Caught at check 5.</b> Checks 1 to 4 cannot tell this milestone from a real one: the bytes hash to the id, the path reaches the root,
          the pinned keys signed it and the sender's signature holds. Only the checkpoint on IOTA Rebased, a ledger the sample keys do not control,
          shows that our Tangle never had this milestone: your browser read record {{ facts.record }} from the chain and it commits to another
          checkpoint.
        </p>
        <p v-else-if="verdict === 'PARTIAL'" class="x-note" role="note">
          IOTA Rebased did not answer, so check 5 was not evaluated, and partial is not a pass. Run the checks again to read the record.
        </p>
        <p class="x-sec-note more">
          From a clone of the repository, the Python verifier gives the same ladder:
          <span class="mono">uv run --package witness-cli witness verify witness-forged-milestone.json --config console/src/config/verifier.json</span>.
          Back to a <RouterLink class="x-link" to="/live">real message</RouterLink>.
        </p>
      </section>
    </div>
  </ConsoleShell>
</template>

<style scoped>
.facts {
  margin-top: 24px;
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
.x-note {
  margin-top: 18px;
}
.more {
  margin-top: 18px;
}
.more .mono {
  overflow-wrap: anywhere;
}
</style>
