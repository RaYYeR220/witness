<script setup lang="ts">
import { ref } from "vue";

import LandingFooter from "@/components/LandingFooter.vue";
import SiteNav from "@/components/SiteNav.vue";
import FlipByte from "@/landing/FlipByte.vue";
import SkyStage from "@/landing/SkyStage.vue";

const reduced = typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;
const stage = ref<InstanceType<typeof SkyStage> | null>(null);

function toFlip() {
  document.getElementById("flip")?.scrollIntoView({ behavior: reduced ? "auto" : "smooth", block: "start" });
}
function toHow() {
  if (reduced) document.getElementById("how")?.scrollIntoView({ block: "start" });
  else stage.value?.scrollToP(0.12);
}
</script>

<template>
  <a class="skip-link" href="#flip">Skip to the byte you can flip</a>
  <SiteNav @how="toHow" />
  <main>
    <SkyStage ref="stage" :still="reduced" @verify="toFlip" />
    <FlipByte />
  </main>
  <LandingFooter />
</template>
