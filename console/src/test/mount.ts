/** Mounting a console screen in tests: a memory router with the console's route names, and swapped data. */
import { mount } from "@vue/test-utils";
import { defineComponent, h, type Component } from "vue";
import { createMemoryHistory, createRouter } from "vue-router";

import type { WitnessData } from "@/api/client";
import { DATA_KEY, LOOKUPS_KEY } from "@/console/data";
import type { TrustedLookups } from "@/verify/lookups";

const Stub = defineComponent({ render: () => h("div") });

export async function mountScreen(view: Component, opts: { path: string; data: WitnessData; lookups?: TrustedLookups }) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/", name: "landing", component: Stub },
      { path: "/live", name: "live", component: Stub },
      { path: "/search", name: "search", component: Stub },
      { path: "/m/:blockId", name: "verify", component: Stub },
      { path: "/:rest(.*)*", name: "other", component: Stub },
    ],
  });
  await router.push(opts.path);
  await router.isReady();
  const provide: Record<symbol, unknown> = { [DATA_KEY as symbol]: opts.data };
  if (opts.lookups) provide[LOOKUPS_KEY as symbol] = opts.lookups;
  const w = mount(view, { attachTo: document.body, global: { plugins: [router], provide } });
  return { w, router };
}

/** Polls until `ok()` holds (or fails the test after `ms`). */
export async function until(ok: () => boolean, ms = 3000) {
  const end = Date.now() + ms;
  while (!ok()) {
    if (Date.now() > end) throw new Error("timed out waiting");
    await new Promise((r) => setTimeout(r, 10));
  }
}
