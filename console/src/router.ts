import { createRouter, createWebHistory, type RouteRecordRaw } from "vue-router";

import { SCREENS } from "@/screens";
import LandingView from "@/views/LandingView.vue";

const ComingSoon = () => import("@/views/ComingSoon.vue");

/** Screens that are built; the rest show their placeholder until their task lands. */
const VIEWS: Record<string, RouteRecordRaw["component"]> = {
  live: () => import("@/views/LiveView.vue"),
  search: () => import("@/views/SearchView.vue"),
};

const routes: RouteRecordRaw[] = [
  { path: "/", name: "landing", component: LandingView, meta: { title: "Witness" } },
  ...SCREENS.map(
    (s) => ({ path: s.path, name: s.name, component: VIEWS[s.name] ?? ComingSoon, meta: { title: s.title, blurb: s.blurb } }) as RouteRecordRaw,
  ),
  { path: "/:pathMatch(.*)*", redirect: "/" },
];

export const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes,
  scrollBehavior(to, from, saved) {
    if (saved) return saved;
    if (to.hash) return { el: to.hash };
    if (to.name === from.name && to.name === "search") return false; // paging and refining keep the place
    return { top: 0 };
  },
});

router.afterEach((to) => {
  const t = to.meta.title;
  document.title = to.name === "landing" || !t ? "Witness" : `${String(t)} – Witness`;
});
