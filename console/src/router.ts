import { createRouter, createWebHistory, type RouteRecordRaw } from "vue-router";

import { SCREENS } from "@/screens";
import LandingView from "@/views/LandingView.vue";

const ComingSoon = () => import("@/views/ComingSoon.vue");

const routes: RouteRecordRaw[] = [
  { path: "/", name: "landing", component: LandingView, meta: { title: "Witness" } },
  ...SCREENS.map((s) => ({ path: s.path, name: s.name, component: ComingSoon, meta: { title: s.title, blurb: s.blurb } })),
  { path: "/:pathMatch(.*)*", redirect: "/" },
];

export const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes,
  scrollBehavior(to, _from, saved) {
    if (saved) return saved;
    if (to.hash) return { el: to.hash };
    return { top: 0 };
  },
});

router.afterEach((to) => {
  const t = to.meta.title;
  document.title = to.name === "landing" || !t ? "Witness" : `${String(t)} – Witness`;
});
