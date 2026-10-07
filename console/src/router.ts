import { createRouter, createWebHistory, type RouteRecordRaw } from "vue-router";

import { SCREENS } from "@/screens";
import LandingView from "@/views/LandingView.vue";

/** The view of each screen in screens.ts. */
const VIEWS: Record<string, RouteRecordRaw["component"]> = {
  live: () => import("@/views/LiveView.vue"),
  search: () => import("@/views/SearchView.vue"),
  verify: () => import("@/views/VerifyView.vue"),
  lineage: () => import("@/views/LineageView.vue"),
  integrity: () => import("@/views/IntegrityView.vue"),
  identity: () => import("@/views/IdentityView.vue"),
  anchors: () => import("@/views/AnchorsView.vue"),
  posture: () => import("@/views/PostureView.vue"),
  reports: () => import("@/views/ReportsView.vue"),
};

const routes: RouteRecordRaw[] = [
  { path: "/", name: "landing", component: LandingView, meta: { title: "Witness" } },
  ...SCREENS.map(
    (s) => ({ path: s.path, name: s.name, component: VIEWS[s.name]!, meta: { title: s.title, blurb: s.blurb } }) as RouteRecordRaw,
  ),
  // incidents live on Integrity
  { path: "/incidents", redirect: { name: "integrity" } },
  { path: "/incidents/:id", redirect: (to) => ({ name: "integrity", query: { incident: String(to.params.id) } }) },
  { path: "/:pathMatch(.*)*", redirect: "/" },
];

export const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes,
  scrollBehavior(to, from, saved) {
    if (saved) return saved;
    if (to.hash) return { el: to.hash };
    if (to.name === from.name && (to.name === "search" || to.name === "integrity")) return false; // paging, filtering and picking keep the place
    return { top: 0 };
  },
});

router.afterEach((to) => {
  const t = to.meta.title;
  document.title = to.name === "landing" || !t ? "Witness" : `${String(t)} – Witness`;
});
