/** The data source's health for the console's status line, polled while a console screen is open. */

import { onBeforeUnmount, onMounted, ref } from "vue";

import type { SourceHealth } from "@/api/client";

import { useData } from "./data";

const POLL_MS = 20_000;

export function useHealth() {
  const data = useData();
  const health = ref<SourceHealth | null>(null);
  let timer: ReturnType<typeof setInterval> | null = null;

  async function check() {
    health.value = await data.health();
  }

  onMounted(() => {
    void check();
    if (data.mode === "live") timer = setInterval(() => void check(), POLL_MS);
  });
  onBeforeUnmount(() => {
    if (timer) clearInterval(timer);
  });

  return { health, mode: data.mode, check };
}
