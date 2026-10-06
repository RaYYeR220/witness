import vue from "@vitejs/plugin-vue";
import { fileURLToPath, URL } from "node:url";
import type { ProxyOptions } from "vite";
import { defineConfig } from "vitest/config";

/**
 * In dev and preview, the console reaches the stack through same-origin paths:
 * /api is witness-api and /anchor the anchor service (its DID resolver), so the
 * browser needs no CORS and the event stream can resume with Last-Event-ID.
 * WITNESS_API_TARGET and WITNESS_ANCHOR_TARGET point them elsewhere.
 */
const target = (env: string | undefined, fallback: string) => env ?? fallback;
const strip = (prefix: string): ProxyOptions["rewrite"] => (path) => path.slice(prefix.length) || "/";
const proxy: Record<string, ProxyOptions> = {
  "/api": { target: target(process.env.WITNESS_API_TARGET, "http://127.0.0.1:7200"), changeOrigin: true, rewrite: strip("/api") },
  "/anchor": { target: target(process.env.WITNESS_ANCHOR_TARGET, "http://127.0.0.1:7300"), changeOrigin: true, rewrite: strip("/anchor") },
};

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  server: { proxy },
  preview: { proxy },
  build: {
    target: "es2022",
    chunkSizeWarningLimit: 700,
  },
  test: {
    include: ["src/**/*.test.ts", "scripts/**/*.test.ts"],
    environment: "node",
    passWithNoTests: true,
    maxWorkers: 2,
    minWorkers: 1,
  },
});
