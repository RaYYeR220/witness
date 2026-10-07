import vue from "@vitejs/plugin-vue";
import { rmSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath, URL } from "node:url";
import type { Plugin, ProxyOptions, UserConfig } from "vite";
import { defineConfig } from "vitest/config";

/**
 * In dev and preview, the console reaches the stack through same-origin paths:
 * /api is witness-api and /anchor/resolve/ the anchor service's DID resolver
 * (nothing else of the anchor service: its admin endpoints stay unreachable),
 * so the browser needs no CORS and the event stream can resume with
 * Last-Event-ID. WITNESS_API_TARGET and WITNESS_ANCHOR_TARGET point them
 * elsewhere. Deployments must proxy the same two paths (docs/operations.md).
 */
const target = (env: string | undefined, fallback: string) => env ?? fallback;
const strip = (prefix: string): ProxyOptions["rewrite"] => (path) => path.slice(prefix.length) || "/";
const proxy: Record<string, ProxyOptions> = {
  "/api": { target: target(process.env.WITNESS_API_TARGET, "http://127.0.0.1:7200"), changeOrigin: true, rewrite: strip("/api") },
  "/anchor/resolve/": { target: target(process.env.WITNESS_ANCHOR_TARGET, "http://127.0.0.1:7300"), changeOrigin: true, rewrite: strip("/anchor") },
};

/**
 * `vite build --mode lib` builds WitnessLineage alone, for the aeriOS
 * Management Portal to embed (dist-lib/): an ES module and a UMD script with
 * Vue as a peer (the host's own copy, global `Vue` for the UMD), and one CSS
 * file that carries the design tokens on the widget's root.
 */
const lib: UserConfig["build"] = {
  target: "es2022",
  outDir: "dist-lib",
  copyPublicDir: false,
  lib: {
    entry: fileURLToPath(new URL("./src/lib/witness-lineage.ts", import.meta.url)),
    name: "WitnessLineage",
    formats: ["es", "umd"],
    fileName: (format) => (format === "es" ? "witness-lineage.js" : "witness-lineage.umd.cjs"),
  },
  rollupOptions: {
    external: ["vue"],
    output: { globals: { vue: "Vue" }, assetFileNames: "witness-lineage.[ext]", exports: "named" },
  },
};

/**
 * The recorded snapshot in public/replay/ is for replay builds only: any other
 * build drops it from its output. A replay build also gets a 404.html that is
 * the app itself, because static hosts (GitHub Pages) answer a path they do not
 * hold with that file: a deep link such as /m/0x… then opens its screen.
 */
function replayOutput(mode: string): Plugin {
  let outDir = "dist";
  return {
    name: "witness-replay-output",
    apply: "build",
    enforce: "post",
    configResolved(c) {
      outDir = resolve(c.root, c.build.outDir);
    },
    generateBundle(_, bundle) {
      const index = bundle["index.html"];
      if (mode === "replay" && index?.type === "asset") this.emitFile({ type: "asset", fileName: "404.html", source: index.source });
    },
    closeBundle() {
      if (mode !== "replay") rmSync(resolve(outDir, "replay"), { recursive: true, force: true });
    },
  };
}

export default defineConfig(({ mode }) => ({
  plugins: [vue(), ...(mode === "lib" ? [] : [replayOutput(mode)])],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  server: { proxy },
  preview: { proxy },
  build:
    mode === "lib"
      ? lib
      : {
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
}));
