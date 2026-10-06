import { createRequire } from "node:module";
import { dirname, join } from "node:path";

import { defineConfig } from "vitest/config";

// Pin jose to its browser build (WebCrypto), the one bundlers ship to the console,
// instead of the node:crypto build Node's resolver would pick.
const joseRoot = dirname(createRequire(import.meta.url).resolve("jose/package.json"));

export default defineConfig({
  resolve: { alias: { jose: join(joseRoot, "dist/browser/index.js") } },
  test: {
    // The library ships to the browser: run every suite in a DOM environment.
    environment: "jsdom",
    include: ["test/**/*.test.ts"],
    server: { deps: { inline: ["jose"] } },
    // jsdom per worker is memory-hungry; a couple of workers is plenty here.
    maxWorkers: 2,
    minWorkers: 1,
  },
});
