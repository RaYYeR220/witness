#!/usr/bin/env node
/**
 * Records a replay snapshot of a running stack for a `VITE_MODE=replay` build:
 * the same responses the console asks the API for, saved as static files, so
 * the console runs with no backend. Proofs in the snapshot are still verified
 * in the browser against the console's pinned config, and step 5 still reads
 * IOTA Rebased live.
 *
 *   manifest.json            what, when, from where
 *   messages.json            the newest messages (one page of GET /messages)
 *   messages/<id>.json       GET /messages/{id}
 *   lifecycle/<id>.json      GET /messages/{id}/lifecycle
 *   bundles/<id>.json        GET /proofs/{id}, byte for byte
 *   dids/<did>.json          the anchor resolver's answer for each issuer
 *                            (':' replaced by '_' in the file name)
 *   verifier-config.json     GET /config/verifier (informational)
 *   anchors.json             GET /anchors (the newest checkpoints)
 *   stream.json              the latest events of GET /stream
 *
 * Run: node scripts/record-replay.mjs [--api http://127.0.0.1:7200]
 *        [--resolver http://127.0.0.1:7300] [--out public/replay] [--limit 60]
 */

import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

function args(argv) {
  const out = { api: "http://127.0.0.1:7200", resolver: "http://127.0.0.1:7300", out: resolve(here, "../public/replay"), limit: 60, events: 150 };
  for (let i = 0; i < argv.length; i += 2) {
    const k = argv[i]?.replace(/^--/, "");
    if (!(k in out)) throw new Error(`unknown option ${argv[i]}`);
    out[k] = typeof out[k] === "number" ? Number(argv[i + 1]) : argv[i + 1];
  }
  return out;
}

/** The file name a DID is stored under (and looked up by, see src/verify/lookups.ts). */
const didFile = (did) => `${did.replace(/[^A-Za-z0-9._-]/g, "_")}.json`;

async function fetchText(url, init = {}) {
  const res = await fetch(url, { ...init, signal: AbortSignal.timeout(15_000) });
  if (!res.ok) throw new Error(`${url} answered ${res.status}`);
  return res.text();
}

/** The latest `keep` events: read the log from the start for a few seconds and keep the tail. */
async function recentEvents(api, keep) {
  const types = "message,milestone,alert,anchor,incident";
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 6000);
  const events = [];
  try {
    const res = await fetch(`${api}/stream?after=0&limit=5000&types=${types}`, { signal: ctl.signal, headers: { accept: "text/event-stream" } });
    if (!res.ok || !res.body) return [];
    const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
    let buf = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += value.replace(/\r\n?/g, "\n");
      let cut;
      while ((cut = buf.indexOf("\n\n")) >= 0) {
        const block = buf.slice(0, cut);
        buf = buf.slice(cut + 2);
        const data = block
          .split(/\r?\n/)
          .filter((l) => l.startsWith("data:"))
          .map((l) => l.slice(5).trimStart())
          .join("\n");
        if (data) events.push(JSON.parse(data));
      }
    }
  } catch {
    /* the timeout ends the read */
  } finally {
    clearTimeout(timer);
  }
  return events.slice(-keep);
}

async function main() {
  const o = args(process.argv.slice(2));
  const api = o.api.replace(/\/+$/, "");
  const resolver = o.resolver.replace(/\/+$/, "");
  rmSync(o.out, { recursive: true, force: true });
  const write = (name, text) => {
    const file = join(o.out, name);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, text);
  };
  const json = (v) => JSON.stringify(v, null, 1) + "\n";

  const page = JSON.parse(await fetchText(`${api}/messages?limit=${o.limit}`));
  write("messages.json", json({ ...page, nextCursor: null }));
  const dids = new Set();
  let bundles = 0;
  for (const m of page.items) {
    const id = m.blockId;
    write(`messages/${id}.json`, await fetchText(`${api}/messages/${id}`));
    write(`lifecycle/${id}.json`, await fetchText(`${api}/messages/${id}/lifecycle`));
    try {
      write(`bundles/${id}.json`, await fetchText(`${api}/proofs/${id}`));
      bundles += 1;
    } catch {
      /* not in an indexed milestone yet: Verify says so */
    }
    if (m.iss) dids.add(m.iss);
  }
  for (const did of dids) {
    try {
      write(`dids/${didFile(did)}`, await fetchText(`${resolver}/resolve/${encodeURIComponent(did)}`));
    } catch (e) {
      console.warn(`no DID document for ${did}: ${e.message}`);
    }
  }
  write("verifier-config.json", await fetchText(`${api}/config/verifier`));
  write("anchors.json", await fetchText(`${api}/anchors?limit=20`));
  const events = await recentEvents(api, o.events);
  write("stream.json", json(events));
  write(
    "manifest.json",
    json({
      about: "A recorded snapshot of a running Witness stack. Proofs are verified in your browser against the console's pinned config.",
      recordedAtMs: Date.now(),
      source: "witness-api and the anchor service's DID resolver",
    }),
  );
  console.log(`recorded ${page.items.length} messages, ${bundles} bundles, ${dids.size} DIDs, ${events.length} events into ${o.out}`);
}

main().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
