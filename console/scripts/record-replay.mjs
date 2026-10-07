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
 *   ie.json                  GET /ie
 *   lineage/<ie>.json        GET /ie/{id}/lineage for each IE (file name as dids/)
 *   alerts.json              GET /alerts (the newest 500)
 *   incidents.json           GET /incidents
 *   incidents/<id>.json      GET /incidents/{id} (first 500 events and alerts)
 *   identity.json            GET /identity (its DIDs are resolved into dids/ too)
 *   posture.json, stats.json GET /posture, GET /stats
 *   reports.json             GET /reports, with reports/<hash>.json and .html
 *   scorecard.json           the evaluation scorecard given with --scorecard, if any
 *
 * Blocks the lineage and incident screens point at (the newest entries of
 * each lineage, every incident event) are recorded like the message page, up
 * to --blocks in all, so Verify works from those screens too.
 *
 * Run: node scripts/record-replay.mjs [--api http://127.0.0.1:7200]
 *        [--resolver http://127.0.0.1:7300] [--out public/replay] [--limit 60]
 *        [--blocks 120] [--scorecard results/scorecard.json]
 */

import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

function args(argv) {
  const out = {
    api: "http://127.0.0.1:7200",
    resolver: "http://127.0.0.1:7300",
    out: resolve(here, "../public/replay"),
    limit: 60,
    events: 150,
    blocks: 120,
    scorecard: "",
  };
  for (let i = 0; i < argv.length; i += 2) {
    const k = argv[i]?.replace(/^--/, "");
    if (!(k in out)) throw new Error(`unknown option ${argv[i]}`);
    out[k] = typeof out[k] === "number" ? Number(argv[i + 1]) : argv[i + 1];
  }
  return out;
}

/** The file name an id (a DID, an IE) is stored under, and looked up by (src/verify/lookups.ts, fileKey in src/api/client.ts). */
const fileKey = (id) => id.replace(/[^A-Za-z0-9._-]/g, "_");
const didFile = (did) => `${fileKey(did)}.json`;
const HASH32 = /^0x[0-9a-f]{64}$/;

/**
 * The API serves a report page with a strict Content-Security-Policy header; a static
 * host serving the snapshot sends none. The same policy goes into the page itself, first
 * thing in <head>, so the recorded copy cannot run scripts or load anything either.
 */
export const REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'";
export function withCsp(html) {
  const meta = `<meta http-equiv="Content-Security-Policy" content="${REPORT_CSP}">`;
  const head = /<head(\s[^>]*)?>/i.exec(html);
  if (head) return html.slice(0, head.index + head[0].length) + meta + html.slice(head.index + head[0].length);
  return `<!doctype html><head>${meta}</head>` + html;
}

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
  write("verifier-config.json", await fetchText(`${api}/config/verifier`));
  write("anchors.json", await fetchText(`${api}/anchors?limit=100`));

  // The explorer screens: lineage, integrity, identity, posture, reports.
  const getJson = async (path) => JSON.parse(await fetchText(`${api}${path}`));
  const wanted = []; // blocks those screens link to, most useful first
  const ies = await getJson("/ie");
  write("ie.json", json(ies));
  for (const ie of ies.items.slice(0, 40)) {
    const lineage = await getJson(`/ie/${encodeURIComponent(ie.ieId)}/lineage`);
    write(`lineage/${fileKey(ie.ieId)}.json`, json(lineage));
    for (const e of lineage.entries.slice(-12).reverse()) wanted.push(e.blockId);
  }
  write("alerts.json", await fetchText(`${api}/alerts?limit=500`));
  const incidents = await getJson("/incidents?limit=200");
  write("incidents.json", json(incidents));
  for (const inc of incidents.items) {
    const detail = await getJson(`/incidents/${inc.id}?limit=500`);
    write(`incidents/${inc.id}.json`, json(detail));
    for (const e of detail.events) wanted.unshift(e.blockId);
  }
  const identity = await getJson("/identity");
  write("identity.json", json(identity));
  for (const id of [...(identity.anchor?.identities ?? []), ...(identity.anchor?.previous ?? [])]) {
    if (typeof id?.did === "string") dids.add(id.did);
  }
  write("posture.json", await fetchText(`${api}/posture`));
  write("stats.json", await fetchText(`${api}/stats`));
  const reports = await getJson("/reports?limit=200");
  write("reports.json", json({ ...reports, nextCursor: null }));
  for (const r of reports.items) {
    if (!HASH32.test(r.reportHash)) continue;
    write(`reports/${r.reportHash}.json`, await fetchText(`${api}/reports/${r.reportHash}`));
    write(`reports/${r.reportHash}.html`, withCsp(await fetchText(`${api}/reports/${r.reportHash}.html`)));
    if (r.blockId) wanted.unshift(r.blockId);
  }
  if (o.scorecard) {
    const card = JSON.parse(readFileSync(o.scorecard, "utf8"));
    if (card?.schema !== "witness-chaos/scorecard/v1") throw new Error(`${o.scorecard} is not a witness-chaos/scorecard/v1 scorecard`);
    write("scorecard.json", json(card));
  }
  const recorded = new Set(page.items.map((m) => m.blockId));
  let extra = 0;
  for (const id of wanted) {
    if (extra >= o.blocks) break;
    if (!HASH32.test(id) || recorded.has(id)) continue;
    recorded.add(id);
    try {
      const m = JSON.parse(await fetchText(`${api}/messages/${id}`));
      write(`messages/${id}.json`, json(m));
      write(`lifecycle/${id}.json`, await fetchText(`${api}/messages/${id}/lifecycle`));
      write(`bundles/${id}.json`, await fetchText(`${api}/proofs/${id}`));
      if (m.iss) dids.add(m.iss);
      extra += 1;
    } catch {
      /* not indexed (an orphaned block) or no proof yet: Verify says so */
    }
  }
  for (const did of dids) {
    try {
      write(`dids/${didFile(did)}`, await fetchText(`${resolver}/resolve/${encodeURIComponent(did)}`));
    } catch (e) {
      console.warn(`no DID document for ${did}: ${e.message}`);
    }
  }
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
  console.log(
    `recorded ${page.items.length} messages (+${extra} linked blocks), ${bundles} bundles, ${dids.size} DIDs, ${ies.items.length} IEs, ` +
      `${incidents.items.length} incidents, ${reports.items.length} reports, ${events.length} events into ${o.out}`,
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((e) => {
    console.error(e.message);
    process.exit(1);
  });
}
