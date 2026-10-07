#!/usr/bin/env node
/**
 * Records a replay snapshot of a running stack for a `VITE_MODE=replay` build:
 * the same responses the console asks the API for, saved as static files, so
 * the console runs with no backend. Proofs in the snapshot are still verified
 * in the browser against the console's pinned config, and step 5 still reads
 * IOTA Rebased live. It only reads: GET everywhere, plus POST /lookup/blind,
 * which is a lookup.
 *
 *   manifest.json            what, when, from where, up to which milestone
 *   messages.json            the listed messages (see "Which messages" below)
 *   messages/<id>.json       GET /messages/{id}
 *   lifecycle/<id>.json      GET /messages/{id}/lifecycle
 *   bundles/<id>.json        GET /proofs/{id}, byte for byte
 *   dids/<did>.json          the anchor resolver's answer for each did:iota issuer
 *                            (':' replaced by '_' in the file name)
 *   verifier-config.json     GET /config/verifier (informational)
 *   anchors.json             GET /anchors (the newest checkpoints)
 *   stream.json              the latest events of GET /stream (up to the cut)
 *   blind.json               POST /lookup/blind for the tokens in --include files
 *   ie.json                  GET /ie
 *   lineage/<ie>.json        GET /ie/{id}/lineage for each IE (file name as dids/)
 *   alerts.json              GET /alerts (the newest 500)
 *   incidents.json           GET /incidents
 *   incidents/<id>.json      GET /incidents/{id} (first 500 events and alerts)
 *   flows-<by>.json          GET /flows?by=issuer|corr|ie|service
 *   flows/<by>/<key>.json    GET /flows/{by}/{key} for the 8 most active of each
 *   identity.json            GET /identity (its DIDs are resolved into dids/ too)
 *   posture.json, stats.json GET /posture, GET /stats
 *   reports.json             GET /reports, with reports/<hash>.json and .html
 *   scorecard.json           the first evaluation scorecard given with --scorecard;
 *   scorecard-<run>.json     the others, separate runs (named by their directory)
 *
 * Which messages. The newest --limit messages, and with --until anchored only
 * those whose milestone an anchored checkpoint covers, so every listed proof
 * can pass all five checks. --include adds every message a file names
 * ("blockId" values, e.g. an evaluation's trials.jsonl) and --sample N up to
 * N more of each tag, verdict and sealed-or-not, newest first; both stay
 * within the cut. --exclude names blocks never to record (comma-separated
 * ids), listed or linked. Each listed message gets its detail, lifecycle and
 * proof.
 *
 * Blocks the lineage and incident screens point at (the newest entries of
 * each lineage, every incident event), and a few trust scores from anchored
 * windows, are recorded like the message page, up to --blocks in all, so
 * Verify works from those screens too.
 *
 * Run: node scripts/record-replay.mjs [--api http://127.0.0.1:7200]
 *        [--resolver http://127.0.0.1:7300] [--out public/replay] [--limit 60]
 *        [--until anchored|<milestone>] [--include a.jsonl,b.jsonl] [--sample 0] [--exclude 0x…,0x…]
 *        [--blocks 120] [--events 400] [--scorecard results/x/scorecard.json,results/y/scorecard.json]
 */

import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

function args(argv) {
  const out = {
    api: "http://127.0.0.1:7200",
    resolver: "http://127.0.0.1:7300",
    out: resolve(here, "../public/replay"),
    limit: 60,
    events: 400,
    blocks: 120,
    scorecard: "",
    until: "",
    include: "",
    exclude: "",
    sample: 0,
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

/**
 * Block ids and blind-search tokens a file names: every "blockId" (or "firstBlockId") and "blindToken" value in it.
 * @param {string} text
 */
export function namedIn(text) {
  const ids = new Set();
  for (const m of text.matchAll(/"(?:blockId|firstBlockId)"\s*:\s*"(0x[0-9a-fA-F]{64})"/g)) ids.add(m[1].toLowerCase());
  const tokens = new Set();
  for (const m of text.matchAll(/"blindToken"\s*:\s*"([A-Za-z0-9_-]{16,128})"/g)) tokens.add(m[1]);
  return { ids: [...ids], tokens: [...tokens] };
}

/**
 * The last milestone an anchored checkpoint covers, and when that checkpoint was written; null without one.
 * @param {Array<{ status?: string, toMilestone?: number, createdAtMs?: number | null }>} anchors
 * @returns {{ milestone: number, atMs: number | null } | null}
 */
export function lastAnchored(anchors) {
  let best = null;
  for (const a of anchors) {
    if (a?.status !== "anchored" || !Number.isInteger(a.toMilestone)) continue;
    if (!best || a.toMilestone > best.toMilestone) best = a;
  }
  return best ? { milestone: best.toMilestone, atMs: best.createdAtMs ?? null } : null;
}

/**
 * Which messages to list, in the order the API lists them (`scan`, newest
 * first): the newest `limit`, every one `include` names, and up to `sample`
 * of each tag, verdict and sealed-or-not; never one `exclude` names.
 * @template {{ blockId: string, tag: string | null, verdict: string | null, encrypted?: boolean }} M
 * @param {M[]} scan
 * @param {{ limit: number, include?: string[], sample?: number, exclude?: string[] }} opts
 * @returns {M[]}
 */
export function pickMessages(scan, { limit, include = [], sample = 0, exclude = [] }) {
  const skip = new Set(exclude);
  scan = scan.filter((m) => !skip.has(m.blockId));
  const chosen = new Set(scan.slice(0, limit).map((m) => m.blockId));
  const wanted = new Set(include);
  for (const m of scan) if (wanted.has(m.blockId)) chosen.add(m.blockId);
  if (sample > 0) {
    const seen = new Map();
    for (const m of scan) {
      const group = `${m.tag}|${m.verdict}|${m.encrypted === true}`;
      const n = seen.get(group) ?? 0;
      if (n >= sample) continue;
      seen.set(group, n + 1);
      chosen.add(m.blockId);
    }
  }
  return scan.filter((m) => chosen.has(m.blockId));
}

/**
 * The recorded events a replay plays back: messages and lifecycles of blocks
 * the snapshot holds, milestones and checkpoints up to the cut milestone, and
 * other events up to a minute after `untilMs` (when the last checkpoint was
 * written). The newest `keep` of them.
 * @template {{ id: number, type: string, atMs: number, payload?: Record<string, unknown> }} E
 * @param {E[]} events
 * @param {{ keep: number, cut?: number | null, untilMs?: number | null, recorded: Set<string> }} opts
 * @returns {E[]}
 */
export function keepEvents(events, { keep, cut = null, untilMs = null, recorded }) {
  const num = (v) => (typeof v === "number" ? v : null);
  const upTo = (index) => cut === null || (num(index) ?? Infinity) <= cut;
  const inTime = (e) => untilMs === null || e.atMs <= untilMs + 60_000;
  const held = (p) => typeof p.blockId === "string" && recorded.has(p.blockId.toLowerCase());
  return events
    .filter((e) => {
      const p = e.payload ?? {};
      if (e.type === "message") return held(p) && upTo(p.msIndex);
      if (e.type === "lifecycle") return held(p) && inTime(e);
      if (e.type === "milestone") return upTo(p.index);
      if (e.type === "anchor") return upTo(p.to);
      return inTime(e);
    })
    .slice(-keep);
}

async function fetchText(url, init = {}) {
  const res = await fetch(url, { ...init, signal: AbortSignal.timeout(30_000) });
  if (!res.ok) throw new Error(`${url} answered ${res.status}`);
  return res.text();
}

/**
 * Events of the log in id order, read page by page with `after` and `limit`.
 * A page that runs dry stays open (the stream tails), so a second without a
 * new event ends it. Stops past `untilMs`.
 */
async function readEvents(api, untilMs) {
  const types = "message,milestone,alert,anchor,incident,lifecycle";
  const page = 2000;
  const events = [];
  let after = 0;
  for (;;) {
    const got = [];
    const ctl = new AbortController();
    let idle = setTimeout(() => ctl.abort(), 5000);
    try {
      const res = await fetch(`${api}/stream?after=${after}&limit=${page}&types=${types}`, { signal: ctl.signal, headers: { accept: "text/event-stream" } });
      if (!res.ok || !res.body) break;
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
            .split("\n")
            .filter((l) => l.startsWith("data:"))
            .map((l) => l.slice(5).trimStart())
            .join("\n");
          if (!data) continue;
          got.push(JSON.parse(data));
          clearTimeout(idle);
          idle = setTimeout(() => ctl.abort(), 1000);
        }
      }
    } catch {
      /* the idle timer ends a page that ran dry */
    } finally {
      clearTimeout(idle);
    }
    events.push(...got);
    if (got.length < page) break;
    after = got[got.length - 1].id;
    if (untilMs !== null && got[got.length - 1].atMs > untilMs) break;
  }
  return events;
}

/** Runs `fn` over `items`, `n` at a time. */
async function pool(items, n, fn) {
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(n, items.length) }, async () => {
      while (next < items.length) await fn(items[next++]);
    }),
  );
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
  const getJson = async (path) => JSON.parse(await fetchText(`${api}${path}`));

  const anchors = await getJson("/anchors?limit=100");
  const anchored = lastAnchored(anchors.items);
  let cut = null;
  let untilMs = null;
  if (o.until === "anchored") {
    if (!anchored) throw new Error("--until anchored: no checkpoint is anchored yet");
    cut = anchored.milestone;
    untilMs = anchored.atMs;
  } else if (o.until) {
    cut = Number(o.until);
    if (!Number.isInteger(cut) || cut < 0) throw new Error(`--until takes "anchored" or a milestone index, not ${o.until}`);
  }

  // The listed messages: one page, or a scan of the log when files or samples ask for more.
  const named = { ids: [], tokens: [] };
  for (const f of o.include ? o.include.split(",") : []) {
    const n = namedIn(readFileSync(f.trim(), "utf8"));
    named.ids.push(...n.ids);
    named.tokens.push(...n.tokens);
  }
  const excluded = new Set((o.exclude ? o.exclude.split(",") : []).map((x) => x.trim().toLowerCase()));
  for (const x of excluded) if (!HASH32.test(x)) throw new Error(`--exclude takes block ids, not ${x}`);
  const scanAll = Boolean(o.include) || o.sample > 0 || excluded.size > 0;
  const msTo = cut === null ? "" : `&ms_to=${cut}`;
  const scan = [];
  for (let cursor = null; ; ) {
    const size = scanAll ? 500 : Math.min(500, o.limit - scan.length);
    const p = await getJson(`/messages?limit=${size}${msTo}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`);
    scan.push(...p.items);
    cursor = p.nextCursor;
    if (!cursor || (!scanAll && scan.length >= o.limit)) break;
  }
  const listed = pickMessages(scan, { limit: o.limit, include: named.ids, sample: o.sample, exclude: [...excluded] });
  write("messages.json", json({ items: listed, nextCursor: null, limit: listed.length }));

  const dids = new Set();
  const recorded = new Set();
  let bundles = 0;
  await pool(listed, 6, async (m) => {
    const id = m.blockId;
    write(`messages/${id}.json`, await fetchText(`${api}/messages/${id}`));
    write(`lifecycle/${id}.json`, await fetchText(`${api}/messages/${id}/lifecycle`));
    recorded.add(id);
    try {
      write(`bundles/${id}.json`, await fetchText(`${api}/proofs/${id}`));
      bundles += 1;
    } catch {
      /* not in an indexed milestone yet: Verify says so */
    }
    if (m.iss) dids.add(m.iss);
  });
  write("verifier-config.json", await fetchText(`${api}/config/verifier`));
  write("anchors.json", json(anchors));

  // The explorer screens: lineage, integrity, identity, posture, reports.
  const wanted = []; // blocks those screens link to, most useful first
  // a few trust scores from anchored windows, so Verify can show all five checks green
  for (const a of anchors.items.filter((x) => x.status === "anchored").slice(0, 4)) {
    const inWindow = await getJson(`/messages?tag=trust.score&ms_from=${a.fromMilestone}&ms_to=${a.toMilestone}&limit=3`);
    for (const m of inWindow.items) wanted.push(m.blockId);
  }
  const ies = await getJson("/ie");
  write("ie.json", json(ies));
  for (const ie of ies.items.slice(0, 200)) {
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
  for (const by of ["issuer", "corr", "ie", "service"]) {
    const list = await getJson(`/flows?by=${by}`);
    write(`flows-${by}.json`, json(list));
    for (const f of list.items.slice(0, 8)) {
      const flow = await getJson(`/flows/${by}/${encodeURIComponent(f.key)}?limit=300`);
      write(`flows/${by}/${fileKey(f.key)}.json`, json(flow));
      if (by === "issuer") for (const m of flow.items.slice(-4)) wanted.push(m.blockId);
    }
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
  const scorecards = [];
  for (const [i, f] of (o.scorecard ? o.scorecard.split(",") : []).entries()) {
    const card = JSON.parse(readFileSync(f.trim(), "utf8"));
    if (card?.schema !== "witness-chaos/scorecard/v1") throw new Error(`${f} is not a witness-chaos/scorecard/v1 scorecard`);
    const name = i === 0 ? "scorecard.json" : `scorecard-${fileKey(basename(dirname(resolve(f.trim()))))}.json`;
    if (scorecards.includes(name)) throw new Error(`two scorecards would both be ${name}`);
    write(name, json(card));
    scorecards.push(name);
  }
  let extra = 0;
  for (const id of wanted) {
    if (extra >= o.blocks) break;
    if (!HASH32.test(id) || recorded.has(id) || excluded.has(id)) continue;
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
    if (did.startsWith("did:key:")) continue; // decoded from the DID itself, never resolved
    try {
      write(`dids/${didFile(did)}`, await fetchText(`${resolver}/resolve/${encodeURIComponent(did)}`));
    } catch (e) {
      console.warn(`no DID document for ${did}: ${e.message}`);
    }
  }
  if (named.tokens.length) {
    const blind = {};
    for (let i = 0; i < named.tokens.length; i += 64) {
      const res = JSON.parse(
        await fetchText(`${api}/lookup/blind`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ tokens: named.tokens.slice(i, i + 64) }),
        }),
      );
      for (const m of res.matches) if (recorded.has(m.blockId)) (blind[m.token] ??= []).push(m);
    }
    write("blind.json", json(blind));
  }
  const events = keepEvents(await readEvents(api, untilMs), { keep: o.events, cut, untilMs, recorded });
  write("stream.json", json(events));
  write(
    "manifest.json",
    json({
      about:
        "A recorded snapshot of a running Witness stack. Proofs are verified in your browser against the console's pinned config." +
        (cut === null ? "" : ` Messages up to milestone ${cut}${o.until === "anchored" ? ", the last one an anchored checkpoint covers" : ""}.`),
      recordedAtMs: Date.now(),
      source: "witness-api and the anchor service's DID resolver",
      untilMilestone: cut,
      ...(scorecards.length ? { scorecards } : {}),
    }),
  );
  console.log(
    `recorded ${listed.length} messages (+${extra} linked blocks), ${bundles} bundles, ${dids.size} DIDs, ${ies.items.length} IEs, ` +
      `${incidents.items.length} incidents, ${reports.items.length} reports, ${events.length} events into ${o.out}` +
      (cut === null ? "" : ` (up to milestone ${cut})`),
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((e) => {
    console.error(e.message);
    process.exit(1);
  });
}
