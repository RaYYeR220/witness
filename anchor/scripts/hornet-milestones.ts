// Serves the witness-api `GET /milestones?from=&to=` contract straight from a HORNET node, so
// the anchoring loop can run against a live private Tangle without the explorer stack.
// Each milestone id is computed locally: BLAKE2b-256 of the essence of the raw milestone payload
// (TIP-29), read with `Accept: application/vnd.iota.serializer-v1`.
//
// It cannot count the messages of a window, so it reports no msgCount: a loop pointed at it
// anchors nothing unless ANCHOR_ALLOW_MISSING_MSGCOUNT=1 (development only, commits 0).
//
//   HORNET_URL=http://127.0.0.1:14265 MILESTONES_PORT=7200 pnpm --filter @witness/anchor milestones:hornet
import http from "node:http";
import { milestoneId, parseMilestonePayload, toHex } from "@witness/verify";

const HORNET = (process.env.HORNET_URL ?? "http://127.0.0.1:14265").replace(/\/+$/, "");
const PORT = Number(process.env.MILESTONES_PORT ?? 7200);
const HOST = process.env.MILESTONES_HOST ?? "127.0.0.1";
const MAX_RANGE = 10_000;
const CONCURRENCY = 8;

/** Milestone id of `index`, or null when the node has no such milestone (yet). */
async function milestoneIdAt(index: number): Promise<string | null> {
  const res = await fetch(`${HORNET}/api/core/v2/milestones/by-index/${index}`, {
    headers: { accept: "application/vnd.iota.serializer-v1" },
    signal: AbortSignal.timeout(10_000),
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`HORNET answered HTTP ${res.status} for milestone ${index}`);
  const payload = parseMilestonePayload(new Uint8Array(await res.arrayBuffer()));
  if (payload.essence.index !== index) throw new Error(`HORNET returned milestone ${payload.essence.index} for ${index}`);
  return toHex(milestoneId(payload.essenceBytes));
}

async function window(from: number, to: number): Promise<{ from: number; to: number; ids: string[]; complete: boolean }> {
  const ids: (string | null)[] = new Array(to - from + 1).fill(null);
  let next = from;
  const worker = async () => {
    for (let i = next++; i <= to; i = next++) ids[i - from] = await milestoneIdAt(i);
  };
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, ids.length) }, worker));
  const present = ids.filter((x): x is string => x !== null);
  return { from, to, ids: present, complete: present.length === ids.length };
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url ?? "/", "http://stub.local");
  const reply = (status: number, body: unknown) => {
    res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
  };
  if (req.method !== "GET" || url.pathname !== "/milestones") return reply(404, { detail: "not found" });
  const from = Number(url.searchParams.get("from"));
  const to = Number(url.searchParams.get("to"));
  if (!Number.isSafeInteger(from) || !Number.isSafeInteger(to) || from < 0 || to < from) return reply(422, { detail: "bad range" });
  if (to - from + 1 > MAX_RANGE) return reply(422, { detail: `at most ${MAX_RANGE} milestones per request` });
  window(from, to).then(
    (w) => reply(200, w),
    (err: Error) => reply(502, { detail: err.message }),
  );
});

server.listen(PORT, HOST, async () => {
  console.log(`milestones from ${HORNET} on http://${HOST}:${PORT}/milestones`);
  // Sanity check: our id for the latest milestone equals the one HORNET reports.
  try {
    const info = (await (await fetch(`${HORNET}/api/core/v2/info`)).json()) as { status: { latestMilestone: { index: number; milestoneId: string } } };
    const { index, milestoneId: reported } = info.status.latestMilestone;
    const ours = await milestoneIdAt(index);
    console.log(`latest milestone ${index}: HORNET ${reported}, computed ${ours} -> ${ours === reported ? "match" : "MISMATCH"}`);
  } catch (err) {
    console.log(`could not cross-check against /info: ${(err as Error).message}`);
  }
});
