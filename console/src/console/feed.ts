/**
 * The Live screen's feed: stream events and listed messages turned into rows,
 * newest first, with pause/resume and a cap on what stays on screen.
 */

import { computed, onBeforeUnmount, onMounted, reactive, ref, shallowRef } from "vue";

import type { MessageSummary, StreamEvent, StreamStatus, StreamType, WitnessData } from "@/api/client";

import { scoreOf } from "./format";

export interface MessageRow {
  kind: "message";
  key: string;
  blockId: string;
  tag: string | null;
  msgKind: string | null;
  verdict: string | null;
  ieId: string | null;
  iss: string | null;
  msIndex: number | null;
  encrypted: boolean;
  atMs: number | null;
  score: number | null;
  reason: string | null;
  fresh: boolean;
}

export interface MilestoneRow {
  kind: "milestone";
  key: string;
  index: number;
  blocks: number | null;
  messages: number | null;
  atMs: number | null;
}

export interface AlertRow {
  kind: "alert";
  key: string;
  rule: string;
  severity: string;
  blockId: string | null;
  ieId: string | null;
  atMs: number | null;
}

export interface AnchorRow {
  kind: "anchor";
  key: string;
  seq: number | null;
  from: number | null;
  to: number | null;
  record: number | null;
  network: string | null;
  tx: string | null;
  atMs: number | null;
}

export interface IncidentRow {
  kind: "incident";
  key: string;
  title: string;
  change: string;
  severity: string | null;
  atMs: number | null;
}

export type FeedRow = MessageRow | MilestoneRow | AlertRow | AnchorRow | IncidentRow;

const str = (v: unknown): string | null => (typeof v === "string" ? v : null);
const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

export function rowFromMessage(m: MessageSummary, fresh = false): MessageRow {
  return {
    kind: "message",
    key: `m:${m.blockId}`,
    blockId: m.blockId,
    tag: m.tag,
    msgKind: m.kind,
    verdict: m.verdict,
    ieId: m.ieId,
    iss: m.iss,
    msIndex: m.msIndex,
    encrypted: m.encrypted,
    atMs: m.dateMs ?? m.milestoneAtMs,
    score: m.encrypted ? null : scoreOf(m.json),
    reason: null,
    fresh,
  };
}

/** A stream event as a feed row; null for event types the feed does not show. */
export function rowFromEvent(e: StreamEvent): FeedRow | null {
  const p = e.payload ?? {};
  switch (e.type) {
    case "message": {
      const blockId = str(p.blockId);
      if (!blockId) return null;
      const ts = num(p.ts);
      return {
        kind: "message",
        key: `m:${blockId}`,
        blockId,
        tag: str(p.tag),
        msgKind: str(p.kind),
        verdict: str(p.verdict),
        ieId: str(p.ieId),
        iss: str(p.iss),
        msIndex: num(p.msIndex),
        encrypted: p.encrypted === true,
        atMs: ts !== null ? ts * 1000 : e.atMs,
        score: null,
        reason: str(p.reason),
        fresh: true,
      };
    }
    case "milestone": {
      const index = num(p.index);
      if (index === null) return null;
      const ts = num(p.ts);
      return { kind: "milestone", key: `ms:${index}`, index, blocks: num(p.blocks), messages: num(p.newMessages ?? p.messages), atMs: ts !== null ? ts * 1000 : e.atMs };
    }
    case "alert":
      return {
        kind: "alert",
        key: `a:${e.id}`,
        rule: str(p.rule) ?? "alert",
        severity: str(p.severity) ?? "info",
        blockId: str(p.blockId),
        ieId: str(p.ieId),
        atMs: e.atMs,
      };
    case "anchor":
      return {
        kind: "anchor",
        key: `c:${String(p.seq ?? e.id)}`,
        seq: num(p.seq),
        from: num(p.from),
        to: num(p.to),
        record: num(p.record),
        network: str(p.network),
        tx: str(p.tx),
        atMs: e.atMs,
      };
    case "incident":
      // {action: opened | joined | closed | ..., incidentId, status, severity, title, ...}
      return {
        kind: "incident",
        key: `i:${e.id}`,
        title: str(p.title) ?? "Incident",
        change: str(p.action) ?? "updated",
        severity: str(p.severity),
        atMs: num(p.atMs) ?? e.atMs,
      };
    default:
      return null;
  }
}

export const FEED_TYPES: readonly StreamType[] = ["message", "milestone", "alert", "anchor", "incident"];
export const FEED_MAX = 200;

/**
 * `row` in a newest-first list, by its time: above every row that is older,
 * below every row that is newer (a recorded stream played back, or a listed
 * message arriving after newer events, lands where it belongs). Among equal
 * times the newest arrival goes first; a row without a time goes on top. Any
 * earlier copy of the same row is replaced.
 */
export function placeByTime(list: FeedRow[], row: FeedRow, max = FEED_MAX): FeedRow[] {
  const rest = list.filter((r) => r.key !== row.key);
  const at = row.atMs;
  const i = at === null ? 0 : rest.findIndex((r) => r.atMs !== null && r.atMs <= at);
  const pos = i < 0 ? rest.length : i;
  return [...rest.slice(0, pos), row, ...rest.slice(pos)].slice(0, max);
}

/** The feed state for one Live screen: initial page, then the stream on top. */
export function useLiveFeed(data: WitnessData) {
  const rows = ref<FeedRow[]>([]);
  const held = shallowRef<FeedRow[]>([]);
  const paused = ref(false);
  const loading = ref(true);
  const loadError = ref<string | null>(null);
  const conn = reactive<{ status: StreamStatus; retryInMs: number | null; reason: string | null; lastId: number | null }>({
    status: "connecting",
    retryInMs: null,
    reason: null,
    lastId: null,
  });
  const counts = reactive({ signed: 0, unsigned: 0, rejected: 0, alerts: 0 });
  const lastMilestone = ref<MilestoneRow | null>(null);
  const lastAnchor = ref<AnchorRow | null>(null);
  let stop: (() => void) | null = null;

  const showMilestones = ref(true);
  const visible = computed(() => (showMilestones.value ? rows.value : rows.value.filter((r) => r.kind !== "milestone")));

  function place(list: FeedRow[], row: FeedRow): FeedRow[] {
    return placeByTime(list, row);
  }

  function tally(row: FeedRow) {
    if (row.kind === "message") {
      const v = row.verdict ?? "";
      if (v === "PRODUCER_SIGNED" || v === "RELAY_ATTESTED") counts.signed += 1;
      else if (v === "UNSIGNED_LEGACY") counts.unsigned += 1;
      else if (v) counts.rejected += 1;
    } else if (row.kind === "alert") counts.alerts += 1;
    else if (row.kind === "milestone") lastMilestone.value = row;
    else if (row.kind === "anchor") lastAnchor.value = row;
  }

  /** Fills in what the stream event does not carry (the score), from the stored message. */
  async function enrich(row: MessageRow) {
    if (row.encrypted) return;
    try {
      const page = await data.messages({ block_id: row.blockId, limit: 1 });
      const m = page.items[0];
      if (!m) return;
      const score = scoreOf(m.json);
      const patch = (list: FeedRow[]) => list.map((r) => (r.key === row.key && r.kind === "message" ? { ...r, score } : r));
      rows.value = patch(rows.value);
      held.value = patch(held.value);
    } catch {
      /* the row stays without a score */
    }
  }

  function onEvent(e: StreamEvent) {
    conn.lastId = e.id;
    const row = rowFromEvent(e);
    if (!row) return;
    const isNew = !rows.value.some((r) => r.key === row.key) && !held.value.some((r) => r.key === row.key);
    if (isNew) tally(row);
    if (paused.value) held.value = place(held.value, row);
    else rows.value = place(rows.value, row);
    if (row.kind === "message") void enrich(row);
  }

  function pause() {
    paused.value = true;
  }

  function resume() {
    let next = rows.value;
    for (const r of [...held.value].reverse()) next = place(next, r);
    rows.value = next;
    held.value = [];
    paused.value = false;
  }

  async function load() {
    loading.value = true;
    loadError.value = null;
    try {
      const page = await data.messages({ limit: 25 });
      const seen = new Set(rows.value.map((r) => r.key));
      let next = rows.value;
      for (const r of page.items.map((m) => rowFromMessage(m))) if (!seen.has(r.key)) next = placeByTime(next, r);
      rows.value = next;
    } catch (e) {
      loadError.value = e instanceof Error ? e.message : String(e);
    } finally {
      loading.value = false;
    }
  }

  onMounted(() => {
    stop = data.stream(onEvent, {
      types: FEED_TYPES,
      onStatus: (status, info) => {
        conn.status = status;
        conn.retryInMs = info.retryInMs ?? null;
        conn.reason = info.reason ?? null;
      },
    });
    void load();
  });
  onBeforeUnmount(() => stop?.());

  return { rows, visible, held, paused, pause, resume, loading, loadError, conn, counts, lastMilestone, lastAnchor, showMilestones, reload: load };
}
