"""The indexer's store plus the few read models only the API needs."""

from __future__ import annotations

from psycopg.types.json import Jsonb
from witness_indexer.store import Store


class ExplorerStore(Store):
    async def block_row(self, block_id: bytes) -> dict | None:
        """A block of an indexed milestone cone: id, ms_index, wf_index, raw, payload_type."""
        return await self._one(
            "SELECT id, ms_index, wf_index, raw, payload_type FROM blocks WHERE id = %s",
            (block_id,))

    async def head_event_id(self) -> int:
        """Id of the newest event, 0 when there is none."""
        row = await self._one("SELECT COALESCE(max(id), 0) AS id FROM events")
        return int(row["id"]) if row else 0

    async def score_history(self, ie_id: str) -> list[dict]:
        """Every trust score recorded on the ledger for an IE, oldest milestone first."""
        return await self._fetch(
            "SELECT block_id, ms_index, ts, score, verdict FROM ie_scores WHERE ie_id = %s "
            "ORDER BY ms_index, ts, block_id", (ie_id,))

    async def score_heads(self) -> dict[str, dict]:
        """The latest recorded score per IE."""
        rows = await self._fetch(
            "SELECT DISTINCT ON (ie_id) ie_id, score, ms_index, ts, verdict, block_id "
            "FROM ie_scores ORDER BY ie_id, ms_index DESC, ts DESC, block_id DESC")
        return {r["ie_id"]: r for r in rows}

    async def latest_validation(self, block_id: bytes) -> dict | None:
        """The node's latest metadata answer about a block (check c)."""
        return await self._one(
            "SELECT * FROM validations WHERE block_id = %s "
            "ORDER BY checked_at_ms DESC, id DESC LIMIT 1", (block_id,))

    async def latest_content_check(self, block_id: bytes) -> dict | None:
        """The latest content comparison of a block with the Tangle (check d)."""
        return await self._one(
            "SELECT * FROM content_checks WHERE block_id = %s "
            "ORDER BY checked_at_ms DESC, id DESC LIMIT 1", (block_id,))

    async def validations_page(self, block_id: bytes, before_id: int | None,
                               limit: int) -> tuple[list[dict], int | None]:
        """Metadata answers newest first in pages of `limit`, each page returned oldest
        first, with the id to pass as `before_id` for the next (older) page; None on the
        last one."""
        rows = await self._fetch(
            "SELECT * FROM validations WHERE block_id = %s "
            "AND (%s::bigint IS NULL OR id < %s::bigint) ORDER BY id DESC LIMIT %s",
            (block_id, before_id, before_id, limit + 1))
        more = len(rows) > limit
        rows = rows[:limit]
        return rows[::-1], (rows[-1]["id"] if more else None)

    async def recent_content_checks(self, block_id: bytes, limit: int) -> list[dict]:
        """The newest `limit` content comparisons, oldest first."""
        rows = await self._fetch(
            "SELECT * FROM content_checks WHERE block_id = %s "
            "ORDER BY checked_at_ms DESC, id DESC LIMIT %s", (block_id, limit))
        return rows[::-1]

    async def db_ping(self) -> None:
        await self._one("SELECT 1 AS ok")

    # -- posture --------------------------------------------------------------------------

    async def payload_ratio(self) -> dict:
        """How many stored messages carry a plaintext payload vs an encrypted one."""
        row = await self._one(
            "SELECT count(*) AS total, "
            "count(*) FILTER (WHERE NOT encrypted) AS plaintext, "
            "count(*) FILTER (WHERE encrypted) AS encrypted FROM messages")
        total = int(row["total"]) if row else 0
        plaintext = int(row["plaintext"]) if row else 0
        encrypted = int(row["encrypted"]) if row else 0
        ratio = plaintext / total if total else 0.0
        return {"total": total, "plaintext": plaintext, "encrypted": encrypted, "ratio": ratio}

    # -- reports --------------------------------------------------------------------------

    @staticmethod
    def _report_filter(ie: str | None, ms_from: int | None,
                       ms_to: int | None) -> tuple[str, list]:
        where, params = ["true"], []
        if ie is not None:
            where.append("ie_id = %s")
            params.append(ie)
        if ms_from is not None:
            where.append("ms_index >= %s")
            params.append(ms_from)
        if ms_to is not None:
            where.append("ms_index <= %s")
            params.append(ms_to)
        return " AND ".join(where), params

    async def report_verdicts(self, *, ie: str | None, ms_from: int | None,
                              ms_to: int | None) -> list[dict]:
        """Message totals in a range, grouped by verdict and whether they are encrypted."""
        clause, params = self._report_filter(ie, ms_from, ms_to)
        return await self._fetch(
            f"SELECT verdict, encrypted, count(*) AS n FROM messages WHERE {clause} "
            f"GROUP BY verdict, encrypted", params)

    async def report_confirmed(self, *, ie: str | None, ms_from: int | None,
                               ms_to: int | None) -> int:
        """How many messages in a range are confirmed by a milestone (have a proof)."""
        clause, params = self._report_filter(ie, ms_from, ms_to)
        row = await self._one(
            f"SELECT count(*) AS n FROM messages WHERE {clause} AND ms_index IS NOT NULL",
            params)
        return int(row["n"]) if row else 0

    async def report_messages(self, *, ie: str | None, ms_from: int | None,
                              ms_to: int | None, limit: int) -> list[dict]:
        """Confirmed messages in a range (each one has a proof bundle), oldest first."""
        clause, params = self._report_filter(ie, ms_from, ms_to)
        return await self._fetch(
            f"SELECT block_id, tag, kind, ie_id, iss, verdict, ms_index, wf_index, ts "
            f"FROM messages WHERE {clause} AND ms_index IS NOT NULL "
            f"ORDER BY ms_index, wf_index, block_id LIMIT %s", [*params, limit])

    async def _milestone_window(self, ms_from: int | None,
                                ms_to: int | None) -> tuple[bool, int | None, int | None]:
        """Epoch-ms window [lo, hi) a milestone range covers: from the first indexed
        milestone at or after `ms_from` to the first one after `ms_to` (open when there is
        none yet). The flag is False when `ms_from` lies beyond every indexed milestone."""
        lo = hi = None
        if ms_from is not None:
            row = await self._one("SELECT min(ts) AS ts FROM milestones WHERE idx >= %s",
                                  (ms_from,))
            if row is None or row["ts"] is None:
                return False, None, None
            lo = int(row["ts"]) * 1000
        if ms_to is not None:
            row = await self._one("SELECT min(ts) AS ts FROM milestones WHERE idx > %s",
                                  (ms_to,))
            hi = int(row["ts"]) * 1000 if row and row["ts"] is not None else None
        return True, lo, hi

    async def report_alerts(self, *, ie: str | None, ms_from: int | None,
                            ms_to: int | None) -> list[dict]:
        """Alert counts by severity and rule, filtered like the messages: an alert tied to a
        block counts by that block's milestone; one without a block (anchor or IE-level)
        counts by its time within the range's milestone window."""
        where, params = ["true"], []
        if ie is not None:
            where.append("(a.ie_id = %s OR m.ie_id = %s)")
            params += [ie, ie]
        if ms_from is not None or ms_to is not None:
            known, lo, hi = await self._milestone_window(ms_from, ms_to)
            ms = "COALESCE(m.ms_index, b.ms_index)"
            bound = [f"{ms} IS NOT NULL"]
            if ms_from is not None:
                bound.append(f"{ms} >= %s")
                params.append(ms_from)
            if ms_to is not None:
                bound.append(f"{ms} <= %s")
                params.append(ms_to)
            timed = ["a.block_id IS NULL"]
            if not known:
                timed.append("false")
            if lo is not None:
                timed.append("a.ts >= %s")
                params.append(lo)
            if hi is not None:
                timed.append("a.ts < %s")
                params.append(hi)
            where.append(f"((a.block_id IS NOT NULL AND {' AND '.join(bound)}) "
                         f"OR ({' AND '.join(timed)}))")
        return await self._fetch(
            f"SELECT a.severity, a.rule, count(*) AS n FROM alerts a "
            f"LEFT JOIN messages m ON m.block_id = a.block_id "
            f"LEFT JOIN blocks b ON b.id = a.block_id "
            f"WHERE {' AND '.join(where)} GROUP BY a.severity, a.rule", params)

    async def report_anchors(self, *, ms_from: int | None,
                             ms_to: int | None) -> tuple[list[dict], dict | None]:
        """Checkpoint counts by status for the anchors overlapping a milestone range, and
        the newest of them."""
        where, params = ["true"], []
        if ms_from is not None:
            where.append("to_ms >= %s")
            params.append(ms_from)
        if ms_to is not None:
            where.append("from_ms <= %s")
            params.append(ms_to)
        clause = " AND ".join(where)
        counts = await self._fetch(
            f"SELECT status, count(*) AS n FROM anchors WHERE {clause} GROUP BY status",
            params)
        latest = await self._one(
            f"SELECT seq, from_ms, to_ms, status, network, record, tx FROM anchors "
            f"WHERE {clause} ORDER BY seq DESC LIMIT 1", params)
        return counts, latest

    async def insert_report(self, *, report_hash: bytes, ie: str | None, ms_from: int | None,
                            ms_to: int | None, json: dict, html: str, generated_at_ms: int,
                            created_at_ms: int) -> bool:
        """Phase one: store a report as not anchored. False when it is already stored."""
        return await self._insert(
            "INSERT INTO reports (report_hash, ie, ms_from, ms_to, json, html, anchored, "
            "generated_at_ms, created_at_ms) VALUES (%s,%s,%s,%s,%s,%s,false,%s,%s) "
            "ON CONFLICT (report_hash) DO NOTHING",
            (report_hash, ie, ms_from, ms_to, Jsonb(json), html, generated_at_ms,
             created_at_ms))

    async def last_report_seq(self, iss: str) -> int | None:
        """The highest envelope sequence number claimed for reports signed by `iss`."""
        row = await self._one("SELECT max(seq) AS seq FROM reports WHERE iss = %s", (iss,))
        return int(row["seq"]) if row and row["seq"] is not None else None

    async def claim_report_seq(self, report_hash: bytes, iss: str, seq: int) -> None:
        """Record the sequence number about to be used, before the post goes out."""
        await self._fetch(
            "UPDATE reports SET iss = %s, seq = %s WHERE report_hash = %s "
            "RETURNING report_hash", (iss, seq, report_hash))

    async def mark_report_anchored(self, report_hash: bytes, block_id: bytes, html: str,
                                   at_ms: int) -> None:
        """Phase two: the relay accepted the report; record its block."""
        await self._fetch(
            "UPDATE reports SET anchored = true, block_id = %s, html = %s, "
            "anchored_at_ms = %s WHERE report_hash = %s RETURNING report_hash",
            (block_id, html, at_ms, report_hash))

    async def get_report(self, report_hash: bytes) -> dict | None:
        return await self._one("SELECT * FROM reports WHERE report_hash = %s", (report_hash,))

    async def list_reports(self, limit: int,
                           before: tuple[int, bytes] | None = None) -> list[dict]:
        """Reports newest first; `before` is the (generated_at_ms, report_hash) of the last
        row of the previous page."""
        where, params = "true", []
        if before is not None:
            where = "(generated_at_ms, report_hash) < (%s, %s)"
            params = [before[0], before[1]]
        return await self._fetch(
            f"SELECT report_hash, ie, ms_from, ms_to, anchored, block_id, iss, seq, "
            f"generated_at_ms, created_at_ms, anchored_at_ms FROM reports WHERE {where} "
            f"ORDER BY generated_at_ms DESC, report_hash DESC LIMIT %s", [*params, limit])
