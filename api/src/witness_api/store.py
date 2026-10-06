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

    async def report_messages(self, *, ie: str | None, ms_from: int | None,
                              ms_to: int | None, limit: int) -> list[dict]:
        """Confirmed messages in a range (each one has a proof bundle), oldest first."""
        clause, params = self._report_filter(ie, ms_from, ms_to)
        return await self._fetch(
            f"SELECT block_id, tag, kind, ie_id, iss, verdict, ms_index, wf_index, ts "
            f"FROM messages WHERE {clause} AND ms_index IS NOT NULL "
            f"ORDER BY ms_index, wf_index, block_id LIMIT %s", [*params, limit])

    async def put_report(self, *, report_hash: bytes, ie: str | None, ms_from: int | None,
                         ms_to: int | None, json: dict, html: str, block_id: bytes | None,
                         generated_at_ms: int, created_at_ms: int) -> None:
        await self._fetch(
            "INSERT INTO reports (report_hash, ie, ms_from, ms_to, json, html, block_id, "
            "generated_at_ms, created_at_ms) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) "
            "ON CONFLICT (report_hash) DO UPDATE SET block_id = COALESCE("
            "excluded.block_id, reports.block_id) RETURNING report_hash",
            (report_hash, ie, ms_from, ms_to, Jsonb(json), html, block_id, generated_at_ms,
             created_at_ms))

    async def set_report_block(self, report_hash: bytes, block_id: bytes) -> None:
        await self._fetch(
            "UPDATE reports SET block_id = %s WHERE report_hash = %s RETURNING report_hash",
            (block_id, report_hash))

    async def get_report(self, report_hash: bytes) -> dict | None:
        return await self._one(
            "SELECT report_hash, ie, ms_from, ms_to, json, html, block_id, generated_at_ms, "
            "created_at_ms FROM reports WHERE report_hash = %s", (report_hash,))

    async def list_reports(self, limit: int) -> list[dict]:
        return await self._fetch(
            "SELECT report_hash, ie, ms_from, ms_to, block_id, generated_at_ms, created_at_ms "
            "FROM reports ORDER BY generated_at_ms DESC, report_hash LIMIT %s", (limit,))
