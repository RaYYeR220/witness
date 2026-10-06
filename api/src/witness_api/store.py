"""The indexer's store plus the few read models only the API needs."""

from __future__ import annotations

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

    async def db_ping(self) -> None:
        await self._one("SELECT 1 AS ok")
