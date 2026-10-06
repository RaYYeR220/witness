"""PostgreSQL state of the relay: upload receipts and per-issuer sequence numbers.

Lives in its own schema (default `relay`). `issuer_seq.seq` is the highest sequence
number allocated (relay) or observed (producers); `last_block_id` / `last_block_seq`
point at the issuer's newest block on the Tangle and feed the next envelope's `prev`.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from psycopg import sql
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

_DDL = """
CREATE SCHEMA IF NOT EXISTS {s};
CREATE TABLE IF NOT EXISTS {s}.issuer_seq (
    iss            text PRIMARY KEY,
    seq            bigint NOT NULL,
    last_block_id  text,
    last_block_seq bigint,
    updated_at_ms  bigint NOT NULL
);
CREATE TABLE IF NOT EXISTS {s}.receipts (
    block_id       text PRIMARY KEY,
    sub_id         uuid NOT NULL UNIQUE,
    tag            text NOT NULL,
    iss            text NOT NULL,
    kid            text,
    seq            bigint,
    verdict        text NOT NULL,
    att_sub        text,
    node           text NOT NULL,
    hornet_status  integer NOT NULL,
    received_at_ms bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS receipts_tag_idx ON {s}.receipts (tag, received_at_ms DESC);
CREATE INDEX IF NOT EXISTS receipts_iss_idx ON {s}.receipts (iss, seq DESC);
CREATE INDEX IF NOT EXISTS receipts_time_idx ON {s}.receipts (received_at_ms DESC);
"""


def _now_ms() -> int:
    return int(time.time() * 1000)


@dataclass(frozen=True)
class Receipt:
    block_id: str
    sub_id: str
    tag: str
    iss: str
    kid: str | None
    seq: int | None
    verdict: str
    att_sub: str | None
    node: str
    hornet_status: int
    received_at_ms: int


class ReceiptStore:
    def __init__(self, pool: AsyncConnectionPool, schema: str):
        self._pool = pool
        self._schema = schema
        self._s = sql.Identifier(schema)

    @classmethod
    async def open(cls, dsn: str, schema: str = "relay") -> ReceiptStore:
        pool = AsyncConnectionPool(
            dsn, min_size=1, max_size=8, open=False, kwargs={"autocommit": True}
        )
        await pool.open(wait=True, timeout=15)
        store = cls(pool, schema)
        await store.migrate()
        return store

    async def close(self) -> None:
        await self._pool.close()

    def _q(self, text: str) -> sql.Composed:
        return sql.SQL(text).format(s=self._s)

    async def migrate(self) -> None:
        # Serialise concurrent first starts; CREATE ... IF NOT EXISTS alone can race.
        async with self._pool.connection() as conn, conn.transaction():
            await conn.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))", ("witness-relay:" + self._schema,)
            )
            await conn.execute(self._q(_DDL))

    async def ping(self) -> bool:
        async with self._pool.connection() as conn:
            await conn.execute("SELECT 1")
        return True

    async def allocate(self, iss: str) -> tuple[int, str | None]:
        """Next sequence number for `iss` (persisted before use) and its last block id."""
        async with self._pool.connection() as conn:
            cur = await conn.execute(
                self._q(
                    "INSERT INTO {s}.issuer_seq AS t (iss, seq, updated_at_ms) "
                    "VALUES (%s, 1, %s) "
                    "ON CONFLICT (iss) DO UPDATE SET seq = t.seq + 1, "
                    "updated_at_ms = EXCLUDED.updated_at_ms "
                    "RETURNING seq, last_block_id"
                ),
                (iss, _now_ms()),
            )
            seq, last = await cur.fetchone()
        return seq, last

    async def record(self, receipt: Receipt, *, observed: bool) -> None:
        """Persist a receipt and move the issuer's chain head to its block.

        `observed` is for producer envelopes: their seq was chosen by the producer, so
        the counter only moves forward to it.
        """
        async with self._pool.connection() as conn, conn.transaction():
            if receipt.seq is not None:
                await conn.execute(
                    self._q(
                        "INSERT INTO {s}.issuer_seq AS t "
                        "(iss, seq, last_block_id, last_block_seq, updated_at_ms) "
                        "VALUES (%(iss)s, %(seq)s, %(bid)s, %(seq)s, %(now)s) "
                        "ON CONFLICT (iss) DO UPDATE SET "
                        "seq = CASE WHEN %(observed)s THEN GREATEST(t.seq, EXCLUDED.seq) "
                        "      ELSE t.seq END, "
                        "last_block_id = CASE WHEN t.last_block_seq IS NULL "
                        "      OR EXCLUDED.last_block_seq >= t.last_block_seq "
                        "      THEN EXCLUDED.last_block_id ELSE t.last_block_id END, "
                        "last_block_seq = GREATEST(t.last_block_seq, EXCLUDED.last_block_seq), "
                        "updated_at_ms = EXCLUDED.updated_at_ms"
                    ),
                    {
                        "iss": receipt.iss,
                        "seq": receipt.seq,
                        "bid": receipt.block_id,
                        "now": _now_ms(),
                        "observed": observed,
                    },
                )
            await conn.execute(
                self._q(
                    "INSERT INTO {s}.receipts (block_id, sub_id, tag, iss, kid, seq, verdict, "
                    "att_sub, node, hornet_status, received_at_ms) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
                    "ON CONFLICT (block_id) DO NOTHING"
                ),
                (
                    receipt.block_id,
                    receipt.sub_id,
                    receipt.tag,
                    receipt.iss,
                    receipt.kid,
                    receipt.seq,
                    receipt.verdict,
                    receipt.att_sub,
                    receipt.node,
                    receipt.hornet_status,
                    receipt.received_at_ms,
                ),
            )

    async def receipts(
        self, *, tag: str | None = None, iss: str | None = None, limit: int = 50
    ) -> list[dict]:
        where, args = [], []
        if tag is not None:
            where.append("tag = %s")
            args.append(tag)
        if iss is not None:
            where.append("iss = %s")
            args.append(iss)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        query = self._q(
            "SELECT block_id, sub_id::text AS sub_id, tag, iss, kid, seq, verdict, att_sub, "
            "node, hornet_status, received_at_ms FROM {s}.receipts "
            + clause
            + " ORDER BY received_at_ms DESC, seq DESC NULLS LAST LIMIT %s"
        )
        async with self._pool.connection() as conn:
            cur = conn.cursor(row_factory=dict_row)
            await cur.execute(query, (*args, limit))
            return await cur.fetchall()

    async def issuer_state(self, iss: str) -> dict | None:
        async with self._pool.connection() as conn:
            cur = conn.cursor(row_factory=dict_row)
            await cur.execute(
                self._q(
                    "SELECT iss, seq, last_block_id, last_block_seq, updated_at_ms "
                    "FROM {s}.issuer_seq WHERE iss = %s"
                ),
                (iss,),
            )
            return await cur.fetchone()
