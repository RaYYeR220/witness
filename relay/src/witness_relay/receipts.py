"""PostgreSQL state of the relay: upload receipts and per-issuer sequence numbers.

Lives in its own schema (default `relay`). `issuer_seq.seq` is the highest sequence
number claimed for an issuer: allocated by the relay for its own envelopes, or reserved
for a producer envelope *before* it is sent, so a replayed or concurrent duplicate seq
loses atomically. A claim is released (compare-and-set) when nothing reached the node.
`last_block_id` / `last_block_seq` point at the issuer's newest block on the Tangle and
feed the next relay envelope's `prev`; they only ever move to a strictly newer seq.

The relay can run as a role that owns only its schema (deploy/compose/db-init.sql): a schema
that exists is used as it is, so the role needs no CREATE privilege on the database.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from psycopg import sql
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

_DDL = """
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
    iss            text,
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
ALTER TABLE {s}.receipts ADD COLUMN IF NOT EXISTS nonce text;
CREATE INDEX IF NOT EXISTS receipts_nonce_idx ON {s}.receipts (iss, nonce)
    WHERE nonce IS NOT NULL;
"""


def _now_ms() -> int:
    return int(time.time() * 1000)


@dataclass(frozen=True)
class Receipt:
    block_id: str
    sub_id: str
    tag: str
    iss: str | None  # None for unsigned pass-through messages
    kid: str | None
    seq: int | None
    verdict: str
    att_sub: str | None
    node: str
    hornet_status: int
    received_at_ms: int
    nonce: str | None = None  # a producer envelope's nonce


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
        try:
            await store.migrate()
        except BaseException:
            await pool.close()
            raise
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
            # CREATE SCHEMA IF NOT EXISTS checks the database privilege even when the schema
            # exists, so only create a missing one.
            cur = await conn.execute(
                "SELECT 1 FROM pg_namespace WHERE nspname = %s", (self._schema,)
            )
            if await cur.fetchone() is None:
                await conn.execute(self._q("CREATE SCHEMA {s}"))
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

    async def reserve(self, iss: str, seq: int) -> int | None:
        """Claim a producer's `seq` before sending; None if it is not newer (a replay).

        Returns the previous value, which `release` restores if nothing was sent.
        """
        async with self._pool.connection() as conn, conn.transaction():
            # The placeholder row (-1, below any valid seq) gives FOR UPDATE something to
            # lock even for a first-time issuer, so concurrent claims serialise.
            await conn.execute(
                self._q(
                    "INSERT INTO {s}.issuer_seq (iss, seq, updated_at_ms) VALUES (%s, -1, %s) "
                    "ON CONFLICT (iss) DO NOTHING"
                ),
                (iss, _now_ms()),
            )
            cur = await conn.execute(
                self._q("SELECT seq FROM {s}.issuer_seq WHERE iss = %s FOR UPDATE"), (iss,)
            )
            (current,) = await cur.fetchone()
            if current >= seq:
                return None
            await conn.execute(
                self._q("UPDATE {s}.issuer_seq SET seq = %s, updated_at_ms = %s WHERE iss = %s"),
                (seq, _now_ms(), iss),
            )
        return current

    async def replay_reason(self, iss: str, seq: int, nonce: str | None) -> str | None:
        """Why a producer envelope would replay one already taken: its seq is not newer
        than the last claimed for `iss`, or its nonce is on a block `iss` already sent
        through this relay. Read-only; `reserve` still settles concurrent copies."""
        async with self._pool.connection() as conn:
            cur = await conn.execute(
                self._q("SELECT seq FROM {s}.issuer_seq WHERE iss = %s"), (iss,)
            )
            row = await cur.fetchone()
            if row is not None and row[0] >= seq:
                return f"seq {seq} is not newer than the last from {iss}"
            if nonce is None:
                return None
            cur = await conn.execute(
                self._q("SELECT block_id FROM {s}.receipts WHERE iss = %s AND nonce = %s "
                        "LIMIT 1"),
                (iss, nonce),
            )
            row = await cur.fetchone()
        return None if row is None else f"nonce already used by {row[0]}"

    async def release(self, iss: str, seq: int, previous: int) -> bool:
        """Undo a claim of `seq` (compare-and-set: only if nothing newer was claimed since)."""
        async with self._pool.connection() as conn:
            cur = await conn.execute(
                self._q(
                    "UPDATE {s}.issuer_seq SET seq = %s, updated_at_ms = %s "
                    "WHERE iss = %s AND seq = %s"
                ),
                (previous, _now_ms(), iss, seq),
            )
            return cur.rowcount == 1

    def _advance_query(self) -> sql.Composed:
        return self._q(
            "UPDATE {s}.issuer_seq SET last_block_id = %(bid)s, last_block_seq = %(seq)s, "
            "updated_at_ms = %(now)s "
            "WHERE iss = %(iss)s AND (last_block_seq IS NULL OR last_block_seq < %(seq)s)"
        )

    async def advance(self, iss: str, seq: int, block_id: str) -> None:
        """Move the issuer's chain head to `block_id`, only if `seq` is strictly newer."""
        async with self._pool.connection() as conn:
            await conn.execute(
                self._advance_query(),
                {"iss": iss, "seq": seq, "bid": block_id, "now": _now_ms()},
            )

    async def record(self, receipt: Receipt) -> None:
        """Persist a receipt and, for a signed message, advance the issuer's chain head."""
        async with self._pool.connection() as conn, conn.transaction():
            if receipt.iss is not None and receipt.seq is not None:
                await conn.execute(
                    self._advance_query(),
                    {
                        "iss": receipt.iss,
                        "seq": receipt.seq,
                        "bid": receipt.block_id,
                        "now": _now_ms(),
                    },
                )
            await conn.execute(
                self._q(
                    "INSERT INTO {s}.receipts (block_id, sub_id, tag, iss, kid, seq, verdict, "
                    "att_sub, node, hornet_status, received_at_ms, nonce) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
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
                    receipt.nonce,
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
