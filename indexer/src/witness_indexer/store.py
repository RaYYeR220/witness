"""PostgreSQL store: the parallel database behind the explorer.

Every write is idempotent (`ON CONFLICT`) and reports whether it inserted a new row, so callers
emit an event only for genuinely new data. Reads return plain dicts; bytea columns stay `bytes`.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from .events import NOTIFY_CHANNEL

# (store, connection, owning task) of the active Store.transaction(), if any.
_PIN: ContextVar[tuple[Any, psycopg.AsyncConnection, asyncio.Task | None] | None] = ContextVar(
    "witness_store_tx", default=None)
MIGRATIONS_DIR = Path(__file__).parent / "migrations"

LIFECYCLE_STATUSES = frozenset({
    "RECEIVED", "SUBMITTED", "SOLID", "CONFIRMED", "CONTENT_VERIFIED",
    "CONTENT_MISMATCH", "NOT_FOUND", "ORPHANED", "SHADOW",
})

MESSAGE_COLS = (
    "block_id, tag, kind, data, json, ie_id, canon_hash, iss, kid, seq, iat, verdict, "
    "encrypted, ms_index, wf_index, ts, prev, corr, nonce, status, received_at_ms, confirmed_at_ms"
)

COUNTED_TABLES = (
    "milestones", "blocks", "messages", "blind_index", "ie_scores", "alerts", "anchors",
    "events", "submissions", "validations", "content_checks", "lifecycle", "incidents",
)

# A trust.score body whose score is a JSON number in [0, 1]; CASE keeps the cast from ever
# seeing a non-number.
_SCORE_OK = ("CASE WHEN jsonb_typeof(json->'score') = 'number' "
             "THEN (json->>'score')::numeric END BETWEEN 0 AND 1")

FLOW_KEYS = {
    "issuer": "iss",
    "ie": "ie_id",
    "service": "(json->>'serviceComponentId')",
    "corr": "corr",
}


@dataclass
class MessageRow:
    block_id: bytes
    tag: str | None = None
    kind: str | None = None
    data: bytes | None = None
    json: dict | None = None
    ie_id: str | None = None
    canon_hash: bytes | None = None
    iss: str | None = None
    kid: str | None = None
    seq: int | None = None
    iat: int | None = None
    verdict: str | None = None
    encrypted: bool = False
    ms_index: int | None = None
    ts: int = 0
    wf_index: int | None = None
    prev: bytes | None = None
    corr: str | None = None
    nonce: str | None = None
    status: str | None = None
    received_at_ms: int | None = None
    confirmed_at_ms: int | None = None


@dataclass
class Submission:
    sub_id: str
    source: Literal["mqtt", "http"]
    received_at_ms: int
    tag: str | None = None
    message_json: dict | None = None
    data_hex: str | None = None
    block_id: bytes | None = None
    hornet_status: int | None = None
    relay_verdict: str | None = None
    iss: str | None = None
    seq: int | None = None


@dataclass
class Alert:
    rule: str
    severity: str
    block_id: bytes | None
    ie_id: str | None
    evidence: dict
    ts: int
    dedupe_key: str | None = None


@dataclass
class MessageFilter:
    tag: str | None = None
    ie: str | None = None
    iss: str | None = None
    verdict: str | None = None
    kind: str | None = None
    block_id: bytes | None = None
    ms_from: int | None = None
    ms_to: int | None = None
    t_from: int | None = None
    t_to: int | None = None
    date_from_ms: int | None = None
    date_to_ms: int | None = None
    q: str | None = None
    jsonpath_eq: tuple[str, str] | None = None


def _now_ms() -> int:
    return int(time.time() * 1000)


def _enc_cursor(parts: list) -> str:
    return base64.urlsafe_b64encode(json.dumps(parts).encode()).decode().rstrip("=")


def _dec_cursor(cur: str) -> list:
    pad = "=" * (-len(cur) % 4)
    try:
        g, a, b, bid = json.loads(base64.urlsafe_b64decode(cur + pad))
        return [int(g), int(a), int(b), bytes.fromhex(bid)]
    except (ValueError, TypeError) as e:
        raise ValueError("invalid cursor") from e


def _jb(v: Any) -> Jsonb | None:
    return None if v is None else Jsonb(v)


class Store:
    def __init__(self, pool: AsyncConnectionPool, dsn: str, schema: str) -> None:
        self._pool = pool
        self.dsn = dsn
        self.schema = schema

    @classmethod
    async def open(cls, dsn: str, *, schema: str = "witness") -> Store:
        async with await psycopg.AsyncConnection.connect(dsn, autocommit=True) as c:
            await c.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sql.Identifier(schema)))
        search_path = sql.SQL("SET search_path TO {}, public").format(sql.Identifier(schema))

        async def configure(conn: psycopg.AsyncConnection) -> None:
            await conn.execute(search_path)

        pool = AsyncConnectionPool(
            dsn, open=False, configure=configure,
            kwargs={"autocommit": True, "row_factory": dict_row},
        )
        await pool.open()
        await pool.wait()
        return cls(pool, dsn, schema)

    async def close(self) -> None:
        await self._pool.close()

    async def drop_schema(self) -> None:
        """Remove the whole schema. Used by tests; never called by the services."""
        async with self._pool.connection() as c:
            await c.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(
                sql.Identifier(self.schema)))

    # -- plumbing ---------------------------------------------------------------------------

    def _pinned(self) -> psycopg.AsyncConnection | None:
        pin = _PIN.get()
        if pin is None or pin[0] is not self:
            return None
        if pin[2] is not asyncio.current_task():
            raise RuntimeError("store connection pinned to another task")
        return pin[1]

    @asynccontextmanager
    async def _conn(self) -> AsyncIterator[psycopg.AsyncConnection]:
        pinned = self._pinned()
        if pinned is not None:
            yield pinned
        else:
            async with self._pool.connection() as c:
                yield c

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[None]:
        """Run every store call made by the current task inside one database transaction.

        The connection is pinned to the task that opened the block. Child tasks (create_task,
        gather, TaskGroup) inherit the context but must not share the connection, so a store
        call from one raises RuntimeError. A nested call in the same task joins the outer
        transaction.
        """
        if self._pinned() is not None:
            yield
            return
        async with self._pool.connection() as c, c.transaction():
            token = _PIN.set((self, c, asyncio.current_task()))
            try:
                yield
            finally:
                _PIN.reset(token)

    def in_transaction(self) -> bool:
        """True inside a Store.transaction() opened by (or inherited from) this task."""
        pin = _PIN.get()
        return pin is not None and pin[0] is self

    @asynccontextmanager
    async def savepoint(self) -> AsyncIterator[None]:
        """Inside Store.transaction(), a savepoint: an exception escaping the block undoes only
        the block's statements and leaves the outer transaction usable. Outside one, each
        statement commits on its own anyway, so this is a no-op."""
        pinned = self._pinned()
        if pinned is None:
            yield
            return
        async with pinned.transaction():
            yield

    async def _fetch(self, query: str, params: tuple | list = ()) -> list[dict]:
        async with self._conn() as c:
            cur = await c.execute(query, params)
            return await cur.fetchall()

    async def _one(self, query: str, params: tuple | list = ()) -> dict | None:
        rows = await self._fetch(query, params)
        return rows[0] if rows else None

    async def _insert_like(self, query: str, params: tuple | list) -> bool:
        async with self._conn() as c:
            cur = await c.execute(query, params)
            return cur.rowcount > 0

    async def _insert(self, query: str, params: tuple | list) -> bool:
        """Run an INSERT ... ON CONFLICT DO NOTHING; True when a row was inserted."""
        async with self._conn() as c:
            cur = await c.execute(query, params)
            return cur.rowcount == 1

    # -- migrations -------------------------------------------------------------------------

    async def migrate(self) -> None:
        files = sorted(MIGRATIONS_DIR.glob("[0-9][0-9][0-9][0-9]_*.sql"))
        async with self._pool.connection() as c, c.transaction():
            await c.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (self.schema,))
            await c.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations ("
                "version int PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())")
            done = {r["version"] for r in await (
                await c.execute("SELECT version FROM schema_migrations")).fetchall()}
            for f in files:
                version = int(f.name[:4])
                if version in done:
                    continue
                await c.execute(f.read_text(encoding="utf-8"))
                await c.execute(
                    "INSERT INTO schema_migrations (version) VALUES (%s)", (version,))

    async def applied_versions(self) -> list[int]:
        rows = await self._fetch("SELECT version FROM schema_migrations ORDER BY version")
        return [r["version"] for r in rows]

    # -- cursor -----------------------------------------------------------------------------

    async def get_cursor(self) -> int:
        row = await self._one("SELECT ms FROM cursor WHERE id = 1")
        return row["ms"] if row else 0

    async def set_cursor(self, ms: int) -> None:
        await self._fetch(
            "INSERT INTO cursor (id, ms) VALUES (1, %s) "
            "ON CONFLICT (id) DO UPDATE SET ms = excluded.ms RETURNING ms", (ms,))

    # -- chain data -------------------------------------------------------------------------

    async def put_milestone(self, index: int, id: bytes, ts: int, essence: bytes,
                            sigs: list[dict], inclusion_root: bytes, prev_id: bytes) -> bool:
        return await self._insert(
            "INSERT INTO milestones (idx, id, ts, essence, sigs, inclusion_root, prev_id) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
            (index, id, ts, essence, Jsonb(sigs), inclusion_root, prev_id))

    async def put_block(self, id: bytes, ms_index: int, wf_index: int, raw: bytes,
                        payload_type: int) -> bool:
        return await self._insert(
            "INSERT INTO blocks (id, ms_index, wf_index, raw, payload_type) "
            "VALUES (%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
            (id, ms_index, wf_index, raw, payload_type))

    async def put_message(self, m: MessageRow) -> Literal["inserted", "confirmed"] | None:
        """Insert a message. Returns "inserted" for a new row, "confirmed" when an unconfirmed
        row was completed by a re-put carrying its milestone position, None for a duplicate."""
        query = """
            INSERT INTO messages (block_id, tag, kind, data, json, ie_id, canon_hash, iss, kid,
                seq, iat, verdict, encrypted, ms_index, wf_index, ts, prev, corr, nonce,
                status, received_at_ms, confirmed_at_ms)
            VALUES (%(block_id)s, %(tag)s, %(kind)s, %(data)s, %(json)s, %(ie_id)s,
                %(canon_hash)s, %(iss)s, %(kid)s, %(seq)s, %(iat)s, %(verdict)s, %(encrypted)s,
                %(ms_index)s, COALESCE(%(wf_index)s, (SELECT wf_index FROM blocks
                    WHERE id = %(block_id)s)),
                %(ts)s, %(prev)s, %(corr)s, %(nonce)s,
                COALESCE(%(status)s, (SELECT status FROM lifecycle WHERE block_id = %(block_id)s
                    ORDER BY at_ms DESC, id DESC LIMIT 1)),
                COALESCE(%(received_at_ms)s, (SELECT received_at_ms FROM submissions
                    WHERE block_id = %(block_id)s)),
                COALESCE(%(confirmed_at_ms)s,
                    CASE WHEN %(ms_index)s::bigint IS NOT NULL AND %(ts)s::bigint > 0
                         THEN %(ts)s::bigint * 1000 END,
                    (SELECT min(at_ms) FROM lifecycle
                     WHERE block_id = %(block_id)s AND status = 'CONFIRMED')))
            ON CONFLICT (block_id) DO UPDATE SET
                ms_index = excluded.ms_index,
                wf_index = excluded.wf_index,
                ts = CASE WHEN excluded.ts > 0 THEN excluded.ts ELSE messages.ts END,
                verdict = COALESCE(excluded.verdict, messages.verdict),
                iat = COALESCE(excluded.iat, messages.iat),
                nonce = COALESCE(excluded.nonce, messages.nonce),
                confirmed_at_ms = COALESCE(excluded.confirmed_at_ms, messages.confirmed_at_ms)
            WHERE messages.ms_index IS NULL AND excluded.ms_index IS NOT NULL
            RETURNING (xmax = 0) AS inserted
        """
        params = {
            "block_id": m.block_id, "tag": m.tag, "kind": m.kind, "data": m.data,
            "json": _jb(m.json), "ie_id": m.ie_id, "canon_hash": m.canon_hash, "iss": m.iss,
            "kid": m.kid, "seq": m.seq, "iat": m.iat, "verdict": m.verdict,
            "encrypted": m.encrypted, "ms_index": m.ms_index, "wf_index": m.wf_index,
            "ts": m.ts, "prev": m.prev, "corr": m.corr, "nonce": m.nonce, "status": m.status,
            "received_at_ms": m.received_at_ms, "confirmed_at_ms": m.confirmed_at_ms,
        }
        rows = await self._fetch(query, params)  # type: ignore[arg-type]
        if not rows:
            return None
        return "inserted" if rows[0]["inserted"] else "confirmed"

    async def put_blind(self, token: str, block_id: bytes) -> None:
        await self._insert(
            "INSERT INTO blind_index (token, block_id) VALUES (%s,%s) ON CONFLICT DO NOTHING",
            (token, block_id))

    async def put_ie_score(self, ie_id: str, ms_index: int, ts: int, score: float,
                           block_id: bytes, verdict: str | None) -> bool:
        return await self._insert(
            "INSERT INTO ie_scores (ie_id, ms_index, ts, score, block_id, verdict) "
            "VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
            (ie_id, ms_index, ts, score, block_id, verdict))

    async def put_alert(self, a: Alert) -> bool:
        """Dedupe key is (rule, block_id, ie_id, dedupe_key)."""
        return await self._insert(
            "INSERT INTO alerts (rule, severity, block_id, ie_id, evidence, ts, dedupe_key) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
            (a.rule, a.severity, a.block_id, a.ie_id, Jsonb(a.evidence), a.ts, a.dedupe_key))

    async def put_anchor(self, *, seq: int, from_ms: int, to_ms: int, ms_root: bytes | None,
                         checkpoint: dict | None, checkpoint_hash: bytes | None,
                         network: str | None, created_at_ms: int, tx: str | None = None,
                         record: int | None = None, status: str = "pending") -> bool:
        """Insert an anchor batch keyed by seq; False if that seq already exists."""
        return await self._insert(
            "INSERT INTO anchors (seq, from_ms, to_ms, ms_root, checkpoint, checkpoint_hash, "
            "network, tx, record, status, created_at_ms) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
            (seq, from_ms, to_ms, ms_root, _jb(checkpoint), checkpoint_hash, network, tx,
             record, status, created_at_ms))

    async def set_anchor_status(self, seq: int, status: str, tx: str | None = None,
                                record: int | None = None) -> bool:
        return await self._insert_like(
            "UPDATE anchors SET status = %s, tx = COALESCE(%s, tx), "
            "record = COALESCE(%s, record) WHERE seq = %s", (status, tx, record, seq))

    async def anchor(self, seq: int) -> dict | None:
        return await self._one("SELECT * FROM anchors WHERE seq = %s", (seq,))

    async def anchor_covering(self, ms_index: int) -> dict | None:
        return await self._one(
            "SELECT * FROM anchors WHERE from_ms <= %s AND to_ms >= %s "
            "ORDER BY seq DESC LIMIT 1", (ms_index, ms_index))

    # -- submissions, validation, lifecycle -------------------------------------------------

    async def put_submission(self, s: Submission) -> bool:
        """False when the sub_id, or the block id (via another transport), is already stored."""
        return await self._insert(
            "INSERT INTO submissions (sub_id, received_at_ms, source, tag, message_json, "
            "data_hex, block_id, hornet_status, relay_verdict, iss, seq) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
            (s.sub_id, s.received_at_ms, s.source, s.tag, _jb(s.message_json), s.data_hex,
             s.block_id, s.hornet_status, s.relay_verdict, s.iss, s.seq))

    async def put_validation(self, block_id: bytes, checked_at_ms: int, is_solid: bool,
                             referenced_by_ms: int | None,
                             ledger_inclusion_state: str | None,
                             should_reattach: bool | None) -> None:
        await self._insert(
            "INSERT INTO validations (block_id, checked_at_ms, is_solid, referenced_by_ms, "
            "ledger_inclusion_state, should_reattach) VALUES (%s,%s,%s,%s,%s,%s)",
            (block_id, checked_at_ms, is_solid, referenced_by_ms, ledger_inclusion_state,
             should_reattach))

    async def put_content_check(self, block_id: bytes, checked_at_ms: int, result: str,
                                diff: dict | None) -> None:
        await self._insert(
            "INSERT INTO content_checks (block_id, checked_at_ms, result, diff) "
            "VALUES (%s,%s,%s,%s)", (block_id, checked_at_ms, result, _jb(diff)))

    async def set_lifecycle(self, *, block_id: bytes | None, sub_id: str | None, status: str,
                            at_ms: int, detail: dict | None = None) -> None:
        if status not in LIFECYCLE_STATUSES:
            raise ValueError(f"unknown lifecycle status {status!r}")
        if block_id is None and sub_id is None:
            raise ValueError("block_id or sub_id is required")
        async with self._conn() as c, c.transaction():
            if block_id is None:
                cur = await c.execute(
                    "SELECT block_id FROM submissions WHERE sub_id = %s", (sub_id,))
                found = await cur.fetchone()
                block_id = found["block_id"] if found else None
            await c.execute(
                "INSERT INTO lifecycle (block_id, sub_id, status, at_ms, detail) "
                "VALUES (%s,%s,%s,%s,%s)", (block_id, sub_id, status, at_ms, _jb(detail)))
            if block_id is not None:
                await c.execute(
                    "UPDATE messages SET status = %s, confirmed_at_ms = CASE "
                    "WHEN %s = 'CONFIRMED' THEN COALESCE(confirmed_at_ms, %s) "
                    "ELSE confirmed_at_ms END "
                    "WHERE block_id = %s AND NOT EXISTS (SELECT 1 FROM lifecycle l "
                    "WHERE l.block_id = %s AND l.at_ms > %s)",
                    (status, status, at_ms, block_id, block_id, at_ms))

    async def lifecycle(self, block_id: bytes) -> list[dict]:
        return await self._fetch(
            "SELECT id, block_id, sub_id, status, at_ms, detail FROM lifecycle "
            "WHERE block_id = %(b)s OR sub_id IN (SELECT sub_id FROM submissions "
            "WHERE block_id = %(b)s) ORDER BY at_ms, id", {"b": block_id})  # type: ignore[arg-type]

    async def submission(self, *, sub_id: str | None = None,
                         block_id: bytes | None = None) -> dict | None:
        """One stored submission, looked up by submission id or else by block id."""
        if sub_id is not None:
            return await self._one("SELECT * FROM submissions WHERE sub_id = %s", (sub_id,))
        if block_id is not None:
            return await self._one("SELECT * FROM submissions WHERE block_id = %s", (block_id,))
        raise ValueError("sub_id or block_id is required")

    async def validations(self, block_id: bytes) -> list[dict]:
        return await self._fetch(
            "SELECT * FROM validations WHERE block_id = %s ORDER BY checked_at_ms, id",
            (block_id,))

    async def content_checks(self, block_id: bytes) -> list[dict]:
        return await self._fetch(
            "SELECT * FROM content_checks WHERE block_id = %s ORDER BY checked_at_ms, id",
            (block_id,))

    async def unfinished_submissions(self, limit: int) -> list[dict]:
        """Submitted blocks whose validation never concluded (latest status SUBMITTED, SOLID
        or CONFIRMED), oldest first; picked up again after a restart."""
        return await self._fetch(
            "SELECT s.block_id, s.sub_id FROM submissions s "
            "WHERE s.block_id IS NOT NULL "
            "AND (SELECT l.status FROM lifecycle l WHERE l.block_id = s.block_id "
            "ORDER BY l.at_ms DESC, l.id DESC LIMIT 1) IN ('SUBMITTED', 'SOLID', 'CONFIRMED') "
            "ORDER BY s.received_at_ms, s.sub_id LIMIT %s", (limit,))

    async def reverify_candidates(self, after: bytes | None, limit: int) -> list[dict]:
        """Every block any table says the explorer holds or checked: a MATCH content check,
        a submission with a block id, an indexed message or a CONTENT_VERIFIED lifecycle row
        (hiding a block takes wiping all four). In block id order after `after`, with every
        copy of its content (submission tag/data_hex, message tag/data, for whichever rows
        exist) and `verified_once` (a MATCH check or a CONTENT_VERIFIED row)."""
        return await self._fetch(
            "WITH ids AS ("
            " SELECT block_id FROM content_checks WHERE result = 'MATCH'"
            " UNION SELECT block_id FROM submissions WHERE block_id IS NOT NULL"
            " UNION SELECT block_id FROM messages"
            " UNION SELECT block_id FROM lifecycle"
            "  WHERE status = 'CONTENT_VERIFIED' AND block_id IS NOT NULL"
            "), page AS ("
            " SELECT block_id FROM ids WHERE (%s::bytea IS NULL OR block_id > %s::bytea)"
            " ORDER BY block_id LIMIT %s) "
            "SELECT p.block_id, s.sub_id, s.block_id IS NOT NULL AS has_submission, "
            "s.tag AS sub_tag, s.data_hex, m.block_id IS NOT NULL AS has_message, "
            "m.tag AS msg_tag, m.data AS msg_data, "
            "(EXISTS (SELECT 1 FROM content_checks c WHERE c.block_id = p.block_id "
            "AND c.result = 'MATCH') OR EXISTS (SELECT 1 FROM lifecycle l "
            "WHERE l.block_id = p.block_id AND l.status = 'CONTENT_VERIFIED')) AS verified_once "
            "FROM page p LEFT JOIN submissions s ON s.block_id = p.block_id "
            "LEFT JOIN messages m ON m.block_id = p.block_id "
            "ORDER BY p.block_id", (after, after, limit))

    # -- events -----------------------------------------------------------------------------

    async def emit(self, type: str, payload: dict) -> int:
        """Append an event and NOTIFY. The per-schema emit lock is held until the surrounding
        transaction ends, so inside Store.transaction() call emit last."""
        async with self._conn() as c, c.transaction():
            # Serialise emitters so id allocation order equals commit order; a reader that
            # polls events_after() can then never skip an id that commits late.
            await c.execute("SELECT pg_advisory_xact_lock(hashtext(%s))",
                            (f"{self.schema}:emit",))
            cur = await c.execute(
                "INSERT INTO events (type, payload, ts) VALUES (%s,%s,%s) RETURNING id",
                (type, Jsonb(payload), _now_ms()))
            eid = (await cur.fetchone())["id"]
            await c.execute("SELECT pg_notify(%s, %s)", (NOTIFY_CHANNEL, str(eid)))
        return eid

    async def emit_lock(self) -> None:
        """Take emit()'s per-schema lock now; it is held until the surrounding transaction
        ends. A writer that reads, decides and then emits takes it first, so two writers never
        decide on the same state and there is no second lock to order against emit's."""
        await self._fetch("SELECT pg_advisory_xact_lock(hashtext(%s))",
                          (f"{self.schema}:emit",))

    async def last_event_id(self) -> int:
        row = await self._one("SELECT COALESCE(max(id), 0) AS id FROM events")
        return row["id"] if row else 0

    async def events_of_type_after(self, type: str, id: int, limit: int) -> list[dict]:
        return await self._fetch(
            "SELECT id, type, payload, ts FROM events WHERE id > %s AND type = %s "
            "ORDER BY id LIMIT %s", (id, type, limit))

    async def events_after(self, id: int, limit: int) -> list[dict]:
        return await self._fetch(
            "SELECT id, type, payload, ts FROM events WHERE id > %s ORDER BY id LIMIT %s",
            (id, limit))

    async def listen(self) -> AsyncIterator[int]:
        """Yield event ids as they are emitted (on any connection to this database)."""
        async with await psycopg.AsyncConnection.connect(self.dsn, autocommit=True) as c:
            await c.execute(sql.SQL("LISTEN {}").format(sql.Identifier(NOTIFY_CHANNEL)))
            async for note in c.notifies():
                yield int(note.payload)

    # -- message queries --------------------------------------------------------------------

    async def get_message(self, block_id: bytes) -> dict | None:
        return await self._one(
            f"SELECT {MESSAGE_COLS} FROM messages WHERE block_id = %s", (block_id,))

    async def query_messages(self, f: MessageFilter, cursor: str | None,
                             limit: int) -> tuple[list[dict], str | None]:
        where, params = ["true"], []

        def add(cond: str, *vals: Any) -> None:
            where.append(cond)
            params.extend(vals)

        if f.tag is not None:
            add("tag = %s", f.tag)
        if f.ie is not None:
            add("ie_id = %s", f.ie)
        if f.iss is not None:
            add("iss = %s", f.iss)
        if f.verdict is not None:
            add("verdict = %s", f.verdict)
        if f.kind is not None:
            add("kind = %s", f.kind)
        if f.block_id is not None:
            add("block_id = %s", f.block_id)
        if f.ms_from is not None:
            add("ms_index >= %s", f.ms_from)
        if f.ms_to is not None:
            add("ms_index <= %s", f.ms_to)
        if f.t_from is not None:
            add("ts >= %s", f.t_from)
        if f.t_to is not None:
            add("ts <= %s", f.t_to)
        if f.date_from_ms is not None:
            add("COALESCE(received_at_ms, confirmed_at_ms, ts * 1000) >= %s", f.date_from_ms)
        if f.date_to_ms is not None:
            add("COALESCE(received_at_ms, confirmed_at_ms, ts * 1000) <= %s", f.date_to_ms)
        if f.q:
            add("tsv @@ plainto_tsquery('simple', %s)", f.q)
        if f.jsonpath_eq is not None:
            path, value = f.jsonpath_eq
            add("json #>> %s::text[] = %s", path.split("."), value)

        outer, oparams = "true", []
        if cursor:
            g, a, b, bid = _dec_cursor(cursor)
            outer = "(_g > %s OR (_g = %s AND (_a, _b, block_id) < (%s, %s, %s)))"
            oparams = [g, g, a, b, bid]
        query = f"""
            WITH m AS (
                SELECT {MESSAGE_COLS}, (ms_index IS NOT NULL)::int AS _g,
                       COALESCE(ms_index, received_at_ms, ts) AS _a,
                       COALESCE(wf_index, 0)::bigint AS _b
                FROM messages WHERE {' AND '.join(where)}
            )
            SELECT * FROM m WHERE {outer}
            ORDER BY _g, _a DESC, _b DESC, block_id DESC LIMIT %s
        """
        rows = await self._fetch(query, [*params, *oparams, limit + 1])
        nxt = None
        if len(rows) > limit:
            rows = rows[:limit]
            last = rows[-1]
            nxt = _enc_cursor([last["_g"], last["_a"], last["_b"], last["block_id"].hex()])
        for r in rows:
            for k in ("_g", "_a", "_b"):
                r.pop(k)
        return rows, nxt

    async def lookup_canon(self, h: bytes) -> list[dict]:
        return await self._fetch(
            f"SELECT {MESSAGE_COLS} FROM messages WHERE canon_hash = %s ORDER BY ts, block_id",
            (h,))

    async def lookup_blind(self, tokens: list[str]) -> list[dict]:
        return await self._fetch(
            "SELECT DISTINCT b.token, m.block_id, m.tag, m.kind, m.ie_id, m.iss, m.ms_index, "
            "m.ts, m.verdict FROM blind_index b JOIN messages m ON m.block_id = b.block_id "
            "WHERE b.token = ANY(%s) ORDER BY m.ts, m.block_id", (tokens,))

    # -- informational enterprise (IE) views --------------------------------------------------

    async def ie_list(self) -> list[dict]:
        return await self._fetch(
            "SELECT ie_id, count(*) AS count, min(ts) AS first_ts, max(ts) AS last_ts, "
            "max(ms_index) AS last_ms_index FROM messages WHERE ie_id IS NOT NULL "
            "GROUP BY ie_id ORDER BY last_ts DESC, ie_id")

    async def ie_lineage(self, ie_id: str) -> list[dict]:
        return await self._fetch(
            "SELECT block_id, prev, seq, kind, verdict, ms_index, wf_index, ts FROM messages "
            "WHERE ie_id = %s ORDER BY ms_index NULLS LAST, wf_index NULLS LAST, ts, block_id",
            (ie_id,))

    # -- chain views ------------------------------------------------------------------------

    async def cone_ids(self, ms_index: int) -> list[bytes]:
        rows = await self._fetch(
            "SELECT id FROM blocks WHERE ms_index = %s ORDER BY wf_index", (ms_index,))
        return [r["id"] for r in rows]

    async def milestone(self, index: int) -> dict | None:
        return await self._one("SELECT * FROM milestones WHERE idx = %s", (index,))

    async def milestone_ids(self, frm: int, to: int) -> list[bytes]:
        rows = await self._fetch(
            "SELECT id FROM milestones WHERE idx BETWEEN %s AND %s ORDER BY idx", (frm, to))
        return [r["id"] for r in rows]

    async def message_count(self, frm: int, to: int) -> int:
        """Tagged-data messages referenced by milestones `frm`..`to`, as indexed."""
        row = await self._one(
            "SELECT count(*) AS n FROM messages WHERE ms_index BETWEEN %s AND %s", (frm, to))
        return int(row["n"]) if row else 0

    async def seq_used(self, iss: str, seq: int, exclude_block_id: bytes) -> bytes | None:
        """Another block in which the issuer provably used `seq` (signed verdicts only)."""
        row = await self._one(
            "SELECT block_id FROM messages WHERE iss = %s AND seq = %s "
            "AND verdict IN ('PRODUCER_SIGNED', 'RELAY_ATTESTED') AND block_id <> %s "
            "ORDER BY ms_index NULLS LAST, wf_index NULLS LAST, block_id LIMIT 1",
            (iss, seq, exclude_block_id))
        return bytes(row["block_id"]) if row else None

    async def nonce_used(self, iss: str, nonce: str, exclude_block_id: bytes) -> bytes | None:
        """Another block in which the issuer provably used `nonce` (signed verdicts only)."""
        row = await self._one(
            "SELECT block_id FROM messages WHERE iss = %s AND nonce = %s "
            "AND verdict IN ('PRODUCER_SIGNED', 'RELAY_ATTESTED') AND block_id <> %s "
            "ORDER BY ms_index NULLS LAST, wf_index NULLS LAST, block_id LIMIT 1",
            (iss, nonce, exclude_block_id))
        return bytes(row["block_id"]) if row else None

    async def issuer_state(self, iss: str, exclude_block_id: bytes | None = None
                           ) -> tuple[int | None, set[str]]:
        """Highest sequence number and recent nonces seen for an issuer.

        Only messages whose verdict proves the issuer (producer-signed or relay-attested)
        count, so a forged message cannot move the state. `exclude_block_id` lets a
        reprocessed message be judged without seeing itself.
        """
        args = (iss, exclude_block_id, exclude_block_id)
        cond = ("iss = %s AND verdict IN ('PRODUCER_SIGNED', 'RELAY_ATTESTED') "
                "AND (%s::bytea IS NULL OR block_id <> %s::bytea)")
        top = await self._one(f"SELECT max(seq) AS seq FROM messages WHERE {cond}", args)
        rows = await self._fetch(
            f"SELECT nonce FROM messages WHERE {cond} AND nonce IS NOT NULL "
            f"ORDER BY ts DESC, block_id LIMIT 500", args)
        return (top["seq"] if top else None), {r["nonce"] for r in rows}

    # -- rule queries -----------------------------------------------------------------------
    # `verdicts` arguments name the verdicts whose messages a rule trusts; the rules engine
    # decides which those are.

    async def chain_head(self, iss: str, before_seq: int, verdicts: list[str],
                         exclude_block_id: bytes) -> dict | None:
        """The issuer's message with the highest seq below `before_seq` (block_id, seq)."""
        return await self._one(
            "SELECT block_id, seq FROM messages WHERE iss = %s AND verdict = ANY(%s::text[]) "
            "AND seq < %s AND block_id <> %s ORDER BY seq DESC, ts DESC, block_id LIMIT 1",
            (iss, verdicts, before_seq, exclude_block_id))

    async def chain_siblings(self, iss: str, prev: bytes, verdicts: list[str],
                             exclude_block_id: bytes) -> list[dict]:
        """Other messages of the issuer that name the same `prev` (block_id, seq)."""
        return await self._fetch(
            "SELECT block_id, seq FROM messages WHERE iss = %s AND prev = %s "
            "AND verdict = ANY(%s::text[]) AND block_id <> %s ORDER BY seq, block_id LIMIT 20",
            (iss, prev, verdicts, exclude_block_id))

    async def previous_score(self, ie_id: str, verdicts: list[str],
                             before: tuple[int, int] | None,
                             exclude_block_id: bytes) -> dict | None:
        """The IE's trust.score confirmed just before position `before` (ms_index, wf_index),
        or its latest confirmed one when `before` is None: block_id, score, ts, ms_index."""
        cond, args = "", [ie_id, verdicts, exclude_block_id]
        if before is not None:
            cond = "AND (ms_index, COALESCE(wf_index, 0)) < (%s, %s)"
            args += list(before)
        return await self._one(
            "SELECT block_id, (json->>'score')::float8 AS score, ts, ms_index FROM messages "
            "WHERE ie_id = %s AND kind = 'trust.score' AND verdict = ANY(%s::text[]) "
            f"AND block_id <> %s AND ms_index IS NOT NULL AND {_SCORE_OK} "
            f"{cond} ORDER BY ms_index DESC, COALESCE(wf_index, 0) DESC, block_id DESC LIMIT 1",
            args)

    async def latest_scores(self, verdicts: list[str]) -> list[dict]:
        """Per IE, its latest confirmed trust.score: ie_id, block_id, score, ts, ms_index."""
        return await self._fetch(
            "SELECT DISTINCT ON (ie_id) ie_id, block_id, (json->>'score')::float8 AS score, ts, "
            "ms_index FROM messages WHERE kind = 'trust.score' AND ie_id IS NOT NULL "
            f"AND verdict = ANY(%s::text[]) AND ms_index IS NOT NULL AND {_SCORE_OK} "
            "ORDER BY ie_id, ms_index DESC, COALESCE(wf_index, 0) DESC, block_id DESC",
            (verdicts,))

    async def security_events(self, ie_id: str, tags: list[str], verdicts: list[str],
                              from_ts: int, to_ts: int, limit: int = 20) -> list[dict]:
        """Messages with one of `tags` about the IE between two milestone times (seconds):
        block_id, tag, ts, verdict, plus whether a submission names the block
        (`submitted`) and whether it carries a SHADOW alert (`shadowed`)."""
        return await self._fetch(
            "SELECT m.block_id, m.tag, m.ts, m.verdict, "
            "EXISTS (SELECT 1 FROM submissions s WHERE s.block_id = m.block_id) AS submitted, "
            "EXISTS (SELECT 1 FROM alerts a WHERE a.rule = 'SHADOW' "
            "AND a.block_id = m.block_id) AS shadowed "
            "FROM messages m WHERE m.ie_id = %s AND m.tag = ANY(%s::text[]) "
            "AND m.verdict = ANY(%s::text[]) AND m.ts BETWEEN %s AND %s "
            "ORDER BY m.ts DESC, m.block_id LIMIT %s",
            (ie_id, tags, verdicts, from_ts, to_ts, limit))

    async def shadow_candidates(self, since_ms: int, until_ms: int, exempt_tags: list[str],
                                limit: int) -> list[dict]:
        """Confirmed messages in [since_ms, until_ms] (confirmation time) that no submission
        names and that carry no SHADOW alert yet, oldest first."""
        return await self._fetch(
            "SELECT * FROM (SELECT block_id, tag, iss, ie_id, verdict, ms_index, "
            "COALESCE(confirmed_at_ms, ts * 1000) AS confirmed_ms FROM messages m "
            "WHERE ms_index IS NOT NULL AND (tag IS NULL OR NOT tag = ANY(%s::text[])) "
            "AND NOT EXISTS (SELECT 1 FROM submissions s WHERE s.block_id = m.block_id) "
            "AND NOT EXISTS (SELECT 1 FROM alerts a WHERE a.rule = 'SHADOW' "
            "AND a.block_id = m.block_id)) c "
            "WHERE confirmed_ms BETWEEN %s AND %s ORDER BY confirmed_ms, block_id LIMIT %s",
            (exempt_tags, since_ms, until_ms, limit))

    async def first_submission_ms(self) -> int | None:
        row = await self._one("SELECT min(received_at_ms) AS t FROM submissions")
        return row["t"] if row else None

    async def missing_messages(self, block_ids: list[bytes]) -> list[bytes]:
        """The ids, in the given order, that have no row in `messages`."""
        rows = await self._fetch(
            "SELECT block_id FROM messages WHERE block_id = ANY(%s::bytea[])", (block_ids,))
        known = {bytes(r["block_id"]) for r in rows}
        return [b for b in block_ids if b not in known]

    async def latest_milestone_ts(self) -> int | None:
        row = await self._one("SELECT ts FROM milestones ORDER BY idx DESC LIMIT 1")
        return row["ts"] if row else None

    async def has_alert(self, rule: str, *, block_id: bytes | None = None,
                        ie_id: str | None = None) -> bool:
        row = await self._one(
            "SELECT 1 AS x FROM alerts WHERE rule = %s "
            "AND (%s::bytea IS NULL OR block_id = %s::bytea) "
            "AND (%s::text IS NULL OR ie_id = %s::text) LIMIT 1",
            (rule, block_id, block_id, ie_id, ie_id))
        return row is not None

    async def anchors_to_verify(self, limit: int) -> list[dict]:
        """Anchors not verified yet (unverified or unverifiable), oldest first."""
        return await self._fetch(
            "SELECT * FROM anchors WHERE status <> 'failed' "
            "AND verify_state IN ('unverified', 'unverifiable') ORDER BY seq LIMIT %s",
            (limit,))

    async def anchors_after(self, seq: int, limit: int) -> list[dict]:
        """A page of anchors (any verification state) with seq above `seq`, in seq order."""
        return await self._fetch(
            "SELECT * FROM anchors WHERE status <> 'failed' AND seq > %s ORDER BY seq LIMIT %s",
            (seq, limit))

    async def set_anchor_verification(self, seq: int, state: str, at_ms: int,
                                      detail: str | None = None) -> None:
        """Record an anchor's verification state; `verify_since_ms` keeps the time the
        current state was first reached."""
        await self._fetch(
            "UPDATE anchors SET verify_state = %(st)s, verify_detail = %(d)s, "
            "verify_since_ms = CASE WHEN verify_state = %(st)s "
            "THEN COALESCE(verify_since_ms, %(at)s) ELSE %(at)s END, "
            "verified_at_ms = CASE WHEN %(st)s IN ('verified', 'mismatch') THEN %(at)s "
            "ELSE verified_at_ms END WHERE seq = %(seq)s RETURNING seq",
            {"st": state, "d": detail, "at": at_ms, "seq": seq})  # type: ignore[arg-type]

    # -- rule state -------------------------------------------------------------------------

    async def get_rule_state(self, name: str) -> Any:
        row = await self._one("SELECT value FROM rule_state WHERE name = %s", (name,))
        return None if row is None else row["value"]

    async def set_rule_state(self, name: str, value: Any, *, at_ms: int | None = None) -> None:
        await self._fetch(
            "INSERT INTO rule_state (name, value, at_ms) VALUES (%s,%s,%s) "
            "ON CONFLICT (name) DO UPDATE SET value = excluded.value, at_ms = excluded.at_ms "
            "RETURNING name", (name, Jsonb(value), _now_ms() if at_ms is None else at_ms))

    # -- service health ---------------------------------------------------------------------

    async def set_service_status(self, name: str, status: str, *, detail: str | None = None,
                                 at_ms: int | None = None) -> None:
        if name in COUNTED_TABLES or name == "cursor":
            raise ValueError(f"service name {name!r} collides with a stats key")
        await self._fetch(
            "INSERT INTO service_status (name, status, detail, at_ms) VALUES (%s,%s,%s,%s) "
            "ON CONFLICT (name) DO UPDATE SET status = excluded.status, "
            "detail = excluded.detail, at_ms = excluded.at_ms RETURNING name",
            (name, status, detail, _now_ms() if at_ms is None else at_ms))

    async def service_status(self) -> dict[str, dict]:
        rows = await self._fetch("SELECT name, status, detail, at_ms FROM service_status")
        return {r["name"]: {"status": r["status"], "detail": r["detail"], "at_ms": r["at_ms"]}
                for r in rows}

    # -- flows ------------------------------------------------------------------------------

    async def flows(self, by: Literal["issuer", "ie", "service", "corr"],
                    key: str | None) -> list[dict]:
        col = FLOW_KEYS.get(by)
        if col is None:
            raise ValueError(f"unknown flow dimension {by!r}")
        if key is None:
            return await self._fetch(
                f"SELECT {col} AS key, count(*) AS count, min(ts) AS first_ts, "
                f"max(ts) AS last_ts FROM messages WHERE {col} IS NOT NULL "
                f"GROUP BY 1 ORDER BY last_ts DESC, key")
        order = "seq NULLS LAST, ts, block_id" if by == "issuer" else "ts, block_id"
        return await self._fetch(
            f"SELECT block_id, prev, seq, tag, kind, verdict, status, ms_index, wf_index, ts, "
            f"iss, ie_id, corr FROM messages WHERE {col} = %s ORDER BY {order}", (key,))

    # -- alerts, anchors, stats -------------------------------------------------------------

    async def alerts(self, f: dict | None = None, limit: int = 200) -> list[dict]:
        f = f or {}
        where, params = ["true"], []
        for k, col in (("rule", "rule"), ("severity", "severity"), ("ie_id", "ie_id"),
                       ("block_id", "block_id")):
            if f.get(k) is not None:
                where.append(f"{col} = %s")
                params.append(f[k])
        if f.get("since") is not None:
            where.append("ts >= %s")
            params.append(f["since"])
        return await self._fetch(
            f"SELECT id, rule, severity, block_id, ie_id, evidence, ts, dedupe_key FROM alerts "
            f"WHERE {' AND '.join(where)} ORDER BY ts DESC, id DESC LIMIT %s",
            [*params, limit])

    async def anchors(self, limit: int = 100) -> list[dict]:
        return await self._fetch("SELECT * FROM anchors ORDER BY seq DESC LIMIT %s", (limit,))

    async def stats(self) -> dict:
        parts = " UNION ALL ".join(
            f"SELECT '{t}' AS t, count(*) AS n FROM {t}" for t in COUNTED_TABLES)
        out = {r["t"]: r["n"] for r in await self._fetch(parts)}
        out["cursor"] = await self.get_cursor()
        # Service health as last observed, e.g. out["orion"] == "unreachable".
        for name, s in (await self.service_status()).items():
            out[name] = s["status"]
        return out

    # -- incidents --------------------------------------------------------------------------

    async def put_incident(self, *, opened_at_ms: int, severity: str, title: str,
                           ie_id: str | None = None, status: str = "open",
                           closed_at_ms: int | None = None, keys: list[str] | None = None,
                           last_event_ms: int | None = None,
                           anchor_ms: int | None = None,
                           baseline_score: float | None = None,
                           baseline_block_id: bytes | None = None,
                           low_score: float | None = None) -> int:
        rows = await self._fetch(
            "INSERT INTO incidents (opened_at_ms, closed_at_ms, ie_id, severity, title, status, "
            "keys, last_event_ms, anchor_ms, baseline_score, baseline_block_id, low_score, "
            "updated_at_ms) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
            (opened_at_ms, closed_at_ms, ie_id, severity, title, status, keys or [],
             opened_at_ms if last_event_ms is None else last_event_ms,
             opened_at_ms if anchor_ms is None else anchor_ms, baseline_score,
             baseline_block_id, low_score, _now_ms()))
        return rows[0]["id"]

    async def attach_incident_event(self, incident_id: int, block_id: bytes, role: str, *,
                                    at_ms: int | None = None,
                                    detail: dict | None = None) -> bool:
        """False when the block is already part of the incident."""
        return await self._insert(
            "INSERT INTO incident_events (incident_id, block_id, role, attached_at_ms, at_ms, "
            "detail) VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
            (incident_id, block_id, role, _now_ms(), at_ms, _jb(detail)))

    _INCIDENT_FIELDS = frozenset({
        "severity", "title", "ie_id", "keys", "last_event_ms", "anchor_ms", "baseline_score",
        "baseline_block_id", "low_score"})

    async def update_incident(self, id: int, **fields: Any) -> None:
        """Set correlation fields of an incident (see `_INCIDENT_FIELDS`)."""
        unknown = set(fields) - self._INCIDENT_FIELDS
        if unknown:
            raise ValueError(f"not an updatable incident field: {sorted(unknown)}")
        if not fields:
            return
        cols = sorted(fields)  # names from the fixed set above, safe to splice in
        assign = ", ".join(f"{c} = %s" for c in cols)
        await self._fetch(
            f"UPDATE incidents SET {assign}, updated_at_ms = %s WHERE id = %s RETURNING id",
            [*(fields[c] for c in cols), _now_ms(), id])

    async def close_incident(self, id: int, status: str, *, closed_at_ms: int,
                             closed_by: bytes | None = None) -> bool:
        """Close an open incident; False if it was not open."""
        return await self._insert_like(
            "UPDATE incidents SET status = %s, closed_at_ms = %s, closed_by = %s, "
            "updated_at_ms = %s WHERE id = %s AND status = 'open'",
            (status, closed_at_ms, closed_by, _now_ms(), id))

    async def open_incidents(self, keys: list[str]) -> list[dict]:
        """Open incidents sharing at least one key, most recently active first."""
        return await self._fetch(
            "SELECT * FROM incidents WHERE status = 'open' AND keys && %s::text[] "
            "ORDER BY last_event_ms DESC NULLS LAST, id DESC LIMIT 50", (keys,))

    async def idle_incidents(self, before_ms: int, limit: int = 500) -> list[dict]:
        """Open incidents whose latest event is older than `before_ms`."""
        return await self._fetch(
            "SELECT * FROM incidents WHERE status = 'open' "
            "AND COALESCE(last_event_ms, opened_at_ms) < %s ORDER BY id LIMIT %s",
            (before_ms, limit))

    async def incidents_with_block(self, block_id: bytes) -> list[dict]:
        """Incidents the block is an event of, open ones first, then newest."""
        return await self._fetch(
            "SELECT i.*, e.role AS event_role, e.at_ms AS event_at_ms, "
            "e.detail AS event_detail FROM incident_events e "
            "JOIN incidents i ON i.id = e.incident_id WHERE e.block_id = %s "
            "ORDER BY (i.status = 'open') DESC, i.id DESC", (block_id,))

    async def revoke_incident_event(self, incident_id: int, block_id: bytes,
                                    reason: str) -> str | None:
        """Turn an event into `alert` evidence, recording why and its former role (returned);
        None if it was evidence only already."""
        row = await self._one(
            "UPDATE incident_events SET role = 'alert', detail = COALESCE(detail, '{}'::jsonb) "
            "|| jsonb_build_object('revoked', %s::text, 'was', role) "
            "WHERE incident_id = %s AND block_id = %s AND role <> 'alert' "
            "RETURNING detail->>'was' AS was", (reason, incident_id, block_id))
        return None if row is None else row["was"]

    async def reopen_incident(self, id: int, closed_by: bytes) -> bool:
        """Reopen an incident that `closed_by` closed on recovery; False otherwise."""
        return await self._insert_like(
            "UPDATE incidents SET status = 'open', closed_at_ms = NULL, closed_by = NULL, "
            "updated_at_ms = %s WHERE id = %s AND status = 'closed:recovered' "
            "AND closed_by = %s", (_now_ms(), id, closed_by))

    async def incident_proven_drops(self, incident_id: int) -> list[dict]:
        """The incident's proven trust drops that still count, oldest first: block_id, at_ms,
        detail (score, previousScore, previousBlockId)."""
        return await self._fetch(
            "SELECT block_id, at_ms, detail FROM incident_events WHERE incident_id = %s "
            "AND detail->>'trust' = 'proven' AND detail->>'revoked' IS NULL "
            "AND (role = 'trust-drop' OR (role = 'trigger' AND detail->>'as' = 'trust-drop')) "
            "ORDER BY at_ms, block_id", (incident_id,))

    async def link_incident_alert(self, alert_id: int, incident_id: int, at_ms: int) -> bool:
        """False if the alert already belongs to an incident."""
        return await self._insert(
            "INSERT INTO incident_alerts (alert_id, incident_id, attached_at_ms) "
            "VALUES (%s,%s,%s) ON CONFLICT DO NOTHING", (alert_id, incident_id, at_ms))

    async def incident_alert_linked(self, alert_id: int) -> bool:
        return await self._one(
            "SELECT 1 AS x FROM incident_alerts WHERE alert_id = %s", (alert_id,)) is not None

    INCIDENT_PAGE = 500

    async def incident_header(self, id: int) -> dict | None:
        """The incident row alone, without its events."""
        return await self._one("SELECT * FROM incidents WHERE id = %s", (id,))

    async def incident_counts(self, id: int) -> dict:
        """How many events and alerts the incident has: {"events": n, "alerts": m}."""
        row = await self._one(
            "SELECT (SELECT count(*) FROM incident_events WHERE incident_id = %(id)s) AS events, "
            "(SELECT count(*) FROM incident_alerts WHERE incident_id = %(id)s) AS alerts",
            {"id": id})  # type: ignore[arg-type]
        return {"events": row["events"], "alerts": row["alerts"]} if row else {
            "events": 0, "alerts": 0}

    async def incident_alerts(self, incident_id: int, *, after_id: int | None = None,
                              limit: int = INCIDENT_PAGE) -> list[dict]:
        """A page of the alerts that joined the incident, in id order after `after_id`."""
        return await self._fetch(
            "SELECT a.id, a.rule, a.severity, a.block_id, a.ie_id, a.evidence, a.ts, "
            "a.dedupe_key "
            "FROM incident_alerts l JOIN alerts a ON a.id = l.alert_id "
            "WHERE l.incident_id = %s AND (%s::bigint IS NULL OR a.id > %s::bigint) "
            "ORDER BY a.id LIMIT %s", (incident_id, after_id, after_id, limit))

    async def incident_timeline(self, incident_id: int, *,
                                after: tuple[int, bytes] | None = None,
                                limit: int = INCIDENT_PAGE) -> list[dict]:
        """A page of the incident's events in time order, after the (sort_ms, block_id) of
        the last one seen. Each with what the database knows about its block: message fields
        and its status, the latest lifecycle status (else CONFIRMED for a block of a
        milestone cone that never came through the Messages API), and `sort_ms`."""
        after_ms, after_bid = after if after is not None else (None, None)
        return await self._fetch(
            "WITH ev AS (SELECT e.block_id, e.role, e.at_ms, e.attached_at_ms, e.detail, "
            "m.tag, m.kind, m.verdict, m.ie_id, m.iss, m.ms_index, m.ts, m.received_at_ms, "
            "m.confirmed_at_ms, (m.block_id IS NOT NULL) AS indexed, "
            "COALESCE((SELECT l.status FROM lifecycle l WHERE l.block_id = e.block_id "
            " ORDER BY l.at_ms DESC, l.id DESC LIMIT 1), m.status, "
            " CASE WHEN m.ms_index IS NOT NULL THEN 'CONFIRMED' END) AS status, "
            "COALESCE(e.at_ms, m.received_at_ms, m.confirmed_at_ms, m.ts * 1000, "
            " e.attached_at_ms) AS sort_ms "
            "FROM incident_events e LEFT JOIN messages m ON m.block_id = e.block_id "
            "WHERE e.incident_id = %(id)s) "
            "SELECT * FROM ev WHERE %(after_ms)s::bigint IS NULL "
            "OR (sort_ms, block_id) > (%(after_ms)s::bigint, %(after_bid)s::bytea) "
            "ORDER BY sort_ms, block_id LIMIT %(limit)s",
            {"id": incident_id, "after_ms": after_ms, "after_bid": after_bid,
             "limit": limit})  # type: ignore[arg-type]

    async def block_alert_rules(self, block_id: bytes) -> set[str]:
        """The rules of every alert raised on a block."""
        rows = await self._fetch("SELECT DISTINCT rule FROM alerts WHERE block_id = %s",
                                 (block_id,))
        return {r["rule"] for r in rows}

    async def trusted_previous_score(self, ie_id: str, *, relayed: bool,
                                     before: tuple[int, int] | None, exclude_block_id: bytes,
                                     issuers: list[str] | None = None,
                                     unsigned: bool = True) -> dict | None:
        """The IE's confirmed trust.score just before position `before` (ms_index, wf_index),
        or its latest when `before` is None, among producer-signed scores, plus (`relayed`)
        relay-attested ones and (`unsigned`) unsigned ones a submission names. Signed ones
        only from `issuers` when given; never one with an UNSIGNED or SHADOW alert.
        block_id, score, ts, ms_index."""
        cond = ""
        args: dict[str, Any] = {"ie": ie_id, "ex": exclude_block_id, "relayed": relayed,
                                "any": issuers is None, "issuers": issuers or [],
                                "unsigned": unsigned}
        if before is not None:
            cond = "AND (ms_index, COALESCE(wf_index, 0)) < (%(ms)s, %(wf)s)"
            args.update(ms=before[0], wf=before[1])
        return await self._one(
            "SELECT block_id, (json->>'score')::float8 AS score, ts, ms_index FROM messages m "
            "WHERE ie_id = %(ie)s AND kind = 'trust.score' AND block_id <> %(ex)s "
            f"AND ms_index IS NOT NULL AND {_SCORE_OK} "
            "AND ((verdict = 'PRODUCER_SIGNED' OR (%(relayed)s AND verdict = 'RELAY_ATTESTED')) "
            "  AND (%(any)s OR iss = ANY(%(issuers)s::text[])) "
            " OR (%(relayed)s AND %(unsigned)s AND verdict = 'UNSIGNED_LEGACY' "
            "  AND EXISTS (SELECT 1 FROM submissions s WHERE s.block_id = m.block_id))) "
            "AND NOT EXISTS (SELECT 1 FROM alerts a WHERE a.block_id = m.block_id "
            " AND a.rule IN ('UNSIGNED', 'SHADOW')) "
            f"{cond} ORDER BY ms_index DESC, COALESCE(wf_index, 0) DESC, block_id DESC LIMIT 1",
            args)  # type: ignore[arg-type]

    async def alert_by_key(self, rule: str, block_id: bytes | None, ie_id: str | None,
                           dedupe_key: str | None) -> dict | None:
        """The alert with this dedupe key (rule, block, IE, dedupe key), as an `alert` event
        names it."""
        return await self._one(
            "SELECT id, rule, severity, block_id, ie_id, evidence, ts, dedupe_key FROM alerts "
            "WHERE rule = %s AND coalesce(block_id, ''::bytea) = coalesce(%s::bytea, ''::bytea) "
            "AND coalesce(ie_id, '') = coalesce(%s::text, '') "
            "AND coalesce(dedupe_key, '') = coalesce(%s::text, '')",
            (rule, block_id, ie_id, dedupe_key))

    async def incidents(self, f: dict | None = None, limit: int = 200) -> list[dict]:
        f = f or {}
        where, params = ["true"], []
        for k in ("status", "severity", "ie_id"):
            if f.get(k) is not None:
                where.append(f"{k} = %s")
                params.append(f[k])
        if f.get("since") is not None:
            where.append("opened_at_ms >= %s")
            params.append(f["since"])
        return await self._fetch(
            f"SELECT * FROM incidents WHERE {' AND '.join(where)} "
            f"ORDER BY opened_at_ms DESC, id DESC LIMIT %s", [*params, limit])

    async def incident(self, id: int) -> dict | None:
        inc = await self._one("SELECT * FROM incidents WHERE id = %s", (id,))
        if inc is None:
            return None
        inc["events"] = await self._fetch(
            "SELECT e.block_id, e.role FROM incident_events e "
            "LEFT JOIN messages m ON m.block_id = e.block_id WHERE e.incident_id = %s "
            "ORDER BY COALESCE(e.at_ms, m.received_at_ms, m.confirmed_at_ms, m.ts * 1000) "
            "NULLS LAST, e.attached_at_ms, e.block_id", (id,))
        return inc
