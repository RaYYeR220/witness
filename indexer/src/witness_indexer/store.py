"""PostgreSQL store: the parallel database behind the explorer.

Every write is idempotent (`ON CONFLICT`) and reports whether it inserted a new row, so callers
emit an event only for genuinely new data. Reads return plain dicts; bytea columns stay `bytes`.
"""

from __future__ import annotations

import base64
import json
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from .events import NOTIFY_CHANNEL

EMIT_LOCK = 7_700_001
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
    json: dict | None = field(default_factory=dict)
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
        self._tx: ContextVar[psycopg.AsyncConnection | None] = ContextVar(
            f"witness_tx_{id(self)}", default=None)

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

    @asynccontextmanager
    async def _conn(self) -> AsyncIterator[psycopg.AsyncConnection]:
        pinned = self._tx.get()
        if pinned is not None:
            yield pinned
        else:
            async with self._pool.connection() as c:
                yield c

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[None]:
        """Run every store call made in this task inside one database transaction."""
        if self._tx.get() is not None:
            yield  # nested: join the outer transaction
            return
        async with self._pool.connection() as c, c.transaction():
            token = self._tx.set(c)
            try:
                yield
            finally:
                self._tx.reset(token)

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
                    CASE WHEN %(ms_index)s::bigint IS NOT NULL THEN %(ts)s::bigint * 1000 END,
                    (SELECT min(at_ms) FROM lifecycle
                     WHERE block_id = %(block_id)s AND status = 'CONFIRMED')))
            ON CONFLICT (block_id) DO UPDATE SET
                ms_index = excluded.ms_index,
                wf_index = excluded.wf_index,
                ts = excluded.ts,
                verdict = excluded.verdict,
                iat = excluded.iat,
                nonce = excluded.nonce,
                confirmed_at_ms = excluded.ts * 1000
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

    # -- events -----------------------------------------------------------------------------

    async def emit(self, type: str, payload: dict) -> int:
        async with self._conn() as c, c.transaction():
            # Serialise emitters so id allocation order equals commit order; a reader that
            # polls events_after() can then never skip an id that commits late.
            await c.execute("SELECT pg_advisory_xact_lock(%s)", (EMIT_LOCK,))
            cur = await c.execute(
                "INSERT INTO events (type, payload, ts) VALUES (%s,%s,%s) RETURNING id",
                (type, Jsonb(payload), _now_ms()))
            eid = (await cur.fetchone())["id"]
            await c.execute("SELECT pg_notify(%s, %s)", (NOTIFY_CHANNEL, str(eid)))
        return eid

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
        return out

    # -- incidents --------------------------------------------------------------------------

    async def put_incident(self, *, opened_at_ms: int, severity: str, title: str,
                           ie_id: str | None = None, status: str = "open",
                           closed_at_ms: int | None = None) -> int:
        rows = await self._fetch(
            "INSERT INTO incidents (opened_at_ms, closed_at_ms, ie_id, severity, title, status) "
            "VALUES (%s,%s,%s,%s,%s,%s) RETURNING id",
            (opened_at_ms, closed_at_ms, ie_id, severity, title, status))
        return rows[0]["id"]

    async def attach_incident_event(self, incident_id: int, block_id: bytes, role: str) -> None:
        await self._insert(
            "INSERT INTO incident_events (incident_id, block_id, role, attached_at_ms) "
            "VALUES (%s,%s,%s,%s) ON CONFLICT DO NOTHING",
            (incident_id, block_id, role, _now_ms()))

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
            "ORDER BY m.ts NULLS LAST, e.attached_at_ms, e.block_id", (id,))
        return inc
