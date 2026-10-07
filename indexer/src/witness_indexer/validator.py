"""Tangle validation of forwarded submissions: the brief's checks (c) and (d).

For every submission that got a block id the validator walks the lifecycle

    RECEIVED -> SUBMITTED -> SOLID -> CONFIRMED -> CONTENT_VERIFIED | CONTENT_MISMATCH | NOT_FOUND

(c) polls HORNET `GET /api/core/v2/blocks/{id}/metadata` with exponential backoff until the
block is referenced by a milestone, or gives up after `timeout_s` (ORPHANED). Every metadata
answer is kept in `validations`. ORPHANED is only ever concluded from answers the node gave;
an unreachable node (or one returning something that is not an answer) decides nothing.

(d) then fetches the original block with `GET /api/core/v2/blocks/{id}` as raw bytes and
compares it with what the explorer received: the BLAKE2b-256 of the bytes must be the block
id (a node serving another block for an id is a mismatch too), the payload must be tagged
data, and tag and data must be byte-for-byte what the Messages API sent. Each comparison is
kept in `content_checks`; a mismatch carries a field diff and a canonical-JSON diff for the UI.

A validation that could not conclude keeps its current status and is retried by the worker
with a growing delay; a periodic `resume` also re-queues anything left unfinished. One that
cannot run because no usable copy of the received content is stored is not retried.

`reverify_all` repeats (d) later for every block whose content ever matched, against the
copies held in the parallel database. If those no longer match the Tangle, the database was
altered: DB_TAMPER. `reverify_pass` is the scheduled form (the indexer runs it every
`--reverify-every-s`): one pass over every candidate, resuming after the block the last
pass reached, so every stored copy is compared again within one interval plus one pass.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import psycopg
from witness_core import nesting
from witness_core.canon import jcs
from witness_core.codec import (
    DecodeError,
    MilestonePayload,
    OtherPayload,
    TaggedData,
    parse_block,
)
from witness_core.codec import block_id as compute_block_id
from witness_core.ids import blake2b256, from_hex

from . import events
from .hornet_rest import HornetRest, HornetUnavailable
from .store import Alert, Store

log = logging.getLogger(__name__)

METADATA_VIA = "GET /api/core/v2/blocks/{blockId}/metadata"
BLOCK_VIA = "GET /api/core/v2/blocks/{blockId}"
# Statuses that close a validation run; written again only when the outcome changes.
OUTCOMES = frozenset({"CONTENT_VERIFIED", "CONTENT_MISMATCH", "NOT_FOUND", "ORPHANED"})
# Outcomes the validator raises an alert of the same name (and this severity) for. Those
# alerts are about the forwarded copy (the submission): re-verification leaves that copy to
# them, and still holds the indexed message copy to the Tangle.
ALERTED_OUTCOMES = frozenset({"CONTENT_MISMATCH", "NOT_FOUND", "ORPHANED"})
# A worker stops retrying a block once its status is one of these.
TERMINAL = OUTCOMES | {"RECEIVED"}
MAX_JSON_CHANGES = 200
_PLAIN_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass(frozen=True)
class ValidatorConfig:
    initial_backoff_s: float = 0.5
    max_backoff_s: float = 8.0
    timeout_s: float = 60.0
    reverify_batch: int = 200  # candidates read from the database per query
    # Blocks whose Tangle content a pass keeps in memory (a digest each), so later passes
    # compare stored copies without asking the node again; 0 turns that off.
    tangle_cache_size: int = 100_000
    max_concurrent: int = 32
    retry_initial_s: float = 5.0
    retry_max_s: float = 300.0
    resume_every_s: float = 60.0


def _hex(b: bytes) -> str:
    return "0x" + b.hex()


def _now_ms() -> int:
    return int(time.time() * 1000)


def _iso(ms: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ms / 1000))


@dataclass(frozen=True)
class PassResult:
    """One scheduled re-verification pass."""

    checked: int
    alerts: list[Alert]
    complete: bool  # False when the node stopped answering mid-pass
    error: str | None = None


@dataclass(frozen=True)
class _TangleCopy:
    """What the node served for a block id that hashed to it. Immutable, so a later pass can
    compare stored copies with it without fetching the block again."""

    tag: str | None  # None when the tag is not UTF-8 (stored tags are then not compared)
    data_digest: bytes


# -- content comparison ----------------------------------------------------------------------

def _canon(v: Any) -> bytes:
    try:
        return jcs(v)
    except ValueError:  # e.g. integers beyond the I-JSON range; still a stable rendering
        return json.dumps(v, sort_keys=True, separators=(",", ":")).encode()


def _child(path: str, key: str) -> str:
    return f"{path}.{key}" if _PLAIN_KEY.fullmatch(key) else f"{path}[{json.dumps(key)}]"


def _full(out: list[dict]) -> bool:
    return len(out) > MAX_JSON_CHANGES  # one past the cap marks the diff as truncated


def _walk(path: str, e: Any, a: Any, out: list[dict]) -> None:
    if isinstance(e, dict) and isinstance(a, dict):
        for k in sorted(set(e) | set(a)):
            if _full(out):
                return
            p = _child(path, k)
            if k not in a:
                out.append({"path": p, "kind": "removed", "expected": e[k]})
            elif k not in e:
                out.append({"path": p, "kind": "added", "actual": a[k]})
            else:
                _walk(p, e[k], a[k], out)
    elif isinstance(e, list) and isinstance(a, list):
        for i in range(max(len(e), len(a))):
            if _full(out):
                return
            p = f"{path}[{i}]"
            if i >= len(a):
                out.append({"path": p, "kind": "removed", "expected": e[i]})
            elif i >= len(e):
                out.append({"path": p, "kind": "added", "actual": a[i]})
            else:
                _walk(p, e[i], a[i], out)
    elif _canon(e) != _canon(a):
        out.append({"path": path, "kind": "changed", "expected": e, "actual": a})


def json_diff(expected: bytes, actual: bytes) -> dict:
    """Key-level difference between two JSON documents (any JSON value, not only objects),
    compared in canonical form so key order and whitespace do not count. Used for the human
    view only; the verdict itself is the exact byte comparison."""
    try:
        e, a = nesting.loads(expected), nesting.loads(actual)
        changes: list[dict] = []
        _walk("$", e, a, changes)
    except (ValueError, RecursionError):  # not JSON, past the shared cap, or too deep to walk
        return {"comparable": False}
    out = {"comparable": True, "equal": not changes, "changes": changes[:MAX_JSON_CHANGES]}
    if len(changes) > MAX_JSON_CHANGES:
        out["truncated"] = True
    return out


def _first_diff(a: bytes, b: bytes) -> int:
    for i, (x, y) in enumerate(zip(a, b, strict=False)):
        if x != y:
            return i
    return min(len(a), len(b))


def _bytes_field(name: str, expected: bytes, actual: bytes) -> dict:
    return {"field": name, "expected": _hex(expected), "actual": _hex(actual),
            "firstDiffOffset": _first_diff(expected, actual)}


def _payload_kind(payload: Any) -> str:
    if payload is None:
        return "no payload"
    if isinstance(payload, MilestonePayload):
        return "milestone (type 7)"
    if isinstance(payload, OtherPayload):
        return f"payload type {payload.type}"
    return type(payload).__name__


def compare_content(block_id: bytes, raw: bytes, tag: bytes, data: bytes) -> dict | None:
    """Compare a block fetched from the node with the tag and data the explorer received.
    Returns None when they match, else `{"fields": [{field, expected, actual}], "json": …}`."""
    fields: list[dict] = []
    actual_id = compute_block_id(raw)
    if actual_id != block_id:
        fields.append({"field": "blockId", "expected": _hex(block_id), "actual": _hex(actual_id)})
    try:
        payload = parse_block(raw).payload
    except DecodeError as e:
        fields.append({"field": "block", "expected": "a valid Stardust block",
                       "actual": f"undecodable: {e}"})
        return {"fields": fields, "json": {"comparable": False}}
    if not isinstance(payload, TaggedData):
        fields.append({"field": "payload", "expected": "tagged data (type 5)",
                       "actual": _payload_kind(payload)})
        return {"fields": fields, "json": {"comparable": False}}
    if payload.tag != tag:
        fields.append(_bytes_field("tag", tag, payload.tag))
    if payload.data != data:
        fields.append(_bytes_field("data", data, payload.data))
    if not fields:
        return None
    return {"fields": fields, "json": json_diff(data, payload.data)}


# -- validation runs -------------------------------------------------------------------------

@dataclass
class _Run:
    block_id: bytes
    sub_id: str | None
    seen: set[str] = field(default_factory=set)
    latest: str | None = None

    def note(self, status: str) -> None:
        self.seen.add(status)
        self.latest = status

    def should_write(self, status: str) -> bool:
        if status in OUTCOMES:
            return self.latest != status
        return status not in self.seen


@dataclass(frozen=True)
class _Expected:
    tag: bytes
    data: bytes
    sub_id: str | None


class NoUsableContent(LookupError):
    """No stored copy of what was received for a block can be compared with the Tangle (all
    gone, NULL, or not valid hex). Retrying cannot fix it, so the worker does not."""


class _Unavailable:
    pass


_UNAVAILABLE = _Unavailable()


class _BlockLock:
    __slots__ = ("lock", "users")

    def __init__(self) -> None:
        self.lock = asyncio.Lock()
        self.users = 0


def _referenced_index(meta: dict) -> int | None:
    ms = meta.get("referencedByMilestoneIndex")
    return ms if type(ms) is int else None


class Validator:
    """Runs checks (c) and (d) for queued submissions.

    `sleep` and `clock` drive the polling backoff inside one validation (tests inject fakes);
    the worker's retry and resume timers run on the event loop's own clock.
    """

    def __init__(self, store: Store, hornet: HornetRest, cfg: ValidatorConfig | None = None, *,
                 sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
                 clock: Callable[[], float] = time.monotonic,
                 now_ms: Callable[[], int] = _now_ms) -> None:
        self.store = store
        self.hornet = hornet
        self.cfg = cfg or ValidatorConfig()
        self._sleep = sleep
        self._clock = clock
        self._now_ms = now_ms
        self._queue: asyncio.Queue[tuple[bytes, str]] = asyncio.Queue()
        self._pending: set[bytes] = set()
        self._attempts: dict[bytes, int] = {}
        self._locks: dict[bytes, _BlockLock] = {}
        self._workers: set[asyncio.Task] = set()
        self._timers: set[asyncio.Task] = set()
        self._task: asyncio.Task | None = None
        self._stopping = False
        self._tangle: dict[bytes, _TangleCopy] = {}
        self._pass_after: bytes | None = None  # last block a scheduled pass judged

    # -- worker ----------------------------------------------------------------------------

    @property
    def pending(self) -> int:
        """Blocks queued, being validated or waiting for a retry."""
        return len(self._pending)

    def is_in_flight(self, block_id: bytes) -> bool:
        """Whether the block is on its first validation attempt in this validator (queued or
        running). Held in memory only, so no database row can fake it. It lasts one attempt:
        once a block waits for a retry it no longer counts, so nothing that makes validation
        fail can keep a block in flight for good."""
        return block_id in self._pending and self._attempts.get(block_id, 0) == 0

    def enqueue(self, block_id: bytes | None, sub_id: str) -> None:
        """Queue a submission for validation. A failed submit (no block id) has nothing on the
        Tangle to check and is not queued; a block already queued, running or waiting for a
        retry is not queued twice."""
        if block_id is None:
            log.debug("submission %s has no block id; not validated", sub_id)
            return
        if block_id in self._pending:
            return
        self._pending.add(block_id)
        self._queue.put_nowait((block_id, sub_id))

    async def resume(self, limit: int = 10_000) -> int:
        """Queue submissions whose validation has not concluded (cut short by a restart, an
        unreachable node or an error); returns how many rows were found. Idempotent: blocks
        already pending are skipped. `run` calls it at start and every `resume_every_s`."""
        rows = await self.store.unfinished_submissions(limit)
        for row in rows:
            self.enqueue(bytes(row["block_id"]), row["sub_id"])
        return len(rows)

    async def run(self) -> None:
        """Validate queued blocks, up to `max_concurrent` at a time, until stopped.

        A validation that ends without an outcome (node unreachable, content check still
        owed) or raises is queued again after `retry_initial_s`, doubling up to `retry_max_s`;
        one that raises NoUsableContent is dropped instead (`resume` may queue it again).
        """
        self._task = asyncio.current_task()
        slots = asyncio.Semaphore(self.cfg.max_concurrent)
        resumer = asyncio.create_task(self._resume_loop())
        try:
            while True:
                block_id, sub_id = await self._queue.get()
                await slots.acquire()
                task = asyncio.create_task(self._work(block_id, sub_id, slots))
                self._workers.add(task)
                task.add_done_callback(self._workers.discard)
        except asyncio.CancelledError:
            if not self._stopping:
                raise
        finally:
            tasks = [resumer, *self._workers, *self._timers]
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _resume_loop(self) -> None:
        while True:
            try:
                await self.resume()
            except Exception:
                log.exception("could not look up unfinished validations")
            await asyncio.sleep(self.cfg.resume_every_s)

    async def _work(self, block_id: bytes, sub_id: str, slots: asyncio.Semaphore) -> None:
        status = None
        permanent = False
        try:
            status = await self.validate_once(block_id, sub_id)
        except NoUsableContent as e:  # nothing usable to compare with; a retry cannot help
            permanent = True
            log.warning("validation of block %s cannot run: %s; not retried", _hex(block_id), e)
        except Exception:
            log.exception("validation of block %s failed", _hex(block_id))
        finally:
            slots.release()
        if permanent or status in TERMINAL:
            self._attempts.pop(block_id, None)
            self._pending.discard(block_id)
        else:
            self._retry_later(block_id, sub_id)

    def _retry_later(self, block_id: bytes, sub_id: str) -> None:
        n = self._attempts.get(block_id, 0)
        self._attempts[block_id] = n + 1
        delay = min(self.cfg.retry_initial_s * 2 ** min(n, 20), self.cfg.retry_max_s)
        log.info("validation of block %s not concluded; retry %d in %.1f s",
                 _hex(block_id), n + 1, delay)
        timer = asyncio.create_task(self._requeue_after(block_id, sub_id, delay))
        self._timers.add(timer)
        timer.add_done_callback(self._timers.discard)

    async def _requeue_after(self, block_id: bytes, sub_id: str, delay: float) -> None:
        await asyncio.sleep(delay)
        self._queue.put_nowait((block_id, sub_id))  # still in _pending

    async def stop(self) -> None:
        self._stopping = True
        task = self._task
        if task is not None and task is not asyncio.current_task() and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    @asynccontextmanager
    async def _block_lock(self, block_id: bytes) -> AsyncIterator[None]:
        """Serialise all work on one block (worker, direct API calls, re-verification)."""
        entry = self._locks.get(block_id)
        if entry is None:
            entry = self._locks[block_id] = _BlockLock()
        entry.users += 1
        try:
            async with entry.lock:
                yield
        finally:
            entry.users -= 1
            if entry.users == 0:
                del self._locks[block_id]

    @asynccontextmanager
    async def _database_lock(self, block_id: bytes) -> AsyncIterator[None]:
        """Serialise validations of one block across processes: the indexer's worker and the
        API's on-demand checks share the database, not memory. A session advisory lock on a
        connection of its own (not a pooled one, which validations need for their writes),
        held for the whole validation and released when that connection closes."""
        key = f"{self.store.schema}:validate:{block_id.hex()}"
        async with await psycopg.AsyncConnection.connect(self.store.dsn, autocommit=True) as c:
            await c.execute("SELECT pg_advisory_lock(hashtextextended(%s, 0))", (key,))
            yield

    # -- one validation --------------------------------------------------------------------

    async def validate_once(self, block_id: bytes | None, sub_id: str | None) -> str:
        """Run checks (c) and (d) for one block and return its lifecycle status afterwards.

        A submission without a block id stays RECEIVED and nothing is asked of the node.
        When the node could not be asked (unreachable, or answering with something that is
        not an answer about the block), nothing is concluded or written: the current status
        (SUBMITTED, SOLID or CONFIRMED) is returned and the block stays due for a retry. Calls
        for the same block are serialised, in this process and across processes sharing the
        database, so a direct call cannot race the worker.
        """
        if block_id is None:
            return "RECEIVED"
        async with self._block_lock(block_id), self._database_lock(block_id):
            expected = await self._expected(block_id, sub_id)
            run = _Run(block_id, expected.sub_id)
            for row in await self.store.lifecycle(block_id):
                run.note(row["status"])
            outcome = await self._await_confirmation(run)
            if outcome != "CONFIRMED":
                return outcome or run.latest or "SUBMITTED"
            return await self._check_content(run, expected)

    async def _expected(self, block_id: bytes, sub_id: str | None) -> _Expected:
        sub = await self.store.submission(sub_id=sub_id) if sub_id else None
        if sub is None or sub["block_id"] != block_id:
            sub = await self.store.submission(block_id=block_id)
        if sub is not None and sub["tag"] is not None and sub["data_hex"] is not None:
            try:
                data = from_hex(sub["data_hex"])
            except ValueError as e:
                raise NoUsableContent(f"stored data_hex of block {_hex(block_id)} is not "
                                      f"hex: {e}") from e
            return _Expected(sub["tag"].encode("utf-8"), data, sub["sub_id"])
        msg = await self.store.get_message(block_id)
        if msg is not None and msg["tag"] is not None and msg["data"] is not None:
            return _Expected(msg["tag"].encode("utf-8"), bytes(msg["data"]), sub_id)
        raise NoUsableContent(f"no received content stored for block {_hex(block_id)}")

    async def _await_confirmation(self, run: _Run) -> str | None:
        """Check (c): poll metadata until the block is referenced by a milestone (CONFIRMED).

        At the deadline the block is ORPHANED only if the node itself said so: the final poll
        got a definitive answer (metadata, or 404 "unknown block") and so did at least one
        poll inside the window. Otherwise the node was not really asked and None is returned
        with nothing written.
        """
        cfg = self.cfg
        deadline = self._clock() + cfg.timeout_s
        backoff = cfg.initial_backoff_s
        polls = answered = 0
        last: dict | None = None
        last_error: str | None = None
        while True:
            polls += 1
            definitive = True
            try:
                meta = await self.hornet.block_metadata(run.block_id)
            except HornetUnavailable as e:
                meta, definitive, last_error = None, False, str(e)
            if meta is not None:
                last = meta
                await self._record_metadata(run, meta)
                if _referenced_index(meta) is not None:
                    return "CONFIRMED"
            remaining = deadline - self._clock()
            if remaining <= 0:
                if definitive and answered > 0:
                    await self._orphan(run, polls, answered + 1, last, last_error)
                    return "ORPHANED"
                log.warning("block %s: no usable answer from the node at the deadline "
                            "(%d of %d polls answered, last error: %s); not concluding",
                            _hex(run.block_id), answered + int(definitive), polls, last_error)
                return None
            if definitive:
                answered += 1
            await self._sleep(min(backoff, remaining))
            backoff = min(backoff * 2, cfg.max_backoff_s)

    async def _record_metadata(self, run: _Run, meta: dict) -> None:
        at = self._now_ms()
        solid = meta.get("isSolid") is True
        ms = _referenced_index(meta)
        state = meta.get("ledgerInclusionState")
        state = state if isinstance(state, str) else None
        reattach = meta.get("shouldReattach")
        reattach = reattach if isinstance(reattach, bool) else None
        steps: list[tuple[str, dict]] = []
        if (solid or ms is not None) and run.should_write("SOLID"):
            steps.append(("SOLID", {"via": METADATA_VIA, "isSolid": solid}))
        if ms is not None and run.should_write("CONFIRMED"):
            steps.append(("CONFIRMED", {
                "via": METADATA_VIA, "referencedByMilestoneIndex": ms,
                "ledgerInclusionState": state, "whiteFlagIndex": meta.get("whiteFlagIndex"),
            }))
        async with self.store.transaction():
            await self.store.put_validation(run.block_id, at, solid, ms, state, reattach)
            for status, detail in steps:
                await self.store.set_lifecycle(block_id=run.block_id, sub_id=run.sub_id,
                                               status=status, at_ms=at, detail=detail)
            for status, detail in steps:
                await self.store.emit(events.LIFECYCLE, self._lifecycle_event(
                    run, status, at, detail))
        for status, _ in steps:
            run.note(status)

    async def _orphan(self, run: _Run, polls: int, answered: int, last: dict | None,
                      last_error: str | None) -> None:
        at = self._now_ms()
        evidence = {"subId": run.sub_id, "via": METADATA_VIA, "timeoutS": self.cfg.timeout_s,
                    "polls": polls, "answeredPolls": answered, "lastMetadata": last,
                    "lastError": last_error}
        detail = {"via": METADATA_VIA, "timeoutS": self.cfg.timeout_s, "polls": polls,
                  "answeredPolls": answered,
                  "solid": bool(last and last.get("isSolid") is True)}
        await self._conclude(run, "ORPHANED", at, detail,
                             alert=Alert("ORPHANED", "high", run.block_id, None, evidence, at))

    async def _fetch_raw(self, run: _Run) -> bytes | None | _Unavailable:
        deadline = self._clock() + self.cfg.timeout_s
        backoff = self.cfg.initial_backoff_s
        while True:
            try:
                return await self.hornet.block_raw(run.block_id)
            except HornetUnavailable as e:
                remaining = deadline - self._clock()
                if remaining <= 0:
                    log.warning("block %s confirmed but its content could not be fetched: %s",
                                _hex(run.block_id), e)
                    return _UNAVAILABLE
                await self._sleep(min(backoff, remaining))
                backoff = min(backoff * 2, self.cfg.max_backoff_s)

    async def _check_content(self, run: _Run, expected: _Expected) -> str:
        """Check (d): the block on the Tangle carries exactly the bytes that were received."""
        raw = await self._fetch_raw(run)
        if isinstance(raw, _Unavailable):
            return run.latest or "CONFIRMED"  # content check still owed; nothing written
        at = self._now_ms()
        if raw is None:
            evidence = {"subId": run.sub_id, "via": BLOCK_VIA,
                        "reason": "the node reports the block confirmed but does not return it"}
            await self._conclude(
                run, "NOT_FOUND", at, {"via": BLOCK_VIA}, check=("NOT_FOUND", None),
                alert=Alert("NOT_FOUND", "critical", run.block_id, None, evidence, at))
            return "NOT_FOUND"
        diff = compare_content(run.block_id, raw, expected.tag, expected.data)
        if diff is None:
            await self._conclude(run, "CONTENT_VERIFIED", at,
                                 {"via": BLOCK_VIA, "bytes": len(raw)}, check=("MATCH", None))
            return "CONTENT_VERIFIED"
        evidence = {"subId": run.sub_id, "via": BLOCK_VIA, "diff": diff}
        await self._conclude(
            run, "CONTENT_MISMATCH", at,
            {"via": BLOCK_VIA, "fields": [f["field"] for f in diff["fields"]]},
            check=("MISMATCH", diff),
            alert=Alert("CONTENT_MISMATCH", "critical", run.block_id, None, evidence, at,
                        dedupe_key=blake2b256(raw).hex()))
        return "CONTENT_MISMATCH"

    async def _conclude(self, run: _Run, status: str, at: int, detail: dict, *,
                        check: tuple[str, dict | None] | None = None,
                        alert: Alert | None = None) -> bool:
        """Write one outcome atomically; returns whether the alert was new. A content check
        identical to the block's latest one (same result and diff) is not written again, so
        repeated passes over an unchanged block leave no trail of duplicate rows."""
        write = run.should_write(status)
        async with self.store.transaction():
            if check is not None:
                previous = await self.store.content_checks(run.block_id)
                if not previous or (previous[-1]["result"], _canon(previous[-1]["diff"])) != (
                        check[0], _canon(check[1])):
                    await self.store.put_content_check(run.block_id, at, check[0], check[1])
            if write:
                await self.store.set_lifecycle(block_id=run.block_id, sub_id=run.sub_id,
                                               status=status, at_ms=at, detail=detail)
            new_alert = alert is not None and await self.store.put_alert(alert)
            if write:
                await self.store.emit(events.LIFECYCLE,
                                      self._lifecycle_event(run, status, at, detail))
            if new_alert:
                await self.store.emit(events.ALERT, _alert_event(alert))
        if write:
            run.note(status)
        return bool(new_alert)

    @staticmethod
    def _lifecycle_event(run: _Run, status: str, at: int, detail: dict) -> dict:
        return {"blockId": _hex(run.block_id), "subId": run.sub_id, "status": status,
                "atMs": at, "detail": detail}

    # -- re-verification of the parallel database -------------------------------------------

    async def reverify_all(self, limit: int | None = None) -> list[Alert]:
        """Re-fetch the blocks the explorer holds and compare them with every copy of their
        content stored now. A block an earlier pass fetched is compared with the digest of
        its Tangle content kept in memory instead, and fetched again only when a stored copy
        differs (for the evidence) or its content was removed.

        Candidates come from four tables (MATCH content checks, submissions, messages and
        CONTENT_VERIFIED lifecycle rows), so deleting one kind of row does not hide a block.
        The only block skipped is one on its first validation attempt in this validator
        (queued or running: `is_in_flight`). That is in-memory state no database row can
        forge, and it lasts one attempt: a block waiting for a retry is judged, and one whose
        stored content is unusable is dropped by the worker rather than retried, so making its
        validation fail cannot keep a block exempt. Lifecycle rows and content checks never
        exempt a block. A block that was verified once is always judged, and all its copies
        being gone or NULL is itself DB_TAMPER ("content removed"). A block never verified is
        judged once the node confirms it is referenced by a milestone (definitive answers
        only), so an unconfirmed block can never raise DB_TAMPER. When a block's latest
        validation outcome is CONTENT_MISMATCH, NOT_FOUND or ORPHANED and the validator's
        alert for it exists (same rule; critical, or high for ORPHANED), its submission copy
        is not judged: that alert already reports it differing from the Tangle (or the block
        missing). Its indexed message copy is still compared with the Tangle, since the
        alert says nothing about it. An outcome row without that alert exempts nothing, so
        exempting a copy by forging rows means raising a critical or high alert on the
        block. The CONTENT_MISMATCH rows written for DB_TAMPER do not count as outcomes: a
        block verified once and then tampered with stays fully judged, and its alert is
        deduplicated per block and stored content.

        The parallel DB is not the trust root: an attacker who wipes every copy of a block from
        all four tables leaves nothing to re-verify here. That is detected by re-indexing the
        Tangle (Task 9 SHADOW / re-scan) and by the public anchor.

        Returns the DB_TAMPER alerts raised by this pass. Stops early, keeping what it found,
        if the node becomes unreachable.
        """
        found: list[Alert] = []
        after: bytes | None = None
        checked = 0
        while limit is None or checked < limit:
            size = self.cfg.reverify_batch
            if limit is not None:
                size = min(size, limit - checked)
            rows = await self.store.reverify_candidates(after, size)
            for row in rows:
                after = bytes(row["block_id"])
                checked += 1
                try:
                    alert = await self._reverify_row(row)
                except HornetUnavailable as e:
                    log.warning("re-verification stopped after %d blocks: %s", checked - 1, e)
                    return found
                if alert is not None:
                    found.append(alert)
            if len(rows) < size:
                break
        return found

    async def reverify_pass(self) -> PassResult:
        """One scheduled pass of `reverify_all` over every candidate, in block id order,
        starting after the block the previous pass judged last and wrapping around, so a
        pass the node cuts short resumes where it stopped instead of starting over.
        Candidates are read `reverify_batch` at a time. The stored copies of a block this
        validator already fetched are compared with the Tangle content it kept in memory;
        only a difference (or a block not fetched yet) goes to the node."""
        start = self._pass_after
        found: list[Alert] = []
        checked = 0
        # From after `start` to the end, then from the beginning through `start`.
        phases = [(None, None)] if start is None else [(start, None), (None, start)]
        for after, until in phases:
            while True:
                rows = await self.store.reverify_candidates(after, self.cfg.reverify_batch)
                for row in rows:
                    bid = bytes(row["block_id"])
                    if until is not None and bid > until:
                        return PassResult(checked, found, True)
                    try:
                        alert = await self._reverify_row(row)
                    except HornetUnavailable as e:
                        log.warning("re-verification pass stopped after %d blocks: %s",
                                    checked, e)
                        return PassResult(checked, found, False, str(e)[:200])
                    self._pass_after = after = bid
                    checked += 1
                    if alert is not None:
                        found.append(alert)
                if len(rows) < self.cfg.reverify_batch:
                    break
        return PassResult(checked, found, True)

    async def scheduled_reverify(self) -> PassResult:
        """`reverify_pass`, with its outcome published as the `reverify` service status."""
        try:
            result = await self.reverify_pass()
        except Exception as e:
            await self._status("error", f"{type(e).__name__}: {e}"[:500])
            raise
        at = _iso(self._now_ms())
        if result.complete:
            await self._status("ok", f"last pass at {at}: {result.checked} blocks, "
                                     f"{len(result.alerts)} new DB_TAMPER")
        else:
            await self._status("retrying (node unavailable)",
                               f"pass at {at} stopped after {result.checked} blocks: "
                               f"{result.error}")
        return result

    async def _status(self, status: str, detail: str) -> None:
        try:
            await self.store.set_service_status("reverify", status, detail=detail)
        except Exception as e:  # noqa: BLE001 - the database may be what is down
            log.debug("could not record reverify status %r: %s", status, e)

    async def _reverify_row(self, row: dict) -> Alert | None:
        if row["outcome"] in ALERTED_OUTCOMES and row["outcome_alerted"]:
            if not row["has_message"]:
                return None  # the validator's own alert covers the submission copy
            row = {**row, "has_submission": False}  # ... but not the indexed message copy
        bid = bytes(row["block_id"])
        copy = self._tangle.get(bid)
        if copy is not None and _matches_copy(row, copy):
            return None  # every stored copy still equals what the node served
        async with self._block_lock(bid):
            return await self._reverify_block(bid, row)

    def _remember(self, bid: bytes, payload: TaggedData) -> None:
        if self.cfg.tangle_cache_size <= 0:
            return
        if bid not in self._tangle and len(self._tangle) >= self.cfg.tangle_cache_size:
            del self._tangle[next(iter(self._tangle))]  # oldest first
        try:
            tag: str | None = payload.tag.decode("utf-8")
        except UnicodeDecodeError:
            tag = None
        self._tangle[bid] = _TangleCopy(tag, blake2b256(payload.data))

    async def _reverify_block(self, bid: bytes, row: dict) -> Alert | None:
        if self.is_in_flight(bid):
            return None  # its validation is running; judge it on a later pass
        verified = row["verified_once"]
        if not verified:
            meta = await self.hornet.block_metadata(bid)
            if meta is None or _referenced_index(meta) is None:
                return None  # not confirmed on the Tangle: nothing to hold the copies to
        raw = await self.hornet.block_raw(bid)
        if raw is None:
            log.info("block %s is no longer served by the node (pruned?)", _hex(bid))
            return None
        if compute_block_id(raw) != bid:
            log.warning("node returned another block for %s; not judging the database",
                        _hex(bid))
            return None
        try:
            payload = parse_block(raw).payload
        except DecodeError:
            return None
        if not isinstance(payload, TaggedData):
            return None
        self._remember(bid, payload)
        if verified and not _has_stored_content(row):
            reason = "content removed"
            fields = [{"field": "content", "expected": _hex(payload.data), "actual": None}]
        else:
            reason = "stored copy differs from the Tangle"
            fields = _stored_differences(row, payload)
        if not fields:
            return None
        at = self._now_ms()
        stored = blake2b256(_canon({f["field"]: f["actual"] for f in fields})).hex()
        evidence = {"subId": row["sub_id"], "via": BLOCK_VIA, "reference": "tangle",
                    "reason": reason, "fields": fields}
        alert = Alert("DB_TAMPER", "critical", bid, None, evidence, at,
                      dedupe_key=f"{bid.hex()}:{stored}")
        run = _Run(bid, row["sub_id"])
        for r in await self.store.lifecycle(bid):
            run.note(r["status"])
        detail = {"cause": "DB_TAMPER", "reason": reason, "via": BLOCK_VIA,
                  "fields": [f["field"] for f in fields]}
        new = await self._conclude(
            run, "CONTENT_MISMATCH", at, detail, alert=alert,
            check=("MISMATCH", {"cause": "DB_TAMPER", "reason": reason, "fields": fields}))
        return alert if new else None


def _has_stored_content(row: dict) -> bool:
    """Whether any stored copy of the block's content is left: a submission or message row
    with a non-NULL tag or data."""
    sub = row["has_submission"] and (row["sub_tag"] is not None or row["data_hex"] is not None)
    msg = row["has_message"] and (row["msg_tag"] is not None or row["msg_data"] is not None)
    return bool(sub or msg)


def _matches_copy(row: dict, copy: _TangleCopy) -> bool:
    """True when `_stored_differences` would find nothing and no verified content is gone,
    decided from the kept digest alone. Anything else goes to the node for evidence."""
    if row["verified_once"] and not _has_stored_content(row):
        return False

    def same(tag: str | None, data: bytes | None) -> bool:
        if copy.tag is not None and tag != copy.tag:
            return False
        return data is not None and blake2b256(data) == copy.data_digest

    if row["has_submission"]:
        try:
            sub = from_hex(row["data_hex"]) if row["data_hex"] is not None else None
        except ValueError:
            return False
        if not same(row["sub_tag"], sub):
            return False
    if row["has_message"]:
        msg = None if row["msg_data"] is None else bytes(row["msg_data"])
        if not same(row["msg_tag"], msg):
            return False
    return True


def _stored_differences(row: dict, payload: TaggedData) -> list[dict]:
    """Compare every stored copy of a block's content with the Tangle. `expected` is the
    Tangle value, `actual` the value found in the database; a copy NULLed on an existing row
    is a difference too."""
    out: list[dict] = []
    try:
        tangle_tag: str | None = payload.tag.decode("utf-8")
    except UnicodeDecodeError:
        tangle_tag = None

    def text(name: str, stored: str | None) -> None:
        if tangle_tag is not None and stored != tangle_tag:
            out.append({"field": name, "expected": tangle_tag, "actual": stored})

    def data(name: str, stored: bytes | None, shown: Any) -> None:
        if stored != payload.data:
            out.append({"field": name, "expected": _hex(payload.data), "actual": shown})

    if row["has_submission"]:
        text("submissions.tag", row["sub_tag"])
        try:
            sub_data = from_hex(row["data_hex"]) if row["data_hex"] is not None else None
        except ValueError:
            sub_data = None
        data("submissions.data_hex", sub_data, row["data_hex"])
    if row["has_message"]:
        text("messages.tag", row["msg_tag"])
        msg_data = None if row["msg_data"] is None else bytes(row["msg_data"])
        data("messages.data", msg_data, None if msg_data is None else _hex(msg_data))
    return out


def _alert_event(a: Alert) -> dict:
    return {"rule": a.rule, "severity": a.severity,
            "blockId": None if a.block_id is None else _hex(a.block_id), "ieId": a.ie_id,
            "ts": a.ts, "dedupeKey": a.dedupe_key}
