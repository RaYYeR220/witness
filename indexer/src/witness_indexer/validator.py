"""Tangle validation of forwarded submissions: the brief's checks (c) and (d).

For every submission that got a block id the validator walks the lifecycle

    RECEIVED -> SUBMITTED -> SOLID -> CONFIRMED -> CONTENT_VERIFIED | CONTENT_MISMATCH | NOT_FOUND

(c) polls HORNET `GET /api/core/v2/blocks/{id}/metadata` with exponential backoff until the
block is referenced by a milestone, or gives up after `timeout_s` (ORPHANED). Every metadata
answer is kept in `validations`.

(d) then fetches the original block with `GET /api/core/v2/blocks/{id}` as raw bytes and
compares it with what the explorer received: the BLAKE2b-256 of the bytes must be the block
id (a node serving another block for an id is a mismatch too), the payload must be tagged
data, and tag and data must be byte-for-byte what the Messages API sent. Each comparison is
kept in `content_checks`; a mismatch carries a field diff and a canonical-JSON diff for the UI.

`reverify_all` repeats (d) later for verified messages, against the copies held in the
parallel database. If those no longer match the Tangle, the database was altered: DB_TAMPER.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

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
MAX_JSON_CHANGES = 200
_PLAIN_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass(frozen=True)
class ValidatorConfig:
    initial_backoff_s: float = 0.5
    max_backoff_s: float = 8.0
    timeout_s: float = 60.0
    reverify_batch: int = 200
    max_concurrent: int = 32


def _hex(b: bytes) -> str:
    return "0x" + b.hex()


def _now_ms() -> int:
    return int(time.time() * 1000)


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
        e, a = json.loads(expected), json.loads(actual)
        changes: list[dict] = []
        _walk("$", e, a, changes)
    except (ValueError, RecursionError):
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


class _Unavailable:
    pass


_UNAVAILABLE = _Unavailable()


def _referenced_index(meta: dict) -> int | None:
    ms = meta.get("referencedByMilestoneIndex")
    return ms if type(ms) is int else None


class Validator:
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
        self._workers: set[asyncio.Task] = set()
        self._task: asyncio.Task | None = None
        self._stopping = False

    # -- worker ----------------------------------------------------------------------------

    @property
    def pending(self) -> int:
        """Blocks queued or being validated."""
        return len(self._pending)

    def enqueue(self, block_id: bytes | None, sub_id: str) -> None:
        """Queue a submission for validation. A failed submit (no block id) has nothing on the
        Tangle to check and is not queued; a block already queued is not queued twice."""
        if block_id is None:
            log.debug("submission %s has no block id; not validated", sub_id)
            return
        if block_id in self._pending:
            return
        self._pending.add(block_id)
        self._queue.put_nowait((block_id, sub_id))

    async def resume(self, limit: int = 10_000) -> int:
        """Queue submissions whose validation was cut short (e.g. by a restart); returns how
        many were queued. Call once before `run`."""
        rows = await self.store.unfinished_submissions(limit)
        for row in rows:
            self.enqueue(bytes(row["block_id"]), row["sub_id"])
        return len(rows)

    async def run(self) -> None:
        """Validate queued blocks, up to `max_concurrent` at a time, until stopped."""
        self._task = asyncio.current_task()
        slots = asyncio.Semaphore(self.cfg.max_concurrent)
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
            for task in list(self._workers):
                task.cancel()
            await asyncio.gather(*self._workers, return_exceptions=True)

    async def _work(self, block_id: bytes, sub_id: str, slots: asyncio.Semaphore) -> None:
        try:
            await self.validate_once(block_id, sub_id)
        except Exception:
            log.exception("validation of block %s failed", _hex(block_id))
        finally:
            slots.release()
            self._pending.discard(block_id)

    async def stop(self) -> None:
        self._stopping = True
        task = self._task
        if task is not None and task is not asyncio.current_task() and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    # -- one validation --------------------------------------------------------------------

    async def validate_once(self, block_id: bytes | None, sub_id: str | None) -> str:
        """Run checks (c) and (d) for one block and return its final lifecycle status.

        A submission without a block id stays RECEIVED and nothing is asked of the node.
        Returns CONFIRMED when the node stayed unreachable for the content fetch, so the
        content check is still owed.
        """
        if block_id is None:
            return "RECEIVED"
        expected = await self._expected(block_id, sub_id)
        run = _Run(block_id, expected.sub_id)
        for row in await self.store.lifecycle(block_id):
            run.note(row["status"])
        if not await self._await_confirmation(run):
            return "ORPHANED"
        return await self._check_content(run, expected)

    async def _expected(self, block_id: bytes, sub_id: str | None) -> _Expected:
        sub = await self.store.submission(sub_id=sub_id) if sub_id else None
        if sub is None or sub["block_id"] != block_id:
            sub = await self.store.submission(block_id=block_id)
        if sub is not None and sub["tag"] is not None and sub["data_hex"] is not None:
            return _Expected(sub["tag"].encode("utf-8"), from_hex(sub["data_hex"]),
                             sub["sub_id"])
        msg = await self.store.get_message(block_id)
        if msg is not None and msg["tag"] is not None and msg["data"] is not None:
            return _Expected(msg["tag"].encode("utf-8"), bytes(msg["data"]), sub_id)
        raise LookupError(f"no received content stored for block {_hex(block_id)}")

    async def _await_confirmation(self, run: _Run) -> bool:
        """Check (c): poll metadata until referenced by a milestone (True) or timed out."""
        cfg = self.cfg
        deadline = self._clock() + cfg.timeout_s
        backoff = cfg.initial_backoff_s
        polls, last, last_error = 0, None, None
        while True:
            polls += 1
            try:
                meta = await self.hornet.block_metadata(run.block_id)
            except HornetUnavailable as e:
                meta, last_error = None, str(e)
            if meta is not None:
                last = meta
                await self._record_metadata(run, meta)
                if _referenced_index(meta) is not None:
                    return True
            remaining = deadline - self._clock()
            if remaining <= 0:
                await self._orphan(run, polls, last, last_error)
                return False
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

    async def _orphan(self, run: _Run, polls: int, last: dict | None,
                      last_error: str | None) -> None:
        at = self._now_ms()
        evidence = {"subId": run.sub_id, "via": METADATA_VIA, "timeoutS": self.cfg.timeout_s,
                    "polls": polls, "lastMetadata": last, "lastError": last_error}
        detail = {"via": METADATA_VIA, "timeoutS": self.cfg.timeout_s, "polls": polls,
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
            return "CONFIRMED"
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
        """Write one outcome atomically; returns whether the alert was new."""
        write = run.should_write(status)
        async with self.store.transaction():
            if check is not None:
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
        """Re-fetch verified blocks and compare them with the content stored for them.

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
            rows = await self.store.verified_content(after, size)
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

    async def _reverify_row(self, row: dict) -> Alert | None:
        bid = bytes(row["block_id"])
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
        fields = _stored_differences(row, payload)
        if not fields:
            return None
        at = self._now_ms()
        stored = blake2b256(_canon({f["field"]: f["actual"] for f in fields})).hex()
        evidence = {"subId": row["sub_id"], "via": BLOCK_VIA, "reference": "tangle",
                    "fields": fields}
        alert = Alert("DB_TAMPER", "critical", bid, None, evidence, at,
                      dedupe_key=f"{bid.hex()}:{stored}")
        run = _Run(bid, row["sub_id"], {"CONTENT_VERIFIED"}, "CONTENT_VERIFIED")
        detail = {"cause": "DB_TAMPER", "via": BLOCK_VIA, "fields": [f["field"] for f in fields]}
        new = await self._conclude(run, "CONTENT_MISMATCH", at, detail,
                                   check=("MISMATCH", {"cause": "DB_TAMPER", "fields": fields}),
                                   alert=alert)
        return alert if new else None


def _stored_differences(row: dict, payload: TaggedData) -> list[dict]:
    """Compare every stored copy of a block's content with the Tangle. `expected` is the
    Tangle value, `actual` the value found in the database."""
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

    text("submissions.tag", row["sub_tag"])
    try:
        sub_data = from_hex(row["data_hex"]) if row["data_hex"] is not None else None
    except ValueError:
        sub_data = None
    data("submissions.data_hex", sub_data, row["data_hex"])
    if row["has_message"]:
        if row["msg_tag"] is not None:
            text("messages.tag", row["msg_tag"])
        if row["msg_data"] is not None:
            msg_data = bytes(row["msg_data"])
            data("messages.data", msg_data, _hex(msg_data))
    return out


def _alert_event(a: Alert) -> dict:
    return {"rule": a.rule, "severity": a.severity,
            "blockId": None if a.block_id is None else _hex(a.block_id), "ieId": a.ie_id,
            "ts": a.ts, "dedupeKey": a.dedupe_key}
