"""On-demand re-run of the brief's checks (c) and (d) for one block.

The validator does the work (`Validator.validate_once`, serialised per block with the
background worker). `RecordingHornet` sits between the validator and the node and notes, for
the request that asked, every call made and what came back, so the answer shows the evidence
of this run rather than only what the database held before.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from typing import Any

from witness_indexer.hornet_rest import BLOCKS_PATH, HornetRest, HornetUnavailable
from witness_indexer.validator import OUTCOMES, Validator

from . import models as m
from .store import ExplorerStore
from .views import hx, iso, solid_ok

_CALLS: ContextVar[list[dict] | None] = ContextVar("witness_api_node_calls", default=None)

_CONTENT_RESULT = {"CONTENT_VERIFIED": "MATCH", "CONTENT_MISMATCH": "MISMATCH",
                   "NOT_FOUND": "NOT_FOUND"}


def _now_ms() -> int:
    return int(time.time() * 1000)


class RecordingHornet:
    """A HornetRest that records each call into the current request's call list, if any."""

    def __init__(self, inner: HornetRest) -> None:
        self.inner = inner

    async def close(self) -> None:
        await self.inner.close()

    async def block(self, block_id: bytes) -> dict | None:
        return await self._call("", block_id, self.inner.block)

    async def block_raw(self, block_id: bytes) -> bytes | None:
        return await self._call("", block_id, self.inner.block_raw, raw=True)

    async def block_metadata(self, block_id: bytes) -> dict | None:
        return await self._call("/metadata", block_id, self.inner.block_metadata)

    async def _call(self, suffix: str, block_id: bytes,
                    fn: Callable[[bytes], Awaitable[Any]], raw: bool = False) -> Any:
        calls = _CALLS.get()
        if calls is None:
            return await fn(block_id)
        entry: dict[str, Any] = {"request": f"GET {BLOCKS_PATH}/{hx(block_id)}{suffix}",
                                 "at_ms": _now_ms(), "outcome": "unavailable",
                                 "error": "interrupted before the node answered"}
        started = time.monotonic()
        try:
            result = await fn(block_id)
        except HornetUnavailable as e:
            # The node's address is deployment detail; the request path already says what
            # was asked.
            entry.update(http_status=e.status,
                         error=str(e).replace(self.inner.base_url, "").strip())
            raise
        finally:
            entry["duration_ms"] = int((time.monotonic() - started) * 1000)
            calls.append(entry)
        entry["error"] = None
        if result is None:
            entry.update(outcome="not_found", http_status=404)
        else:
            entry.update(outcome="answered", http_status=200)
            if raw:
                entry["size"] = len(result)
            else:
                entry["body"] = result
        return result


def _solid(calls: list[dict]) -> m.SolidCheck:
    meta = [c for c in calls if c["request"].endswith("/metadata")]
    if not meta:
        return m.SolidCheck(detail="the node was not asked")
    last = meta[-1]
    at = {"checked_at_ms": last["at_ms"], "checked_at": iso(last["at_ms"])}
    if last["outcome"] == "unavailable":
        return m.SolidCheck(detail=f"node unavailable: {last.get('error')}", **at)
    if last["outcome"] == "not_found":
        return m.SolidCheck(ok=False, detail="the node does not know this block", **at)
    body = last["body"]
    ms = body.get("referencedByMilestoneIndex")
    ms = ms if type(ms) is int else None
    state = body.get("ledgerInclusionState")
    state = state if isinstance(state, str) else None
    solid = body.get("isSolid") is True
    detail = None if ms is not None else "solid, not yet referenced by a milestone" if solid \
        else "not solid yet"
    return m.SolidCheck(ok=solid_ok(solid, state), is_solid=solid,
                        referenced_by_milestone_index=ms, ledger_inclusion_state=state,
                        detail=detail, **at)


def _content(calls: list[dict], status: str | None, checks: list[dict]) -> m.ContentCheck:
    raw = [c for c in calls if not c["request"].endswith("/metadata")]
    if not raw:
        return m.ContentCheck(detail="not run: the block is not confirmed by a milestone yet")
    last = raw[-1]
    at = {"checked_at_ms": last["at_ms"], "checked_at": iso(last["at_ms"])}
    if last["outcome"] == "unavailable":
        return m.ContentCheck(detail=f"node unavailable: {last.get('error')}", **at)
    result = _CONTENT_RESULT.get(status or "")
    if result is None:
        return m.ContentCheck(detail="no outcome", **at)
    diff = checks[-1]["diff"] if checks and checks[-1]["result"] == result else None
    return m.ContentCheck(ok=result == "MATCH", result=result, diff=diff, **at)


async def verify_now(validator: Validator, store: ExplorerStore, block_id: bytes,
                     timeout_s: float) -> m.VerifyResult:
    """Run (c) and (d) now; gives up waiting after `timeout_s` (the worker carries on)."""
    calls: list[dict] = []
    token = _CALLS.set(calls)
    started = _now_ms()
    timed_out = False
    try:
        status = await asyncio.wait_for(validator.validate_once(block_id, None), timeout_s)
    except TimeoutError:
        timed_out = True
        history = await store.lifecycle(block_id)
        status = history[-1]["status"] if history else None
    finally:
        _CALLS.reset(token)
    finished = _now_ms()
    content_rows = await store.content_checks(block_id)
    return m.VerifyResult(
        block_id=hx(block_id), status=status, concluded=status in OUTCOMES,
        timed_out=timed_out, started_at_ms=started, started_at=iso(started),
        finished_at_ms=finished, finished_at=iso(finished),
        checks=m.Checks(solid=_solid(calls), content=_content(calls, status, content_rows)),
        calls=[m.NodeCall(**{k: v for k, v in c.items() if k != "body"}, at=iso(c["at_ms"]))
               for c in calls],
    )
