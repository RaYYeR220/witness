"""Background passes beside the indexer, each outside any milestone transaction.

`Every` repeats a coroutine on an interval (the rules' periodic pass, the Tangle re-scan).
`Rescanner` reads back the cones of milestones the indexer already stored, straight from the
node, and hands their tagged-data block ids to `RulesEngine.rescan`, which raises
MISSING_IN_DB for any the database no longer holds.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable, Iterable
from typing import Any, Protocol

from witness_core import codec

from .source import BlockSource
from .store import Alert, Store

log = logging.getLogger(__name__)


def _now_ms() -> int:
    return int(time.time() * 1000)


class Every:
    """Call `fn()` every `interval_s` seconds (first after `initial_delay_s`) until `stop()`.
    A failing call is logged and the next one still happens."""

    def __init__(self, name: str, interval_s: float, fn: Callable[[], Awaitable[Any]], *,
                 initial_delay_s: float = 0.0) -> None:
        self.name = name
        self.interval_s = interval_s
        self.initial_delay_s = initial_delay_s
        self.fn = fn
        self.runs = 0
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None

    async def _pause(self, seconds: float) -> None:
        try:
            await asyncio.wait_for(self._stop.wait(), seconds)
        except TimeoutError:
            pass

    async def run(self) -> None:
        self._task = asyncio.current_task()
        await self._pause(self.initial_delay_s)
        while not self._stop.is_set():
            try:
                await self.fn()
            except Exception:
                log.exception("%s pass failed", self.name)
            self.runs += 1
            await self._pause(self.interval_s)

    async def stop(self, grace_s: float = 10.0) -> None:
        """Let a pass in progress finish (up to `grace_s`), then end the loop."""
        self._stop.set()
        task = self._task
        if task is None or task is asyncio.current_task() or task.done():
            return
        done, _ = await asyncio.wait({task}, timeout=grace_s)
        if not done:
            log.warning("%s pass still running after %g s; cancelling it", self.name, grace_s)
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


class Rescannable(Protocol):
    async def rescan(self, confirmed_block_ids: Iterable[bytes], *,
                     now_ms: int | None = None) -> list[Alert]: ...


class Rescanner:
    """Each `run_once` re-reads up to `batch` already indexed milestones from the node,
    rotating through 1..cursor, and reports their tagged-data block ids to the rules."""

    def __init__(self, source: BlockSource, store: Store, rules: Rescannable, *,
                 batch: int = 200, now_ms: Callable[[], int] = _now_ms) -> None:
        self.source = source
        self.store = store
        self.rules = rules
        self.batch = batch
        self._now_ms = now_ms
        self.next_index = 1

    async def run_once(self) -> list[Alert]:
        cursor = await self.store.get_cursor()
        if cursor < 1:
            return []
        start = self.next_index if self.next_index <= cursor else 1
        end = min(cursor, start + self.batch - 1)
        ids: list[bytes] = []
        unreadable = 0
        for index in range(start, end + 1):
            try:
                cone = [b async for b in self.source.cone(index)]
            except Exception as e:  # noqa: BLE001 - pruned on the node, or the node is away
                unreadable += 1
                log.debug("re-scan: cone of milestone %d unavailable: %s", index, e)
                continue
            for b in cone:
                try:
                    payload = codec.parse_block(b.raw).payload
                except codec.DecodeError:
                    continue
                if isinstance(payload, codec.TaggedData):
                    ids.append(b.block_id)
        self.next_index = end + 1
        if unreadable:
            log.info("re-scan of milestones %d..%d: %d cone(s) not readable from %s",
                     start, end, unreadable, self.source.name)
        return await self.rules.rescan(ids, now_ms=self._now_ms())
