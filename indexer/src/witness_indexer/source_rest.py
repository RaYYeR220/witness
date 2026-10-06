"""Milestones and cones over HORNET's core REST API, for nodes whose INX port is not reachable.

Milestones come from `/api/core/v2/milestones/by-index/{i}` as raw bytes; new ones are found
by polling `/api/core/v2/info`. A cone is rebuilt by walking block metadata back from the
milestone's parents: every block whose `referencedByMilestoneIndex` is the milestone belongs
to it, at its `whiteFlagIndex`, and the walk stops at blocks an older milestone referenced.
Only core routes are used, so this works with the debug API disabled.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any, Self

import httpx

from .source import ConeBlock, MilestoneData, SourceError, SourceUnavailable, check_cone

log = logging.getLogger(__name__)

RAW = "application/vnd.iota.serializer-v1"
CORE = "/api/core/v2"


def _hex(b: bytes) -> str:
    return "0x" + b.hex()


class RestSource:
    name = "rest"

    def __init__(self, base_url: str, *, poll_s: float = 1.0, timeout_s: float = 10.0,
                 concurrency: int = 8, client: httpx.AsyncClient | None = None,
                 sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep) -> None:
        self.base_url = base_url.rstrip("/")
        self.poll_s = poll_s
        self._http = client or httpx.AsyncClient(base_url=self.base_url, timeout=timeout_s)
        self._own_client = client is None
        self._slots = asyncio.Semaphore(concurrency)
        self._sleep = sleep
        self._parents: dict[int, list[bytes]] = {}

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def close(self) -> None:
        if self._own_client:
            await self._http.aclose()

    # -- HTTP -------------------------------------------------------------------------------

    async def _get(self, path: str, *, raw: bool = False) -> httpx.Response | None:
        """GET a path; None on 404. Transport errors and 5xx raise SourceUnavailable."""
        headers = {"Accept": RAW} if raw else {"Accept": "application/json"}
        async with self._slots:
            try:
                r = await self._http.get(path, headers=headers)
            except httpx.HTTPError as e:
                raise SourceUnavailable(f"{self.base_url}{path}: {type(e).__name__}: {e}") from e
        if r.status_code == 404:
            return None
        if r.status_code >= 500:
            raise SourceUnavailable(f"{self.base_url}{path}: HTTP {r.status_code}")
        if r.status_code != 200:
            raise SourceError(f"{self.base_url}{path}: HTTP {r.status_code}")
        return r

    async def _json(self, path: str) -> dict | None:
        r = await self._get(path)
        if r is None:
            return None
        try:
            body = r.json()
        except ValueError as e:
            raise SourceError(f"{self.base_url}{path}: response is not JSON") from e
        if not isinstance(body, dict):
            raise SourceError(f"{self.base_url}{path}: response is not a JSON object")
        return body

    async def info(self) -> tuple[int, int]:
        """(confirmed milestone index, pruning index) of the node."""
        body = await self._json(f"{CORE}/info")
        try:
            status = body["status"]  # type: ignore[index]
            return int(status["confirmedMilestone"]["index"]), int(status.get("pruningIndex", 0))
        except (TypeError, KeyError, ValueError) as e:
            raise SourceError(f"{self.base_url}: unexpected /info response") from e

    async def connect(self) -> None:
        """Raise SourceUnavailable unless the node answers."""
        await self.info()

    async def milestone(self, index: int) -> MilestoneData | None:
        r = await self._get(f"{CORE}/milestones/by-index/{index}", raw=True)
        if r is None:
            return None
        m = MilestoneData.from_payload(r.content)
        if m.index != index:
            raise SourceError(f"asked for milestone {index}, node returned {m.index}")
        self._parents[index] = m.parents
        while len(self._parents) > 16:
            self._parents.pop(next(iter(self._parents)))
        return m

    # -- BlockSource ------------------------------------------------------------------------

    async def milestones(self, start: int) -> AsyncIterator[MilestoneData]:
        index = max(start, 1)
        while True:
            confirmed, pruning = await self.info()
            if index <= pruning:
                log.warning("milestones up to %d are pruned on %s; starting at %d",
                            pruning, self.base_url, pruning + 1)
                index = pruning + 1
            while index <= confirmed:
                m = await self.milestone(index)
                if m is None:
                    log.warning("milestone %d is gone from %s (pruned?); skipping it",
                                index, self.base_url)
                else:
                    yield m
                index += 1
            await self._sleep(self.poll_s)

    async def cone(self, index: int) -> AsyncIterator[ConeBlock]:
        parents = self._parents.pop(index, None)
        if parents is None:
            m = await self.milestone(index)
            if m is None:
                raise SourceError(f"milestone {index} not found on {self.base_url}")
            parents = self._parents.pop(index)

        positions: dict[bytes, int] = {}
        seen: set[bytes] = set()
        frontier = list(dict.fromkeys(parents))
        while frontier:
            seen.update(frontier)
            metas = await asyncio.gather(
                *(self._json(f"{CORE}/blocks/{_hex(b)}/metadata") for b in frontier))
            nxt: list[bytes] = []
            for bid, md in zip(frontier, metas, strict=True):
                # Unknown to the node (pruned, genesis) or confirmed earlier: outside the cone.
                if md is None or md.get("referencedByMilestoneIndex") != index:
                    continue
                try:
                    positions[bid] = int(md["whiteFlagIndex"])
                    nxt.extend(bytes.fromhex(p[2:]) for p in md.get("parents", []))
                except (KeyError, TypeError, ValueError) as e:
                    raise SourceError(f"bad metadata for block {_hex(bid)}") from e
            frontier = [b for b in dict.fromkeys(nxt) if b not in seen]

        raws = await asyncio.gather(
            *(self._get(f"{CORE}/blocks/{_hex(b)}", raw=True) for b in positions))
        blocks = []
        for (bid, wf), r in zip(positions.items(), raws, strict=True):
            if r is None:
                raise SourceError(f"block {_hex(bid)} of milestone {index} not found")
            blocks.append(ConeBlock(bid, r.content, wf))
        for b in check_cone(index, blocks):
            yield b
