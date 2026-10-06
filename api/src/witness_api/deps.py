"""Shared request plumbing: the services a route needs, and input parsing that the
declarative validation cannot express (dates, JSON bodies)."""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta
from typing import TYPE_CHECKING, Annotated, Any

import httpx
from fastapi import Depends, HTTPException, Path, Request
from witness_core.policy import WriterPolicy

from .settings import Settings
from .store import ExplorerStore
from .views import Linker

if TYPE_CHECKING:
    from witness_indexer.validator import Validator

    from .node_mount import NodeRoute
    from .routes_stream import EventHub

BLOCK_ID_PATTERN = r"^0x[0-9a-fA-F]{64}$"
BLOCK_ID_EXAMPLE = "0x972a878cf06f2cf6b7d4a1443dbb5f12fdda376fa7537a82dad8e7257a477967"
MAX_BODY = 256 * 1024
_MS = re.compile(r"\d{1,16}")


@dataclass
class Services:
    settings: Settings
    store: ExplorerStore
    http: httpx.AsyncClient
    link: Linker
    hub: EventHub
    hornet: Any = None
    validator: Validator | None = None
    validator_task: asyncio.Task | None = None
    node: NodeRoute | None = None
    policy: WriterPolicy | None = None
    background: list[asyncio.Task] = field(default_factory=list)

    @property
    def validating(self) -> bool:
        return self.validator_task is not None and not self.validator_task.done()


def services(request: Request) -> Services:
    return request.app.state.services


Svc = Annotated[Services, Depends(services)]

BlockIdPath = Annotated[str, Path(pattern=BLOCK_ID_PATTERN, examples=[BLOCK_ID_EXAMPLE],
                                  description="Message (block) id: 0x + 64 hex digits")]


def block_bytes(block_id: str) -> bytes:
    return bytes.fromhex(block_id[2:])


def parse_when(value: str | None, name: str, *, end: bool = False) -> int | None:
    """ISO 8601 date/datetime or epoch milliseconds -> epoch ms. A datetime without an offset
    is UTC; a bare date means the start of that day (or its last millisecond when `end`)."""
    if value is None:
        return None
    v = value.strip()
    if _MS.fullmatch(v):
        return int(v)
    try:
        if len(v) == 10:
            d = date.fromisoformat(v)
            moment = datetime.combine(d, time.min, UTC)
            if end:
                moment += timedelta(days=1, milliseconds=-1)
        else:
            moment = datetime.fromisoformat(v)
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=UTC)
    except ValueError:
        raise HTTPException(422, f"{name}: expected ISO 8601 (e.g. 2026-10-06 or "
                                 f"2026-10-06T10:46:19Z) or epoch milliseconds") from None
    delta = moment - datetime(1970, 1, 1, tzinfo=UTC)
    return delta // timedelta(milliseconds=1)


async def read_json(request: Request, *, max_bytes: int = MAX_BODY) -> Any:
    """The request body as JSON, refusing oversize bodies (413) and invalid JSON (400)."""
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > max_bytes:
        raise HTTPException(413, f"body larger than {max_bytes} bytes")
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > max_bytes:
            raise HTTPException(413, f"body larger than {max_bytes} bytes")
    try:
        return json.loads(body)
    except (ValueError, RecursionError):
        raise HTTPException(400, "body is not valid JSON") from None
