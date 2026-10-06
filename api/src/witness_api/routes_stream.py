"""`GET /stream`: the explorer's event log as Server-Sent Events.

Events are read from the `events` table in id order, so a client that reconnects with
`Last-Event-ID` gets exactly what it missed: no gap, no duplicate. One shared LISTEN
connection (`EventHub`) wakes every open stream when an event is written; a slow poll covers
the moments that connection is being re-established.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException, Query, Request
from sse_starlette.event import ServerSentEvent
from sse_starlette.sse import EventSourceResponse
from witness_indexer import events

from .deps import Svc
from .store import ExplorerStore
from .views import iso

log = logging.getLogger(__name__)
router = APIRouter(tags=["stream"])

PAGE = 200
EVENT_TYPES = (events.MESSAGE, events.MILESTONE, events.ALERT, events.ANCHOR, events.POSTURE,
               events.SUBMISSION, events.LIFECYCLE, events.INCIDENT)


class EventHub:
    """Fans PostgreSQL NOTIFY out to the open streams of this process."""

    def __init__(self, store: ExplorerStore, *, retry_max_s: float = 30.0) -> None:
        self.store = store
        self.retry_max_s = retry_max_s
        self._waiters: set[asyncio.Event] = set()
        self._task: asyncio.Task | None = None

    @property
    def subscribers(self) -> int:
        return len(self._waiters)

    def subscribe(self) -> asyncio.Event:
        ev = asyncio.Event()
        self._waiters.add(ev)
        return ev

    def unsubscribe(self, ev: asyncio.Event) -> None:
        self._waiters.discard(ev)

    def _wake(self) -> None:
        for ev in self._waiters:
            ev.set()

    async def run(self) -> None:
        delay = 1.0
        while True:
            try:
                async for _ in self.store.listen():
                    delay = 1.0
                    self._wake()
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001 - keep streaming via polling meanwhile
                log.warning("event listener lost its connection (%s); retrying in %.0f s", e,
                            delay)
            self._wake()
            await asyncio.sleep(delay)
            delay = min(delay * 2, self.retry_max_s)

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self.run(), name="event-hub")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        self._wake()


def _sse(row: dict) -> ServerSentEvent:
    data = {"id": row["id"], "type": row["type"], "atMs": row["ts"], "at": iso(row["ts"]),
            "payload": row["payload"]}
    return ServerSentEvent(data=json.dumps(data, separators=(",", ":")), event=row["type"],
                           id=str(row["id"]))


async def tail(store: ExplorerStore, hub: EventHub, after: int, *, types: set[str] | None,
               limit: int | None, poll_s: float) -> AsyncIterator[ServerSentEvent]:
    """Every event with id > `after`, then each new one as it is written."""
    wake = hub.subscribe()
    sent = 0
    try:
        while True:
            wake.clear()  # before reading, so a NOTIFY during the read is not lost
            rows = await store.events_after(after, PAGE)
            for row in rows:
                after = row["id"]
                if types is not None and row["type"] not in types:
                    continue
                yield _sse(row)
                sent += 1
                if limit is not None and sent >= limit:
                    return
            if len(rows) == PAGE:
                continue
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(wake.wait(), poll_s)
    finally:
        hub.unsubscribe(wake)


@router.get(
    "/stream", summary="Live event stream (SSE)",
    response_class=EventSourceResponse,
    description=(
        "Server-Sent Events for `message`, `milestone`, `alert`, `anchor`, `submission`, "
        "`lifecycle` and `incident` events. Each event carries its id; reconnect with the "
        "`Last-Event-ID` header (browsers do this automatically) or `?after=<id>` to resume "
        "without gaps or duplicates. Without either, the stream starts at the newest event. "
        "A comment line is sent every 15 s as a heartbeat."),
    responses={200: {"content": {"text/event-stream": {"example": (
        'id: 42\nevent: alert\ndata: {"id":42,"type":"alert","atMs":1791283579000,'
        '"at":"2026-10-06T10:46:19.000Z","payload":{"rule":"FORGED"}}\n\n')}}},
        400: {"description": "Last-Event-ID is not an event id"}},
)
async def stream(
    request: Request, svc: Svc,
    last_event_id: Annotated[str | None, Header(alias="Last-Event-ID")] = None,
    after: Annotated[int | None, Query(ge=0, description="Resume after this event id")] = None,
    types: Annotated[str | None, Query(
        description="Comma-separated event types to deliver: " + ", ".join(EVENT_TYPES),
        examples=["alert,anchor"], max_length=200)] = None,
    limit: Annotated[int | None, Query(
        ge=1, le=10_000, description="Close the stream after this many events")] = None,
) -> EventSourceResponse:
    start = after
    if last_event_id is not None:
        if not last_event_id.strip().isdigit():
            raise HTTPException(400, "Last-Event-ID must be an event id")
        start = int(last_event_id.strip())
    wanted = None
    if types:
        wanted = {t.strip() for t in types.split(",") if t.strip()}
        unknown = wanted - set(EVENT_TYPES)
        if unknown:
            raise HTTPException(422, f"unknown event types: {', '.join(sorted(unknown))}")
    if start is None:
        start = await svc.store.head_event_id()
    gen = tail(svc.store, svc.hub, start, types=wanted, limit=limit,
               poll_s=svc.settings.stream_poll_s)
    return EventSourceResponse(gen, ping=svc.settings.stream_ping_s,
                               headers={"Cache-Control": "no-store",
                                        "X-Accel-Buffering": "no"})
