"""Integrity alerts raised by the rules and the validator, and the incidents (correlated
trust events on a timeline) they belong to."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, Query

from . import models as m
from . import views
from .deps import BLOCK_ID_PATTERN, Svc, block_bytes, parse_when

router = APIRouter(tags=["integrity"])

SINCE_DOC = "Only items at or after this moment: ISO 8601 or epoch milliseconds"


@router.get("/alerts", response_model=m.AlertList, summary="Integrity alerts",
            description="Alerts newest first: FORGED, REPLAY, DRIFT, CONTENT_MISMATCH, "
                        "DB_TAMPER, ORPHANED, SHADOW, ANCHOR_MISMATCH, …")
async def alerts(
    svc: Svc,
    rule: Annotated[str | None, Query(max_length=64, examples=["FORGED"])] = None,
    severity: Annotated[str | None, Query(max_length=16, examples=["critical"])] = None,
    ie: Annotated[str | None, Query(max_length=256)] = None,
    block_id: Annotated[str | None, Query(pattern=BLOCK_ID_PATTERN)] = None,
    since: Annotated[str | None, Query(max_length=40, description=SINCE_DOC)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> m.AlertList:
    f = {"rule": rule, "severity": severity, "ie_id": ie,
         "block_id": block_bytes(block_id) if block_id else None,
         "since": parse_when(since, "since")}
    rows = await svc.store.alerts(f, limit)
    return m.AlertList(items=[views.alert(r) for r in rows])


@router.get("/incidents", response_model=m.IncidentList, summary="Incidents",
            description="Correlated trust events (a security trigger and what followed), "
                        "newest first.")
async def incidents(
    svc: Svc,
    status: Annotated[str | None, Query(max_length=32, examples=["open"])] = None,
    severity: Annotated[str | None, Query(max_length=16)] = None,
    ie: Annotated[str | None, Query(max_length=256)] = None,
    since: Annotated[str | None, Query(max_length=40, description=SINCE_DOC)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> m.IncidentList:
    f = {"status": status, "severity": severity, "ie_id": ie,
         "since": parse_when(since, "since")}
    rows = await svc.store.incidents(f, limit)
    return m.IncidentList(items=[m.Incident(**views.incident(r)) for r in rows])


@router.get("/incidents/{incident_id}", response_model=m.IncidentDetail,
            summary="One incident with its timeline",
            description="Each event with its verdict, lifecycle status and proof link, in "
                        "time order.",
            responses={404: {"description": "Unknown incident"}})
async def incident(
    incident_id: Annotated[int, Path(ge=1, le=2**63 - 1)], svc: Svc,
) -> m.IncidentDetail:
    row = await svc.store.incident(incident_id)
    if row is None:
        raise HTTPException(404, f"no incident {incident_id}")
    events = []
    for e in row["events"]:
        bid = bytes(e["block_id"])
        msg = await svc.store.get_message(bid)
        hexid = views.hx(bid)
        item = views.message(msg, svc.link) if msg is not None else None
        events.append(m.IncidentEvent(
            block_id=hexid, role=e["role"], tag=item and item.tag, kind=item and item.kind,
            verdict=item and item.verdict, status=item and item.status,
            ms_index=item and item.ms_index, date_ms=item and item.date_ms,
            date=item and item.date, links=svc.link.message(hexid)))
    return m.IncidentDetail(**views.incident(row), events=events)
