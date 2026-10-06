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
EVENTS_CURSOR = r"^-?[0-9]{1,19}:[0-9a-f]{64}$"


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
            description="Each event with its role, verdict, lifecycle status and proof "
                        "link, in time order, and the alerts that joined it; at most "
                        "`limit` of each, with cursors for the next pages.",
            responses={404: {"description": "Unknown incident"}})
async def incident(
    incident_id: Annotated[int, Path(ge=1, le=2**63 - 1)], svc: Svc,
    limit: Annotated[int, Query(ge=1, le=500, description="Events and alerts per page")] = 500,
    events_after: Annotated[str | None, Query(
        alias="eventsAfter", pattern=EVENTS_CURSOR,
        description="`nextEventsCursor` of the previous page")] = None,
    alerts_after: Annotated[int | None, Query(
        alias="alertsAfter", ge=0, le=2**63 - 1,
        description="`nextAlertsAfter` of the previous page")] = None,
) -> m.IncidentDetail:
    row = await svc.store.incident_header(incident_id)
    if row is None:
        raise HTTPException(404, f"no incident {incident_id}")
    after = None
    if events_after is not None:
        ms, bid = events_after.split(":")
        after = (int(ms), bytes.fromhex(bid))
    rows = await svc.store.incident_timeline(incident_id, after=after, limit=limit + 1)
    alert_rows = await svc.store.incident_alerts(incident_id, after_id=alerts_after,
                                                 limit=limit + 1)
    counts = await svc.store.incident_counts(incident_id)
    next_events = None
    if len(rows) > limit:
        rows = rows[:limit]
        next_events = f"{rows[-1]['sort_ms']}:{bytes(rows[-1]['block_id']).hex()}"
    next_alerts = None
    if len(alert_rows) > limit:
        alert_rows = alert_rows[:limit]
        next_alerts = alert_rows[-1]["id"]
    return m.IncidentDetail(
        **views.incident(row), events=[views.incident_event(e, svc.link) for e in rows],
        events_total=counts["events"], next_events_cursor=next_events,
        alerts=[views.alert(a) for a in alert_rows], alerts_total=counts["alerts"],
        next_alerts_after=next_alerts)
