"""Health and statistics."""

from __future__ import annotations

import asyncio
import logging
import time

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from . import __version__
from . import models as m
from .deps import Svc

log = logging.getLogger(__name__)
router = APIRouter(tags=["system"])


def node_route_status(svc: Svc) -> m.NodeRouteStatus:
    """Whether the node proxies the API. No node address and no raw error text: those are
    deployment details and go to the server log."""
    node = svc.node
    if node is None:
        return m.NodeRouteStatus(enabled=False)
    return m.NodeRouteStatus(enabled=True, route=node.route, registered=node.registered,
                             error=node.error)


async def _counts(svc: Svc) -> dict[str, int]:
    """Row counts, cached for `stats_cache_s`: counting every table is not free and status
    pages poll."""
    now = time.monotonic()
    cached = svc.stats_cache
    if cached is not None and now - cached[0] < svc.settings.stats_cache_s:
        return cached[1]
    counts = {k: int(v) for k, v in (await svc.store.stats()).items()}
    svc.stats_cache = (now, counts)
    return counts


@router.get("/healthz", response_model=m.Health, summary="Liveness and database check",
            responses={503: {"model": m.Health, "description": "Database unreachable"}})
async def healthz(svc: Svc) -> m.Health | JSONResponse:
    db = "ok"
    try:
        await asyncio.wait_for(svc.store.db_ping(), 2.0)
    except Exception as e:  # noqa: BLE001 - any failure means the database is not usable
        log.warning("health check: database unreachable: %s", e)
        db = "unreachable"
    health = m.Health(status="ok" if db == "ok" else "degraded", db=db,
                      network=svc.settings.network, version=__version__)
    if db != "ok":
        return JSONResponse(health.model_dump(by_alias=True), status_code=503)
    return health


@router.get("/stats", response_model=m.Stats, summary="Counts and component status",
            description="Row counts per table (refreshed every few seconds), the indexer "
                        "cursor (last milestone indexed), validation backlog, node mount and "
                        "open streams.")
async def stats(svc: Svc) -> m.Stats:
    counts = await _counts(svc)
    validator = m.ValidatorStatus(configured=svc.validator is not None,
                                  running=svc.validating,
                                  pending=svc.validator.pending if svc.validator else 0)
    return m.Stats(counts=counts, validator=validator, node_route=node_route_status(svc),
                   stream_subscribers=svc.hub.subscribers)
