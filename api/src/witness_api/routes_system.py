"""Health and statistics."""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from . import __version__
from . import models as m
from .deps import Svc

log = logging.getLogger(__name__)
router = APIRouter(tags=["system"])


def node_route_status(svc: Svc) -> m.NodeRouteStatus:
    node = svc.node
    if node is None:
        return m.NodeRouteStatus(enabled=False)
    hornet = svc.settings.hornet_url
    url = f"{hornet.rstrip('/')}/api/{node.route}" if hornet else None
    return m.NodeRouteStatus(enabled=True, route=node.route, registered=node.registered,
                             error=node.error, url=url)


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
            description="Row counts per table, the indexer cursor (last milestone indexed), "
                        "validation backlog, node mount and open streams.")
async def stats(svc: Svc) -> m.Stats:
    counts = {k: int(v) for k, v in (await svc.store.stats()).items()}
    validator = m.ValidatorStatus(configured=svc.validator is not None,
                                  running=svc.validating,
                                  pending=svc.validator.pending if svc.validator else 0)
    return m.Stats(counts=counts, validator=validator, node_route=node_route_status(svc),
                   stream_subscribers=svc.hub.subscribers)
