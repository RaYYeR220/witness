"""The Advanced Explorer's REST API.

`create_app(settings)` wires the routers to one store, the node's REST API (for the brief's
solid/content checks), the anchor service and Orion-LD. Each feature lives in its own router
module; further routers are added with `create_app(settings, routers=[...])` or by
`app.include_router` on the returned app.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager

import httpx
from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from witness_indexer.hornet_rest import HornetRest
from witness_indexer.validator import Validator, ValidatorConfig

from . import (
    __version__,
    routes_alerts,
    routes_anchors,
    routes_flows,
    routes_identity,
    routes_ie,
    routes_ingest,
    routes_messages,
    routes_posture,
    routes_proofs,
    routes_reports,
    routes_stream,
    routes_system,
)
from .deps import Services
from .node_mount import NodeRoute
from .nodecheck import RecordingHornet
from .settings import Settings
from .store import ExplorerStore
from .views import Linker

log = logging.getLogger(__name__)

ROUTERS: tuple[APIRouter, ...] = (
    routes_messages.router, routes_messages.lookups, routes_ingest.router, routes_ie.router,
    routes_proofs.router, routes_flows.router, routes_alerts.router, routes_anchors.router,
    routes_identity.router, routes_posture.router, routes_reports.router,
    routes_stream.router, routes_system.router,
)

TAGS = [
    {"name": "messages", "description": "Search stored messages (by block id, date, tag and "
     "more) and see the brief's checks: (c) solid via the node's block metadata, (d) content "
     "equal to the block on the Tangle."},
    {"name": "lookup", "description": "Was this exact message stored? Canonical JSON and "
     "blind-index lookups."},
    {"name": "ingest", "description": "Submission records forwarded by the Messages API."},
    {"name": "proofs", "description": "Offline-verifiable proof bundles and the verifier's "
     "pinned configuration."},
    {"name": "ie", "description": "Trust-score lineage per Infrastructure Element vs Orion."},
    {"name": "flows", "description": "Related messages by issuer, IE, service or "
     "correlation id."},
    {"name": "integrity", "description": "Alerts and incidents."},
    {"name": "anchors", "description": "Checkpoints anchored on IOTA Rebased."},
    {"name": "identity", "description": "Component DIDs and the writer policy."},
    {"name": "posture", "description": "Node security posture: constructive findings about "
     "the HORNET deployment (sample keys, open admin routes, debug API, dashboard, …)."},
    {"name": "reports", "description": "Signed audit reports whose hash is anchored on the "
     "Tangle as an audit.report message, with JSON and a self-contained HTML page."},
    {"name": "stream", "description": "Live events over Server-Sent Events."},
    {"name": "system", "description": "Health and statistics."},
]

DESCRIPTION = """\
REST API of **Witness — an IOTA Advanced Explorer for Eclipse aeriOS**.

Every message submitted through the aeriOS Messages API is forwarded here, stored in a
parallel PostgreSQL database and checked against the HORNET node: valid and solid
(`GET /api/core/v2/blocks/{id}/metadata`) and carrying exactly the bytes that were
received (`GET /api/core/v2/blocks/{id}`). Stored messages are retrieved with
`GET /messages` by block id, date and tag (and issuer, verdict, IE, full text, …), and
each one has a self-contained proof bundle that verifies offline.

Bytes are lowercase `0x` hex. Timestamps come as epoch milliseconds (`…Ms`) and ISO 8601 UTC.
The same API is mounted on the node at `/api/witness/v1`.
"""


def create_app(settings: Settings, *, store: ExplorerStore | None = None,
               routers: Iterable[APIRouter] = ()) -> FastAPI:
    """Build the API. Pass `store` to share an open store (it is then neither migrated nor
    closed here); otherwise one is opened on `settings.db` at startup and migrated unless
    `settings.migrate` is off."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        own_store = store is None
        st = store if store is not None else await ExplorerStore.open(
            settings.db, schema=settings.schema)
        http = hornet = svc = None
        try:
            if own_store and settings.migrate:
                await st.migrate()
            policy = routes_identity.load_policy(settings.policy_path)
            http = httpx.AsyncClient(timeout=settings.upstream_timeout_s,
                                     headers={"User-Agent": f"witness-api/{__version__}"})
            svc = Services(settings=settings, store=st, http=http,
                           link=Linker(settings.public_base_url),
                           hub=routes_stream.EventHub(st), policy=policy)
            if settings.hornet_url:
                hornet = RecordingHornet(HornetRest(settings.hornet_url))
                svc.hornet = hornet
                # validate_once also locks the block in the database, so on-demand checks
                # here and the indexer's worker never run on one block at the same time.
                svc.validator = Validator(st, hornet, ValidatorConfig())
                svc.verify_slots = asyncio.Semaphore(settings.verify_concurrency)
                if settings.validate:
                    svc.validator_task = asyncio.create_task(svc.validator.run(),
                                                             name="validator")
            svc.hub.start()
            if settings.inx_addr:
                svc.node = NodeRoute(settings.inx_addr, settings.node_route,
                                     settings.route_host, settings.port,
                                     refresh_s=settings.node_refresh_s)
                svc.node.start()
            app.state.services = svc
            yield
        finally:
            if svc is not None:
                if svc.node is not None:
                    await svc.node.stop()
                if svc.validator_task is not None:
                    await svc.validator.stop()
                    with contextlib.suppress(asyncio.CancelledError):
                        await svc.validator_task
                await svc.hub.stop()
            if hornet is not None:
                await hornet.close()
            if http is not None:
                await http.aclose()
            if own_store:
                await st.close()

    app = FastAPI(
        title="Witness — IOTA Advanced Explorer API", version=__version__,
        description=DESCRIPTION, openapi_tags=TAGS, lifespan=lifespan,
        license_info={"name": "Apache-2.0", "identifier": "Apache-2.0"},
        servers=[{"url": settings.public_base_url}] if settings.public_base_url else None,
    )
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=False,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "Last-Event-ID"], max_age=600)
    for router in (*ROUTERS, *routers):
        app.include_router(router)
    return app
