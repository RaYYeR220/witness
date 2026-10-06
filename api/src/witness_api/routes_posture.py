"""Node security posture: the last scan (`GET /posture`) and running a new one
(`POST /posture/scan`, bearer token). Findings are constructive — each names a fix.

Scanning reads the node this API is configured against (`WITNESS_HORNET_URL`, INX and an
optional dashboard). Active probes (a harmless invalid `POST` to a protected route, a
dashboard default-credentials login) run only with `?active=true` and only against a
loopback or allow-listed host; passive scans never POST or attempt a login.
"""

from __future__ import annotations

import hmac
import logging
import time
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import models as m
from . import posture
from .deps import Svc
from .views import iso

log = logging.getLogger(__name__)
router = APIRouter(tags=["posture"])
bearer = HTTPBearer(auto_error=False, scheme_name="postureToken",
                    description="The value of WITNESS_POSTURE_TOKEN")


def _authorize(svc: Svc, creds: HTTPAuthorizationCredentials | None) -> None:
    token = svc.settings.posture_token
    if token is None:
        raise HTTPException(403, "posture scanning is disabled (WITNESS_POSTURE_TOKEN is "
                                 "not set)")
    if creds is None or not hmac.compare_digest(creds.credentials.encode(), token.encode()):
        raise HTTPException(401, "a valid bearer token is required",
                            headers={"WWW-Authenticate": "Bearer"})


def _posture_model(findings: list[posture.Finding], scanned_at_ms: int,
                   active: bool) -> m.Posture:
    summary: dict[str, int] = {}
    for f in findings:
        summary[f.severity] = summary.get(f.severity, 0) + 1
    return m.Posture(
        scanned_at_ms=scanned_at_ms, scanned_at=iso(scanned_at_ms), active=active,
        summary=summary,
        findings=[m.Finding(id=f.id, severity=f.severity, title=f.title, evidence=f.evidence,
                            fix=f.fix) for f in findings])


@router.get(
    "/posture", response_model=m.Posture, summary="Last node posture scan",
    description=(
        "The findings from the most recent scan of the node this explorer watches, with the "
        "time it ran. Each finding carries a severity, the evidence observed (no node address "
        "or secret) and a concrete fix. Empty with `scannedAtMs: null` until the first "
        "`POST /posture/scan`."))
async def get_posture(svc: Svc) -> m.Posture:
    cached = svc.posture_cache
    return cached if cached is not None else m.Posture()


@router.post(
    "/posture/scan", response_model=m.Posture, summary="Run a posture scan",
    description=(
        "Scan the node now and cache the result for `GET /posture`. Passive by default: only "
        "`GET`/`HEAD`/`OPTIONS` and a TCP connect to INX. With `active=true` it additionally "
        "sends a harmless invalid `POST` to a protected route (which never prunes anything) "
        "and tries the dashboard's default credentials — but only against a loopback or "
        "allow-listed host, never a third party's node. Requires WITNESS_POSTURE_TOKEN."),
    responses={401: {"description": "Missing or wrong bearer token"},
               403: {"description": "Posture scanning disabled (token unset)"}},
)
async def scan_posture(
    svc: Svc,
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    active: Annotated[bool, Query(description="Allow active probes on loopback/allowed "
                                  "hosts")] = False,
) -> m.Posture:
    _authorize(svc, creds)
    s = svc.settings
    async with svc.posture_lock:
        plaintext = await svc.store.payload_ratio()
        findings = await posture.scan(
            http=svc.http, node_url=s.hornet_url, inx_addr=s.inx_addr,
            dashboard_url=s.posture_dashboard_url, config_keys=s.coordinator_keys,
            plaintext=plaintext, active=active,
            allow_active_hosts=frozenset(s.posture_allow_active_hosts),
            timeout_s=s.posture_timeout_s)
        model = _posture_model(findings, int(time.time() * 1000), active)
        svc.posture_cache = model
        return model
