"""Signed audit reports: build one and post its hash to the Tangle (`POST /reports`,
bearer token), list them (`GET /reports`), and fetch the JSON (`GET /reports/{hash}`) or the
self-contained HTML page (`GET /reports/{hash}.html`).

`POST /reports` writes to the Tangle, so it requires WITNESS_REPORT_TOKEN (403 when the
server sets none, 401 when the bearer is wrong). The signing key is loaded from
WITNESS_REPORT_SIGNER_KEY and is never logged or returned.
"""

from __future__ import annotations

import hmac
import logging
import time
from typing import Annotated

from fastapi import APIRouter, Body, Depends, HTTPException, Path
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import models as m
from . import reports
from .deps import Svc
from .views import hx, iso

log = logging.getLogger(__name__)
router = APIRouter(tags=["reports"])
bearer = HTTPBearer(auto_error=False, scheme_name="reportToken",
                    description="The value of WITNESS_REPORT_TOKEN")

HASH_PATTERN = r"^0x[0-9a-f]{64}$"
HASH_EXAMPLE = "0x" + "cd" * 32
HashPath = Annotated[str, Path(pattern=HASH_PATTERN, examples=[HASH_EXAMPLE],
                               description="Report hash: 0x + 64 lowercase hex digits")]


def _authorize(svc: Svc, creds: HTTPAuthorizationCredentials | None) -> None:
    token = svc.settings.report_token
    if token is None:
        raise HTTPException(403, "report writing is disabled (WITNESS_REPORT_TOKEN is not set)")
    if creds is None or not hmac.compare_digest(creds.credentials.encode(), token.encode()):
        raise HTTPException(401, "a valid bearer token is required",
                            headers={"WWW-Authenticate": "Bearer"})


def _links(svc: Svc, report_hash: str) -> dict[str, str]:
    return {"self": svc.link(f"/reports/{report_hash}"),
            "html": svc.link(f"/reports/{report_hash}.html")}


@router.post(
    "/reports", response_model=m.ReportResult, status_code=201,
    summary="Build a report and anchor its hash",
    description=(
        "Build an audit report over the stored data (optionally limited to one IE and a "
        "milestone range), store its JSON and a rendered HTML page, and post the report hash "
        "to the Tangle as an `audit.report` message through the relay, signed with a "
        "component DID key. The response carries the report hash, the block id and the full "
        "report JSON (its canonical form hashes to that id). Requires WITNESS_REPORT_TOKEN."),
    responses={201: {"description": "Report built and anchored"},
               401: {"description": "Missing or wrong bearer token"},
               403: {"description": "Report writing disabled (token unset)"},
               502: {"description": "The relay refused the report or was unreachable"},
               503: {"description": "Report signing or the relay is not configured"}},
)
async def create_report(
    svc: Svc,
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    req: Annotated[m.ReportRequest, Body(default_factory=m.ReportRequest)],
) -> m.ReportResult:
    _authorize(svc, creds)
    s = svc.settings
    if not s.report_signer_key or not s.relay_url:
        raise HTTPException(503, "report anchoring is not configured (set "
                                 "WITNESS_REPORT_SIGNER_KEY and WITNESS_RELAY_URL)")
    try:
        signer = reports.load_signer(s.report_signer_key)
    except (OSError, ValueError) as e:
        log.error("report signer key could not be loaded: %s", e)
        raise HTTPException(503, "report signing key is unavailable") from None
    if req.ms_from is not None and req.ms_to is not None and req.ms_from > req.ms_to:
        raise HTTPException(400, "msFrom is after msTo")

    report = await reports.build(svc.store, network=s.network, ie=req.ie, frm=req.ms_from,
                                 to=req.ms_to)
    rhash = reports.report_hash(report)
    rhash_hex = "0x" + rhash.hex()
    html = reports.render_html(report, rhash_hex)
    now = int(time.time() * 1000)
    await svc.store.put_report(report_hash=rhash, ie=req.ie, ms_from=req.ms_from,
                               ms_to=req.ms_to, json=report, html=html, block_id=None,
                               generated_at_ms=report["generatedAt"], created_at_ms=now)
    block_id = None
    try:
        block_id = await reports.post_report(
            svc.http, relay_url=s.relay_url, node=s.report_relay_node, signer=signer,
            body=reports.report_body(rhash_hex, report))
    except reports.RelayError as e:
        raise HTTPException(502, f"could not anchor the report: {e}") from None
    await svc.store.set_report_block(rhash, bytes.fromhex(block_id[2:]))
    return m.ReportResult(report_hash=rhash_hex, block_id=block_id,
                          links=_links(svc, rhash_hex), report=report)


@router.get(
    "/reports", response_model=m.ReportList, summary="List audit reports",
    description="Reports newest first, by the time they were generated.")
async def list_reports(svc: Svc) -> m.ReportList:
    rows = await svc.store.list_reports(limit=200)
    return m.ReportList(items=[_summary(svc, r) for r in rows])


# The `.html` route is declared before the JSON one so a `…64hex.html` path matches it
# rather than being captured whole by `{report_hash}` and rejected as a bad hash.
@router.get(
    "/reports/{report_hash}.html", response_class=HTMLResponse, summary="Report HTML page",
    description="A self-contained HTML page for the report (no external assets); it shows "
                "the report hash.",
    responses={404: {"description": "Unknown report"}})
async def get_report_html(report_hash: HashPath, svc: Svc) -> HTMLResponse:
    row = await svc.store.get_report(bytes.fromhex(report_hash[2:]))
    if row is None:
        raise HTTPException(404, "no such report")
    return HTMLResponse(row["html"])


@router.get(
    "/reports/{report_hash}", summary="Report JSON",
    description="The report's canonical JSON. Its BLAKE2b-256 (RFC 8785 form) equals the "
                "report hash and the `reportHash` in the on-chain `audit.report` message.",
    responses={404: {"description": "Unknown report"}})
async def get_report(report_hash: HashPath, svc: Svc) -> dict:
    row = await svc.store.get_report(bytes.fromhex(report_hash[2:]))
    if row is None:
        raise HTTPException(404, "no such report")
    return row["json"]


def _summary(svc: Svc, row: dict) -> m.ReportSummary:
    rhash = hx(row["report_hash"])
    return m.ReportSummary(
        report_hash=rhash, ie=row["ie"], ms_from=row["ms_from"], ms_to=row["ms_to"],
        block_id=hx(row["block_id"]), generated_at_ms=row["generated_at_ms"],
        generated_at=iso(row["generated_at_ms"]), links=_links(svc, rhash))
