"""Signed audit reports: build one and post its hash to the Tangle (`POST /reports`,
bearer token), list them (`GET /reports`), and fetch one with its anchoring state
(`GET /reports/{hash}`) or as a self-contained HTML page (`GET /reports/{hash}.html`).

`POST /reports` writes to the Tangle, so it requires WITNESS_REPORT_TOKEN (403 when the
server sets none, 401 when the bearer is wrong). The signing key is loaded from
WITNESS_REPORT_SIGNER_KEY and is never logged or returned.

Anchoring happens in two phases: the report is stored as not anchored, then marked anchored
with its block id once the relay accepts the `audit.report` message, so a failed post never
leaves a report that looks anchored. Posts are serialised and each claims the envelope
sequence number max(now, last claimed + 1); the signer DID must therefore belong to reports
alone, written by one API instance.
"""

from __future__ import annotations

import base64
import hmac
import json
import logging
from typing import Annotated

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from witness_core import nesting

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

# The report page is static: no scripts, no external resources, inline styles only.
HTML_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
                               "base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
}


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


def _summary_fields(svc: Svc, row: dict) -> dict:
    rhash = hx(row["report_hash"])
    return {
        "report_hash": rhash, "anchored": bool(row["anchored"]), "block_id": hx(row["block_id"]),
        "ie": row["ie"], "ms_from": row["ms_from"], "ms_to": row["ms_to"], "iss": row["iss"],
        "seq": row["seq"], "generated_at_ms": row["generated_at_ms"],
        "generated_at": iso(row["generated_at_ms"]), "anchored_at_ms": row["anchored_at_ms"],
        "anchored_at": iso(row["anchored_at_ms"]), "links": _links(svc, rhash)}


def _result(svc: Svc, row: dict) -> m.ReportResult:
    return m.ReportResult(**_summary_fields(svc, row), report=row["json"])


@router.post(
    "/reports", response_model=m.ReportResult, status_code=201,
    summary="Build a report and anchor its hash",
    description=(
        "Build an audit report over the stored data (optionally limited to one IE and a "
        "milestone range), store its JSON and a rendered HTML page, and post the report hash "
        "to the Tangle as a producer-signed `audit.report` message through the witness-relay. "
        "The report is stored first with `anchored: false` and marked anchored with its "
        "`blockId` only once the relay accepts it; if the post fails the report stays stored "
        "with `anchored: false`. A report identical to a stored one (same hash) is not stored "
        "twice: it is returned (200) when already anchored, else its anchoring is retried. "
        "Posts run one at a time and each claims the envelope sequence number "
        "max(now in ms, last claimed + 1), so the signer DID must not be shared with other "
        "producers. The relay must identify itself as a witness-relay on `GET /healthz`. "
        "Requires WITNESS_REPORT_TOKEN."),
    responses={200: {"model": m.ReportResult, "description": "Already anchored"},
               201: {"description": "Report built and anchored"},
               400: {"description": "msFrom is after msTo"},
               401: {"description": "Missing or wrong bearer token"},
               403: {"description": "Report writing disabled (token unset)"},
               502: {"description": "The relay refused the report, is degraded or is "
                                    "unreachable; the report stays stored, not anchored"},
               503: {"description": "Signing or relay not configured, or the relay URL is "
                                    "not a witness-relay"}},
)
async def create_report(
    svc: Svc,
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    req: Annotated[m.ReportRequest, Body(default_factory=m.ReportRequest)],
) -> m.ReportResult | JSONResponse:
    _authorize(svc, creds)
    s = svc.settings
    if not s.report_signer_key or not s.relay_url:
        raise HTTPException(503, "report anchoring is not configured (set "
                                 "WITNESS_REPORT_SIGNER_KEY and WITNESS_RELAY_URL)")
    try:
        signer = reports.load_signer(s.report_signer_key)
    except (OSError, ValueError) as e:
        log.error("report signer key could not be loaded: %s", type(e).__name__)
        raise HTTPException(503, "report signing key is unavailable") from None
    if req.ms_from is not None and req.ms_to is not None and req.ms_from > req.ms_to:
        raise HTTPException(400, "msFrom is after msTo")
    iss = signer[0]

    async with svc.report_lock:
        try:
            await reports.check_relay(svc.http, s.relay_url)
        except reports.NotWitnessRelay:
            raise HTTPException(503, "relay is not a witness relay") from None
        except reports.RelayError as e:
            raise HTTPException(502, f"could not anchor the report: {e}") from None

        report = await reports.build(svc.store, network=s.network, ie=req.ie,
                                     frm=req.ms_from, to=req.ms_to)
        rhash = reports.report_hash(report)
        rhash_hex = "0x" + rhash.hex()
        now = reports.now_ms()
        await svc.store.insert_report(
            report_hash=rhash, ie=req.ie, ms_from=req.ms_from, ms_to=req.ms_to, json=report,
            html=reports.render_html(report, rhash_hex, anchored=False),
            generated_at_ms=report["generatedAt"], created_at_ms=now)
        row = await svc.store.get_report(rhash)
        if row["anchored"]:
            return JSONResponse(_result(svc, row).model_dump(by_alias=True), status_code=200)

        last = await svc.store.last_report_seq(iss)
        seq = max(reports.now_ms(), (last or 0) + 1)
        await svc.store.claim_report_seq(rhash, iss, seq)
        try:
            block_id = await reports.post_report(
                svc.http, relay_url=s.relay_url, node=s.report_relay_node, signer=signer,
                body=reports.report_body(rhash_hex, row["json"]), seq=seq)
        except reports.RelayError as e:
            raise HTTPException(502, f"could not anchor the report: {e}") from None
        html = reports.render_html(row["json"], rhash_hex, anchored=True, block_id=block_id,
                                   signer=iss)
        await svc.store.mark_report_anchored(rhash, bytes.fromhex(block_id[2:]), html,
                                             reports.now_ms())
        return _result(svc, await svc.store.get_report(rhash))


def _encode_cursor(row: dict) -> str:
    raw = json.dumps([row["generated_at_ms"], bytes(row["report_hash"]).hex()]).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _decode_cursor(cursor: str) -> tuple[int, bytes]:
    try:
        gen, h = nesting.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
        digest = bytes.fromhex(h)
        if not isinstance(gen, int) or len(digest) != 32:
            raise ValueError
        return gen, digest
    except (ValueError, TypeError):
        raise HTTPException(400, "invalid cursor") from None


@router.get(
    "/reports", response_model=m.ReportList, summary="List audit reports",
    description="Reports newest first, by the time they were generated, with whether each "
                "one is anchored. Pages are cut with the opaque `cursor` returned as "
                "`nextCursor`.",
    responses={400: {"description": "Invalid cursor"}})
async def list_reports(
    svc: Svc,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    cursor: Annotated[str | None, Query(max_length=256)] = None,
) -> m.ReportList:
    before = _decode_cursor(cursor) if cursor else None
    rows = await svc.store.list_reports(limit + 1, before)
    nxt = _encode_cursor(rows[limit - 1]) if len(rows) > limit else None
    return m.ReportList(items=[m.ReportSummary(**_summary_fields(svc, r)) for r in rows[:limit]],
                        next_cursor=nxt, limit=limit)


# The `.html` route is declared before the JSON one so a `…64hex.html` path matches it
# rather than being captured whole by `{report_hash}` and rejected as a bad hash.
@router.get(
    "/reports/{report_hash}.html", response_class=HTMLResponse, summary="Report HTML page",
    description="A self-contained HTML page for the report (no scripts, no external "
                "resources). It shows the report hash and whether it is anchored.",
    responses={404: {"description": "Unknown report"}})
async def get_report_html(report_hash: HashPath, svc: Svc) -> HTMLResponse:
    row = await svc.store.get_report(bytes.fromhex(report_hash[2:]))
    if row is None:
        raise HTTPException(404, "no such report")
    return HTMLResponse(row["html"], headers=HTML_HEADERS)


@router.get(
    "/reports/{report_hash}", response_model=m.ReportResult, summary="One report",
    description="The report with its anchoring state. `report` is the report JSON: its "
                "BLAKE2b-256 (RFC 8785 form) equals `reportHash` and the `reportHash` in the "
                "on-chain `audit.report` message at `blockId`.",
    responses={404: {"description": "Unknown report"}})
async def get_report(report_hash: HashPath, svc: Svc) -> m.ReportResult:
    row = await svc.store.get_report(bytes.fromhex(report_hash[2:]))
    if row is None:
        raise HTTPException(404, "no such report")
    return _result(svc, row)
