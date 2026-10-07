"""Stored messages: search, detail, lifecycle with the brief's checks, on-demand
re-verification, and lookups by content (canonical JSON) or by blind index token."""

from __future__ import annotations

import hmac
import math
import time
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from witness_core import canon, envelope
from witness_indexer.store import MessageFilter
from witness_indexer.validator import NoUsableContent

from . import models as m
from . import views
from .deps import BLOCK_ID_EXAMPLE, BLOCK_ID_PATTERN, BlockIdPath, Svc, block_bytes, parse_when
from .deps import read_json as read_json_body
from .nodecheck import stored_result, verify_now

router = APIRouter(tags=["messages"])
lookups = APIRouter(tags=["lookup"])
verify_bearer = HTTPBearer(auto_error=False, scheme_name="verifyToken",
                           description="WITNESS_VERIFY_TOKEN, when the server sets one")

CONTENT_CHECKS_SHOWN = 50

JSONPATH_PATTERN = r"^[A-Za-z0-9_\-]{1,64}(\.[A-Za-z0-9_\-]{1,64}){0,7}=.{0,200}$"
DATE_DOC = ("ISO 8601 date or date-time (`2026-10-06`, `2026-10-06T10:46:19Z`, offsets "
            "allowed; no offset means UTC) or epoch milliseconds (11-16 digits). Inclusive, to "
            "the millisecond: `date_to=2026-10-06T10:46:19Z` ends at 10:46:19.000, so write "
            "`…19.999Z` to include that whole second. A bare date in `date_to` covers that "
            "whole day.")


@router.get(
    "/messages", response_model=m.MessagePage, summary="Search stored messages",
    description=(
        "Every tagged-data message the explorer stores, newest first (blocks still waiting "
        "for a milestone come first). The brief's criteria are `block_id`, `date_from`/"
        "`date_to` and `tag`; they combine with the others. A message's date is when the "
        "Messages API received it, else when a milestone confirmed it. Pages are cut with "
        "the opaque `cursor` returned as `nextCursor`."),
    responses={400: {"description": "Invalid cursor"}},
)
async def list_messages(
    svc: Svc,
    block_id: Annotated[str | None, Query(pattern=BLOCK_ID_PATTERN, description=(
        "Message (block) identifier"), examples=[BLOCK_ID_EXAMPLE])] = None,
    tag: Annotated[str | None, Query(max_length=255, description="Exact tag",
                                     examples=["trust.score"])] = None,
    date_from: Annotated[str | None, Query(max_length=40, description=DATE_DOC,
                                           examples=["2026-10-06T10:00:00Z"])] = None,
    date_to: Annotated[str | None, Query(max_length=40, description=DATE_DOC,
                                         examples=["2026-10-06"])] = None,
    iss: Annotated[str | None, Query(max_length=256, description="Issuer DID")] = None,
    verdict: Annotated[m.Verdict | None, Query()] = None,
    kind: Annotated[str | None, Query(max_length=64, examples=["trust.score"])] = None,
    ie: Annotated[str | None, Query(max_length=256, description="Infrastructure Element id",
                                    examples=["MyDomain:fa163e5e25ef"])] = None,
    ms_from: Annotated[int | None, Query(ge=0, le=0xFFFFFFFF,
                                         description="First milestone index")] = None,
    ms_to: Annotated[int | None, Query(ge=0, le=0xFFFFFFFF,
                                       description="Last milestone index")] = None,
    q: Annotated[str | None, Query(max_length=200, description="Full-text search in the "
                                   "JSON body")] = None,
    jsonpath: Annotated[str | None, Query(pattern=JSONPATH_PATTERN, description=(
        "`path=value`: the JSON body's value at the dotted path equals `value`"),
        examples=["event=scale"])] = None,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
) -> m.MessagePage:
    start = parse_when(date_from, "date_from")
    end = parse_when(date_to, "date_to", end=True)
    if start is not None and end is not None and start > end:
        raise HTTPException(400, "date_from is after date_to")
    path_eq = None
    if jsonpath is not None:
        path, _, value = jsonpath.partition("=")
        path_eq = (path, value)
    f = MessageFilter(tag=tag, ie=ie, iss=iss, verdict=verdict, kind=kind,
                      block_id=block_bytes(block_id) if block_id else None,
                      ms_from=ms_from, ms_to=ms_to, date_from_ms=start, date_to_ms=end, q=q,
                      jsonpath_eq=path_eq)
    try:
        rows, nxt = await svc.store.query_messages(f, cursor, limit)
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    return m.MessagePage(items=[views.message(r, svc.link) for r in rows], next_cursor=nxt,
                         limit=limit)


async def _status(svc: Svc, bid: bytes, message: dict | None) -> str | None:
    if message is not None and message["status"] is not None:
        return message["status"]
    history = await svc.store.lifecycle(bid)
    return history[-1]["status"] if history else None


async def _latest_checks(svc: Svc, bid: bytes) -> m.Checks:
    return views.checks(await svc.store.latest_validation(bid),
                        await svc.store.latest_content_check(bid))


@router.get(
    "/messages/{block_id}", response_model=m.MessageDetail, summary="One stored message",
    description=(
        "The message with its exact bytes, the submission record the Messages API "
        "forwarded, and the brief's checks: (c) valid and solid according to "
        "`GET /api/core/v2/blocks/{id}/metadata`, (d) content equal to "
        "`GET /api/core/v2/blocks/{id}`. A block known only from the Messages API (not yet "
        "confirmed by a milestone) is returned with `indexed: false`."),
    responses={404: {"description": "Unknown block"}},
)
async def get_message(block_id: BlockIdPath, svc: Svc) -> m.MessageDetail:
    bid = block_bytes(block_id)
    row = await svc.store.get_message(bid)
    sub = await svc.store.submission(block_id=bid)
    if row is None and sub is None:
        raise HTTPException(404, f"no message {views.hx(bid)}")
    checks = await _latest_checks(svc, bid)
    status = await _status(svc, bid, row)
    if row is not None:
        base = views.message(row, svc.link).model_dump()
        base["status"] = status
        return m.MessageDetail(**base, indexed=True, data_hex=views.hx(row["data"]),
                               submission=views.submission(sub), checks=checks)
    hexid = views.hx(bid)
    received = sub["received_at_ms"]
    return m.MessageDetail(
        block_id=hexid, tag=sub["tag"], status=status, received_at_ms=received,
        received_at=views.iso(received), date_ms=received, date=views.iso(received),
        content=views.submitted_message(sub), links=svc.link.message(hexid), indexed=False,
        data_hex=sub["data_hex"], submission=views.submission(sub), checks=checks)


@router.get(
    "/messages/{block_id}/lifecycle", response_model=m.Lifecycle,
    summary="Lifecycle and Tangle checks of a message",
    description=(
        "RECEIVED → SUBMITTED → SOLID → CONFIRMED → CONTENT_VERIFIED | CONTENT_MISMATCH | "
        "NOT_FOUND (or ORPHANED), with the node's metadata answers (check c; every poll is "
        "kept, so they come in pages: the newest `limit` first, older ones with "
        "`cursor=validationsCursor`) and the newest 50 content comparisons (check d). "
        "`checks` always reflects the latest answer of each kind."),
    responses={404: {"description": "Unknown block"}},
)
async def lifecycle(
    block_id: BlockIdPath, svc: Svc,
    cursor: Annotated[str | None, Query(pattern=r"^[0-9]{1,18}$", description=(
        "`validationsCursor` of the previous page"))] = None,
    limit: Annotated[int, Query(ge=1, le=500, description="Validations per page")] = 50,
) -> m.Lifecycle:
    bid = block_bytes(block_id)
    history = await svc.store.lifecycle(bid)
    sub = await svc.store.submission(block_id=bid)
    row = await svc.store.get_message(bid)
    if not history and sub is None and row is None:
        raise HTTPException(404, f"no message {views.hx(bid)}")
    validations, older = await svc.store.validations_page(
        bid, int(cursor) if cursor else None, limit)
    contents = await svc.store.recent_content_checks(bid, CONTENT_CHECKS_SHOWN)
    return m.Lifecycle(
        block_id=views.hx(bid), status=history[-1]["status"] if history else None,
        transitions=[views.transition(r) for r in history],
        validations=[views.validation(r) for r in validations],
        validations_cursor=None if older is None else str(older),
        content_checks=[views.content_check(r) for r in contents],
        checks=await _latest_checks(svc, bid), submission=views.submission(sub))


def _authorize_verify(svc: Svc, creds: HTTPAuthorizationCredentials | None) -> None:
    token = svc.settings.verify_token
    if token is None:
        return
    if creds is None or not hmac.compare_digest(creds.credentials.encode(), token.encode()):
        raise HTTPException(401, "a valid bearer token is required",
                            headers={"WWW-Authenticate": "Bearer"})


@router.post(
    "/messages/{block_id}/verify", response_model=m.VerifyResult,
    summary="Re-run the solid and content checks now",
    description=(
        "Asks the node again: (c) `GET /api/core/v2/blocks/{id}/metadata`, then, once a "
        "milestone references the block, (d) `GET /api/core/v2/blocks/{id}` compared byte "
        "for byte with what was received. Results are stored like the background "
        "validation's; `calls` lists what the node answered during this run. Waits at most "
        "WITNESS_VERIFY_TIMEOUT_S for a block that is not confirmed yet.\n\n"
        "If the node answered about this block less than WITNESS_VERIFY_COOLDOWN_S ago, the "
        "stored checks are returned with `cached: true` and the node is not asked. Only a few "
        "checks run at once (429 with Retry-After beyond that). When the server sets "
        "WITNESS_VERIFY_TOKEN, a bearer token is required."),
    responses={401: {"description": "WITNESS_VERIFY_TOKEN is set and the bearer is wrong"},
               404: {"description": "Unknown block"},
               409: {"description": "No stored copy of the content to compare"},
               429: {"description": "Too many checks running; retry after Retry-After"},
               503: {"description": "No node configured (WITNESS_HORNET_URL)"}},
)
async def verify(
    block_id: BlockIdPath, svc: Svc,
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(verify_bearer)],
) -> m.VerifyResult:
    _authorize_verify(svc, creds)
    bid = block_bytes(block_id)
    if svc.validator is None or svc.verify_slots is None:
        raise HTTPException(503, "no node configured to verify against (WITNESS_HORNET_URL)")
    if await svc.store.submission(block_id=bid) is None and \
            await svc.store.get_message(bid) is None:
        raise HTTPException(404, f"no message {views.hx(bid)}")
    latest = await svc.store.latest_validation(bid)
    cooldown_ms = svc.settings.verify_cooldown_s * 1000
    if latest is not None and time.time() * 1000 - latest["checked_at_ms"] < cooldown_ms:
        return await stored_result(svc.store, bid, latest)
    slots = svc.verify_slots
    if slots.locked():  # no await between this check and acquiring: no race
        raise HTTPException(429, "too many checks running; try again shortly",
                            headers={"Retry-After": str(math.ceil(
                                svc.settings.verify_timeout_s))})
    async with slots:
        try:
            return await verify_now(svc.validator, svc.store, bid,
                                    svc.settings.verify_timeout_s)
        except NoUsableContent as e:
            raise HTTPException(409, str(e)) from None


# -- lookups ----------------------------------------------------------------------------------

LOOKUP_EXAMPLE = {"id": "MyDomain:fa163e5e25ef", "score": 0.91}


@lookups.post(
    "/lookup", response_model=m.LookupResult, summary="Was this exact message stored?",
    description=(
        "Post any JSON document. It is canonicalised (RFC 8785), so key order and whitespace "
        "do not matter, and matched against every stored message body. A posted witness/v1 "
        "envelope is matched by its body as well. Each match links to its proof bundle."),
    openapi_extra={"requestBody": {"required": True, "content": {"application/json": {
        "schema": {"description": "Any JSON value"}, "example": LOOKUP_EXAMPLE}}}},
    responses={400: {"description": "Not JSON, or not canonicalisable"},
               413: {"description": "Body over 256 KiB"}},
)
async def lookup(request: Request, svc: Svc) -> m.LookupResult:
    doc = await read_json_body(request)
    try:
        digest = canon.canon_hash(doc)
        body_digest = None
        if envelope.is_envelope(doc) and isinstance(doc.get("body"), dict):
            body_digest = canon.canon_hash(doc["body"])
    except (ValueError, TypeError, RecursionError) as e:
        raise HTTPException(400, f"JSON cannot be canonicalised: {e}") from None
    rows = await svc.store.lookup_canon(digest)
    if body_digest is not None:
        rows += await svc.store.lookup_canon(body_digest)
    seen: set[bytes] = set()
    matches = []
    for r in rows:
        if bytes(r["block_id"]) not in seen:
            seen.add(bytes(r["block_id"]))
            matches.append(views.message(r, svc.link))
    return m.LookupResult(canon_hash=views.hx(digest), body_canon_hash=views.hx(body_digest),
                          matches=matches)


@lookups.post(
    "/lookup/blind", response_model=m.BlindResult, summary="Find sealed messages by token",
    description=(
        "Encrypted messages carry blind index tokens, `b64u(HMAC-SHA256(K_search, "
        "\"ie:\"+id | \"tag:\"+tag))`. Compute the tokens where the search key lives and "
        "post them; the key itself never reaches the explorer."),
)
async def lookup_blind(query: m.BlindQuery, svc: Svc) -> m.BlindResult:
    rows = await svc.store.lookup_blind(query.tokens)
    out = []
    for r in rows:
        bid = views.hx(r["block_id"])
        at = views.sec_to_ms(r["ts"])
        out.append(m.BlindMatch(
            token=r["token"], block_id=bid, tag=r["tag"], kind=r["kind"], ie_id=r["ie_id"],
            iss=r["iss"], verdict=r["verdict"], ms_index=r["ms_index"], milestone_at_ms=at,
            milestone_at=views.iso(at), links=svc.link.message(bid)))
    return m.BlindResult(matches=out)
