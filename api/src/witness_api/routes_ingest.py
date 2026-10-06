"""`POST /ingest`: the HTTP fallback through which the Messages API forwards every
submission record (MQTT is the primary path). Deduplicated with MQTT by submission id and
block id."""

from __future__ import annotations

import hmac
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from witness_indexer.ingest import handle_record, parse_record

from . import models as m
from .deps import Svc, read_json
from .views import hx

log = logging.getLogger(__name__)
router = APIRouter(tags=["ingest"])
bearer = HTTPBearer(auto_error=False, scheme_name="ingestToken",
                    description="The value of WITNESS_INGEST_TOKEN")

RECORD_EXAMPLE = {
    "subId": "6f1c2a9e-4b1d-4c55-9a35-0d2f4e8b7a10",
    "receivedAtMs": 1791283570000,
    "tag": "trust.score",
    "message": {"score": 0.5, "id": "MyDomain:aabbccddeeff"},
    "dataHex": "0x7b2273636f7265223a20302e352c20226964223a20224d79446f6d61696e3a616162626363"
               "646465656666227d",
    "blockId": "0x972a878cf06f2cf6b7d4a1443dbb5f12fdda376fa7537a82dad8e7257a477967",
    "hornetStatus": 201,
    "relay": {"verdict": "RELAY_ATTESTED", "iss": "did:iota:testnet:0x01", "seq": 42},
}
RECORD_SCHEMA = {
    "type": "object",
    "required": ["subId", "receivedAtMs", "tag", "message", "dataHex", "blockId",
                 "hornetStatus", "relay"],
    "properties": {
        "subId": {"type": "string", "minLength": 1},
        "receivedAtMs": {"type": "integer", "minimum": 0},
        "tag": {"type": "string"},
        "message": {"description": "The message as the Messages API received it"},
        "dataHex": {"type": ["string", "null"], "pattern": "^0x([0-9a-fA-F]{2})*$",
                    "description": "Exact bytes sent to the node"},
        "blockId": {"type": ["string", "null"], "pattern": "^0x[0-9a-fA-F]{64}$",
                    "description": "null when the node did not accept the block"},
        "hornetStatus": {"type": ["integer", "null"]},
        "relay": {"type": "object", "properties": {
            "verdict": {"type": ["string", "null"]}, "iss": {"type": ["string", "null"]},
            "seq": {"type": ["integer", "null"]}}},
    },
}


class _ResumeLater:
    """Stands in for the validator when this process does not run the validation worker:
    the indexer's validator picks unfinished submissions up on its periodic resume."""

    def enqueue(self, block_id: bytes | None, sub_id: str) -> None:
        log.debug("submission %s stored; validation left to the indexer", sub_id)


def _authorize(svc: Svc, creds: HTTPAuthorizationCredentials | None) -> None:
    token = svc.settings.ingest_token
    if token is None:
        raise HTTPException(403, "HTTP ingest is disabled (WITNESS_INGEST_TOKEN is not set)")
    if creds is None or not hmac.compare_digest(creds.credentials.encode(), token.encode()):
        raise HTTPException(401, "a valid bearer token is required",
                            headers={"WWW-Authenticate": "Bearer"})


@router.post(
    "/ingest", status_code=202, response_model=m.IngestResult,
    summary="Forward a submission record (HTTP fallback)",
    description=(
        "Called by the modified Messages API after every upload, with the same record it "
        "publishes to MQTT (`aerios/iota/submissions/{tag}`). A new record is stored, opens "
        "its lifecycle and is queued for the Tangle checks: 202. A record already received "
        "(same `subId`, or the same `blockId` via MQTT): 200 with `duplicate: true`."),
    openapi_extra={"requestBody": {"required": True, "content": {"application/json": {
        "schema": RECORD_SCHEMA, "example": RECORD_EXAMPLE}}}},
    responses={200: {"model": m.IngestResult, "description": "Already received"},
               400: {"description": "Not a submission record"},
               401: {"description": "Missing or wrong bearer token"},
               403: {"description": "HTTP ingest disabled"},
               413: {"description": "Body over 256 KiB"}},
)
async def ingest(
    request: Request, svc: Svc,
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> m.IngestResult | JSONResponse:
    _authorize(svc, creds)
    record = await read_json(request)
    try:
        sub = parse_record(record, source="http")
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    enqueuer = svc.validator if svc.validating else _ResumeLater()
    try:
        new = await handle_record(svc.store, enqueuer, record, source="http")
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    if new:
        return m.IngestResult(accepted=True, duplicate=False, sub_id=sub.sub_id,
                              block_id=hx(sub.block_id),
                              status="SUBMITTED" if sub.block_id else "RECEIVED")
    status = None
    if sub.block_id is not None:
        history = await svc.store.lifecycle(sub.block_id)
        status = history[-1]["status"] if history else None
    body = m.IngestResult(accepted=False, duplicate=True, sub_id=sub.sub_id,
                          block_id=hx(sub.block_id), status=status)
    return JSONResponse(body.model_dump(by_alias=True), status_code=200)
