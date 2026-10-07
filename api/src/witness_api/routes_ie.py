"""Infrastructure Elements: the trust-score lineage the ledger holds for each one, next to
what the aeriOS context broker (Orion-LD) currently says."""

from __future__ import annotations

import math
from typing import Annotated, Any
from urllib.parse import quote

import httpx
from fastapi import APIRouter, HTTPException, Path, Query
from witness_core import verdicts
from witness_indexer.incidents import DISTRUST_RULES

from . import models as m
from . import views
from .deps import Svc

router = APIRouter(tags=["ie"])

IE_URN = "urn:ngsi-ld:InfrastructureElement:"
ENTITIES = "/ngsi-ld/v1/entities/"
IePath = Annotated[str, Path(min_length=1, max_length=256, pattern=r"^[^/\s]+$",
                             examples=["MyDomain:fa163e5e25ef"])]


@router.get("/ie", response_model=m.IeList, summary="Infrastructure Elements with scores",
            description="Every IE that has messages on the ledger, most recently active first.")
async def ie_list(svc: Svc) -> m.IeList:
    heads = await svc.store.score_heads()
    items = []
    for r in await svc.store.ie_list():
        first, last = views.sec_to_ms(r["first_ts"]), views.sec_to_ms(r["last_ts"])
        head = heads.get(r["ie_id"])
        items.append(m.IeSummary(
            ie_id=r["ie_id"], count=r["count"], first_at_ms=first, first_at=views.iso(first),
            last_at_ms=last, last_at=views.iso(last), last_ms_index=r["last_ms_index"],
            latest_score=head["score"] if head else None))
    return m.IeList(items=items)


def _score_value(attr: Any) -> float | None:
    """`trustScore` in normalized (`{"type": "Property", "value": x}`) or keyValues form."""
    value = attr.get("value") if isinstance(attr, dict) else attr
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    value = float(value)
    return value if math.isfinite(value) else None


async def orion_state(svc: Svc, ie_id: str) -> m.OrionState:
    """The IE's current `trustScore` in Orion: one GET, `upstream_timeout_s` at most."""
    entity = ie_id if ie_id.startswith(IE_URN) else IE_URN + ie_id
    base = svc.settings.orion_url
    if not base:
        return m.OrionState(status="not_configured", entity_id=entity)
    headers = {"Accept": "application/json"}
    if svc.settings.orion_context:
        headers["Link"] = (f'<{svc.settings.orion_context}>; '
                           f'rel="http://www.w3.org/ns/json-ld#context"; '
                           f'type="application/ld+json"')
    url = base.rstrip("/") + ENTITIES + quote(entity, safe=":")
    try:
        resp = await svc.http.get(url, headers=headers, timeout=svc.settings.upstream_timeout_s)
    except httpx.HTTPError:
        return m.OrionState(status="unreachable", entity_id=entity)
    if resp.status_code == 404:
        return m.OrionState(status="unknown_entity", entity_id=entity)
    if resp.status_code != 200:
        return m.OrionState(status="unreachable", entity_id=entity)
    try:
        body = resp.json()
    except ValueError:
        return m.OrionState(status="unreachable", entity_id=entity)
    value = _score_value(body.get("trustScore")) if isinstance(body, dict) else None
    if value is None:
        return m.OrionState(status="no_score", entity_id=entity)
    return m.OrionState(status="ok", value=value, entity_id=entity)


@router.get(
    "/ie/{ie_id}/lineage", response_model=m.Lineage, summary="Score lineage vs Orion",
    description=(
        "Every ledger message about the IE in milestone order with its score, the latest "
        "score the ledger vouches for (a proven one: PRODUCER_SIGNED, with no UNSIGNED or "
        "SHADOW alert on its block), Orion's current `trustScore` and whether they drift "
        "apart by more than `epsilon`. When Orion cannot be asked, `drift` is null."),
    responses={404: {"description": "No ledger messages about this IE"}},
)
async def lineage(
    ie_id: IePath, svc: Svc,
    limit: Annotated[int, Query(ge=1, le=10_000, description="Newest entries returned")] = 1000,
) -> m.Lineage:
    rows = await svc.store.ie_lineage(ie_id)
    if not rows:
        raise HTTPException(404, f"no ledger messages about {ie_id}")
    scores = {bytes(r["block_id"]): r["score"] for r in await svc.store.score_history(ie_id)}
    entries = []
    for r in rows:
        bid = views.hx(r["block_id"])
        at = views.sec_to_ms(r["ts"])
        entries.append(m.LineageEntry(
            block_id=bid, prev=views.hx(r["prev"]), seq=r["seq"], kind=r["kind"],
            verdict=r["verdict"], ms_index=r["ms_index"], wf_index=r["wf_index"], at_ms=at,
            at=views.iso(at), score=scores.get(bytes(r["block_id"])),
            links=svc.link.message(bid)))
    # Only a proven score is what the ledger vouches for: producer-signed (the pipeline gives
    # an unauthorised writer its own verdict) and not taken out of evidence by an UNSIGNED or
    # SHADOW alert, as the incident engine judges it. Drift is measured against that one.
    distrusted = await svc.store.blocks_with_alert(
        [bytes(r["block_id"]) for r in rows if bytes(r["block_id"]) in scores], DISTRUST_RULES)
    ledger = None
    for e, r in zip(reversed(entries), reversed(rows)):
        if (e.score is not None and e.verdict == verdicts.PRODUCER_SIGNED
                and bytes(r["block_id"]) not in distrusted):
            ledger = m.LedgerScore(score=e.score, block_id=e.block_id, verdict=e.verdict,
                                   ms_index=e.ms_index, at_ms=e.at_ms, at=e.at)
            break
    orion = await orion_state(svc, ie_id)
    drift = None
    if orion.status == "ok" and orion.value is not None and ledger is not None:
        drift = abs(orion.value - ledger.score) > svc.settings.drift_epsilon
    return m.Lineage(ie_id=ie_id, entries=entries[-limit:], total=len(entries), ledger=ledger,
                     orion=orion, drift=drift, epsilon=svc.settings.drift_epsilon)
