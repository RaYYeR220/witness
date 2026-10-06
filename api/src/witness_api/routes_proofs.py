"""Proofs: self-contained `witness-proof/v1` bundles (or the inx-poi shape), the pinned
verifier configuration, and milestone ids for the anchor service."""

from __future__ import annotations

import logging
from typing import Annotated, Literal
from urllib.parse import quote

import httpx
from fastapi import APIRouter, HTTPException, Query
from witness_core import bundle

from . import models as m
from . import proofs
from .deps import BlockIdPath, Svc, block_bytes

log = logging.getLogger(__name__)
router = APIRouter(tags=["proofs"])

MAX_MILESTONE_RANGE = 10_000
BUNDLE_EXAMPLE = {
    "v": 1, "network": "private_tangle1",
    "block": {"id": "0x972a…7967", "raw": "0x0204…"},
    "milestone": {"index": 370, "id": "0x1f67…7745", "essence": "0x7201…",
                  "signatures": [{"pk": "0xed3c…248c", "sig": "0x0359…2708"}]},
    "inclusion": {"leafIndex": 4, "leafCount": 6,
                  "path": [{"side": "L", "hash": "0x7999…a808"}]},
    "envelope": {"verdict": "PRODUCER_SIGNED", "didDoc": {"doc": {"id": "did:iota:…"},
                 "version": "4", "keys": []}, "didVersion": "4"},
    "anchor": {"checkpoint": {"kind": "witness.checkpoint"}, "msPath": [],
               "rebased": {"network": "testnet", "trail": "0x…", "record": 17, "tx": "…"}},
}


async def did_snapshot(svc: Svc, did: str) -> dict | None:
    """The issuer's DID document from the anchor service's resolver, or None if unavailable."""
    base = svc.settings.anchor_url
    if not base:
        return None
    url = f"{base.rstrip('/')}/resolve/{quote(did, safe=':')}"
    try:
        resp = await svc.http.get(url, timeout=svc.settings.upstream_timeout_s)
        if resp.status_code != 200:
            return None
        body = resp.json()
    except (httpx.HTTPError, ValueError) as e:
        log.info("DID snapshot for %s unavailable: %s", did, e)
        return None
    if not isinstance(body, dict) or not isinstance(body.get("keys"), list):
        return None
    doc = body.get("doc")
    if not isinstance(doc, dict) or doc.get("id") != did:
        return None
    return body


@router.get(
    "/proofs/{block_id}", summary="Proof bundle for a block",
    description=(
        "A self-contained `witness-proof/v1` bundle: raw block, milestone essence and "
        "signatures, Merkle audit path to the milestone's inclusion root, the envelope verdict "
        "with a DID document snapshot (when the anchor service answers), and the anchored "
        "checkpoint covering the milestone (when there is one). Verify it offline against "
        "`GET /config/verifier`. `?format=inx-poi` returns the shape of inx-poi's "
        "`/api/poi/v1/create` instead, accepted by its `/validate`."),
    responses={200: {"content": {"application/json": {"example": BUNDLE_EXAMPLE}}},
               404: {"description": "Block not in an indexed milestone cone"},
               409: {"description": "Stored block bytes do not hash to the block id"},
               422: {"description": "Bad id or format, or not renderable as inx-poi"}},
)
async def proof(
    block_id: BlockIdPath, svc: Svc,
    format: Annotated[Literal["witness", "inx-poi"], Query(
        description="Bundle format")] = "witness",
) -> dict:
    bid = block_bytes(block_id)
    try:
        mat = await proofs.material(svc.store, bid)
    except proofs.NoProof as e:
        raise HTTPException(404, str(e)) from None
    except proofs.Inconsistent as e:
        raise HTTPException(409, str(e)) from None
    if format == "inx-poi":
        try:
            return proofs.inx_poi(mat)
        except proofs.Unrenderable as e:
            raise HTTPException(422, str(e)) from None
    message = await svc.store.get_message(bid)
    snapshot = None
    if message is not None and message.get("iss"):
        snapshot = await did_snapshot(svc, message["iss"])
    anchor = await proofs.anchor_section(svc.store, mat["ms_index"],
                                         trail_id=svc.settings.trail_id,
                                         rebased_network=svc.settings.rebased_network)
    return proofs.build_bundle(svc.settings.network, mat, message, snapshot, anchor)


@router.get(
    "/config/verifier", response_model=m.VerifierConfigOut,
    summary="What a verifier pins",
    description=(
        "The configuration an independent verifier pins out of band: the Tangle network "
        "label, the coordinator public keys and signature threshold, and the IOTA Rebased "
        "network and Audit Trail holding the anchors. Compare it with a source you trust "
        "rather than taking it from the same server as the bundle."),
)
async def verifier_config(svc: Svc) -> m.VerifierConfigOut:
    s = svc.settings
    return m.VerifierConfigOut(bundle_version=bundle.VERSION, network=s.network,
                               trusted_coordinator_keys=s.coordinator_keys,
                               threshold=s.threshold, rebased_network=s.rebased_network,
                               trail_id=s.trail_id)


@router.get(
    "/milestones", response_model=m.MilestoneIds, summary="Milestone ids in a range",
    description=(
        "Ids of the indexed milestones `from`..`to` (inclusive), in index order: what the "
        "anchor service commits to in a checkpoint's `msRoot`. `complete` is false when "
        "some milestone of the range is not indexed."),
    responses={422: {"description": "Bad range (to < from, or more than 10 000)"}},
)
async def milestone_ids(
    svc: Svc,
    frm: Annotated[int, Query(alias="from", ge=0, le=0xFFFFFFFF)],
    to: Annotated[int, Query(ge=0, le=0xFFFFFFFF)],
) -> m.MilestoneIds:
    if to < frm:
        raise HTTPException(422, "`to` is before `from`")
    if to - frm + 1 > MAX_MILESTONE_RANGE:
        raise HTTPException(422, f"at most {MAX_MILESTONE_RANGE} milestones per request")
    ids = await svc.store.milestone_ids(frm, to)
    return m.MilestoneIds(from_=frm, to=to, ids=["0x" + bytes(i).hex() for i in ids],
                          complete=len(ids) == to - frm + 1)
