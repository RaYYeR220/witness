"""Anchors: the checkpoints that commit milestone ranges to an IOTA Rebased Audit Trail."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query

from . import models as m
from . import views
from .deps import Svc

router = APIRouter(tags=["anchors"])


@router.get("/anchors", response_model=m.AnchorList, summary="Anchored checkpoints",
            description="Newest first. `status` is pending, anchored, failed or mismatch "
                        "(the recomputed root differs from the on-chain record).")
async def anchors(svc: Svc, limit: Annotated[int, Query(ge=1, le=500)] = 100) -> m.AnchorList:
    return m.AnchorList(items=[views.anchor(r) for r in await svc.store.anchors(limit)])
