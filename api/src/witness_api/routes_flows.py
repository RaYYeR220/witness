"""Traceability of related messages: flows by issuer (with its `prev` hash chain), by IE, by
service component, or by correlation id."""

from __future__ import annotations

from collections import Counter
from typing import Annotated

from fastapi import APIRouter, Path, Query
from witness_core import verdicts

from . import models as m
from . import views
from .deps import Svc

router = APIRouter(tags=["flows"])

KEY_PATH = Annotated[str, Path(min_length=1, max_length=256, pattern=r"^[^/]+$",
                               examples=["did:iota:testnet:0x5e1f…"])]


# Verdicts that prove the issuer wrote the message; anything else only claims it.
PROVEN = frozenset({verdicts.PRODUCER_SIGNED, verdicts.RELAY_ATTESTED})


def claims_issuer(iss: str | None, verdict: str | None) -> bool:
    return iss is not None and verdict not in PROVEN


def chain_view(items: list[m.FlowItem]) -> m.ChainView:
    """Each proven message's `prev` against the issuer's previous proven message (flow in
    `seq` order). Anyone can name an issuer: a forged or unsigned message that does is
    listed in the flow but never links, gaps or forks its chain (the same messages the
    indexer's R15/R16 look at)."""
    proven = [i for i in items if not i.claims_issuer]
    links, gaps = 0, []
    before: str | None = None
    for item in proven:
        if item.prev is not None:
            if item.prev == before:
                links += 1
            else:
                gaps.append(item.block_id)
        before = item.block_id
    claimed = Counter(i.prev for i in proven if i.prev is not None)
    forks = sorted(p for p, n in claimed.items() if n > 1)
    return m.ChainView(links=links, gaps=gaps, forks=forks)


@router.get("/flows", response_model=m.FlowList, summary="Flows of related messages",
            description="One row per issuer, IE, service component or correlation id, most "
                        "recently active first.")
async def flows(
    svc: Svc,
    by: Annotated[m.FlowBy, Query(description="Grouping")] = "issuer",
) -> m.FlowList:
    items = []
    for r in await svc.store.flows(by, None):
        first, last = views.sec_to_ms(r["first_ts"]), views.sec_to_ms(r["last_ts"])
        items.append(m.FlowSummary(key=str(r["key"]), count=r["count"], first_at_ms=first,
                                   first_at=views.iso(first), last_at_ms=last,
                                   last_at=views.iso(last)))
    return m.FlowList(by=by, items=items)


@router.get("/flows/{by}/{key}", response_model=m.Flow, summary="One flow",
            description="The messages of one flow in order (issuer flows by `seq`, others by "
                        "time). Issuer flows also report their hash chain over the messages "
                        "that prove the issuer (PRODUCER_SIGNED, RELAY_ATTESTED): messages "
                        "linked by `prev`, gaps and forks. Others only claim the issuer "
                        "(`claimsIssuer`) and stay out of the chain.")
async def flow(
    by: Annotated[m.FlowBy, Path()], key: KEY_PATH, svc: Svc,
    limit: Annotated[int, Query(ge=1, le=10_000, description="Newest messages returned")] = 1000,
) -> m.Flow:
    items = []
    for r in await svc.store.flows(by, key):
        bid = views.hx(r["block_id"])
        at = views.sec_to_ms(r["ts"])
        items.append(m.FlowItem(
            block_id=bid, prev=views.hx(r["prev"]), seq=r["seq"], tag=r["tag"], kind=r["kind"],
            verdict=r["verdict"], status=r["status"], iss=r["iss"], ie_id=r["ie_id"],
            corr=r["corr"], ms_index=r["ms_index"], wf_index=r["wf_index"], at_ms=at,
            at=views.iso(at), links=svc.link.message(bid),
            claims_issuer=claims_issuer(r["iss"], r["verdict"])))
    return m.Flow(by=by, key=key, items=items[-limit:], total=len(items),
                  chain=chain_view(items) if by == "issuer" else None)
