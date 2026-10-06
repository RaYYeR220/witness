"""Identity: the component DIDs published by the anchor service and the writer policy."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import httpx
from fastapi import APIRouter
from witness_core import policy as wpolicy

from . import models as m
from .deps import Svc

log = logging.getLogger(__name__)
router = APIRouter(tags=["identity"])


def load_policy(path: str | None) -> wpolicy.WriterPolicy | None:
    if path is None:
        return None
    return wpolicy.load(json.loads(Path(path).read_text(encoding="utf-8")))


def policy_summary(p: wpolicy.WriterPolicy | None) -> m.PolicySummary | None:
    if p is None:
        return None

    def rule(r: wpolicy.TagRule) -> m.TagRuleOut:
        return m.TagRuleOut(allowed=list(r.allowed), require_signature=r.require_signature,
                            legacy_grace=r.legacy_grace)

    return m.PolicySummary(version=p.version, hash="0x" + wpolicy.policy_hash(p).hex(),
                           tags={t: rule(r) for t, r in p.tags.items()}, default=rule(p.default))


async def anchor_identities(svc: Svc) -> m.AnchorIdentities:
    base = svc.settings.anchor_url
    if not base:
        return m.AnchorIdentities(status="not_configured")
    try:
        resp = await svc.http.get(f"{base.rstrip('/')}/identities",
                                  timeout=svc.settings.upstream_timeout_s)
        body = resp.json() if resp.status_code == 200 else None
    except (httpx.HTTPError, ValueError) as e:
        log.info("anchor service identities unavailable: %s", e)
        body = None
    if not isinstance(body, dict) or not isinstance(body.get("identities"), list):
        return m.AnchorIdentities(status="unreachable")
    previous = body.get("previous")
    network = body.get("network")
    return m.AnchorIdentities(status="ok", network=network if isinstance(network, str) else None,
                              identities=body["identities"],
                              previous=previous if isinstance(previous, list) else [])


@router.get("/identity", response_model=m.Identity, summary="DIDs and writer policy",
            description=(
                "The component identities (domain DID, Trust Manager, LLO, self-orchestrator, "
                "relay, anchor) with their public keys, as the anchor service publishes them, "
                "and a summary of the writer policy (who may write which tag) with the hash "
                "every checkpoint commits to."))
async def identity(svc: Svc) -> m.Identity:
    return m.Identity(anchor=await anchor_identities(svc), policy=policy_summary(svc.policy))
