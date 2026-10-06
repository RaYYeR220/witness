"""Fail-closed admission: who may put what on which tag.

Producer envelopes must verify, use an unrevoked key and come from an issuer the
writer policy allows for the tag. Legacy messages are admitted for relay attestation
unless the tag demands signatures without a legacy grace and the caller is anonymous.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Literal

from witness_core import envelope, policy, verdicts
from witness_core.policy import WriterPolicy

from .auth import ANONYMOUS
from .keys import KeyResolver

_ACCEPTED = (verdicts.PRODUCER_SIGNED, verdicts.RELAY_ATTESTED)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    verdict: str
    mode: Literal["producer", "relay"]
    iss: str | None = None
    kid: str | None = None
    seq: int | None = None
    caller: str | None = None
    reason: str | None = None


def load_policy(path: str) -> WriterPolicy:
    with open(path, encoding="utf-8") as f:
        return policy.load(json.load(f))


class PolicyGate:
    def __init__(self, writer_policy: WriterPolicy, resolver: KeyResolver, relay_did: str):
        self.policy = writer_policy
        self._resolver = resolver
        self._relay_did = relay_did

    async def check_envelope(self, tag: str, env: dict) -> Decision:
        kid = env.get("kid")
        info = await self._resolver.resolve(kid) if isinstance(kid, str) else None
        check = envelope.verify(env, tag, lambda k: info if k == kid else None)

        def refuse(verdict: str, reason: str) -> Decision:
            return Decision(
                False, verdict, "producer", check.iss, check.kid, check.seq, reason=reason
            )

        if check.verdict not in _ACCEPTED:
            return refuse(check.verdict, check.reason or "envelope rejected")
        if info.revoked_at_ms is not None and info.revoked_at_ms <= int(time.time() * 1000):
            return refuse(verdicts.REVOKED_KEY, "signing key is revoked")
        if check.iss == self._relay_did:
            # Only this relay signs as itself; an incoming copy is a resubmission.
            return refuse(verdicts.REPLAY, "relay-issued envelopes cannot be resubmitted")
        if not policy.allowed(self.policy, tag, check.iss):
            return refuse(verdicts.UNAUTHORIZED_WRITER, f"{check.iss} may not write tag {tag!r}")
        return Decision(True, check.verdict, "producer", check.iss, check.kid, check.seq)

    def check_legacy(self, tag: str, caller: str) -> Decision:
        rule = self.policy.tags.get(tag, self.policy.default)
        if rule.require_signature and not rule.legacy_grace and caller == ANONYMOUS:
            return Decision(
                False,
                verdicts.UNAUTHORIZED_WRITER,
                "relay",
                reason=f"tag {tag!r} requires a signed envelope or an authenticated caller",
            )
        return Decision(True, verdicts.RELAY_ATTESTED, "relay", iss=self._relay_did, caller=caller)
