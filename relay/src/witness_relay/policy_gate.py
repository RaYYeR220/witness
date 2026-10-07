"""Fail-closed admission: who may put what on which tag.

Producer envelopes must verify, use an unrevoked key, come from an issuer the writer
policy allows for the tag, and carry a body that fits the tag's schema (the explorer stores
a signed message with a broken body as MALFORMED; the relay refuses it with 400 instead of
posting it). Legacy messages are admitted for relay attestation (or, on pass-through tags,
posted unsigned exactly as the original API did) unless the tag demands signatures without
a legacy grace and the caller is anonymous.

Encrypted tags (`RELAY_ENCRYPT_TAGS`) are about legacy writes: the relay seals those to the
domain's recipient key before attesting them. A producer that signs its own envelope owns
its confidentiality and may send it sealed or not; the writer policy already limits who
that can be.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

from witness_core import envelope, policy, schema, verdicts
from witness_core.envelope import KeyInfo
from witness_core.ids import NON_CANONICAL_DID
from witness_core.policy import WriterPolicy

from .auth import ANONYMOUS
from .keys import KeyResolver, NonCanonicalDid

_ACCEPTED = (verdicts.PRODUCER_SIGNED, verdicts.RELAY_ATTESTED)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    verdict: str
    mode: Literal["producer", "relay", "passthrough"]
    iss: str | None = None
    kid: str | None = None
    seq: int | None = None
    caller: str | None = None
    reason: str | None = None
    status: int = 403  # HTTP status of a refusal


def load_policy(path: str) -> WriterPolicy:
    with open(path, encoding="utf-8") as f:
        return policy.load(json.load(f))


def tags_without_relay(writer_policy: WriterPolicy, relay_did: str) -> list[str]:
    """Policy rules under which relay-attested messages would be flagged as unauthorized."""
    rules = [*writer_policy.tags.items(), ("(default)", writer_policy.default)]
    return [tag for tag, rule in rules if "*" not in rule.allowed and relay_did not in rule.allowed]


class PolicyGate:
    def __init__(
        self,
        writer_policy: WriterPolicy,
        resolver: KeyResolver,
        relay_did: str,
        *,
        passthrough_tags: Iterable[str] = (),
    ):
        self.policy = writer_policy
        self._resolver = resolver
        self._relay_did = relay_did
        self._passthrough_tags = frozenset(passthrough_tags)

    async def check_envelope(self, tag: str, env: dict) -> Decision:
        # First pass without keys: only an envelope that gets as far as the key lookup
        # (well-formed, tag-bound, kid belonging to iss) triggers a resolution.
        asked: list[str] = []

        def no_key(kid: str) -> KeyInfo | None:
            asked.append(kid)
            return None

        check = envelope.verify(env, tag, no_key)
        info = None
        if asked:
            kid = asked[0]
            try:
                info = await self._resolver.resolve(kid)
            except NonCanonicalDid:
                return Decision(False, verdicts.FORGED, "producer", check.iss, check.kid,
                                check.seq, reason=NON_CANONICAL_DID)
            check = envelope.verify(env, tag, lambda k: info if k == kid else None)

        def refuse(verdict: str, reason: str, status: int = 403) -> Decision:
            return Decision(
                False,
                verdict,
                "producer",
                check.iss,
                check.kid,
                check.seq,
                reason=reason,
                status=status,
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
        # Same rule as the indexer's (schema.classify of these bytes).
        problem = schema.body_problem(tag, env)
        if problem is not None:
            return refuse(verdicts.MALFORMED, problem, 400)
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
        if tag in self._passthrough_tags:
            return Decision(True, verdicts.UNSIGNED_LEGACY, "passthrough", caller=caller)
        return Decision(True, verdicts.RELAY_ATTESTED, "relay", iss=self._relay_did, caller=caller)
