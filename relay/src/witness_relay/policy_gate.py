"""Fail-closed admission: who may put what on which tag.

Producer envelopes must verify, use an unrevoked key, come from an issuer the writer
policy allows for the tag, and carry ciphertext on tags the relay encrypts. Legacy
messages are admitted for relay attestation (or, on pass-through tags, posted unsigned
exactly as the original API did) unless the tag demands signatures without a legacy
grace and the caller is anonymous.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

from witness_core import envelope, policy, verdicts
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
        encrypt_tags: Iterable[str] = (),
        passthrough_tags: Iterable[str] = (),
    ):
        self.policy = writer_policy
        self._resolver = resolver
        self._relay_did = relay_did
        self._encrypt_tags = frozenset(encrypt_tags)
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
        if tag in self._encrypt_tags and "enc" not in env:
            return refuse(verdicts.MALFORMED, f"tag {tag!r} requires encryption")
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
