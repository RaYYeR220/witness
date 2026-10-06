"""Offline key resolution: `did:key` identifiers plus an optional pinned key table.

This is the resolver the indexer uses when no DID resolver service is configured. It never
does I/O, so it can sit inside the synchronous `envelope.verify` callback.
"""

from __future__ import annotations

from collections.abc import Mapping

from witness_core.envelope import KeyInfo

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58)}
_ED25519_PUB = b"\xed\x01"  # multicodec ed25519-pub, as an unsigned varint
_PREFIX = "did:key:z"


def _b58decode(s: str) -> bytes | None:
    n = 0
    for ch in s:
        digit = _B58_INDEX.get(ch)
        if digit is None:
            return None
        n = n * 58 + digit
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(s) - len(s.lstrip("1"))) + body


def ed25519_from_did_key(did: str) -> bytes | None:
    """The Ed25519 public key a `did:key` encodes, or None if it encodes something else."""
    if not did.startswith(_PREFIX) or len(did) > 64:
        return None
    raw = _b58decode(did[len(_PREFIX):])
    if raw is None or len(raw) != 34 or not raw.startswith(_ED25519_PUB):
        return None
    return raw[2:]


class OfflineResolver:
    """Key resolution without a registry: `resolver(kid)` or `await aresolve_kid(kid, at_ms)`.

    Pinned keys win (they can carry a revocation time, which the caller compares with the
    message's time); otherwise a `did:key` resolves to the key it encodes, under its own
    fragment (`did:key:z…#z…`) or with no fragment. Never raises.
    """

    def __init__(self, pinned: Mapping[str, KeyInfo] | None = None) -> None:
        self._pinned = dict(pinned or {})

    def __call__(self, kid: str) -> KeyInfo | None:
        if not isinstance(kid, str):
            return None
        if kid in self._pinned:
            return self._pinned[kid]
        did, _, fragment = kid.partition("#")
        pub = ed25519_from_did_key(did)
        if pub is None or fragment not in ("", did[len("did:key:"):]):
            return None
        return KeyInfo(kid, pub, None, None)

    async def aresolve_kid(self, kid: str, at_ms: int | None = None) -> KeyInfo | None:
        return self(kid)
