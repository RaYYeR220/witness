"""did:key signers resolved locally: the DID is its own Ed25519 public key.

The indexer and the relay never ask a registry about a did:key, and neither should anyone
checking a proof bundle: the anchor service only resolves did:iota. `document(did)` answers
in the anchor's resolve shape, the reply the indexer builds for a did:key, and
`with_did_key(resolve_did)` puts it in front of any other resolver (the CLI and the MCP
server use it; `withDidKey` in @witness/verify is the TypeScript twin, held to this one by
core/tests/vectors/did_key.json).
"""

from __future__ import annotations

from collections.abc import Callable

PREFIX = "did:key:"
MAX_LENGTH = 128  # longer DIDs are refused everywhere (indexer, relay, anchor)
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58)}
_ED25519_PUB = b"\xed\x01"  # multicodec ed25519-pub, as an unsigned varint

Resolver = Callable[[str], dict | None]


def _b58decode(s: str) -> bytes | None:
    n = 0
    for ch in s:
        digit = _B58_INDEX.get(ch)
        if digit is None:
            return None
        n = n * 58 + digit
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(s) - len(s.lstrip("1"))) + body


def _b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


def from_public_key(ed25519_public: bytes) -> str:
    """The did:key of an Ed25519 public key."""
    return PREFIX + "z" + _b58encode(_ED25519_PUB + ed25519_public)


def public_key(did: str) -> bytes | None:
    """The Ed25519 public key a did:key encodes, or None (not a did:key, or not Ed25519)."""
    if not isinstance(did, str) or len(did) > MAX_LENGTH or not did.startswith(PREFIX + "z"):
        return None
    raw = _b58decode(did[len(PREFIX) + 1:])
    if raw is None or len(raw) != 34 or not raw.startswith(_ED25519_PUB):
        return None
    return raw[2:]


def document(did: str) -> dict | None:
    """The resolve reply for a did:key; None for any other DID.

    One Ed25519 key, never revoked, under the key's own fragment (`did:key:z…#z…`) and
    under the bare DID, the two kids the indexer accepts. A did:key that encodes no
    Ed25519 key gets no keys: nothing it names verifies (the indexer judges it FORGED).
    """
    if not isinstance(did, str) or not did.startswith(PREFIX):
        return None
    public = public_key(did)
    keys = []
    if public is not None:
        key = {"type": "Ed25519", "publicKeyHex": "0x" + public.hex(), "revokedAtMs": None}
        keys = [{"kid": f"{did}#{did[len(PREFIX):]}", **key}, {"kid": did, **key}]
    return {"doc": {"id": did}, "version": None, "keys": keys, "historyComplete": True}


def with_did_key(resolve_did: Resolver | None = None) -> Resolver:
    """`resolve_did` with every did:key answered locally (never forwarded). Without a
    resolver, any other DID resolves to None (step 4 not evaluated)."""

    def resolve(did: str) -> dict | None:
        local = document(did)
        if local is not None:
            return local
        return None if resolve_did is None else resolve_did(did)

    return resolve
