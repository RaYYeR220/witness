"""Relay attestation: wrap a legacy message in a signed `witness/v1` envelope.

The relay signs as its own DID with `att = {mode: relay, sub: <caller>}`. Tags listed
in `encrypt_tags` carry a JWE (`enc`) instead of `body`, plus blind-index tokens for
the tag and, when the message names one, the infrastructure element (`id`).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from witness_core import canon, envelope
from witness_core.sealed import Recipient, blind_token, encrypt_body

MAX_SEQ = 2**53 - 1
_PREV_PLACEHOLDER = "0x" + "f" * 64

# Stardust block around a tagged-data payload, with the maximum of 8 parents:
# version(1) + parentCount(1) + parents(8*32) + payloadLength(4)
# + type(4) + tagLength(1) + dataLength(4) + nonce(8)
BLOCK_OVERHEAD = 1 + 1 + 8 * 32 + 4 + 4 + 1 + 4 + 8


def load_signing_key(path: str) -> Ed25519PrivateKey:
    with open(path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"{path} is not an Ed25519 private key")
    return key


def legacy_body(message: Any) -> dict:
    """Envelope bodies are JSON objects; any other legacy message is wrapped."""
    return message if isinstance(message, dict) else {"value": message}


def block_size(tag: str, data: bytes) -> int:
    return BLOCK_OVERHEAD + len(tag.encode("utf-8")) + len(data)


def envelope_data(env: dict) -> bytes:
    """Bytes placed in the tagged-data payload: the envelope's canonical JSON."""
    return canon.jcs(env)


@dataclass(frozen=True)
class Attestor:
    did: str
    kid: str
    key: Ed25519PrivateKey
    encrypt_tags: frozenset[str] = frozenset()
    recipients: tuple[Recipient, ...] = ()
    search_key: bytes | None = None

    def __post_init__(self) -> None:
        if self.kid.split("#", 1)[0] != self.did:
            raise ValueError("relay kid must belong to the relay DID")
        if self.encrypt_tags and not self.recipients:
            raise ValueError("encrypt_tags needs at least one recipient")

    def protect(self, tag: str, message: Any) -> dict:
        """The content part of the envelope: `{body}` or `{enc, bix}`."""
        body = legacy_body(message)
        if tag not in self.encrypt_tags:
            return {"body": body}
        enc = encrypt_body(body, list(self.recipients))
        if self.search_key is None:
            return {"enc": enc}
        bix = [blind_token(self.search_key, "tag", tag)]
        ie = body.get("id")
        if isinstance(ie, str) and ie:
            bix.append(blind_token(self.search_key, "ie", ie))
        return {"enc": enc, "bix": bix}

    def seal(self, tag: str, content: dict, *, caller: str, seq: int, prev: str | None) -> dict:
        return envelope.seal(
            tag,
            content.get("body"),
            iss=self.did,
            kid=self.kid,
            sign_key=self.key,
            seq=seq,
            att_mode="relay",
            att_sub=caller,
            enc=content.get("enc"),
            bix=content.get("bix"),
            prev=prev,
        )

    def worst_case_size(self, tag: str, content: dict, *, caller: str) -> int:
        """Block size with the largest possible seq and a prev link: an upper bound."""
        probe = self.seal(tag, content, caller=caller, seq=MAX_SEQ, prev=_PREV_PLACEHOLDER)
        return block_size(tag, envelope_data(probe))
