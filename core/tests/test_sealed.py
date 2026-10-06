import base64
import copy
import hashlib
import hmac
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from witness_core import commit, envelope, sealed, verdicts
from witness_core.envelope import KeyInfo
from witness_core.sealed import Recipient

VECTORS = Path(__file__).parent / "vectors" / "sealed.json"
DID = "did:iota:testnet:0xabc"
KID = DID + "#sig-1"
NOW = 1_700_000_000_000
BODY = {"score": 0.745, "id": "D:x", "n": [1, 2, 3]}


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _x(n: int) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(bytes([n]) * 32)


def _rcpt(kid: str, key: X25519PrivateKey) -> Recipient:
    return Recipient(kid, key.public_key().public_bytes_raw())


A, B, C = _x(1), _x(2), _x(3)


def _jwe():
    return sealed.encrypt_body(BODY, [_rcpt("a#k", A), _rcpt("b#k", B)])


def test_roundtrip_two_recipients():
    jwe = _jwe()
    assert jwe["protected"]
    assert len(jwe["recipients"]) == 2
    assert sealed.decrypt_body(jwe, "a#k", A) == BODY
    assert sealed.decrypt_body(jwe, "b#k", B) == BODY


def test_jwe_header_shape():
    jwe = _jwe()
    prot = json.loads(base64.urlsafe_b64decode(jwe["protected"] + "=="))
    assert prot == {"enc": "A256GCM"}
    for r, kid in zip(jwe["recipients"], ["a#k", "b#k"]):
        assert r["header"]["alg"] == "ECDH-ES+A256KW"
        assert r["header"]["kid"] == kid
        assert r["header"]["epk"]["crv"] == "X25519"


def test_non_recipient_rejected():
    with pytest.raises(sealed.NotARecipient):
        sealed.decrypt_body(_jwe(), "c#k", C)


def test_wrong_key_for_listed_kid():
    with pytest.raises(sealed.DecryptError):
        sealed.decrypt_body(_jwe(), "a#k", C)


def test_ciphertext_tamper():
    jwe = _jwe()
    raw = bytearray(base64.urlsafe_b64decode(jwe["ciphertext"] + "=="))
    raw[0] ^= 1
    jwe["ciphertext"] = _b64(bytes(raw))
    with pytest.raises(sealed.DecryptError):
        sealed.decrypt_body(jwe, "a#k", A)


def test_sealed_envelope_signature_covers_ciphertext():
    sk = Ed25519PrivateKey.from_private_bytes(b"\x07" * 32)
    info = KeyInfo(KID, sk.public_key().public_bytes_raw(), None, None)
    env = envelope.seal(
        "trust.score", None, iss=DID, kid=KID, sign_key=sk, seq=1,
        att_mode="producer", now_ms=NOW, enc=_jwe(), bix=["x"],
    )
    assert "body" not in env
    check = envelope.verify(env, "trust.score", lambda k: info)
    assert check.verdict == verdicts.PRODUCER_SIGNED
    bad = copy.deepcopy(env)
    raw = bytearray(base64.urlsafe_b64decode(bad["enc"]["ciphertext"] + "=="))
    raw[0] ^= 1
    bad["enc"]["ciphertext"] = _b64(bytes(raw))
    assert envelope.verify(bad, "trust.score", lambda k: info).verdict == verdicts.FORGED


def test_blind_token_deterministic_and_keyed():
    k1, k2 = b"\x01" * 32, b"\x02" * 32
    t = sealed.blind_token(k1, "ie", "D:x")
    assert t == sealed.blind_token(k1, "ie", "D:x")
    assert t != sealed.blind_token(k2, "ie", "D:x")
    assert t != sealed.blind_token(k1, "tag", "D:x")
    assert t == _b64(hmac.new(k1, b"ie:D:x", hashlib.sha256).digest())


def _jwk(key: X25519PrivateKey) -> dict:
    return {
        "kty": "OKP",
        "crv": "X25519",
        "x": _b64(key.public_key().public_bytes_raw()),
        "d": _b64(key.private_bytes_raw()),
    }


def test_write_sealed_vectors():
    cases = []
    for n, kid in ((1, "a#k"), (2, "b#k")):
        cases.append({"kid": kid, "private_jwk": _jwk(_x(n))})
    jwe = _jwe()
    key = b"\x09" * 32
    tokens = [
        {"key_hex": key.hex(), "kind": kind, "value": v,
         "token": sealed.blind_token(key, kind, v)}
        for kind, v in (("ie", "D:x"), ("tag", "iot"), ("ie", "ünï"))
    ]
    salt = bytes(range(16))
    commitments = [
        {"value": v, "salt_hex": salt.hex(), "commitment": commit.commit(v, salt)}
        for v in (0.42, "x", {"a": [1, 2]})
    ]
    VECTORS.write_text(
        json.dumps(
            {"recipients": cases, "jwe": jwe, "body": BODY,
             "blind_tokens": tokens, "commitments": commitments},
            indent=2, ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    for c in cases:
        k = X25519PrivateKey.from_private_bytes(
            base64.urlsafe_b64decode(c["private_jwk"]["d"] + "==")
        )
        assert sealed.decrypt_body(jwe, c["kid"], k) == BODY
