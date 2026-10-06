import base64
import copy
import hashlib
import hmac
import json
import os
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


def _flip(b64: str) -> str:
    raw = bytearray(base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4)))
    raw[0] ^= 1
    return _b64(bytes(raw))


@pytest.mark.parametrize("field", ["iv", "tag", "protected"])
def test_field_tamper(field):
    jwe = _jwe()
    jwe[field] = _flip(jwe[field])
    with pytest.raises(sealed.DecryptError):
        sealed.decrypt_body(jwe, "a#k", A)


def test_encrypted_key_tamper():
    jwe = _jwe()
    jwe["recipients"][0]["encrypted_key"] = _flip(jwe["recipients"][0]["encrypted_key"])
    with pytest.raises(sealed.DecryptError):
        sealed.decrypt_body(jwe, "a#k", A)
    assert sealed.decrypt_body(jwe, "b#k", B) == BODY


def test_recipient_entry_missing_header_or_kid():
    jwe = _jwe()
    del jwe["recipients"][0]["header"]
    with pytest.raises(sealed.NotARecipient):
        sealed.decrypt_body(jwe, "a#k", A)
    jwe = _jwe()
    del jwe["recipients"][0]["header"]["kid"]
    with pytest.raises(sealed.NotARecipient):
        sealed.decrypt_body(jwe, "a#k", A)
    jwe = _jwe()
    del jwe["recipients"][0]["header"]["alg"]
    with pytest.raises(sealed.DecryptError):
        sealed.decrypt_body(jwe, "a#k", A)


@pytest.mark.parametrize("bad", [None, [], "x", 5, {}, {"recipients": "x"}])
def test_non_dict_or_malformed_jwe(bad):
    with pytest.raises(sealed.DecryptError):
        sealed.decrypt_body(bad, "a#k", A)


@pytest.mark.parametrize(
    "header",
    [{"enc": "A128GCM"}, {"enc": "A256GCM", "zip": "DEF"}, {}, {"enc": "A256GCM", "x": 1}],
)
def test_protected_header_pinned(header):
    jwe = _jwe()
    jwe["protected"] = _b64(json.dumps(header).encode())
    with pytest.raises(sealed.DecryptError):
        sealed.decrypt_body(jwe, "a#k", A)


@pytest.mark.parametrize("alg", ["ECDH-ES", "ECDH-ES+A128KW", "dir", "none"])
def test_recipient_alg_pinned(alg):
    jwe = _jwe()
    jwe["recipients"][0]["header"]["alg"] = alg
    with pytest.raises(sealed.DecryptError):
        sealed.decrypt_body(jwe, "a#k", A)


def test_shared_unprotected_header_rejected():
    jwe = _jwe()
    jwe["unprotected"] = {"zip": "DEF"}
    with pytest.raises(sealed.DecryptError):
        sealed.decrypt_body(jwe, "a#k", A)


def test_blind_token_rejects_bad_kind_and_empty_key():
    with pytest.raises(ValueError):
        sealed.blind_token(b"" * 32, "other", "v")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        sealed.blind_token(b"", "ie", "v")


def _jwk(key: X25519PrivateKey) -> dict:
    return {
        "kty": "OKP",
        "crv": "X25519",
        "x": _b64(key.public_key().public_bytes_raw()),
        "d": _b64(key.private_bytes_raw()),
    }


def _priv(jwk: dict) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(jwk["d"] + "=="))


def _deterministic() -> dict:
    key = b"	" * 32
    salt = bytes(range(16))
    return {
        "recipients": [
            {"kid": kid, "private_jwk": _jwk(_x(n))} for n, kid in ((1, "a#k"), (2, "b#k"))
        ],
        "body": BODY,
        "blind_tokens": [
            {"key_hex": key.hex(), "kind": kind, "value": v,
             "token": sealed.blind_token(key, kind, v)}
            for kind, v in (("ie", "D:x"), ("tag", "iot"), ("ie", "ünï"))
        ],
        "commitment_salt_len": 16,
        "commitments": [
            {"value": v, "salt_hex": salt.hex(), "commitment": commit.commit(v, salt)}
            for v in (0.42, "x", {"a": [1, 2]})
        ],
    }


def _generate() -> dict:
    data = _deterministic()
    jwe = _jwe()
    tampered = copy.deepcopy(jwe)
    tampered["ciphertext"] = _flip(tampered["ciphertext"])
    data["jwe"] = jwe
    data["negative"] = [
        {"name": "non_recipient", "kid": "c#k", "private_jwk": _jwk(C),
         "jwe": jwe, "error": "NotARecipient"},
        {"name": "tampered_ciphertext", "kid": "a#k", "private_jwk": _jwk(A),
         "jwe": tampered, "error": "DecryptError"},
    ]
    return data


def test_sealed_vectors():
    if not VECTORS.exists() or os.environ.get("WITNESS_REGEN_VECTORS") == "1":
        VECTORS.write_text(
            json.dumps(_generate(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    for name, expected in _deterministic().items():
        assert data[name] == expected, name
    for r in data["recipients"]:
        assert sealed.decrypt_body(data["jwe"], r["kid"], _priv(r["private_jwk"])) == data["body"]
    errors = {"NotARecipient": sealed.NotARecipient, "DecryptError": sealed.DecryptError}
    assert {n["error"] for n in data["negative"]} == set(errors)
    for n in data["negative"]:
        with pytest.raises(errors[n["error"]]):
            sealed.decrypt_body(n["jwe"], n["kid"], _priv(n["private_jwk"]))
