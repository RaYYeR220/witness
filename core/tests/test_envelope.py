import copy
import json
import math
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from witness_core import envelope, verdicts
from witness_core.envelope import KeyInfo

VECTORS = Path(__file__).parent / "vectors" / "envelopes.json"
DID = "did:iota:testnet:0xabc"
KID = DID + "#sig-1"
NOW = 1_700_000_000_000
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def _pub(key):
    return key.public_key().public_bytes_raw()


def _resolver(key, kid=KID):
    info = KeyInfo(kid, _pub(key), None, None)
    return lambda k: info if k == kid else None


def _seal(key, **kw):
    args = {
        "iss": DID,
        "kid": KID,
        "sign_key": key,
        "seq": 7,
        "att_mode": "producer",
        "now_ms": NOW,
    }
    args.update(kw)
    return envelope.seal("trust.score", {"score": 0.745, "id": "D:x"}, **args)


def _verdict(env, key, tag="trust.score"):
    return envelope.verify(env, tag, _resolver(key)).verdict


def _noncanonical(s):
    """Same decoded bytes, different final character (unused low bits flipped)."""
    return s[:-1] + ALPHABET[ALPHABET.index(s[-1]) ^ 1]


def test_seal_verify_producer():
    key = Ed25519PrivateKey.generate()
    env = _seal(key)
    assert envelope.is_envelope(env) and env["w"] == 1
    res = envelope.verify(env, "trust.score", _resolver(key))
    assert res.verdict == verdicts.PRODUCER_SIGNED
    assert (res.iss, res.kid, res.seq, res.iat) == (DID, KID, 7, NOW)


def test_seal_verify_relay():
    key = Ed25519PrivateKey.generate()
    env = _seal(key, att_mode="relay", att_sub="svc")
    assert _verdict(env, key) == verdicts.RELAY_ATTESTED


def test_tampered_body_forged():
    key = Ed25519PrivateKey.generate()
    env = _seal(key)
    env["body"]["score"] = 0.1
    assert _verdict(env, key) == verdicts.FORGED


def test_cross_tag_replay_forged():
    key = Ed25519PrivateKey.generate()
    res = envelope.verify(_seal(key), "LLO-K8s", _resolver(key))
    assert res.verdict == verdicts.FORGED
    assert "tag" in res.reason


def test_unknown_kid_forged():
    key = Ed25519PrivateKey.generate()
    assert envelope.verify(_seal(key), "trust.score", lambda k: None).verdict == verdicts.FORGED


def test_kid_iss_mismatch_forged():
    key = Ed25519PrivateKey.generate()
    other = "did:iota:testnet:0xdef#sig-1"
    env = _seal(key, kid=other)
    res = envelope.verify(env, "trust.score", _resolver(key, other))
    assert res.verdict == verdicts.FORGED


def test_wrong_key_forged():
    key = Ed25519PrivateKey.generate()
    res = envelope.verify(_seal(key), "trust.score", _resolver(Ed25519PrivateKey.generate()))
    assert res.verdict == verdicts.FORGED


def test_missing_public_key_forged():
    key = Ed25519PrivateKey.generate()
    info = KeyInfo(KID, None, None, None)
    assert envelope.verify(_seal(key), "trust.score", lambda k: info).verdict == verdicts.FORGED


def test_malformed():
    key = Ed25519PrivateKey.generate()
    env = _seal(key)
    no_sig = {k: v for k, v in env.items() if k != "sig"}
    assert _verdict(no_sig, key) == verdicts.MALFORMED
    assert _verdict({**env, "seq": "7"}, key) == verdicts.MALFORMED
    assert _verdict({**env, "seq": True}, key) == verdicts.MALFORMED
    bad_w = {**env, "w": 2}
    assert not envelope.is_envelope(bad_w)
    assert _verdict(bad_w, key) == verdicts.MALFORMED
    assert _verdict({**env, "sig": "!!not base64!!"}, key) == verdicts.MALFORMED


def test_prev_corr_signed():
    key = Ed25519PrivateKey.generate()
    env = _seal(key, prev="0x" + "11" * 32, corr="req-1")
    res = envelope.verify(env, "trust.score", _resolver(key))
    assert res.verdict == verdicts.PRODUCER_SIGNED
    assert (res.prev, res.corr) == ("0x" + "11" * 32, "req-1")
    for field, value in (("prev", "0x" + "22" * 32), ("corr", "req-2")):
        t = copy.deepcopy(env)
        t[field] = value
        assert _verdict(t, key) == verdicts.FORGED


def test_optional_fields_omitted_when_none():
    env = _seal(Ed25519PrivateKey.generate())
    assert "prev" not in env and "corr" not in env


def test_seal_random_nonce_differs():
    key = Ed25519PrivateKey.generate()
    assert _seal(key)["nonce"] != _seal(key)["nonce"]


def test_header_fields_are_signed():
    key = Ed25519PrivateKey.generate()
    env = _seal(key, nonce=bytes(range(16)))
    assert _verdict({**env, "tag": "LLO-K8s"}, key, "LLO-K8s") == verdicts.FORGED
    assert _verdict({**env, "att": {"mode": "relay", "sub": "s"}}, key) == verdicts.FORGED
    assert _verdict({**env, "seq": 8}, key) == verdicts.FORGED
    assert _verdict({**env, "iat": NOW + 1}, key) == verdicts.FORGED
    other = envelope._b64(bytes(range(1, 17)))
    assert _verdict({**env, "nonce": other}, key) == verdicts.FORGED


def test_sig_and_nonce_encoding_strict():
    key = Ed25519PrivateKey.generate()
    env = _seal(key)
    sig, nonce = env["sig"], env["nonce"]
    assert len(sig) == 86 and len(nonce) == 22
    bad_sigs = [
        sig + "=",
        sig + "==",
        _noncanonical(sig),
        sig[:-1] + "+",
        sig[:-2] + "/_",
        sig[:-1] + "!",
        sig[:-1],
        sig + "A",
        "",
    ]
    for bad in bad_sigs:
        assert _verdict({**env, "sig": bad}, key) == verdicts.MALFORMED, bad
    for bad in (nonce + "==", nonce[:-1] + "+", nonce[:-1], _noncanonical(nonce), ""):
        assert _verdict({**env, "nonce": bad}, key) == verdicts.MALFORMED, bad


def test_optional_field_types_malformed():
    key = Ed25519PrivateKey.generate()
    env = _seal(key, bix=["a"], cmt={"k": "v"}, prev="0x" + "ab" * 32, corr="c")
    assert _verdict(env, key) == verdicts.PRODUCER_SIGNED
    bad = [
        {"bix": "a"},
        {"bix": [1]},
        {"cmt": []},
        {"cmt": {"k": 1}},
        {"prev": "0x" + "AB" * 32},
        {"prev": "0x12"},
        {"prev": 5},
        {"corr": 5},
        {"att": []},
        {"att": {"mode": "other"}},
        {"att": {"mode": "relay"}},
        {"att": {"mode": "relay", "sub": ""}},
        {"att": {"mode": "producer", "sub": 3}},
        {"extra": 1},
        {"enc": {"x": 1}},
        {"body": [1]},
    ]
    for patch in bad:
        assert _verdict({**env, **patch}, key) == verdicts.MALFORMED, patch
    enc_only = {k: v for k, v in env.items() if k != "body"}
    assert _verdict({**enc_only, "enc": []}, key) == verdicts.MALFORMED
    assert _verdict(enc_only, key) == verdicts.MALFORMED  # neither body nor enc


def test_enc_envelope_roundtrip():
    key = Ed25519PrivateKey.generate()
    env = envelope.seal(
        "trust.score",
        None,
        iss=DID,
        kid=KID,
        sign_key=key,
        seq=1,
        att_mode="producer",
        enc={"alg": "x"},
        now_ms=NOW,
    )
    assert "body" not in env
    assert _verdict(env, key) == verdicts.PRODUCER_SIGNED
    with pytest.raises(ValueError):
        _seal(key, enc={"alg": "x"})


def test_integer_rule():
    key = Ed25519PrivateKey.generate()
    env = _seal(key)
    for name in ("seq", "iat", "w"):
        for bad in (7.0, True, -1, 2**53, "7"):
            assert _verdict({**env, name: bad}, key) == verdicts.MALFORMED, (name, bad)
    assert _verdict(_seal(key, seq=2**53 - 1), key) == verdicts.PRODUCER_SIGNED
    assert not envelope.is_envelope({**env, "w": 1.0})


def test_canonicalization_errors():
    key = Ed25519PrivateKey.generate()
    for bad_body in ({"x": math.nan}, {"x": math.inf}, {"x": 2**53}, {"x": -(2**53)}):
        with pytest.raises(ValueError):
            envelope.seal(
                "t", bad_body, iss=DID, kid=KID, sign_key=key, seq=1, att_mode="producer"
            )
    for bad in (2**53, math.nan, math.inf):
        env = _seal(key)
        env["body"]["score"] = bad
        assert _verdict(env, key) == verdicts.MALFORMED, bad
    with pytest.raises(ValueError):
        _seal(key, seq=2**53)
    with pytest.raises(ValueError):
        _seal(key, seq=-1)


def _signing_input(env):
    try:
        return envelope._signing_input(env).decode("utf-8")
    except (ValueError, KeyError):
        return None


def _case(name, env, key, block_tag, expected):
    return {
        "name": name,
        "envelope": env,
        "public_key_hex": _pub(key).hex(),
        "block_tag": block_tag,
        "signing_input": _signing_input(env),
        "expected_verdict": expected,
    }


def _build_vectors():
    key = Ed25519PrivateKey.from_private_bytes(bytes([1]) * 32)
    kw = {"now_ms": NOW, "nonce": bytes(range(16))}
    producer = _seal(key, **kw)
    relay = _seal(key, att_mode="relay", att_sub="svc", seq=8, **kw)
    with_pc = _seal(key, prev="0x" + "11" * 32, corr="req-1", seq=9, **kw)

    def twin(base, **patch):
        return {**copy.deepcopy(base), **patch}

    body_twin = copy.deepcopy(producer)
    body_twin["body"]["score"] = 0.1
    no_sig = {k: v for k, v in producer.items() if k != "sig"}
    forged, bad = verdicts.FORGED, verdicts.MALFORMED
    t = "trust.score"
    cases = [
        _case("valid_producer", producer, key, t, verdicts.PRODUCER_SIGNED),
        _case("valid_relay", relay, key, t, verdicts.RELAY_ATTESTED),
        _case("valid_prev_corr", with_pc, key, t, verdicts.PRODUCER_SIGNED),
        _case("tampered_body", body_twin, key, t, forged),
        _case("cross_tag", producer, key, "LLO-K8s", forged),
        _case("tampered_prev", twin(with_pc, prev="0x" + "22" * 32), key, t, forged),
        _case("tampered_corr", twin(with_pc, corr="req-2"), key, t, forged),
        _case("retagged", twin(producer, tag="LLO-K8s"), key, "LLO-K8s", forged),
        _case("att_mode_flipped", twin(producer, att={"mode": "relay", "sub": "svc"}), key, t, forged),
        _case("tampered_seq", twin(producer, seq=8), key, t, forged),
        _case("tampered_iat", twin(producer, iat=NOW + 1), key, t, forged),
        _case("tampered_nonce", twin(producer, nonce=envelope._b64(bytes(range(1, 17)))), key, t, forged),
        _case("missing_sig", no_sig, key, t, bad),
        _case("string_seq", twin(producer, seq="7"), key, t, bad),
        _case("float_seq", twin(producer, seq=7.0), key, t, bad),
        _case("w_2", twin(producer, w=2), key, t, bad),
        _case("padded_sig", twin(producer, sig=producer["sig"] + "="), key, t, bad),
        _case("noncanonical_sig", twin(producer, sig=_noncanonical(producer["sig"])), key, t, bad),
        _case("body_and_enc", twin(producer, enc={"alg": "x"}), key, t, bad),
    ]
    return {
        "description": "witness/v1 envelope vectors. verify(envelope, block_tag) using the "
        "ed25519 public key (hex) registered for envelope.kid. signing_input is the exact "
        "JCS text covered by the signature (envelope without sig), null if not canonicalizable. "
        "float_seq carries seq as the JSON float 7.0 and must be MALFORMED.",
        "cases": cases,
    }


def test_write_envelope_vectors():
    vectors = _build_vectors()
    for c in vectors["cases"]:
        env = c["envelope"]
        info = KeyInfo(env["kid"], bytes.fromhex(c["public_key_hex"]), None, None)
        got = envelope.verify(env, c["block_tag"], lambda k, i=info: i if k == i.kid else None)
        assert got.verdict == c["expected_verdict"], c["name"]
    if not VECTORS.exists():
        VECTORS.parent.mkdir(parents=True, exist_ok=True)
        VECTORS.write_text(json.dumps(vectors, indent=2) + "\n", encoding="utf-8")
    assert json.loads(VECTORS.read_text(encoding="utf-8")) == vectors
