import copy
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from witness_core import envelope, verdicts
from witness_core.envelope import KeyInfo

VECTORS = Path(__file__).parent / "vectors" / "envelopes.json"
DID = "did:iota:testnet:0xabc"
KID = DID + "#sig-1"
NOW = 1_700_000_000_000


def _pub(key):
    return key.public_key().public_bytes_raw()


def _resolver(key, kid=KID):
    info = KeyInfo(kid, _pub(key), None, None)
    return lambda k: info if k == kid else None


def _seal(key, **kw):
    args = {"iss": DID, "kid": KID, "sign_key": key, "seq": 7, "att_mode": "producer", "now_ms": NOW}
    args.update(kw)
    return envelope.seal("trust.score", {"score": 0.745, "id": "D:x"}, **args)


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
    assert envelope.verify(env, "trust.score", _resolver(key)).verdict == verdicts.RELAY_ATTESTED


def test_tampered_body_forged():
    key = Ed25519PrivateKey.generate()
    env = _seal(key)
    env["body"]["score"] = 0.1
    assert envelope.verify(env, "trust.score", _resolver(key)).verdict == verdicts.FORGED


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
    res = _resolver(key)
    env = _seal(key)
    no_sig = {k: v for k, v in env.items() if k != "sig"}
    assert envelope.verify(no_sig, "trust.score", res).verdict == verdicts.MALFORMED
    assert envelope.verify({**env, "seq": "7"}, "trust.score", res).verdict == verdicts.MALFORMED
    assert envelope.verify({**env, "seq": True}, "trust.score", res).verdict == verdicts.MALFORMED
    bad_w = {**env, "w": 2}
    assert not envelope.is_envelope(bad_w)
    assert envelope.verify(bad_w, "trust.score", res).verdict == verdicts.MALFORMED
    bad_sig = envelope.verify({**env, "sig": "!!not base64!!"}, "trust.score", res)
    assert bad_sig.verdict in (verdicts.MALFORMED, verdicts.FORGED)


def test_prev_corr_signed():
    key = Ed25519PrivateKey.generate()
    env = _seal(key, prev="0x" + "11" * 32, corr="req-1")
    res = envelope.verify(env, "trust.score", _resolver(key))
    assert res.verdict == verdicts.PRODUCER_SIGNED
    assert (res.prev, res.corr) == ("0x" + "11" * 32, "req-1")
    for field, value in (("prev", "0x" + "22" * 32), ("corr", "req-2")):
        t = copy.deepcopy(env)
        t[field] = value
        assert envelope.verify(t, "trust.score", _resolver(key)).verdict == verdicts.FORGED


def test_optional_fields_omitted_when_none():
    env = _seal(Ed25519PrivateKey.generate())
    assert "prev" not in env and "corr" not in env


def test_seal_random_nonce_differs():
    key = Ed25519PrivateKey.generate()
    assert _seal(key)["nonce"] != _seal(key)["nonce"]


def _case(name, env, key, block_tag, expected):
    return {
        "name": name,
        "envelope": env,
        "public_key_hex": _pub(key).hex(),
        "block_tag": block_tag,
        "expected_verdict": expected,
    }


def _build_vectors():
    key = Ed25519PrivateKey.from_private_bytes(bytes([1]) * 32)
    kw = {"now_ms": NOW, "nonce": bytes(range(16))}
    producer = _seal(key, **kw)
    relay = _seal(key, att_mode="relay", att_sub="svc", seq=8, **kw)
    with_pc = _seal(key, prev="0x" + "11" * 32, corr="req-1", seq=9, **kw)
    body_twin = copy.deepcopy(producer)
    body_twin["body"]["score"] = 0.1
    prev_twin = copy.deepcopy(with_pc)
    prev_twin["prev"] = "0x" + "22" * 32
    corr_twin = copy.deepcopy(with_pc)
    corr_twin["corr"] = "req-2"
    cases = [
        _case("valid_producer", producer, key, "trust.score", verdicts.PRODUCER_SIGNED),
        _case("valid_relay", relay, key, "trust.score", verdicts.RELAY_ATTESTED),
        _case("valid_prev_corr", with_pc, key, "trust.score", verdicts.PRODUCER_SIGNED),
        _case("tampered_body", body_twin, key, "trust.score", verdicts.FORGED),
        _case("cross_tag", producer, key, "LLO-K8s", verdicts.FORGED),
        _case("tampered_prev", prev_twin, key, "trust.score", verdicts.FORGED),
        _case("tampered_corr", corr_twin, key, "trust.score", verdicts.FORGED),
    ]
    return {
        "description": "witness/v1 envelope vectors. verify(envelope, block_tag) using the "
        "ed25519 public key (hex) registered for envelope.kid.",
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
