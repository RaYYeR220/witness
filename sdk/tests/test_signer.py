import json
from base64 import urlsafe_b64encode

import httpx
import respx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from witness_core import commit, envelope, verdicts
from witness_sdk import keys
from witness_sdk.signer import WitnessSigner

DID = "did:iota:testnet:0x" + "ab" * 32
KID = DID + "#sig-1"
BLOCK_1 = "0x" + "11" * 32
BLOCK_2 = "0x" + "22" * 32


def _b64(raw: bytes) -> str:
    return urlsafe_b64encode(raw).rstrip(b"=").decode()


def _signer(tmp_path, name="state.json"):
    out = keys.generate("tm", str(tmp_path / "secrets"))
    assert out["sig"]["crv"] == "Ed25519" and out["kex"]["crv"] == "X25519"
    pem = str(tmp_path / "secrets" / "tm" / "sig.pem")
    return lambda: WitnessSigner(DID, KID, pem, str(tmp_path / name))


def test_seq_monotonic_across_instances(tmp_path):
    make = _signer(tmp_path)
    a, b = make(), make()
    seqs = [s.seal("trust.score", {"n": i})[0]["seq"] for i, s in enumerate([a, b, a, b, make()])]
    assert seqs == sorted(set(seqs)) and len(seqs) == 5


def test_commitments_verifiable(tmp_path):
    s = _signer(tmp_path)()
    values = {"rel": 0.9, "sec": 0.5, "rep": 1}
    env, salts = s.seal("trust.score", {"id": "x"}, values)
    assert set(env["cmt"]) == set(salts) == set(values)
    for name, value in values.items():
        assert commit.verify(env["cmt"][name], value, bytes.fromhex(salts[name]))
    assert not commit.verify(env["cmt"]["rel"], 0.1, bytes.fromhex(salts["rel"]))


def test_envelope_verifies(tmp_path):
    s = _signer(tmp_path)()
    env, _ = s.seal("trust.score", {"id": "x"})
    pub = s._key.public_key().public_bytes_raw()
    check = envelope.verify(env, "trust.score", lambda k: envelope.KeyInfo(k, pub, None, None))
    assert check.verdict == verdicts.PRODUCER_SIGNED


def _ok(block):
    return httpx.Response(
        200, json={"status_code": 201, "return_payload": "{}", "witness": {"blockId": block}}
    )


@respx.mock
def test_upload_calls_relay_and_chains_prev(tmp_path):
    make = _signer(tmp_path)
    s = make()
    route = respx.post("http://relay.test/upload").mock(side_effect=[_ok(BLOCK_1), _ok(BLOCK_2)])
    r1 = s.upload("http://relay.test", "iota-hornet", "trust.score", {"id": "a"})
    r2 = s.upload("http://relay.test", "iota-hornet", "trust.score", {"id": "b"})
    assert r1["witness"]["blockId"] == BLOCK_1
    first, second = (json.loads(c.request.content) for c in route.calls)
    assert route.calls[0].request.url.params["node"] == "iota-hornet"
    assert first["tag"] == "trust.score" and first["message"]["iss"] == DID
    assert "prev" not in first["message"]
    assert second["message"]["prev"] == BLOCK_1
    assert second["message"]["seq"] > first["message"]["seq"]
    assert r2["witness"]["blockId"] == BLOCK_2
    # the chain survives a restart
    assert make().seal("trust.score", {})[0]["prev"] == BLOCK_2


@respx.mock
def test_upload_returns_salts(tmp_path):
    s = _signer(tmp_path)()
    respx.post("http://relay.test/upload").mock(return_value=_ok(BLOCK_1))
    out = s.upload("http://relay.test", "n", "trust.score", {}, {"rel": 1})
    assert set(out["salts"]) == {"rel"}


@respx.mock
def test_replay_bumps_seq_and_retries_once(tmp_path):
    s = _signer(tmp_path)()
    replay = httpx.Response(403, json={"error": "seq 1 is not newer", "verdict": "REPLAY"})
    route = respx.post("http://relay.test/upload").mock(side_effect=[replay, _ok(BLOCK_1)])
    out = s.upload("http://relay.test", "n", "trust.score", {})
    assert out["witness"]["blockId"] == BLOCK_1
    seqs = [json.loads(c.request.content)["message"]["seq"] for c in route.calls]
    assert seqs[1] > seqs[0]


@respx.mock
def test_replay_twice_gives_up(tmp_path):
    s = _signer(tmp_path)()
    replay = httpx.Response(403, json={"error": "x", "verdict": "REPLAY"})
    route = respx.post("http://relay.test/upload").mock(return_value=replay)
    out = s.upload("http://relay.test", "n", "trust.score", {})
    assert route.call_count == 2 and out["verdict"] == "REPLAY"


def test_load_component_reads_anchor_jwk(tmp_path):
    priv = Ed25519PrivateKey.generate()
    d = tmp_path / "tm"
    d.mkdir()
    (d / "sig-1.jwk.json").write_text(
        json.dumps(
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": _b64(priv.public_key().public_bytes_raw()),
                "d": _b64(priv.private_bytes_raw()),
                "kid": KID,
            }
        )
    )
    iss, kid, key = keys.load_component("tm", str(tmp_path))
    assert (iss, kid) == (DID, KID)
    assert key.public_key().public_bytes_raw() == priv.public_key().public_bytes_raw()
    s = WitnessSigner(iss, kid, str(d / "sig-1.jwk.json"), str(tmp_path / "st.json"))
    assert s.seal("t", {})[0]["kid"] == KID
