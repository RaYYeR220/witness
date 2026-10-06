import json
import time

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from witness_core import canon, envelope, verdicts
from witness_core.envelope import KeyInfo
from witness_core.sealed import blind_token, decrypt_body

UPLOAD = {"node": "iota-hornet"}
SCORE = {"score": 0.5, "id": "MyDomain:aabbccddeeff"}


def _seal(ident, tag="trust.score", body=None, seq=7, **kw):
    return envelope.seal(
        tag,
        SCORE if body is None else body,
        iss=ident.did,
        kid=ident.kid,
        sign_key=ident.key,
        seq=seq,
        att_mode="producer",
        **kw,
    )


def _resolver(*idents):
    infos = {
        i.kid: KeyInfo(i.kid, i.key.public_key().public_bytes_raw(), None, None) for i in idents
    }
    return infos.get


async def test_ssrf_blocked(make_cfg, hornet, relay):
    async with relay(make_cfg()) as client:
        for params in ({"node": "evil.example"}, {"node": "127.0.0.1:6379/x?"}, {}):
            resp = await client.post(
                "/upload", params=params, json={"tag": "trust.score", "message": SCORE}
            )
            assert resp.status_code == 400
            assert resp.json() == {"error": "unknown node"}
    assert hornet.router.calls.call_count == 0


async def test_producer_envelope_passthrough(make_cfg, hornet, relay, ids, helpers):
    env = _seal(ids.producer, seq=7)
    async with relay(make_cfg()) as client:
        resp = await client.post(
            "/upload", params=UPLOAD, json={"tag": "trust.score", "message": env}
        )
        assert resp.status_code == 200
        witness = resp.json()["witness"]
        assert witness["verdict"] == verdicts.PRODUCER_SIGNED
        assert witness["iss"] == ids.producer.did
        assert witness["seq"] == 7

        # HORNET got the producer's envelope byte for byte (canonical JSON), untouched.
        assert helpers.sent_data(hornet.sent[0]) == canon.jcs(env)
        assert hornet.sent[0]["payload"]["tag"] == "0x" + b"trust.score".hex()

        store = client.app.state.relay.store
        state = await store.issuer_state(ids.producer.did)
        assert state["seq"] == 7
        assert state["last_block_id"] == witness["blockId"]

        listed = await client.get("/receipts", params={"iss": ids.producer.did})
        assert listed.status_code == 200
        [receipt] = listed.json()["receipts"]
        assert receipt["blockId"] == witness["blockId"]
        assert receipt["seq"] == 7


async def test_forged_envelope_rejected(make_cfg, hornet, relay, ids):
    env = _seal(ids.producer)
    env["body"] = {**env["body"], "score": 1.0}
    async with relay(make_cfg()) as client:
        resp = await client.post(
            "/upload", params=UPLOAD, json={"tag": "trust.score", "message": env}
        )
    assert resp.status_code == 403
    assert resp.json()["verdict"] == verdicts.FORGED
    assert hornet.route.call_count == 0


async def test_unauthorized_writer_rejected(make_cfg, hornet, relay, ids):
    env = _seal(ids.outsider)
    async with relay(make_cfg()) as client:
        resp = await client.post(
            "/upload", params=UPLOAD, json={"tag": "trust.score", "message": env}
        )
    assert resp.status_code == 403
    assert resp.json()["verdict"] == verdicts.UNAUTHORIZED_WRITER
    assert hornet.route.call_count == 0


async def test_revoked_key_rejected(make_cfg, hornet, relay, ids, tmp_path, helpers):
    pub = ids.producer.key.public_key().public_bytes_raw()
    keys = tmp_path / "keys.json"
    keys.write_text(
        json.dumps(
            [
                {
                    "kid": ids.producer.kid,
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": helpers.b64u(pub),
                    "revokedAtMs": int(time.time() * 1000) - 1000,
                }
            ]
        )
    )
    async with relay(make_cfg(trusted_keys_path=str(keys))) as client:
        resp = await client.post(
            "/upload", params=UPLOAD, json={"tag": "trust.score", "message": _seal(ids.producer)}
        )
    assert resp.status_code == 403
    assert resp.json()["verdict"] == verdicts.REVOKED_KEY
    assert hornet.route.call_count == 0


async def test_relay_envelope_cannot_be_resubmitted(make_cfg, hornet, relay, helpers):
    async with relay(make_cfg()) as client:
        first = await client.post(
            "/upload", params=UPLOAD, json={"tag": "trust.score", "message": SCORE}
        )
        assert first.status_code == 200
        replayed = helpers.sent_envelope(hornet.sent[0])
        again = await client.post(
            "/upload", params=UPLOAD, json={"tag": "trust.score", "message": replayed}
        )
    assert again.status_code == 403
    assert again.json()["verdict"] == verdicts.REPLAY
    assert hornet.route.call_count == 1


async def test_relay_attestation_anonymous(make_cfg, hornet, relay, ids, helpers):
    async with relay(make_cfg()) as client:
        resp = await client.post(
            "/upload", params=UPLOAD, json={"tag": "trust.score", "message": SCORE}
        )
        assert resp.status_code == 200
    env = helpers.sent_envelope(hornet.sent[0])
    assert env["att"] == {"mode": "relay", "sub": "anonymous"}
    assert env["body"] == SCORE
    assert env["iss"] == ids.relay.did
    check = envelope.verify(env, "trust.score", _resolver(ids.relay))
    assert check.verdict == verdicts.RELAY_ATTESTED


async def test_non_object_message_is_wrapped(make_cfg, hornet, relay, helpers):
    async with relay(make_cfg()) as client:
        resp = await client.post(
            "/upload", params=UPLOAD, json={"tag": "LLO-K8s", "message": [1, "a"]}
        )
        assert resp.status_code == 200
    assert helpers.sent_envelope(hornet.sent[0])["body"] == {"value": [1, "a"]}


def _jwks_setup(hornet, jwks_url):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": "k1", "use": "sig", "alg": "RS256"})
    enc_key = {**jwk, "kid": "k-enc", "use": "enc", "alg": "RSA-OAEP"}
    hornet.router.get(jwks_url).mock(
        return_value=httpx.Response(200, json={"keys": [enc_key, jwk]})
    )

    def token(sub, **claims):
        payload = {"sub": sub, "exp": int(time.time()) + 300, **claims}
        return jwt.encode(payload, key, algorithm="RS256", headers={"kid": "k1"})

    return token


async def test_relay_attestation_with_jwt(make_cfg, hornet, relay, ids, helpers):
    jwks_url = "http://keycloak.test/realms/aerios/protocol/openid-connect/certs"
    token = _jwks_setup(hornet, jwks_url)
    cfg = make_cfg(keycloak_jwks_url=jwks_url)
    async with relay(cfg) as client:
        ok = await client.post(
            "/upload",
            params=UPLOAD,
            json={"tag": "locked", "message": {"status": "deployed"}},
            headers={"Authorization": "Bearer " + token("llo-k8s-svc")},
        )
        assert ok.status_code == 200, ok.text
        env = helpers.sent_envelope(hornet.sent[0])
        assert env["att"] == {"mode": "relay", "sub": "llo-k8s-svc"}
        assert (
            envelope.verify(env, "locked", _resolver(ids.relay)).verdict == verdicts.RELAY_ATTESTED
        )

        bad = await client.post(
            "/upload",
            params=UPLOAD,
            json={"tag": "trust.score", "message": SCORE},
            headers={"Authorization": "Bearer " + token("x")[:-4] + "AAAA"},
        )
        assert bad.status_code == 403
        expired = await client.post(
            "/upload",
            params=UPLOAD,
            json={"tag": "trust.score", "message": SCORE},
            headers={"Authorization": "Bearer " + token("x", exp=int(time.time()) - 60)},
        )
        assert expired.status_code == 403
    assert len(hornet.sent) == 1


async def test_encryption_applied(make_cfg, hornet, relay, ids, helpers):
    cfg = make_cfg(encrypt_tags=["trust.score"])
    async with relay(cfg) as client:
        resp = await client.post(
            "/upload", params=UPLOAD, json={"tag": "trust.score", "message": SCORE}
        )
        assert resp.status_code == 200
    env = helpers.sent_envelope(hornet.sent[0])
    assert "body" not in env
    assert "enc" in env
    assert set(env["bix"]) == {
        blind_token(ids.search_key, "tag", "trust.score"),
        blind_token(ids.search_key, "ie", "MyDomain:aabbccddeeff"),
    }
    assert decrypt_body(env["enc"], ids.kex_kid, ids.kex) == SCORE
    assert (
        envelope.verify(env, "trust.score", _resolver(ids.relay)).verdict == verdicts.RELAY_ATTESTED
    )
    # Plaintext never reaches the node.
    assert b"MyDomain" not in helpers.sent_data(hornet.sent[0])


async def test_oversize_413(make_cfg, hornet, relay):
    async with relay(make_cfg()) as client:
        resp = await client.post(
            "/upload", params=UPLOAD, json={"tag": "trust.score", "message": {"blob": "x" * 40_000}}
        )
        assert resp.status_code == 413
        # Bodies that cannot possibly fit are refused before they are buffered.
        huge = b'{"tag": "t", "message": "' + b"x" * 300_000 + b'"}'
        assert (await client.post("/upload", params=UPLOAD, content=huge)).status_code == 413
        # The refused upload did not burn a sequence number.
        ok = await client.post(
            "/upload", params=UPLOAD, json={"tag": "trust.score", "message": SCORE}
        )
        assert ok.json()["witness"]["seq"] == 1
    assert hornet.route.call_count == 1


async def test_seq_persists_restart(make_cfg, hornet, relay, helpers):
    cfg = make_cfg()
    async with relay(cfg) as client:
        a = (
            await client.post("/upload", params=UPLOAD, json={"tag": "t", "message": {"n": 1}})
        ).json()
        b = (
            await client.post("/upload", params=UPLOAD, json={"tag": "t", "message": {"n": 2}})
        ).json()
    assert b["witness"]["seq"] == a["witness"]["seq"] + 1
    env_b = helpers.sent_envelope(hornet.sent[1])
    assert env_b["prev"] == a["witness"]["blockId"]
    assert "prev" not in helpers.sent_envelope(hornet.sent[0])

    async with relay(cfg) as client:
        c = (
            await client.post("/upload", params=UPLOAD, json={"tag": "t", "message": {"n": 3}})
        ).json()
    assert c["witness"]["seq"] == b["witness"]["seq"] + 1
    assert helpers.sent_envelope(hornet.sent[2])["prev"] == b["witness"]["blockId"]


async def test_failed_hornet_submit_burns_seq_but_keeps_chain(make_cfg, hornet, relay, helpers):
    async with relay(make_cfg()) as client:
        a = (await client.post("/upload", params=UPLOAD, json={"tag": "t", "message": {}})).json()
        hornet.state.status = 400
        failed = await client.post("/upload", params=UPLOAD, json={"tag": "t", "message": {}})
        assert failed.status_code == 502
        hornet.state.status = 201
        c = (await client.post("/upload", params=UPLOAD, json={"tag": "t", "message": {}})).json()
    assert c["witness"]["seq"] == a["witness"]["seq"] + 2
    assert helpers.sent_envelope(hornet.sent[2])["prev"] == a["witness"]["blockId"]


async def test_receipts_and_healthz(make_cfg, hornet, relay, ids):
    async with relay(make_cfg()) as client:
        for tag in ("trust.score", "LLO-K8s", "trust.score"):
            await client.post("/upload", params=UPLOAD, json={"tag": tag, "message": {"x": tag}})
        resp = await client.get("/receipts", params={"tag": "trust.score", "limit": 1})
        assert resp.status_code == 200
        [latest] = resp.json()["receipts"]
        assert latest["tag"] == "trust.score"
        assert latest["seq"] == 3
        assert latest["iss"] == ids.relay.did
        assert latest["verdict"] == verdicts.RELAY_ATTESTED
        everything = (await client.get("/receipts")).json()["receipts"]
        assert [r["seq"] for r in everything] == [3, 2, 1]
        health = await client.get("/healthz")
        assert health.status_code == 200
        assert health.json()["status"] == "ok"
