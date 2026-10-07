import asyncio
import json
import logging
import time
from urllib.parse import quote

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from witness_core import canon, envelope, verdicts
from witness_core.envelope import KeyInfo
from witness_core.sealed import blind_token, decrypt_body, encrypt_body
from witness_relay.app import create_app
from witness_relay.receipts import ReceiptStore

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


async def test_definitive_failures_release_relay_seq(make_cfg, hornet, relay, helpers):
    async with relay(make_cfg()) as client:
        a = (await client.post("/upload", params=UPLOAD, json={"tag": "t", "message": {}})).json()
        # HORNET rejects the block (4xx): nothing stored, the seq goes back.
        hornet.state.status = 400
        failed = await client.post("/upload", params=UPLOAD, json={"tag": "t", "message": {}})
        assert failed.status_code == 502
        hornet.state.status = 201
        # Connection refused: never sent, the seq goes back too.
        hornet.state.error = httpx.ConnectError("refused")
        unreachable = await client.post("/upload", params=UPLOAD, json={"tag": "t", "message": {}})
        assert unreachable.status_code == 400
        hornet.state.error = None
        # Sent but no answer (timeout): it may be on the Tangle, so the seq stays used.
        hornet.state.error = httpx.ReadTimeout("slow")
        await client.post("/upload", params=UPLOAD, json={"tag": "t", "message": {}})
        hornet.state.error = None
        c = (await client.post("/upload", params=UPLOAD, json={"tag": "t", "message": {}})).json()
    assert c["witness"]["seq"] == a["witness"]["seq"] + 2
    assert helpers.sent_envelope(hornet.sent[-1])["prev"] == a["witness"]["blockId"]


async def test_tag_longer_than_64_bytes_is_400(make_cfg, hornet, relay, recorder):
    async with relay(make_cfg(), forwarders=[recorder]) as client:
        resp = await client.post("/upload", params=UPLOAD, json={"tag": "é" * 33, "message": {}})
        assert resp.status_code == 400
        ok = await client.post("/upload", params=UPLOAD, json={"tag": "t", "message": {}})
        assert ok.json()["witness"]["seq"] == 1  # no seq consumed by the refused tag
    assert hornet.route.call_count == 1
    assert [r["tag"] for r in recorder.records] == ["t"]


async def test_chain_head_moves_even_if_receipt_write_fails(make_cfg, hornet, relay, helpers):
    async with relay(make_cfg()) as client:
        # PostgreSQL text cannot hold NUL, so this receipt insert fails after HORNET accepted.
        first = await client.post(
            "/upload", params=UPLOAD, json={"tag": "nul\u0000tag", "message": {}}
        )
        assert first.status_code == 200
        second = await client.post("/upload", params=UPLOAD, json={"tag": "t", "message": {}})
        assert second.status_code == 200
    assert helpers.sent_envelope(hornet.sent[1])["prev"] == first.json()["witness"]["blockId"]


async def test_producer_replay_rejected(make_cfg, hornet, relay, ids):
    env7 = _seal(ids.producer, seq=7)
    async with relay(make_cfg()) as client:
        first = await client.post(
            "/upload", params=UPLOAD, json={"tag": "trust.score", "message": env7}
        )
        assert first.status_code == 200
        for env in (env7, _seal(ids.producer, seq=5), _seal(ids.producer, seq=7)):
            again = await client.post(
                "/upload", params=UPLOAD, json={"tag": "trust.score", "message": env}
            )
            assert again.status_code == 403
            assert again.json()["verdict"] == verdicts.REPLAY
        newer = await client.post(
            "/upload",
            params=UPLOAD,
            json={"tag": "trust.score", "message": _seal(ids.producer, seq=8)},
        )
        assert newer.status_code == 200
        state = await client.app.state.relay.store.issuer_state(ids.producer.did)
    assert hornet.route.call_count == 2
    assert state["seq"] == 8
    assert state["last_block_id"] == newer.json()["witness"]["blockId"]


async def test_producer_nonce_reuse_rejected_like_the_indexer(make_cfg, hornet, relay, ids):
    nonce = bytes(range(16))
    async with relay(make_cfg()) as client:
        first = await client.post("/upload", params=UPLOAD, json={
            "tag": "trust.score", "message": _seal(ids.producer, seq=7, nonce=nonce)})
        assert first.status_code == 200
        # Newer seq, same nonce: the indexer would record REPLAY, so it is not posted.
        again = await client.post("/upload", params=UPLOAD, json={
            "tag": "trust.score", "message": _seal(ids.producer, seq=8, nonce=nonce)})
        assert again.status_code == 403
        assert again.json()["verdict"] == verdicts.REPLAY
        assert first.json()["witness"]["blockId"] in again.json()["error"]
        # A replayed seq is named before a broken body, in the indexer's order.
        broken = await client.post("/upload", params=UPLOAD, json={
            "tag": "trust.score", "message": _seal(ids.producer, seq=7, body={"score": 7})})
        assert broken.json()["verdict"] == verdicts.REPLAY
    assert hornet.route.call_count == 1


async def test_legacy_message_past_the_nesting_cap_is_400(make_cfg, hornet, relay):
    deep: object = "leaf"
    for _ in range(64):  # 64 levels: 65 inside the relay's envelope
        deep = {"n": deep}
    async with relay(make_cfg()) as client:
        r = await client.post("/upload", params=UPLOAD, json={"tag": "t", "message": deep})
        assert r.status_code == 400
        assert r.json()["verdict"] == verdicts.MALFORMED
    assert hornet.route.call_count == 0


async def test_concurrent_same_seq_exactly_one_wins(make_cfg, hornet, relay, ids):
    a = _seal(ids.producer, seq=3, body={"score": 0.1, "id": "D:aabbccddeeff"})
    b = _seal(ids.producer, seq=3, body={"score": 0.9, "id": "D:aabbccddeeff"})
    async with relay(make_cfg()) as client:
        results = await asyncio.gather(
            *(
                client.post("/upload", params=UPLOAD, json={"tag": "trust.score", "message": env})
                for env in (a, b)
            )
        )
    assert sorted(r.status_code for r in results) == [200, 403]
    [loser] = [r for r in results if r.status_code == 403]
    assert loser.json()["verdict"] == verdicts.REPLAY
    assert hornet.route.call_count == 1


async def test_producer_seq_released_when_nothing_was_sent(make_cfg, hornet, relay, ids):
    env = _seal(ids.producer, seq=4)
    msg = {"tag": "trust.score", "message": env}
    async with relay(make_cfg()) as client:
        hornet.state.status = 400
        assert (await client.post("/upload", params=UPLOAD, json=msg)).status_code == 502
        hornet.state.status = 201
        hornet.state.error = httpx.ConnectError("refused")
        assert (await client.post("/upload", params=UPLOAD, json=msg)).status_code == 400
        hornet.state.error = None
        # The producer can retry the very same envelope.
        assert (await client.post("/upload", params=UPLOAD, json=msg)).status_code == 200


async def test_chain_head_never_moves_back(make_cfg, ids):
    cfg = make_cfg()
    store = await ReceiptStore.open(cfg.db_url, cfg.db_schema)
    try:
        iss = ids.producer.did
        assert await store.reserve(iss, 5) == -1
        await store.advance(iss, 5, "0x" + "a" * 64)
        await store.advance(iss, 5, "0x" + "b" * 64)
        await store.advance(iss, 4, "0x" + "c" * 64)
        assert (await store.issuer_state(iss))["last_block_id"] == "0x" + "a" * 64
        assert await store.reserve(iss, 5) is None
        assert await store.reserve(iss, 6) == 5
        assert await store.release(iss, 6, 5)
        assert not await store.release(iss, 6, 5)  # compare-and-set: already released
        await store.advance(iss, 6, "0x" + "d" * 64)
        assert (await store.issuer_state(iss))["last_block_id"] == "0x" + "d" * 64
    finally:
        await store.close()


async def test_runs_as_a_role_that_owns_only_its_schema(make_cfg):
    # deploy/compose/db-init.sql gives the relay a role that owns its schema and nothing else:
    # no CREATE on the database, so the store must not try to create a schema that exists.
    import secrets as pysecrets

    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo

    cfg = make_cfg()
    role, password = f"relay_{pysecrets.token_hex(6)}", pysecrets.token_urlsafe(16)
    with psycopg.connect(cfg.db_url, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
            sql.Identifier(role), sql.Literal(password)))
        admin.execute(sql.SQL("CREATE SCHEMA {} AUTHORIZATION {}").format(
            sql.Identifier(cfg.db_schema), sql.Identifier(role)))
    try:
        dsn = make_conninfo(cfg.db_url, user=role, password=password)
        store = await ReceiptStore.open(dsn, cfg.db_schema)
        try:
            assert await store.reserve("did:example:a", 1) == -1
            await store.migrate()  # a second start finds everything in place
        finally:
            await store.close()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            await ReceiptStore.open(dsn, cfg.db_schema + "_other")
    finally:
        with psycopg.connect(cfg.db_url, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(
                sql.Identifier(cfg.db_schema)))
            admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))


async def test_encrypt_tag_seals_legacy_writes_only(make_cfg, hornet, relay, ids, helpers):
    """On an encrypted tag the relay seals what it attests. An allowed producer's own
    envelope goes through as signed, sealed or not: the producer owns its confidentiality
    (the API's signed audit reports rely on that)."""
    cfg = make_cfg(encrypt_tags=["trust.score"])
    plain = _seal(ids.producer, seq=1)
    sealed = envelope.seal(
        "trust.score",
        None,
        iss=ids.producer.did,
        kid=ids.producer.kid,
        sign_key=ids.producer.key,
        seq=2,
        att_mode="producer",
        enc=encrypt_body(SCORE, cfg.recipients),
    )
    async with relay(cfg) as client:
        for env in (plain, sealed):
            resp = await client.post(
                "/upload", params=UPLOAD, json={"tag": "trust.score", "message": env}
            )
            assert resp.status_code == 200
            assert resp.json()["witness"]["verdict"] == verdicts.PRODUCER_SIGNED
        legacy = await client.post(
            "/upload", params=UPLOAD, json={"tag": "trust.score", "message": SCORE}
        )
        assert legacy.json()["witness"]["verdict"] == verdicts.RELAY_ATTESTED
    assert [helpers.sent_data(s) for s in hornet.sent[:2]] == [canon.jcs(plain), canon.jcs(sealed)]
    attested = helpers.sent_envelope(hornet.sent[2])
    assert "body" not in attested and decrypt_body(attested["enc"], ids.kex_kid, ids.kex) == SCORE


async def test_sealed_legacy_plaintext_never_leaves_the_relay(
    make_cfg, hornet, relay, ids, helpers, eventually
):
    """What the relay seals goes out only sealed: the forwarded record (MQTT and /ingest)
    carries no `message` for it, accepted or refused, and none of its bytes show the
    plaintext. A producer's own envelope on the same tag is forwarded as sent."""
    secret = {"reportId": "r-77", "secret": "s0123456789abcdef"}

    class Encoded(helpers.Recording):
        def __init__(self):
            super().__init__()
            self.raw: list[bytes] = []

        async def send(self, item) -> None:
            self.raw.append(item.payload)
            await super().send(item)

    rec = Encoded()
    cfg = make_cfg(encrypt_tags=["audit.report"])
    report = _seal(ids.producer, tag="audit.report",
                   body={"reportHash": "0x" + "ab" * 32, "generatedAt": 1}, seq=1)
    async with relay(cfg, forwarders=[rec]) as client:
        ok = await client.post("/upload", params=UPLOAD,
                               json={"tag": "audit.report", "message": secret})
        assert ok.status_code == 200
        big = {**secret, "pad": "x" * 40_000}
        too_big = await client.post("/upload", params=UPLOAD,
                                    json={"tag": "audit.report", "message": big})
        assert too_big.status_code == 413
        signed = await client.post("/upload", params=UPLOAD,
                                   json={"tag": "audit.report", "message": report})
        assert signed.status_code == 200
        await eventually(lambda: len(rec.records) == 3)
    sealed_ok, sealed_refused, producer = rec.records
    for r in (sealed_ok, sealed_refused):
        assert (r["message"], r["messageSealed"]) == (None, True)
    assert sealed_ok["dataHex"] is not None and sealed_refused["dataHex"] is None
    for raw in rec.raw[:2]:
        assert b"r-77" not in raw and b"s0123456789abcdef" not in raw
    assert (producer["message"], producer["messageSealed"]) == (report, False)
    sent = helpers.sent_envelope(hornet.sent[0])
    assert "body" not in sent and decrypt_body(sent["enc"], ids.kex_kid, ids.kex) == secret


async def test_signed_body_that_breaks_the_schema_refused(
    make_cfg, hornet, relay, ids, recorder, eventually
):
    """The explorer stores a validly signed message whose body breaks its tag's schema as
    MALFORMED; the relay refuses it up front (400) and spends no seq on it."""
    broken = _seal(ids.producer, body={"id": "not-an-ie-id", "score": 7}, seq=3)
    async with relay(make_cfg(), forwarders=[recorder]) as client:
        refused = await client.post(
            "/upload", params=UPLOAD, json={"tag": "trust.score", "message": broken}
        )
        assert refused.status_code == 400
        assert refused.json() == {
            "error": "body breaks the trust.score schema",
            "verdict": verdicts.MALFORMED,
        }
        assert hornet.route.call_count == 0
        await eventually(lambda: recorder.records)
        assert recorder.records[0]["relay"]["verdict"] == verdicts.MALFORMED
        null_body = envelope.seal("trust.score", None, iss=ids.producer.did,
                                  kid=ids.producer.kid, sign_key=ids.producer.key, seq=3,
                                  att_mode="producer")
        refused = await client.post(
            "/upload", params=UPLOAD, json={"tag": "trust.score", "message": null_body}
        )
        assert refused.status_code == 400
        assert refused.json()["error"] == "body is not a JSON object"
        fixed = _seal(ids.producer, seq=3)
        ok = await client.post("/upload", params=UPLOAD, json={"tag": "trust.score", "message": fixed})
        assert ok.status_code == 200
        assert ok.json()["witness"]["verdict"] == verdicts.PRODUCER_SIGNED


async def test_passthrough_tag_is_byte_exact_legacy(
    make_cfg, hornet, relay, recorder, helpers, eventually
):
    vec = json.loads((helpers.vectors / "legacy_upload_response.json").read_text())
    legacy_block_id = json.loads(json.loads(vec["bodyUtf8"])["return_payload"])["blockId"]
    blocks = json.loads((helpers.vectors / "rest_block.json").read_text())
    [legacy] = [b["block"]["payload"] for b in blocks if b["blockId"] == legacy_block_id]

    async with relay(make_cfg(passthrough_tags=["trust.score"]), forwarders=[recorder]) as client:
        resp = await client.post("/upload", params=UPLOAD, json=vec["request"])
        assert resp.status_code == 200
        witness = resp.json()["witness"]
        receipts = (await client.get("/receipts", params={"tag": "trust.score"})).json()["receipts"]
        await eventually(lambda: recorder.records)

    # The node receives exactly what the original API sent for this request.
    assert hornet.sent[0]["payload"]["tag"] == legacy["tag"]
    assert hornet.sent[0]["payload"]["data"] == legacy["data"]
    assert witness["verdict"] == verdicts.UNSIGNED_LEGACY
    assert witness["iss"] is None and witness["seq"] is None
    assert [r["blockId"] for r in receipts] == [witness["blockId"]]
    assert receipts[0]["verdict"] == verdicts.UNSIGNED_LEGACY
    [record] = recorder.records
    assert record["dataHex"] == legacy["data"]
    assert record["relay"] == {"verdict": verdicts.UNSIGNED_LEGACY, "iss": None, "seq": None}


def test_encryption_needs_recipients_and_a_search_key(make_cfg):
    from dataclasses import replace

    cfg = make_cfg(encrypt_tags=["audit.report"])
    with pytest.raises(ValueError, match="RELAY_SEARCH_KEY_PATH"):
        create_app(replace(cfg, search_key_path=None))
    with pytest.raises(ValueError, match="RELAY_RECIPIENTS_PATH"):
        create_app(replace(cfg, recipients=[]))
    create_app(replace(make_cfg(), search_key_path=None, recipients=[]))  # nothing sealed


def test_passthrough_and_encryption_cannot_overlap(make_cfg):
    with pytest.raises(ValueError):
        create_app(make_cfg(encrypt_tags=["x"], passthrough_tags=["x"]))


def test_startup_warns_about_tags_without_relay(make_cfg, ids, caplog):
    policy = {
        "version": 1,
        "tags": {
            "only-producer": {"allowed": [ids.producer.did]},
            "with-relay": {"allowed": [ids.relay.did]},
            "legacy": {"allowed": []},
        },
        "default": {"allowed": ["*"]},
    }
    with caplog.at_level(logging.WARNING, logger="witness_relay"):
        create_app(make_cfg(policy=policy, passthrough_tags=["legacy"]))
    warned = [r.getMessage() for r in caplog.records if "relay DID" in r.getMessage()]
    assert len(warned) == 1 and "only-producer" in warned[0]


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


async def test_bodies_nested_too_deep_are_refused(make_cfg, hornet, relay):
    """Past the shared parse cap the body is refused as such (2501 levels parse with
    json.loads on every platform); a message too deep for the relay to sign is a 400 too,
    never a server error."""
    deep = b'{"tag":"trust.score","message":' + b"[" * 2500 + b"]" * 2500 + b"}"
    nested: list = []
    for _ in range(600):
        nested = [nested]
    async with relay(make_cfg()) as client:
        r = await client.post("/upload", params=UPLOAD, content=deep,
                              headers={"content-type": "application/json"})
        assert r.status_code == 400
        assert r.json()["error"] == "body is JSON nested deeper than 2500 levels"
        r = await client.post("/upload", params=UPLOAD,
                              json={"tag": "trust.score", "message": {"x": nested}})
        assert r.status_code == 400
        assert r.json()["error"].startswith("message cannot be signed")
    assert hornet.route.call_count == 0


async def test_non_canonical_did_is_refused_not_retried(make_cfg, hornet, relay):
    """An upper-case did:iota DID used to make the relay answer 503 forever (the anchor
    answers for the lower-case spelling). It is FORGED now, without a lookup."""
    did = "did:iota:testnet:0x" + "AB" * 32
    env = envelope.seal("free", {"a": 1}, iss=did, kid=did + "#sig-1",
                        sign_key=Ed25519PrivateKey.generate(), seq=1, att_mode="producer")
    route = hornet.router.get(url__startswith="http://anchor.test/").mock(
        return_value=httpx.Response(503))
    async with relay(make_cfg(resolver_url="http://anchor.test")) as client:
        resp = await client.post("/upload", params=UPLOAD, json={"tag": "free", "message": env})
    assert resp.status_code == 403, resp.text
    assert resp.json() == {"error": "non-canonical DID", "verdict": verdicts.FORGED}
    assert route.call_count == 0 and hornet.route.call_count == 0


async def test_hostile_did_document_is_refused_not_retried(make_cfg, hornet, relay):
    """A DID document nested 600 levels deep names no usable key: FORGED (403), not 503."""
    did = "did:iota:testnet:0x" + "ab" * 32
    key = Ed25519PrivateKey.generate()
    env = envelope.seal("free", {"a": 1}, iss=did, kid=did + "#sig-1", sign_key=key, seq=1,
                        att_mode="producer")
    deep: object = "leaf"
    for _ in range(600):
        deep = {"n": deep}
    doc = {"doc": {"id": did, "x": deep}, "version": 1, "historyComplete": True,
           "keys": [{"kid": "#sig-1", "type": "Ed25519", "revokedAtMs": None,
                     "publicKeyHex": key.public_key().public_bytes_raw().hex()}]}
    route = hornet.router.get(f"http://anchor.test/resolve/{quote(did, safe='')}").mock(
        return_value=httpx.Response(200, json=doc))
    async with relay(make_cfg(resolver_url="http://anchor.test")) as client:
        for _ in range(2):
            resp = await client.post("/upload", params=UPLOAD,
                                     json={"tag": "free", "message": env})
            assert resp.status_code == 403, resp.text
            assert resp.json()["verdict"] == verdicts.FORGED
    assert route.call_count == 1 and hornet.route.call_count == 0


async def test_resolver_outage_is_a_temporary_refusal(make_cfg, hornet, relay):
    """A DID resolver that cannot answer (here 401, then 503) refuses with 503 and caches
    nothing; once it answers, the same envelope goes through."""
    did = "did:iota:testnet:0x" + "ab" * 32
    key = Ed25519PrivateKey.generate()
    env = envelope.seal("free", {"a": 1}, iss=did, kid=did + "#sig-1", sign_key=key, seq=1,
                        att_mode="producer")
    doc = {"doc": {"id": did}, "version": 1, "historyComplete": True,
           "keys": [{"kid": "#sig-1", "type": "Ed25519", "revokedAtMs": None,
                     "publicKeyHex": key.public_key().public_bytes_raw().hex()}]}
    route = hornet.router.get(f"http://anchor.test/resolve/{quote(did, safe='')}")
    async with relay(make_cfg(resolver_url="http://anchor.test")) as client:
        for status in (401, 503):
            route.mock(return_value=httpx.Response(status))
            resp = await client.post("/upload", params=UPLOAD,
                                     json={"tag": "free", "message": env})
            assert resp.status_code == 503
            assert resp.headers["retry-after"] == "5"
            assert "retry later" in resp.json()["error"]
            assert "verdict" not in resp.json()
        assert hornet.route.call_count == 0
        route.mock(return_value=httpx.Response(200, json=doc))
        resp = await client.post("/upload", params=UPLOAD, json={"tag": "free", "message": env})
    assert resp.status_code == 200, resp.text
    assert hornet.route.call_count == 1
    assert route.call_count == 3
