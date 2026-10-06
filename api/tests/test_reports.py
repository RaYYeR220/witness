"""Signed audit reports: the report hash is the canon_hash of the JSON, the HTML shows it,
POST /reports anchors it through the relay and stores both representations, and the write
endpoint fails closed without a token."""

import base64
import json

import httpx
import pytest
import respx
from apiseed import seed_chain
from conftest import PG
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from witness_api import reports
from witness_api.app import create_app
from witness_api.settings import Settings
from witness_core import canon, envelope, schema

RELAY = "http://relay.test"
REPORT_TOKEN = "report-token-0123456789abc"
SIGNER_DID = "did:iota:testnet:0x" + "6b" * 32
SIGNER_KID = SIGNER_DID + "#sig-1"
BLOCK_ID = "0x" + "ab" * 32


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@pytest.fixture
def signer_key(tmp_path):
    key = Ed25519PrivateKey.generate()
    jwk = {"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "kid": SIGNER_KID,
           "d": _b64u(key.private_bytes_raw()), "x": _b64u(key.public_key().public_bytes_raw())}
    path = tmp_path / "sig-1.jwk.json"
    path.write_text(json.dumps(jwk), encoding="utf-8")
    return str(path), key


def _settings(store, signer_path, *, report_token=REPORT_TOKEN) -> Settings:
    return Settings(db=PG, schema=store.schema, coordinator_keys=["0x" + "11" * 32],
                    threshold=1, hornet_url=None, inx_addr=None, report_token=report_token,
                    relay_url=RELAY, report_relay_node="iota-hornet",
                    report_signer_key=signer_path, validate=False)


@pytest.fixture
async def reports_client(store, signer_key):
    app = create_app(_settings(store, signer_key[0]), store=store)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://witness.test") as c:
            yield c


async def test_build_hash_matches_canon_and_html_shows_it(store, vectors):
    await seed_chain(store, vectors)
    report = await reports.build(store, network="private_tangle1", now_ms=1_791_000_000_000)
    rhash = reports.report_hash(report)
    assert rhash == canon.canon_hash(report)
    html = reports.render_html(report, "0x" + rhash.hex())
    assert "0x" + rhash.hex() in html
    assert report["messages"]["total"] > 0  # the seeded chain has messages


async def test_post_report_anchors_and_stores(reports_client, store, vectors, signer_key):
    await seed_chain(store, vectors)
    captured = {}

    def relay_handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        captured["payload"] = payload
        return httpx.Response(200, json={"status_code": 201, "return_payload": "{}",
                                         "witness": {"blockId": BLOCK_ID}})

    async with respx.mock() as mock:
        mock.post(f"{RELAY}/upload").mock(side_effect=relay_handler)
        r = await reports_client.post("/reports", headers={"Authorization": f"Bearer {REPORT_TOKEN}"},
                                      json={})
    assert r.status_code == 201, r.text
    body = r.json()
    rhash_hex = body["reportHash"]
    assert body["blockId"] == BLOCK_ID
    # the returned report JSON canon-hashes to the reportHash
    assert "0x" + canon.canon_hash(body["report"]).hex() == rhash_hex

    # the relay received a producer-signed audit.report envelope naming the same hash
    msg = captured["payload"]["message"]
    assert captured["payload"]["tag"] == "audit.report"
    assert envelope.is_envelope(msg) and msg["att"]["mode"] == "producer"
    assert msg["iss"] == SIGNER_DID and msg["kid"] == SIGNER_KID
    _, key = signer_key
    check = envelope.verify(msg, "audit.report",
                            lambda kid: envelope.KeyInfo(kid, key.public_key().public_bytes_raw(),
                                                         None, None))
    assert check.verdict == "PRODUCER_SIGNED"
    body_env = msg["body"]
    assert body_env["reportHash"] == rhash_hex
    assert schema.classify("audit.report", canon.jcs(msg)).kind == "audit.report"

    # JSON and HTML are retrievable; the HTML shows the hash; block id is stored
    got = await reports_client.get(f"/reports/{rhash_hex}")
    assert got.status_code == 200
    assert "0x" + canon.canon_hash(got.json()).hex() == rhash_hex
    html = await reports_client.get(f"/reports/{rhash_hex}.html")
    assert html.status_code == 200 and rhash_hex in html.text
    assert html.headers["content-type"].startswith("text/html")

    listing = await reports_client.get("/reports")
    items = listing.json()["items"]
    assert len(items) == 1 and items[0]["reportHash"] == rhash_hex
    assert items[0]["blockId"] == BLOCK_ID


async def test_post_report_fails_closed_without_token(store, signer_key):
    # token unset -> 403 even with a bearer; token set but wrong -> 401
    app = create_app(_settings(store, signer_key[0], report_token=None), store=store)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://witness.test") as c:
            assert (await c.post("/reports", json={})).status_code == 403
            assert (await c.post("/reports", headers={"Authorization": "Bearer nope"},
                                 json={})).status_code == 403

    app2 = create_app(_settings(store, signer_key[0]), store=store)
    async with app2.router.lifespan_context(app2):
        transport = httpx.ASGITransport(app=app2)
        async with httpx.AsyncClient(transport=transport, base_url="http://witness.test") as c:
            assert (await c.post("/reports", headers={"Authorization": "Bearer wrong-token-xxxxxxxx"},
                                 json={})).status_code == 401


async def test_post_report_502_when_relay_rejects(reports_client, store, vectors):
    await seed_chain(store, vectors)
    async with respx.mock() as mock:
        mock.post(f"{RELAY}/upload").respond(403, json={"error": "nope", "verdict": "UNAUTHORIZED_WRITER"})
        r = await reports_client.post("/reports", headers={"Authorization": f"Bearer {REPORT_TOKEN}"},
                                      json={})
    assert r.status_code == 502
    # the report JSON/HTML were still stored, so the attempt is auditable
    assert len((await reports_client.get("/reports")).json()["items"]) == 1


async def test_report_range_validation(reports_client):
    r = await reports_client.post("/reports", headers={"Authorization": f"Bearer {REPORT_TOKEN}"},
                                  json={"msFrom": 10, "msTo": 5})
    assert r.status_code == 400
