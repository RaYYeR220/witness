"""Signed audit reports: the report hash is the canon_hash of the JSON and the HTML shows
it; anchoring is two-phase (a failed post leaves a report marked NOT anchored); posts are
serialised with strictly increasing sequence numbers; only a witness-relay is posted to;
the HTML page is locked down and escapes everything; totals cover the whole range."""

import base64
import json

import httpx
import pytest
import respx
from apiseed import _row, seed_chain
from conftest import PG
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException
from witness_api import reports, routes_reports
from witness_api.app import create_app
from witness_api.settings import Settings
from witness_core import canon, envelope, schema
from witness_core.ids import from_hex
from witness_indexer.store import Alert

RELAY = "http://relay.test"
REPORT_TOKEN = "report-token-0123456789abc"
AUTH = {"Authorization": f"Bearer {REPORT_TOKEN}"}
SIGNER_DID = "did:iota:testnet:0x" + "6b" * 32
SIGNER_KID = SIGNER_DID + "#sig-1"
RELAY_HEALTH = {"status": "ok", "relay": "did:iota:testnet:0x" + "e6" * 32, "db": True,
                "forward": {"queued": 0}}
IE_A = "MyDomain:fa163e5e25ef"
IE_B = "MyDomain:0123456789ab"
SCRIPT_IE = "<script>alert(1)</script>:aabbccddeeff"
SCRIPT_TAG = "<script>t()</script>"
CSP = ("default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "
       "form-action 'none'; frame-ancestors 'none'")


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


def _settings(store, signer_path, *, report_token=REPORT_TOKEN, relay_url=RELAY) -> Settings:
    return Settings(db=PG, schema=store.schema, coordinator_keys=["0x" + "11" * 32],
                    threshold=1, hornet_url=None, inx_addr=None, report_token=report_token,
                    relay_url=relay_url, report_relay_node="iota-hornet",
                    report_signer_key=signer_path, validate=False)


async def _client(settings, store):
    app = create_app(settings, store=store)
    ctx = app.router.lifespan_context(app)
    await ctx.__aenter__()
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                               base_url="http://witness.test")
    return ctx, client


@pytest.fixture
async def reports_client(store, signer_key):
    ctx, client = await _client(_settings(store, signer_key[0]), store)
    try:
        yield client
    finally:
        await client.aclose()
        await ctx.__aexit__(None, None, None)


class Relay:
    """A witness-relay stand-in: answers /healthz like one and records every upload."""

    def __init__(self, mock, *, upload_status=200):
        self.envelopes: list[dict] = []
        self.upload_status = upload_status
        mock.get(f"{RELAY}/healthz").respond(200, json=RELAY_HEALTH)
        mock.post(f"{RELAY}/upload").mock(side_effect=self._upload)

    def _upload(self, request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        assert request.url.params["node"] == "iota-hornet"
        assert payload["tag"] == "audit.report"
        self.envelopes.append(payload["message"])
        if self.upload_status != 200:
            return httpx.Response(self.upload_status,
                                  json={"error": "nope", "verdict": "UNAUTHORIZED_WRITER"})
        block = "0x" + f"{len(self.envelopes):064x}"
        return httpx.Response(200, json={"status_code": 201, "return_payload": "{}",
                                         "witness": {"blockId": block}})


# -- hash and HTML ------------------------------------------------------------------------------

async def test_build_hash_matches_canon_and_html_shows_it(store, vectors):
    await seed_chain(store, vectors)
    report = await reports.build(store, network="private_tangle1", at_ms=1_791_000_000_000)
    rhash = reports.report_hash(report)
    assert rhash == canon.canon_hash(report)
    html = reports.render_html(report, "0x" + rhash.hex())
    assert "0x" + rhash.hex() in html
    assert "NOT anchored" in html
    assert report["messages"]["total"] > 0 and report["messages"]["confirmed"] > 0


def test_html_escapes_markup_in_ie_and_tag():
    report = {"v": 1, "kind": reports.KIND, "network": "private_tangle1", "generatedAt": 1,
              "range": {"msFrom": None, "msTo": None}, "ie": SCRIPT_IE,
              "messages": {"total": 1, "encrypted": 0, "plaintext": 1, "confirmed": 1,
                           "byVerdict": {"<b>V</b>": 1}},
              "alerts": {"total": 0, "bySeverity": {}, "byRule": {}},
              "anchors": {"total": 0, "byStatus": {}, "latest": None},
              "proofs": [{"blockId": "0x" + "ab" * 32, "tag": SCRIPT_TAG, "kind": "unknown",
                          "ieId": SCRIPT_IE, "iss": None, "verdict": "UNSIGNED_LEGACY",
                          "msIndex": 1, "wfIndex": 0, "proof": "/proofs/0x"}],
              "proofsTruncated": False}
    html = reports.render_html(report, "0x" + "cd" * 32, anchored=True,
                               block_id="0x" + "ef" * 32, signer="did:x:<i>")
    assert "<script>" not in html and "<b>" not in html and "<i>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&lt;script&gt;t()&lt;/script&gt;" in html


# -- POST /reports ------------------------------------------------------------------------------

async def test_post_report_anchors_and_stores(reports_client, store, vectors, signer_key):
    await seed_chain(store, vectors)
    async with respx.mock() as mock:
        relay = Relay(mock)
        r = await reports_client.post("/reports", headers=AUTH, json={})
    assert r.status_code == 201, r.text
    body = r.json()
    rhash_hex = body["reportHash"]
    assert body["anchored"] is True and body["blockId"] == "0x" + "1".zfill(64)
    assert body["iss"] == SIGNER_DID and body["anchoredAtMs"] is not None
    assert "0x" + canon.canon_hash(body["report"]).hex() == rhash_hex

    # the relay received a producer-signed audit.report envelope naming the same hash
    (msg,) = relay.envelopes
    assert envelope.is_envelope(msg) and msg["att"]["mode"] == "producer"
    assert msg["iss"] == SIGNER_DID and msg["kid"] == SIGNER_KID and msg["seq"] == body["seq"]
    pub = signer_key[1].public_key().public_bytes_raw()
    check = envelope.verify(msg, "audit.report",
                            lambda kid: envelope.KeyInfo(kid, pub, None, None))
    assert check.verdict == "PRODUCER_SIGNED"
    assert msg["body"] == {"reportHash": rhash_hex,
                           "generatedAt": body["report"]["generatedAt"]}
    c = schema.classify("audit.report", canon.jcs(msg))
    assert (c.kind, c.schema_ok) == ("audit.report", True)

    got = (await reports_client.get(f"/reports/{rhash_hex}")).json()
    assert got["anchored"] is True and got["blockId"] == body["blockId"]
    assert "0x" + canon.canon_hash(got["report"]).hex() == rhash_hex
    html = await reports_client.get(f"/reports/{rhash_hex}.html")
    assert html.status_code == 200 and rhash_hex in html.text
    assert "Anchored on the Tangle" in html.text and body["blockId"] in html.text
    assert "NOT anchored" not in html.text
    assert html.headers["content-type"].startswith("text/html")
    assert html.headers["content-security-policy"] == CSP
    assert html.headers["x-content-type-options"] == "nosniff"

    items = (await reports_client.get("/reports")).json()["items"]
    assert [(i["reportHash"], i["anchored"], i["blockId"]) for i in items] == [
        (rhash_hex, True, body["blockId"])]


async def test_failed_post_leaves_report_not_anchored(reports_client, store, vectors):
    await seed_chain(store, vectors)
    async with respx.mock() as mock:
        Relay(mock, upload_status=403)
        r = await reports_client.post("/reports", headers=AUTH, json={})
    assert r.status_code == 502
    (item,) = (await reports_client.get("/reports")).json()["items"]
    assert item["anchored"] is False and item["blockId"] is None and item["seq"] is not None
    got = (await reports_client.get(f"/reports/{item['reportHash']}")).json()
    assert got["anchored"] is False and got["blockId"] is None
    html = (await reports_client.get(f"/reports/{item['reportHash']}.html")).text
    assert "NOT anchored" in html and "Anchored on the Tangle" not in html


async def test_reports_in_the_same_ms_get_increasing_seq(reports_client, store, vectors,
                                                         monkeypatch):
    await seed_chain(store, vectors)
    frozen = 1_791_300_000_000
    monkeypatch.setattr(reports, "now_ms", lambda: frozen)
    async with respx.mock() as mock:
        relay = Relay(mock)
        a = await reports_client.post("/reports", headers=AUTH, json={"ie": IE_A})
        b = await reports_client.post("/reports", headers=AUTH, json={"ie": IE_B})
        # the very same report again: already anchored, nothing is posted
        again = await reports_client.post("/reports", headers=AUTH, json={"ie": IE_A})
    assert (a.status_code, b.status_code, again.status_code) == (201, 201, 200)
    assert a.json()["report"]["generatedAt"] == b.json()["report"]["generatedAt"] == frozen
    assert [e["seq"] for e in relay.envelopes] == [frozen, frozen + 1]
    assert (a.json()["seq"], b.json()["seq"]) == (frozen, frozen + 1)
    assert a.json()["anchored"] and b.json()["anchored"]
    assert again.json()["reportHash"] == a.json()["reportHash"]
    assert again.json()["blockId"] == a.json()["blockId"]


async def test_seq_continues_from_the_database(store, vectors, signer_key, monkeypatch):
    """A restarted API (new process, new lock) still continues above the stored seq."""
    await seed_chain(store, vectors)
    monkeypatch.setattr(reports, "now_ms", lambda: 1_000)
    seqs = []
    for ie in (IE_A, IE_B):
        ctx, client = await _client(_settings(store, signer_key[0]), store)
        try:
            async with respx.mock() as mock:
                relay = Relay(mock)
                r = await client.post("/reports", headers=AUTH, json={"ie": ie})
                assert r.status_code == 201, r.text
                seqs += [e["seq"] for e in relay.envelopes]
        finally:
            await client.aclose()
            await ctx.__aexit__(None, None, None)
    assert seqs == [1_000, 1_001]


async def test_refuses_a_relay_that_is_not_witness_relay(reports_client, store):
    async with respx.mock(assert_all_called=False) as mock:
        mock.get(f"{RELAY}/healthz").respond(404, text="<h1>Not Found</h1>")  # legacy Flask API
        upload = mock.post(f"{RELAY}/upload").respond(200, json={})
        r = await reports_client.post("/reports", headers=AUTH, json={})
    assert r.status_code == 503 and r.json()["detail"] == "relay is not a witness relay"
    assert not upload.called
    assert (await reports_client.get("/reports")).json()["items"] == []


async def test_relay_url_is_required(store, signer_key):
    ctx, client = await _client(_settings(store, signer_key[0], relay_url=None), store)
    try:
        r = await client.post("/reports", headers=AUTH, json={})
        assert r.status_code == 503 and "WITNESS_RELAY_URL" in r.json()["detail"]
    finally:
        await client.aclose()
        await ctx.__aexit__(None, None, None)


async def test_post_report_fails_closed_without_token(store, signer_key):
    ctx, client = await _client(_settings(store, signer_key[0], report_token=None), store)
    try:
        assert (await client.post("/reports", json={})).status_code == 403
        assert (await client.post("/reports", headers={"Authorization": "Bearer nope"},
                                  json={})).status_code == 403
    finally:
        await client.aclose()
        await ctx.__aexit__(None, None, None)
    ctx, client = await _client(_settings(store, signer_key[0]), store)
    try:
        r = await client.post("/reports", headers={"Authorization": "Bearer wrong-token-xxxxx"},
                              json={})
        assert r.status_code == 401
    finally:
        await client.aclose()
        await ctx.__aexit__(None, None, None)


async def test_request_validation(reports_client):
    r = await reports_client.post("/reports", headers=AUTH, json={"msFrom": 10, "msTo": 5})
    assert r.status_code == 400
    r = await reports_client.post("/reports", headers=AUTH, json={"ie": "no-mac-here"})
    assert r.status_code == 422


async def test_markup_in_ie_and_tag_is_escaped_on_the_page(reports_client, store):
    data = b'{"x": 1}'
    row = _row(b"\x42" * 32, SCRIPT_TAG, data, ms_index=5, wf_index=0, ts=1_700_000_000)
    row.ie_id = SCRIPT_IE
    await store.put_message(row)
    async with respx.mock() as mock:
        Relay(mock)
        r = await reports_client.post("/reports", headers=AUTH, json={"ie": SCRIPT_IE})
    assert r.status_code == 201, r.text
    assert r.json()["report"]["proofs"][0]["tag"] == SCRIPT_TAG
    page = await reports_client.get(f"/reports/{r.json()['reportHash']}.html")
    assert "<script>" not in page.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page.text
    assert "&lt;script&gt;t()&lt;/script&gt;" in page.text
    assert page.headers["content-security-policy"] == CSP


# -- listing and totals -----------------------------------------------------------------------

async def test_list_reports_pages_with_a_cursor(reports_client, store, monkeypatch):
    clock = iter(range(1_000, 1_100))
    monkeypatch.setattr(reports, "now_ms", lambda: next(clock))
    async with respx.mock() as mock:
        Relay(mock)
        for _ in range(3):
            assert (await reports_client.post("/reports", headers=AUTH, json={})).status_code \
                == 201
    first = (await reports_client.get("/reports", params={"limit": 2})).json()
    assert len(first["items"]) == 2 and first["nextCursor"]
    gen = [i["generatedAtMs"] for i in first["items"]]
    assert gen == sorted(gen, reverse=True)
    second = (await reports_client.get("/reports", params={"limit": 2,
                                                           "cursor": first["nextCursor"]})).json()
    assert len(second["items"]) == 1 and second["nextCursor"] is None
    seen = {i["reportHash"] for i in first["items"] + second["items"]}
    assert len(seen) == 3
    assert (await reports_client.get("/reports", params={"cursor": "!!"})).status_code == 400
    # A cursor nested past the shared cap: refused by the length limit over HTTP, and by
    # the decoder itself should it ever be reached another way.
    deep = base64.urlsafe_b64encode(b"[" * 2501 + b"]" * 2501).decode().rstrip("=")
    assert (await reports_client.get("/reports", params={"cursor": deep})).status_code == 422
    with pytest.raises(HTTPException) as caught:
        routes_reports._decode_cursor(deep)
    assert (caught.value.status_code, caught.value.detail) == (400, "invalid cursor")
    assert (await reports_client.get("/reports", params={"limit": 201})).status_code == 422


async def test_totals_are_counted_over_the_whole_range(store, vectors):
    tagged = await seed_chain(store, vectors)
    ms_ts = {m["index"]: m["timestamp"] for m in vectors("milestones")}
    lo_ms, hi_ms = min(tagged.values()), max(tagged.values())
    assert lo_ms != hi_ms
    in_block = next(b for b, ms in tagged.items() if ms == lo_ms)
    out_block = next(b for b, ms in tagged.items() if ms == hi_ms)
    after_lo = min(i for i in ms_ts if i > lo_ms)
    alerts = [
        Alert("REPLAY", "high", from_hex(in_block), None, {}, 5),
        Alert("FORGED", "critical", from_hex(out_block), None, {}, 6),
        Alert("ANCHOR_MISMATCH", "critical", None, None, {"k": 1}, ms_ts[lo_ms] * 1000 + 1,
              dedupe_key="in"),
        Alert("ANCHOR_MISMATCH", "critical", None, None, {"k": 2},
              ms_ts[after_lo] * 1000 + 1, dedupe_key="out"),
    ]
    for a in alerts:
        assert await store.put_alert(a)
    await store.put_anchor(seq=1, from_ms=lo_ms, to_ms=hi_ms, ms_root=None, checkpoint=None,
                           checkpoint_hash=None, network="testnet", created_at_ms=1,
                           status="anchored")
    await store.put_anchor(seq=2, from_ms=hi_ms + 100, to_ms=hi_ms + 200, ms_root=None,
                           checkpoint=None, checkpoint_hash=None, network="testnet",
                           created_at_ms=2, status="pending")

    whole = await reports.build(store, network="private_tangle1", at_ms=1)
    assert whole["alerts"]["total"] == 4 and whole["anchors"]["total"] == 2
    ranged = await reports.build(store, network="private_tangle1", frm=lo_ms, to=lo_ms, at_ms=1)
    assert ranged["alerts"]["byRule"] == {"ANCHOR_MISMATCH": 1, "REPLAY": 1}
    assert ranged["anchors"] == {"total": 1, "byStatus": {"anchored": 1},
                                 "latest": ranged["anchors"]["latest"]}
    assert ranged["anchors"]["latest"]["seq"] == 1
    assert ranged["messages"]["total"] == sum(1 for ms in tagged.values() if ms == lo_ms)

    capped = await reports.build(store, network="private_tangle1", at_ms=1, proof_limit=1)
    assert len(capped["proofs"]) == 1 and capped["proofsTruncated"] is True
    assert capped["messages"]["confirmed"] == whole["messages"]["confirmed"] > 1
