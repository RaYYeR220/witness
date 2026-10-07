"""The genuine traffic generator (trap runs), offline: relay and Orion are mocked."""

import itertools
import json
import random

import httpx
import pytest
import respx
from witness_chaos import traffic as T
from witness_core import envelope, schema
from witness_sdk.signer import WitnessSigner

RELAY = "http://relay.test"
ORION = "http://orion.test"


class FakeClock:
    def __init__(self, start: int = 1_800_000_000_000) -> None:
        self.ms = start

    def __call__(self) -> int:
        return self.ms

    async def sleep(self, s: float) -> None:
        self.ms += int(s * 1000)


def plan(seed=5, n=4):
    rng = random.Random(seed)
    return T.TrafficPlan(rng, T.trap_ie_ids(rng, n))


def test_plan_is_deterministic_and_well_formed():
    p1, p2 = plan(), plan()
    m1 = [p1.next() for _ in range(200)]
    m2 = [p2.next() for _ in range(200)]
    assert [(m.tag, m.message, m.ie_id) for m in m1] == [(m.tag, m.message, m.ie_id) for m in m2]
    tags = {m.tag for m in m1}
    assert tags == {"trust.score", "LLO-K8s", "LLO-Docker", "self-orchestrator"}
    for m in m1:
        cl = schema.classify(m.tag, json.dumps(m.message).encode())
        assert cl.schema_ok, m
        if m.tag == "trust.score":
            assert cl.ie_id == m.ie_id and m.ie_id in p1.ies
            assert set(m.commitments) == {"rel", "sec", "rep"}
        if m.tag == "self-orchestrator":
            assert m.message["errorCode"] == 0  # status report, not an incident trigger
            assert cl.ie_id in p1.ies
        if m.tag in T.LLO_TAGS:
            assert m.message["event"] != "Service component failed"


def test_scores_move_slowly_and_round_robin():
    p = plan()
    last = dict(p.scores)
    seen = []
    for _ in range(40):
        m = p.score_message()
        seen.append(m.ie_id)
        assert abs(m.message["score"] - last[m.ie_id]) <= T.MAX_STEP + 1e-9
        assert 0.05 <= m.message["score"] <= 0.95
        last[m.ie_id] = m.message["score"]
    assert seen[:4] == p.ies and seen[4:8] == p.ies


def test_trap_ies_are_unscored_by_the_stock_trust_manager():
    e = T.ie_entity("TrapDomain:aabbccddeeff", 0.7)
    assert "internalIpAddress" not in e  # the stock TM skips entities without one
    assert e["id"] == "urn:ngsi-ld:InfrastructureElement:TrapDomain:aabbccddeeff"
    assert e["trustScore"] == {"type": "Property", "value": 0.7}
    assert "trustScore" not in T.ie_entity("x:y", None)


def _relay_reply(request: httpx.Request, counter: list) -> httpx.Response:
    body = json.loads(request.content)
    counter.append(body)
    bid = "0x" + f"{len(counter):064x}"
    verdict = "PRODUCER_SIGNED" if envelope.is_envelope(body["message"]) else "RELAY_ATTESTED"
    return httpx.Response(200, json={"status_code": 201, "return_payload": "{}",
                                     "witness": {"blockId": bid, "verdict": verdict}})


@respx.mock
async def test_generator_sends_through_relay_with_a_prev_chain(tmp_path):
    sent_bodies: list = []
    route = respx.post(f"{RELAY}/upload").mock(
        side_effect=lambda r: _relay_reply(r, sent_bodies))
    orion = respx.patch(url__regex=rf"{ORION}/ngsi-ld/v1/entities/.*/attrs").mock(
        return_value=httpx.Response(204))
    key = tmp_path / "sig.jwk.json"
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    import base64

    d = base64.urlsafe_b64encode(priv.private_bytes_raw()).rstrip(b"=").decode()
    key.write_text(json.dumps({"kty": "OKP", "crv": "Ed25519", "d": d,
                               "kid": "did:key:zTest#k"}))
    state = tmp_path / "state.json"
    T.seed_signer_state(str(state), 1_800_000_000_000)
    signer = WitnessSigner("did:key:zTest", "did:key:zTest#k", str(key), str(state))
    clock = FakeClock()
    async with httpx.AsyncClient() as http:
        gen = T.TrafficGenerator(
            relay_url=RELAY, relay_node="iota-hornet", plan=plan(),
            upload_score=T.sdk_uploader(signer, str(tmp_path / "disc.jsonl")),
            orion=T.OrionAdmin(ORION, http=http), http=http, rate_per_min=30,
            clock_ms=clock, sleep=clock.sleep)
        sent = await gen.run(duration_s=60, min_messages=10)
    assert len(sent) >= 30 and all(s.block_id and s.error is None for s in sent)
    assert all(r.url.params["node"] == "iota-hornet" for r, _ in route.calls)
    scores = [b["message"] for b in sent_bodies if b["tag"] == "trust.score"]
    assert scores and all(envelope.is_envelope(e) for e in scores)
    # Each signed score continues the producer's chain from its previous upload.
    assert "prev" not in scores[0]
    blocks = {i + 1: b for i, b in enumerate(sent_bodies)}
    ids_of_scores = [f"0x{i:064x}" for i, b in blocks.items() if b["tag"] == "trust.score"]
    assert [e["prev"] for e in scores[1:]] == ids_of_scores[:-1]
    assert [e["seq"] for e in scores] == list(range(scores[0]["seq"], scores[0]["seq"]
                                                    + len(scores)))
    assert scores[0]["seq"] > 1_800_000_000_000
    # Legacy LLO / self-orchestrator messages go unsigned; the relay attests them.
    assert all(not envelope.is_envelope(b["message"]) for b in sent_bodies
               if b["tag"] != "trust.score")
    # Orion got every score before the upload (Trust Manager order).
    assert orion.call_count == len(scores)
    # Every IE was scored within the first seconds and never left silent for 30 s.
    by_ie: dict = {}
    for s in sent:
        if s.tag == "trust.score":
            by_ie.setdefault(s.ie_id, []).append(s.at_ms)
    assert set(by_ie) == set(gen.plan.ies)
    for times in by_ie.values():
        assert all(b - a <= T.SCORE_EVERY_MS + 3_000 for a, b in itertools.pairwise(times))
    assert (tmp_path / "disc.jsonl").exists()


@respx.mock
async def test_generator_records_refusals_and_transport_errors():
    respx.post(f"{RELAY}/upload").mock(side_effect=[
        httpx.Response(403, json={"error": "nope", "verdict": "UNAUTHORIZED_WRITER"}),
        httpx.ConnectError("down")])
    p = plan()
    p.ies = p.ies[:1]

    def no_scores(*a):
        raise AssertionError("no score expected")

    clock = FakeClock()
    async with httpx.AsyncClient() as http:
        gen = T.TrafficGenerator(relay_url=RELAY, relay_node="n", plan=p,
                                 upload_score=no_scores, orion=None, http=http,
                                 clock_ms=clock, sleep=clock.sleep)
        s1 = await gen.send(0, T.Planned("LLO-K8s", {"event": "x", "lloId": "l",
                                                     "serviceComponentId": "c"}))
        s2 = await gen.send(1, T.Planned("LLO-K8s", {"event": "x", "lloId": "l",
                                                     "serviceComponentId": "c"}))
    assert (s1.http_status, s1.block_id) == (403, None) and "nope" in s1.error
    assert s2.http_status is None and "ConnectError" in s2.error


async def test_run_stops_only_when_duration_and_count_are_both_met():
    clock = FakeClock()
    p = plan()
    n = 0

    def upload(*a):
        nonlocal n
        n += 1
        return {"http_status": 200, "witness": {"blockId": "0x" + "1" * 64}}

    class Http:
        async def post(self, *a, **k):
            return httpx.Response(200, json={"witness": {"blockId": "0x" + "2" * 64}})

    gen = T.TrafficGenerator(relay_url=RELAY, relay_node="n", plan=p, upload_score=upload,
                             orion=None, http=Http(), rate_per_min=60, clock_ms=clock,
                             sleep=clock.sleep)
    sent = await gen.run(duration_s=10, min_messages=25)
    assert len(sent) == 25  # count dominates
    gen2 = T.TrafficGenerator(relay_url=RELAY, relay_node="n", plan=plan(), upload_score=upload,
                              orion=None, http=Http(), rate_per_min=60, clock_ms=clock,
                              sleep=clock.sleep)
    assert len(await gen2.run(duration_s=40, min_messages=5)) == 40  # duration dominates
    with pytest.raises(ValueError):
        T.TrafficGenerator(relay_url=RELAY, relay_node="n", plan=p, upload_score=upload,
                           orion=None, http=Http(), rate_per_min=0)


@respx.mock
async def test_orion_admin_requests():
    up = respx.post(f"{ORION}/ngsi-ld/v1/entityOperations/upsert/").mock(
        return_value=httpx.Response(204))
    de = respx.delete(f"{ORION}/ngsi-ld/v1/entities/urn:ngsi-ld:InfrastructureElement:D:1"
                      ).mock(side_effect=[httpx.Response(204), httpx.Response(404)])
    async with httpx.AsyncClient() as http:
        o = T.OrionAdmin(ORION, http=http)
        await o.upsert(["D:1", "D:2"], 0.5)
        assert await o.delete("D:1") is True
        assert await o.delete("D:1") is False
    body = json.loads(up.calls[0].request.content)
    assert [e["id"] for e in body] == [T.ie_urn("D:1"), T.ie_urn("D:2")]
    assert "ngsi-ld-core-context" in up.calls[0].request.headers["link"]
    assert de.call_count == 2
