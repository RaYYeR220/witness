"""Every submit attempt is forwarded to the explorer (MQTT + HTTP), without ever blocking it."""

import asyncio
import json
import time
import uuid
from typing import ClassVar

import httpx
import pytest
import respx
from witness_core import verdicts
from witness_relay.config import RelayConfig
from witness_relay.forward import (
    ForwardQueue,
    HttpForwarder,
    MqttForwarder,
    PermanentForwardError,
    build_forwarders,
    submission_topic,
)

UPLOAD = {"node": "iota-hornet"}
EXPLORER = "http://explorer.test"
RECORD_KEYS = {
    "subId",
    "receivedAtMs",
    "tag",
    "message",
    "dataHex",
    "blockId",
    "hornetStatus",
    "relay",
}


class FakeMqtt:
    """Stands in for aiomqtt.Client: records publishes, can be told to fail."""

    instances: ClassVar[list["FakeMqtt"]] = []

    def __init__(self, **params):
        self.params = params
        self.published: list[tuple[str, bytes, int]] = []
        self.fail = False
        FakeMqtt.instances.append(self)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def publish(self, topic, payload=None, qos=0, **kw):
        if self.fail:
            raise ConnectionError("broker gone")
        self.published.append((topic, payload, qos))


@pytest.fixture
def fake_mqtt():
    FakeMqtt.instances.clear()
    return FakeMqtt


async def test_forward_mqtt_and_http(make_cfg, hornet, relay, ids, fake_mqtt, eventually):
    ingested: list[httpx.Request] = []
    hornet.router.post(EXPLORER + "/ingest").mock(
        side_effect=lambda r: ingested.append(r) or httpx.Response(202)
    )
    mqtt = MqttForwarder("mqtt://broker.test:1883", client_factory=fake_mqtt)
    http = HttpForwarder(EXPLORER, "s3cret")
    message = {"score": 0.5, "id": "MyDomain:aabbccddeeff"}

    async with relay(make_cfg(), forwarders=[mqtt, http]) as client:
        resp = await client.post(
            "/upload", params=UPLOAD, json={"tag": "trust.score", "message": message}
        )
        assert resp.status_code == 200
        await eventually(
            lambda: ingested and fake_mqtt.instances and fake_mqtt.instances[0].published
        )

    [(topic, payload, qos)] = fake_mqtt.instances[0].published
    assert fake_mqtt.instances[0].params["hostname"] == "broker.test"
    assert topic == "aerios/iota/submissions/trust.score"
    assert qos == 1
    [req] = ingested
    assert req.headers["authorization"] == "Bearer s3cret"
    assert req.headers["content-type"] == "application/json"
    # Both sinks receive the identical record.
    assert req.content == payload
    record = json.loads(payload)
    assert set(record) == RECORD_KEYS
    uuid.UUID(record["subId"])
    assert record["tag"] == "trust.score"
    assert record["message"] == message
    assert record["dataHex"] == hornet.sent[0]["payload"]["data"]
    assert record["blockId"] == resp.json()["witness"]["blockId"]
    assert record["hornetStatus"] == 201
    assert record["relay"] == {
        "verdict": verdicts.RELAY_ATTESTED,
        "iss": ids.relay.did,
        "seq": 1,
    }
    assert abs(record["receivedAtMs"] - time.time() * 1000) < 60_000


class Exploding:
    name = "exploding"

    def __init__(self):
        self.calls = 0

    async def send(self, record):
        self.calls += 1
        raise RuntimeError("sink down")

    async def aclose(self):
        pass


class Hanging:
    name = "hanging"

    async def send(self, record):
        await asyncio.sleep(3600)

    async def aclose(self):
        pass


class DeadBroker(FakeMqtt):
    async def __aenter__(self):
        raise ConnectionError("broker unreachable")


async def test_forward_failure_does_not_block_submit(make_cfg, hornet, relay):
    hornet.router.post(EXPLORER + "/ingest").mock(side_effect=httpx.ConnectTimeout("slow"))
    broken_mqtt = MqttForwarder("mqtt://broker.test:1883", client_factory=DeadBroker)
    sinks = [Exploding(), Hanging(), HttpForwarder(EXPLORER, "t"), broken_mqtt]

    async with relay(make_cfg(), forwarders=sinks) as client:
        for i in range(3):
            t0 = time.monotonic()
            # A hanging sink would hold the request forever if it were on the upload path;
            # the per-request bound is far below every sink timeout (5 s).
            resp = await asyncio.wait_for(
                client.post(
                    "/upload", params=UPLOAD, json={"tag": "trust.score", "message": {"i": i}}
                ),
                timeout=4.0,
            )
            assert resp.status_code == 200
            assert set(resp.json()) == {"status_code", "return_payload", "witness"}
            assert time.monotonic() - t0 < 2.5
        assert sinks[0].calls >= 1
        closing = time.monotonic()
    # Shutdown does not hang on a stuck sink either (drain window 0.2 s in tests).
    assert time.monotonic() - closing < 3.0


async def test_failed_submit_forwarded(make_cfg, hornet, relay, ids, recorder, eventually):
    async with relay(make_cfg(), forwarders=[recorder]) as client:
        # HORNET rejects the block.
        hornet.state.status = 400
        resp = await client.post(
            "/upload", params=UPLOAD, json={"tag": "trust.score", "message": {"a": 1}}
        )
        assert resp.status_code == 502
        # HORNET unreachable.
        hornet.state.error = httpx.ConnectError("refused")
        resp = await client.post(
            "/upload", params=UPLOAD, json={"tag": "trust.score", "message": {"a": 2}}
        )
        assert resp.status_code == 400
        hornet.state.error = None
        # Policy refusal.
        resp = await client.post(
            "/upload", params=UPLOAD, json={"tag": "locked", "message": {"a": 3}}
        )
        assert resp.status_code == 403
        # Oversize.
        resp = await client.post(
            "/upload", params=UPLOAD, json={"tag": "trust.score", "message": {"b": "x" * 40_000}}
        )
        assert resp.status_code == 413
        await eventually(lambda: len(recorder.records) == 4)

    rejected, unreachable, refused, oversize = recorder.records
    for rec in recorder.records:
        assert set(rec) == RECORD_KEYS
        assert rec["blockId"] is None

    assert rejected["hornetStatus"] == 400
    assert rejected["dataHex"] == hornet.sent[0]["payload"]["data"]
    assert rejected["relay"]["verdict"] == verdicts.RELAY_ATTESTED
    assert rejected["relay"]["iss"] == ids.relay.did

    assert unreachable["hornetStatus"] is None
    assert unreachable["dataHex"] is None
    assert unreachable["message"] == {"a": 2}

    assert refused["relay"] == {"verdict": verdicts.UNAUTHORIZED_WRITER, "iss": None, "seq": None}
    assert refused["dataHex"] is None and refused["hornetStatus"] is None

    assert oversize["dataHex"] is None and oversize["hornetStatus"] is None


async def test_unknown_node_not_forwarded(make_cfg, hornet, relay, recorder):
    async with relay(make_cfg(), forwarders=[recorder]) as client:
        await client.post("/upload", params={"node": "evil"}, json={"tag": "t", "message": {}})
        await asyncio.sleep(0.05)
    assert recorder.records == []


# --- queue behaviour (no database needed) ----------------------------------------------


class Flaky:
    name = "flaky"

    def __init__(self, failures):
        self.failures = failures
        self.delivered: list[dict] = []

    async def send(self, record):
        if self.failures:
            self.failures -= 1
            raise ConnectionError("try again")
        self.delivered.append(record)

    async def aclose(self):
        pass


async def test_queue_retries_in_order():
    sink = Flaky(failures=2)
    queue = ForwardQueue([sink], backoff_s=(0.01, 0.02))
    await queue.start()
    for i in range(3):
        queue.submit({"tag": "t", "i": i})
    deadline = time.monotonic() + 3
    while len(sink.delivered) < 3 and time.monotonic() < deadline:
        await asyncio.sleep(0.01)
    await queue.stop(drain_s=0.5)
    assert [r["i"] for r in sink.delivered] == [0, 1, 2]
    assert queue.stats()["flaky"]["retries"] == 2


async def test_queue_is_bounded_and_drops_oldest():
    gate = asyncio.Event()

    class Slow:
        name = "slow"
        delivered: ClassVar[list[dict]] = []

        async def send(self, record):
            await gate.wait()
            self.delivered.append(record)

        async def aclose(self):
            pass

    sink = Slow()
    queue = ForwardQueue([sink], maxsize=3)
    await queue.start()
    for i in range(10):
        queue.submit({"tag": "t", "i": i})
        await asyncio.sleep(0)
    gate.set()
    await queue.stop(drain_s=1.0)
    stats = queue.stats()["slow"]
    assert stats["dropped"] > 0
    # The newest records survive; nothing beyond capacity (+1 in flight) is kept.
    assert [r["i"] for r in sink.delivered][-3:] == [7, 8, 9]
    assert len(sink.delivered) <= 4


async def test_queue_drops_permanent_failures():
    class Rejecting:
        name = "rejecting"
        calls = 0

        async def send(self, record):
            Rejecting.calls += 1
            raise PermanentForwardError("400 bad record")

        async def aclose(self):
            pass

    queue = ForwardQueue([Rejecting()], backoff_s=(0.01, 0.02))
    await queue.start()
    queue.submit({"tag": "t"})
    await asyncio.sleep(0.1)
    await queue.stop(drain_s=0.1)
    assert Rejecting.calls == 1
    assert queue.stats()["rejecting"]["dropped"] == 1


async def test_mqtt_forwarder_reconnects(fake_mqtt):
    fwd = MqttForwarder("mqtt://user:pw@broker.test:1999", client_factory=fake_mqtt)
    await fwd.send({"tag": "a/b+c#", "x": 1})
    first = fake_mqtt.instances[0]
    assert first.params["port"] == 1999
    assert first.params["username"] == "user" and first.params["password"] == "pw"
    first.fail = True
    with pytest.raises(ConnectionError):
        await fwd.send({"tag": "t"})
    await fwd.send({"tag": "t"})
    assert len(fake_mqtt.instances) == 2
    assert fake_mqtt.instances[1].published[0][0] == "aerios/iota/submissions/t"
    await fwd.aclose()


def test_submission_topic_is_publishable():
    assert submission_topic("trust.score") == "aerios/iota/submissions/trust.score"
    topic = submission_topic("a+b#c\x00")
    assert "+" not in topic and "#" not in topic and "\x00" not in topic


async def test_http_forwarder_classifies_errors():
    with respx.mock() as router:
        route = router.post(EXPLORER + "/ingest")
        fwd = HttpForwarder(EXPLORER, "t")
        route.mock(return_value=httpx.Response(400))
        with pytest.raises(PermanentForwardError):
            await fwd.send({"tag": "t"})
        route.mock(return_value=httpx.Response(503))
        with pytest.raises(Exception) as exc:
            await fwd.send({"tag": "t"})
        assert not isinstance(exc.value, PermanentForwardError)
        route.mock(return_value=httpx.Response(429))
        with pytest.raises(Exception) as exc:
            await fwd.send({"tag": "t"})
        assert not isinstance(exc.value, PermanentForwardError)
        await fwd.aclose()


def test_build_forwarders_from_config():
    base = {
        "allowed_nodes": {},
        "relay_did": "did:key:z",
        "relay_kid": "did:key:z#z",
        "relay_key_path": "k.pem",
        "policy_path": "policy.json",
        "db_url": "postgresql://x",
    }
    assert build_forwarders(RelayConfig(**base, mqtt_url=None, explorer_url=None)) == []
    sinks = build_forwarders(
        RelayConfig(
            **base,
            mqtt_url="mqtt://127.0.0.1:1883",
            explorer_url=EXPLORER,
            explorer_token="t",
        )
    )
    assert [type(s) for s in sinks] == [MqttForwarder, HttpForwarder]
