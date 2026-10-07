import asyncio
import json
from contextlib import asynccontextmanager

import pytest
from witness_indexer.ingest import MqttIngest, counting_queue, handle_record, parse_record

BID = bytes(range(32))


def record(**over):
    rec = {
        "subId": "sub-1",
        "receivedAtMs": 1_760_000_000_000,
        "tag": "trust.score",
        "message": {"score": 0.5, "id": "MyDomain:aabbccddeeff"},
        "dataHex": "0x" + b'{"score": 0.5}'.hex(),
        "blockId": "0x" + BID.hex(),
        "hornetStatus": 201,
        "relay": {"verdict": "RELAY_ATTESTED", "iss": "did:key:z6Mk", "seq": 4},
    }
    rec.update(over)
    return rec


class RecordingValidator:
    def __init__(self):
        self.enqueued = []

    def enqueue(self, block_id, sub_id):
        self.enqueued.append((block_id, sub_id))


async def statuses(store, sub_id):
    rows = await store._fetch(
        "SELECT status, detail FROM lifecycle WHERE sub_id = %s ORDER BY at_ms, id", (sub_id,))
    return rows


def test_parse_record_strict():
    sub = parse_record(record(), source="mqtt")
    assert sub.sub_id == "sub-1"
    assert sub.source == "mqtt"
    assert sub.received_at_ms == 1_760_000_000_000
    assert sub.tag == "trust.score"
    assert sub.message_json == {"score": 0.5, "id": "MyDomain:aabbccddeeff"}
    assert sub.data_hex == "0x" + b'{"score": 0.5}'.hex()
    assert sub.block_id == BID
    assert sub.hornet_status == 201
    assert (sub.relay_verdict, sub.iss, sub.seq) == ("RELAY_ATTESTED", "did:key:z6Mk", 4)

    failed = parse_record(
        record(subId="sub-2", dataHex=None, blockId=None, hornetStatus=None,
               relay={"verdict": None, "iss": None, "seq": None}, message=[1, "two"]),
        source="http")
    assert failed.block_id is None and failed.data_hex is None
    assert failed.message_json == [1, "two"]
    assert failed.source == "http"

    upper = parse_record(record(dataHex="0xABCD", blockId="0x" + BID.hex().upper()),
                         source="mqtt")
    assert upper.data_hex == "0xabcd" and upper.block_id == BID


def _without(key):
    rec = record()
    del rec[key]
    return rec


def _relay(**over):
    rec = record()
    rec["relay"] = {**rec["relay"], **over}
    return rec


@pytest.mark.parametrize("bad", [
    "not a dict",
    _without("subId"),
    _without("message"),
    _without("relay"),
    _without("dataHex"),
    record(subId=""),
    record(subId=7),
    record(receivedAtMs="1760000000000"),
    record(receivedAtMs=True),
    record(receivedAtMs=-1),
    record(tag=None),
    record(tag=5),
    record(dataHex="abcd"),
    record(dataHex="0xzz"),
    record(dataHex="0xabc"),
    record(blockId="0x1234"),
    record(blockId="0x" + "g" * 64),
    record(blockId=BID.hex()),
    record(dataHex=None),
    record(hornetStatus="201"),
    record(hornetStatus=False),
    record(relay="RELAY_ATTESTED"),
    _relay(seq="4"),
    _relay(verdict=1),
    _relay(iss=[]),
])
def test_parse_record_rejects(bad):
    with pytest.raises(ValueError):
        parse_record(bad, source="mqtt")


SEALED_DATA = json.dumps({"w": 1, "tag": "audit.report", "sig": "x", "enc": {"ciphertext": "AA"},
                          "bix": ["tok"]}).encode()


def test_sealed_legacy_plaintext_is_never_kept():
    secret = {"reportId": "r-1", "secret": "s0123456789abcdef"}
    flagged = parse_record(record(tag="audit.report", message=None, messageSealed=True,
                                  dataHex="0x" + SEALED_DATA.hex()), source="mqtt")
    assert flagged.message_json is None
    # The record says sealed but still carries a message (refused before anything was
    # posted, so there are no bytes to look at): dropped all the same.
    refused = parse_record(record(tag="audit.report", message=secret, messageSealed=True,
                                  dataHex=None, blockId=None), source="http")
    assert refused.message_json is None
    # An older relay that still forwards the plaintext next to the sealed bytes.
    older = parse_record(record(tag="audit.report", message=secret,
                                dataHex="0x" + SEALED_DATA.hex()), source="mqtt")
    assert older.message_json is None
    # A producer's own sealed envelope is not plaintext: kept as sent.
    own = json.loads(SEALED_DATA)
    producer = parse_record(record(tag="audit.report", message=own,
                                   dataHex="0x" + SEALED_DATA.hex()), source="mqtt")
    assert producer.message_json == own


def test_parse_record_rejects_unknown_source():
    with pytest.raises(ValueError):
        parse_record(record(), source="ftp")


async def test_handle_record_dedupe(store):
    v = RecordingValidator()
    assert await handle_record(store, v, record(), source="mqtt") is True
    # The relay sends identical bytes to both sinks; an HTTP retry under a new id too.
    assert await handle_record(store, v, record(), source="http") is False
    assert await handle_record(store, v, record(subId="sub-retry"), source="http") is False

    rows = await statuses(store, "sub-1")
    assert [r["status"] for r in rows] == ["RECEIVED", "SUBMITTED"]
    assert rows[0]["detail"]["source"] == "mqtt"
    assert v.enqueued == [(BID, "sub-1")]
    assert (await store.stats())["submissions"] == 1

    events = await store.events_after(0, 10)
    assert [e["type"] for e in events] == ["submission"]
    assert events[0]["payload"]["subId"] == "sub-1"
    assert events[0]["payload"]["blockId"] == "0x" + BID.hex()


async def test_handle_record_failed_submit_stays_received(store):
    v = RecordingValidator()
    rec = record(subId="sub-f", blockId=None, dataHex=None, hornetStatus=502)
    assert await handle_record(store, v, rec, source="mqtt") is True
    rows = await statuses(store, "sub-f")
    assert [r["status"] for r in rows] == ["RECEIVED"]
    assert rows[0]["detail"]["hornetStatus"] == 502
    assert v.enqueued == [(None, "sub-f")]


async def test_handle_record_malformed_writes_nothing(store):
    with pytest.raises(ValueError):
        await handle_record(store, RecordingValidator(), record(blockId="0x00"), source="http")
    assert (await store.stats())["submissions"] == 0


class FakeSource:
    """Stands in for the broker: one connection delivering `batches[0]`, and so on.

    A connection whose batch is None fails to connect; after the last batch the connection
    stays open and idle until the consumer is stopped.
    """

    def __init__(self, *batches):
        self.batches = list(batches)
        self.connects = 0
        self.idle = asyncio.Event()

    @asynccontextmanager
    async def connect(self):
        self.connects += 1
        if not self.batches:
            self.idle.set()
            await asyncio.Event().wait()
        batch = self.batches.pop(0)
        if batch is None:
            raise ConnectionRefusedError("broker down")

        async def messages():
            for payload in batch:
                yield payload

        yield messages()


async def test_mqtt_bad_message_does_not_crash(store):
    v = RecordingValidator()
    sleeps = []

    async def fake_sleep(s):
        sleeps.append(s)

    good = json.dumps(record()).encode()
    other = json.dumps(record(subId="sub-9", blockId="0x" + "ab" * 32)).encode()
    source = FakeSource(
        None,  # first connect fails
        [b"\xff\xfe not json", b"[1, 2]", json.dumps({"subId": 1}).encode(), good, good],
        [other],  # connection dropped and re-established
    )
    ingest = MqttIngest(store, v, "mqtt://broker.test:1883", connect=source.connect,
                        sleep=fake_sleep)
    task = asyncio.create_task(ingest.run())
    await asyncio.wait_for(source.idle.wait(), 30)
    await ingest.stop()
    await asyncio.wait_for(task, 5)

    assert ingest.stats["received"] == 6
    assert ingest.stats["bad"] == 3
    assert ingest.stats["accepted"] == 2
    assert ingest.stats["duplicates"] == 1
    assert ingest.stats["connect_failures"] == 1
    assert source.connects == 4
    assert sleeps and sleeps[0] == 0.5
    assert [sid for _, sid in v.enqueued] == ["sub-1", "sub-9"]


async def test_mqtt_store_failure_is_counted_not_fatal(store):
    class Boom:
        def enqueue(self, *_):
            raise RuntimeError("queue gone")

    source = FakeSource([json.dumps(record()).encode()])
    ingest = MqttIngest(store, Boom(), "mqtt://broker.test", connect=source.connect)
    task = asyncio.create_task(ingest.run())
    await asyncio.wait_for(source.idle.wait(), 30)
    await ingest.stop()
    await asyncio.wait_for(task, 5)
    assert ingest.stats["errors"] == 1


def test_mqtt_url_validation():
    with pytest.raises(ValueError):
        MqttIngest(None, None, "http://broker:1883")



async def run_until_idle(ingest, source):
    task = asyncio.create_task(ingest.run())
    await asyncio.wait_for(source.idle.wait(), 30)
    await ingest.stop()
    await asyncio.wait_for(task, 5)


async def test_mqtt_nesting_bomb_keeps_connection(store):
    v = RecordingValidator()
    source = FakeSource([b"[" * 100_000, b'{"a":' * 50_000, json.dumps(record()).encode()])
    ingest = MqttIngest(store, v, "mqtt://broker.test", connect=source.connect)
    await run_until_idle(ingest, source)
    assert ingest.stats["bad"] == 2
    assert ingest.stats["accepted"] == 1
    assert ingest.stats["connect_failures"] == 0
    assert ingest.stats["disconnects"] == 1  # only the end of the fake stream
    assert source.connects == 2


async def test_mqtt_record_past_the_shared_cap_is_dropped():
    deep = b'{"a":' + b"[" * 2500 + b"]" * 2500 + b"}"  # 2501 levels
    source = FakeSource([deep])
    validator = RecordingValidator()
    ingest = MqttIngest(None, validator, "mqtt://broker.test", connect=source.connect)
    await run_until_idle(ingest, source)
    assert (ingest.stats["bad"], ingest.stats["accepted"]) == (1, 0)


async def test_mqtt_handler_failure_is_contained():
    class Fragile(MqttIngest):
        async def _on_payload(self, payload):
            if payload == b"boom":
                raise RecursionError("deep")
            self.stats["accepted"] += 1

    source = FakeSource([b"boom", b"fine"])
    ingest = Fragile(None, RecordingValidator(), "mqtt://broker.test", connect=source.connect)
    await run_until_idle(ingest, source)
    assert ingest.stats["bad"] == 1
    assert ingest.stats["accepted"] == 1
    assert ingest.stats["disconnects"] == 1


def test_counting_queue_reports_drops():
    drops = []
    q = counting_queue(lambda: drops.append(1))(maxsize=2)
    q.put_nowait(1)
    q.put_nowait(2)
    with pytest.raises(asyncio.QueueFull):
        q.put_nowait(3)
    assert len(drops) == 1 and q.qsize() == 2


async def test_aiomqtt_source_bounds_buffer(monkeypatch):
    import aiomqtt

    clients = []
    idle = asyncio.Event()

    class Message:
        def __init__(self, payload):
            self.payload = payload

    class Messages:
        def __init__(self, client):
            self.client = client

        def __len__(self):
            return self.client.queue.qsize()

        def __aiter__(self):
            return self

        async def __anext__(self):
            if self.client is not clients[0]:
                idle.set()
                await asyncio.Event().wait()
            if self.client.queue.empty():
                raise StopAsyncIteration
            return self.client.queue.get_nowait()

    class FakeClient:
        def __init__(self, **kw):
            self.kw = kw
            self.queue = kw["queue_type"](maxsize=kw["max_queued_incoming_messages"])
            self.messages = Messages(self)
            clients.append(self)
            first = len(clients) == 1
            for p in (b"x", "y", b"z") if first else ():  # three arrive before the first read
                try:
                    self.queue.put_nowait(Message(p))
                except asyncio.QueueFull:
                    pass  # aiomqtt logs and discards

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def subscribe(self, topic, qos):
            self.subscribed = (topic, qos)

    async def no_sleep(_):
        pass

    monkeypatch.setattr(aiomqtt, "Client", FakeClient)
    ingest = MqttIngest(None, RecordingValidator(), "mqtt://user:pw@broker.test:1884",
                        max_queued=2, sleep=no_sleep)
    task = asyncio.create_task(ingest.run())
    await asyncio.wait_for(idle.wait(), 10)
    await ingest.stop()
    await asyncio.wait_for(task, 5)

    kw = clients[0].kw
    assert (kw["hostname"], kw["port"], kw["username"], kw["password"]) == (
        "broker.test", 1884, "user", "pw")
    assert kw["identifier"] == "witness-indexer-ingest" and kw["clean_session"] is False
    assert kw["max_queued_incoming_messages"] == 2
    assert clients[0].subscribed == ("aerios/iota/submissions/#", 1)
    assert ingest.stats["dropped"] == 1
    assert ingest.stats["received"] == 2 and ingest.stats["bad"] == 2
    assert ingest.stats["backlog"] == 0
