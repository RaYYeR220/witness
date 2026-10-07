"""Submission ingest: the explorer side of "every submitted message is forwarded".

The modified Messages API (relay) publishes one submission record per upload to MQTT
(`aerios/iota/submissions/{tag}`) and POSTs the same bytes to `/ingest`. Both transports end
in `handle_record`, which stores the submission once (deduplicated by submission id and by
block id), opens its lifecycle and hands the block to the validator.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any, Literal, Protocol
from urllib.parse import unquote, urlsplit

from witness_core import envelope, nesting

from . import events
from .store import Store, Submission

log = logging.getLogger(__name__)

SUBMISSIONS_TOPIC = "aerios/iota/submissions/#"
MAX_QUEUED = 10_000
RECORD_KEYS = ("subId", "receivedAtMs", "tag", "message", "dataHex", "blockId", "hornetStatus",
               "relay")
_HEX = re.compile(r"0x(?:[0-9a-fA-F]{2})*")
_BLOCK_ID = re.compile(r"0x[0-9a-fA-F]{64}")


class MalformedRecord(ValueError):
    """A submission record that does not follow the relay's record format."""


class Enqueuer(Protocol):
    def enqueue(self, block_id: bytes | None, sub_id: str) -> None: ...


def _now_ms() -> int:
    return int(time.time() * 1000)


def _int(v: Any, name: str, *, optional: bool = False) -> int | None:
    if v is None and optional:
        return None
    if type(v) is not int:
        raise MalformedRecord(f"{name} must be an integer")
    return v


def _str(v: Any, name: str, *, optional: bool = False) -> str | None:
    if v is None and optional:
        return None
    if not isinstance(v, str):
        raise MalformedRecord(f"{name} must be a string")
    return v


def parse_record(obj: dict, *, source: Literal["mqtt", "http"]) -> Submission:
    """Validate a relay submission record and turn it into a Submission.

    Strict on shape and types: every key of the record format must be present, hex fields
    must be 0x-prefixed whole bytes, and a block id implies the bytes that were sent.
    Unknown extra keys are ignored. Raises MalformedRecord (a ValueError) on anything else.
    """
    if source not in ("mqtt", "http"):
        raise MalformedRecord(f"unknown source {source!r}")
    if not isinstance(obj, dict):
        raise MalformedRecord("submission record must be a JSON object")
    missing = [k for k in RECORD_KEYS if k not in obj]
    if missing:
        raise MalformedRecord(f"submission record misses {', '.join(missing)}")

    sub_id = _str(obj["subId"], "subId")
    if not sub_id:
        raise MalformedRecord("subId must not be empty")
    received = _int(obj["receivedAtMs"], "receivedAtMs")
    if received < 0:
        raise MalformedRecord("receivedAtMs must not be negative")
    tag = _str(obj["tag"], "tag")
    tag.encode("utf-8")  # a lone surrogate cannot be a Tangle tag; UnicodeError is a ValueError

    data_hex = _str(obj["dataHex"], "dataHex", optional=True)
    if data_hex is not None:
        if not _HEX.fullmatch(data_hex):
            raise MalformedRecord("dataHex must be 0x-prefixed hex of whole bytes")
        data_hex = data_hex.lower()

    block_hex = _str(obj["blockId"], "blockId", optional=True)
    block_id = None
    if block_hex is not None:
        if not _BLOCK_ID.fullmatch(block_hex):
            raise MalformedRecord("blockId must be 0x followed by 64 hex digits")
        if data_hex is None:
            raise MalformedRecord("a record with a blockId must carry the dataHex that was sent")
        block_id = bytes.fromhex(block_hex[2:])

    relay = obj["relay"]
    if not isinstance(relay, dict):
        raise MalformedRecord("relay must be an object")

    # A message the relay sealed is kept only as the ciphertext it posted: never its
    # plaintext, whether the record says so (messageSealed) or the posted bytes show it.
    message = obj["message"]
    if obj.get("messageSealed") is True or envelope.relay_sealed(
            None if data_hex is None else bytes.fromhex(data_hex[2:]), message):
        message = None

    return Submission(
        sub_id=sub_id,
        source=source,
        received_at_ms=received,
        tag=tag,
        message_json=message,
        data_hex=data_hex,
        block_id=block_id,
        hornet_status=_int(obj["hornetStatus"], "hornetStatus", optional=True),
        relay_verdict=_str(relay.get("verdict"), "relay.verdict", optional=True),
        iss=_str(relay.get("iss"), "relay.iss", optional=True),
        seq=_int(relay.get("seq"), "relay.seq", optional=True),
    )


async def handle_record(store: Store, validator: Enqueuer, obj: dict, *,
                        source: Literal["mqtt", "http"]) -> bool:
    """Store one submission record. Returns False when it was already known (same submission
    id, or the same block id delivered by the other transport); only a new submission opens a
    lifecycle, emits `submission` and is queued for validation. Raises ValueError for a
    malformed record."""
    sub = parse_record(obj, source=source)
    now = _now_ms()
    block_hex = None if sub.block_id is None else "0x" + sub.block_id.hex()
    async with store.transaction():
        if not await store.put_submission(sub):
            return False
        detail: dict[str, Any] = {"source": source, "relayReceivedAtMs": sub.received_at_ms,
                                  "hornetStatus": sub.hornet_status}
        if sub.block_id is None:
            detail["reason"] = "the Messages API did not get a block id from the node"
        await store.set_lifecycle(block_id=sub.block_id, sub_id=sub.sub_id, status="RECEIVED",
                                  at_ms=now, detail=detail)
        status = "RECEIVED"
        if sub.block_id is not None:
            status = "SUBMITTED"
            await store.set_lifecycle(block_id=sub.block_id, sub_id=sub.sub_id,
                                      status=status, at_ms=now,
                                      detail={"hornetStatus": sub.hornet_status})
        await store.emit(events.SUBMISSION, {
            "subId": sub.sub_id, "blockId": block_hex, "tag": sub.tag, "source": source,
            "status": status, "hornetStatus": sub.hornet_status,
            "relayVerdict": sub.relay_verdict, "iss": sub.iss, "seq": sub.seq,
        })
    validator.enqueue(sub.block_id, sub.sub_id)
    return True


# -- MQTT consumer ---------------------------------------------------------------------------

Connect = Callable[[], AbstractAsyncContextManager[AsyncIterator[bytes]]]


def _payload_bytes(payload: Any) -> bytes:
    if isinstance(payload, (bytes, bytearray)):
        return bytes(payload)
    if payload is None:
        return b""
    return str(payload).encode()


def counting_queue(on_drop: Callable[[], None]) -> type[asyncio.Queue]:
    """Queue class for aiomqtt's incoming buffer that reports each message it has to drop
    because the buffer is full (aiomqtt itself only logs it)."""

    class CountingQueue(asyncio.Queue):
        def put_nowait(self, item: Any) -> None:
            try:
                super().put_nowait(item)
            except asyncio.QueueFull:
                on_drop()
                raise

    return CountingQueue


def aiomqtt_source(url: str, topic: str, *, client_id: str, max_queued: int = MAX_QUEUED,
                   stats: dict[str, int] | None = None) -> Connect:
    """Connect factory for a real broker. A fixed client id with a persistent session lets
    Mosquitto keep QoS 1 records queued while the explorer is reconnecting. Records arriving
    faster than they are stored wait in a buffer of `max_queued`; overflow is dropped and
    counted in `stats["dropped"]`, the current buffer depth is `stats["backlog"]`."""
    stats = stats if stats is not None else {}

    def dropped() -> None:
        stats["dropped"] = stats.get("dropped", 0) + 1

    parts = urlsplit(url)
    params = {
        "hostname": parts.hostname or "127.0.0.1",
        "port": parts.port or 1883,
        "username": unquote(parts.username) if parts.username else None,
        "password": unquote(parts.password) if parts.password else None,
        "identifier": client_id,
        "clean_session": False,
        "max_queued_incoming_messages": max_queued,
        "queue_type": counting_queue(dropped),
    }

    @asynccontextmanager
    async def connect() -> AsyncIterator[AsyncIterator[bytes]]:
        import aiomqtt

        async with aiomqtt.Client(**params) as client:
            await client.subscribe(topic, qos=1)

            async def payloads() -> AsyncIterator[bytes]:
                async for message in client.messages:
                    stats["backlog"] = len(client.messages)
                    yield _payload_bytes(message.payload)

            yield payloads()

    return connect


class MqttIngest:
    """Subscribes to the relay's submission records and feeds them to `handle_record`.

    Survives anything a message can do (bad or absurdly nested JSON, a bad record, a failing
    store write): the message is logged and counted in `stats`, and the next one is read on
    the same connection. A lost connection is retried with exponential backoff. `stats` also
    reports the broker buffer: `backlog` (records waiting) and `dropped` (buffer overflow).
    """

    def __init__(self, store: Store, validator: Enqueuer, mqtt_url: str,
                 topic: str = SUBMISSIONS_TOPIC, *, client_id: str = "witness-indexer-ingest",
                 connect: Connect | None = None, max_queued: int = MAX_QUEUED,
                 sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
                 initial_backoff_s: float = 0.5, max_backoff_s: float = 8.0) -> None:
        scheme = urlsplit(mqtt_url).scheme
        if scheme not in ("mqtt", "tcp"):
            raise ValueError(f"unsupported MQTT URL scheme: {scheme!r}")
        self.store = store
        self.validator = validator
        self.topic = topic
        self.stats = {"received": 0, "accepted": 0, "duplicates": 0, "bad": 0, "errors": 0,
                      "connect_failures": 0, "disconnects": 0, "dropped": 0, "backlog": 0}
        self._connect = connect or aiomqtt_source(mqtt_url, topic, client_id=client_id,
                                                  max_queued=max_queued, stats=self.stats)
        self._sleep = sleep
        self._initial = initial_backoff_s
        self._max = max_backoff_s
        self._stopping = False
        self._task: asyncio.Task | None = None

    async def run(self) -> None:
        self._task = asyncio.current_task()
        backoff = self._initial
        try:
            while not self._stopping:
                connected = False
                try:
                    async with self._connect() as payloads:
                        connected = True
                        backoff = self._initial
                        log.info("subscribed to %s", self.topic)
                        async for payload in payloads:
                            try:
                                await self._on_payload(payload)
                            except Exception:
                                # Whatever one record does must not tear the connection down.
                                self.stats["bad"] += 1
                                log.exception("dropped a submission record that broke ingest")
                    self.stats["disconnects"] += 1
                except Exception as e:  # noqa: BLE001 - any broker/transport failure: back off, retry
                    key = "disconnects" if connected else "connect_failures"
                    self.stats[key] += 1
                    log.warning("MQTT %s: %s: %s", "connection lost" if connected
                                else "connect failed", type(e).__name__, e)
                if self._stopping:
                    break
                await self._sleep(backoff)
                backoff = min(backoff * 2, self._max)
        except asyncio.CancelledError:
            if not self._stopping:
                raise

    async def stop(self) -> None:
        self._stopping = True
        task = self._task
        if task is not None and task is not asyncio.current_task() and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def _on_payload(self, payload: bytes) -> None:
        self.stats["received"] += 1
        try:
            obj = nesting.loads(payload)
        except ValueError as e:  # not JSON, or nested past the shared cap
            self.stats["bad"] += 1
            log.warning("dropped submission record that is not JSON: %s", e)
            return
        try:
            new = await handle_record(self.store, self.validator, obj, source="mqtt")
        except ValueError as e:
            self.stats["bad"] += 1
            log.warning("dropped malformed submission record: %s", e)
            return
        except Exception:
            self.stats["errors"] += 1
            log.exception("failed to ingest submission record")
            return
        self.stats["accepted" if new else "duplicates"] += 1
