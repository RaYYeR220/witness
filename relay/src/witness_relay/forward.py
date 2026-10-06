"""Forward every submission record to the Advanced Explorer.

Each record is published to MQTT (`aerios/iota/submissions/{tag}`, QoS 1) and, when an
explorer URL is configured, POSTed to `{explorer_url}/ingest`. Forwarding never sits on
the upload path: `ForwardQueue.submit` only appends to a bounded in-memory queue per
sink, and a background worker per sink delivers in order with exponential backoff.
When a queue is full the oldest record is dropped and counted.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections import deque
from typing import Any, Protocol
from urllib.parse import unquote, urlsplit

import httpx

from .config import RelayConfig

log = logging.getLogger(__name__)

TOPIC_PREFIX = "aerios/iota/submissions/"


class Forwarder(Protocol):
    name: str

    async def send(self, record: dict) -> None:
        """Deliver one record or raise. PermanentForwardError means: do not retry."""

    async def aclose(self) -> None: ...


class PermanentForwardError(Exception):
    """The sink refused the record itself; retrying would not help."""


def encode_record(record: dict) -> bytes:
    return json.dumps(record, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode(
        "utf-8"
    )


def submission_topic(tag: str) -> str:
    # Wildcards and NUL are not allowed in a publish topic.
    safe = tag.replace("+", "_").replace("#", "_").replace("\x00", "_")
    return TOPIC_PREFIX + safe


class MqttForwarder:
    """Publishes over one long-lived connection; reconnects on the next send after a failure."""

    def __init__(
        self, url: str, *, client_factory: Any = None, qos: int = 1, timeout_s: float = 5.0
    ):
        parts = urlsplit(url)
        if parts.scheme not in ("mqtt", "tcp"):
            raise ValueError(f"unsupported MQTT URL scheme: {parts.scheme!r}")
        self.name = f"mqtt:{parts.hostname}:{parts.port or 1883}"
        self._params = {
            "hostname": parts.hostname or "127.0.0.1",
            "port": parts.port or 1883,
            "username": unquote(parts.username) if parts.username else None,
            "password": unquote(parts.password) if parts.password else None,
            "identifier": f"witness-relay-{uuid.uuid4().hex[:8]}",
        }
        if client_factory is None:
            import aiomqtt

            client_factory = aiomqtt.Client
        self._factory = client_factory
        self._qos = qos
        self._timeout = timeout_s
        self._client: Any = None

    async def send(self, record: dict) -> None:
        if self._client is None:
            client = self._factory(**self._params)
            await asyncio.wait_for(client.__aenter__(), self._timeout)
            self._client = client
        try:
            await asyncio.wait_for(
                self._client.publish(
                    submission_topic(record.get("tag", "")),
                    payload=encode_record(record),
                    qos=self._qos,
                ),
                self._timeout,
            )
        except BaseException:
            await self._disconnect()
            raise

    async def _disconnect(self) -> None:
        client, self._client = self._client, None
        if client is not None:
            try:
                await asyncio.wait_for(client.__aexit__(None, None, None), self._timeout)
            except Exception:  # the connection is already gone either way
                log.debug("MQTT disconnect from %s failed", self.name, exc_info=True)

    async def aclose(self) -> None:
        await self._disconnect()


class HttpForwarder:
    """POST {explorer_url}/ingest with a bearer token."""

    def __init__(
        self,
        base_url: str,
        token: str | None,
        *,
        client: httpx.AsyncClient | None = None,
        timeout_s: float = 5.0,
    ):
        self.name = "http:" + base_url
        self._url = base_url.rstrip("/") + "/ingest"
        self._headers = {"Content-Type": "application/json"}
        if token:
            self._headers["Authorization"] = f"Bearer {token}"
        self._own = client is None
        self._client = client or httpx.AsyncClient(timeout=timeout_s)

    async def send(self, record: dict) -> None:
        resp = await self._client.post(
            self._url, content=encode_record(record), headers=self._headers
        )
        if resp.is_success:
            return
        if 400 <= resp.status_code < 500 and resp.status_code not in (408, 429):
            raise PermanentForwardError(f"{self._url} answered {resp.status_code}")
        raise ConnectionError(f"{self._url} answered {resp.status_code}")

    async def aclose(self) -> None:
        if self._own:
            await self._client.aclose()


def build_forwarders(cfg: RelayConfig) -> list[Forwarder]:
    sinks: list[Forwarder] = []
    if cfg.mqtt_url:
        sinks.append(MqttForwarder(cfg.mqtt_url))
    if cfg.explorer_url:
        sinks.append(HttpForwarder(cfg.explorer_url, cfg.explorer_token))
    return sinks


class _Lane:
    """One sink's queue and worker."""

    def __init__(
        self,
        sink: Forwarder,
        maxsize: int,
        timeout_s: float,
        backoff_s: tuple[float, float],
        max_attempts: int,
    ):
        self.sink = sink
        self.queue: deque[dict] = deque(maxlen=maxsize)
        self.inflight: dict | None = None
        self.wake = asyncio.Event()
        self.timeout = timeout_s
        self.backoff = backoff_s
        self.max_attempts = max_attempts
        self.stats = {"queued": 0, "sent": 0, "retries": 0, "dropped": 0}
        self.task: asyncio.Task | None = None

    def put(self, record: dict) -> None:
        if len(self.queue) == self.queue.maxlen:
            self.stats["dropped"] += 1
            log.warning("forward queue for %s full; dropping oldest record", self.sink.name)
        self.queue.append(record)
        self.wake.set()

    @property
    def idle(self) -> bool:
        return not self.queue and self.inflight is None

    async def run(self) -> None:
        while True:
            while not self.queue:
                self.wake.clear()
                await self.wake.wait()
            self.inflight = self.queue.popleft()
            await self._deliver(self.inflight)
            self.inflight = None

    async def _deliver(self, record: dict) -> None:
        delay = self.backoff[0]
        for attempt in range(1, self.max_attempts + 1):
            try:
                await asyncio.wait_for(self.sink.send(record), self.timeout)
            except PermanentForwardError as exc:
                log.error("%s refused record %s: %s", self.sink.name, record.get("subId"), exc)
                break
            except Exception as exc:  # noqa: BLE001 - any sink failure means "retry later"
                if attempt == self.max_attempts:
                    break
                self.stats["retries"] += 1
                log.warning(
                    "forwarding to %s failed (attempt %d): %r; retry in %.1fs",
                    self.sink.name,
                    attempt,
                    exc,
                    delay,
                )
                await asyncio.sleep(delay)
                delay = min(delay * 2, self.backoff[1])
            else:
                self.stats["sent"] += 1
                return
        self.stats["dropped"] += 1


class ForwardQueue:
    def __init__(
        self,
        sinks: list[Forwarder],
        *,
        maxsize: int = 1000,
        timeout_s: float = 5.0,
        backoff_s: tuple[float, float] = (0.5, 8.0),
        max_attempts: int = 20,
    ):
        self._lanes = [_Lane(s, maxsize, timeout_s, backoff_s, max_attempts) for s in sinks]

    async def start(self) -> None:
        for lane in self._lanes:
            lane.task = asyncio.create_task(lane.run(), name=f"forward-{lane.sink.name}")

    def submit(self, record: dict) -> None:
        """Queue `record` for every sink. Never blocks and never raises."""
        for lane in self._lanes:
            lane.stats["queued"] += 1
            lane.put(record)

    async def stop(self, drain_s: float = 2.0) -> None:
        """Give pending records `drain_s` to go out, then stop workers and close sinks."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + drain_s
        while any(not lane.idle for lane in self._lanes) and loop.time() < deadline:
            await asyncio.sleep(0.02)
        for lane in self._lanes:
            if lane.task is not None:
                lane.task.cancel()
        for lane in self._lanes:
            if lane.task is not None:
                try:
                    await lane.task
                except asyncio.CancelledError:
                    pass
            pending = len(lane.queue) + (lane.inflight is not None)
            if pending:
                lane.stats["dropped"] += pending
                log.warning(
                    "%d record(s) for %s not forwarded before shutdown", pending, lane.sink.name
                )
            try:
                await asyncio.wait_for(lane.sink.aclose(), 2.0)
            except Exception as exc:  # noqa: BLE001 - shutdown continues regardless
                log.warning("closing %s failed: %r", lane.sink.name, exc)

    def stats(self) -> dict[str, dict[str, int]]:
        return {lane.sink.name: {**lane.stats, "pending": len(lane.queue)} for lane in self._lanes}
