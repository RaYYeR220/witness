import asyncio
import asyncio.base_events
import asyncio.proactor_events
import asyncio.selector_events
import json
import socket
import threading
from pathlib import Path

import pytest
import yaml
from witness_core import bundle, checkpoint
from witness_core.bundle import VerifierConfig
from witness_core.codec import Ed25519Sig
from witness_core.ids import blake2b256, from_hex

VECTORS = Path(__file__).resolve().parents[2] / "core" / "tests" / "vectors"
NETWORK = "private_tangle1"
TRAIL = "0x" + "7a" * 32
REBASED = {"network": "testnet", "trail": TRAIL, "record": 3, "tx": "5xGp7rWq2Tz9"}


def vec(name: str):
    return json.loads((VECTORS / f"{name}.json").read_text(encoding="utf-8"))


@pytest.fixture
def sample_keys() -> list[bytes]:
    return [from_hex(k) for k in vec("coordinator_keys")["privateKeys"]]


@pytest.fixture
def cfg() -> VerifierConfig:
    return VerifierConfig(
        network=NETWORK,
        trusted_coordinator_keys={from_hex(k) for k in vec("coordinator_keys")["publicKeys"]},
        threshold=2,
        rebased_network="testnet",
        trail_id=TRAIL,
    )


@pytest.fixture
def real_bundle() -> dict:
    """A genuine bundle for a tagged block of a captured milestone, anchored."""
    milestones, cones, blocks = vec("milestones"), vec("cones"), vec("blocks")
    raw_of = {b["blockId"]: b for b in blocks}
    target = next(
        (ms, cone, bid)
        for ms, cone in zip(milestones, cones, strict=True)
        for bid in cone["blockIdsWhiteFlagOrder"]
        if bid in raw_of and raw_of[bid]["kind"] != "milestone"
    )
    ms, cone, bid = target
    ids = [from_hex(m["milestoneId"]) for m in milestones]
    pos = milestones.index(ms)
    cp = checkpoint.build(
        NETWORK, "MyDomain",
        (milestones[0]["index"], ids[0]), (milestones[-1]["index"], ids[-1]),
        ids, 11, blake2b256(b"writer policy v1"), None,
    )
    return bundle.build(
        network=NETWORK,
        block_raw=from_hex(raw_of[bid]["raw"]),
        milestone_essence=from_hex(ms["essence"]),
        milestone_sigs=[Ed25519Sig(from_hex(s["pk"]), from_hex(s["sig"]))
                        for s in ms["signatures"]],
        cone_ids=[from_hex(i) for i in cone["blockIdsWhiteFlagOrder"]],
        envelope_check=None,
        did_doc_snapshot=None,
        anchor={"checkpoint": cp, "msPath": checkpoint.membership_path(ids, pos),
                "rebased": dict(REBASED)},
    )


@pytest.fixture
def no_network(monkeypatch):
    """Any attempt to open a socket or send an HTTP request fails the test."""
    import httpx

    def boom(*a, **k):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr(httpx.Client, "send", boom)
    monkeypatch.setattr(httpx.AsyncClient, "send", boom)


@pytest.fixture(scope="session")
def key():
    from witness_chaos import attacks

    return yaml.safe_load(
        Path(attacks.__file__).with_name("answer_key.yaml").read_text(encoding="utf-8"))


# ------------------------------------------------------------------------- no-network guard

_guard = threading.local()


def _blocked(where: str, target: object, attempts: list[str]) -> None:
    attempts.append(f"{where} -> {target!r}")
    raise AssertionError(f"network access attempted outside a live test: {where} {target!r}")


@pytest.fixture(autouse=True)
def _never_reach_a_stack(request, monkeypatch):
    """Every chaos test runs with real networking cut off, unless marked `live`.

    The runner talks to a real aeriOS stack on loopback (Orion :1026, relay :5557, API
    :7200, HORNET, MQTT, Postgres). A test that forgets to stub one path must fail here
    instead of injecting traffic into whatever stack happens to run on this machine.
    Blocked: socket connects (sync clients, paho-mqtt), asyncio connects (httpx/anyio,
    aiomqtt, also the Windows proactor path that bypasses socket.connect) and psycopg
    connects (libpq opens its own sockets). In-process mocks (respx, MockTransport,
    fakes) never reach these layers and keep working. The attempt is also recorded and
    re-raised at teardown, so code that swallows exceptions cannot hide it.
    """
    if request.node.get_closest_marker("live"):
        yield
        return
    attempts: list[str] = []
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_socketpair = socket.socketpair

    def allowed(sock) -> bool:
        return getattr(_guard, "socketpair", False) or sock.family not in (
            socket.AF_INET, socket.AF_INET6)

    def connect(self, address):
        if not allowed(self):
            _blocked("socket.connect", address, attempts)
        return real_connect(self, address)

    def connect_ex(self, address):
        if not allowed(self):
            _blocked("socket.connect_ex", address, attempts)
        return real_connect_ex(self, address)

    def socketpair(*a, **k):
        # On Windows socketpair() is a loopback connect; asyncio needs it for every loop.
        _guard.socketpair = True
        try:
            return real_socketpair(*a, **k)
        finally:
            _guard.socketpair = False

    def create_connection(address, *a, **k):
        _blocked("socket.create_connection", address, attempts)

    async def loop_create_connection(self, protocol_factory, host=None, port=None, *a, **k):
        _blocked("loop.create_connection", (host, port), attempts)

    async def loop_sock_connect(self, sock, address):
        _blocked("loop.sock_connect", address, attempts)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    monkeypatch.setattr(socket, "socketpair", socketpair)
    monkeypatch.setattr(socket, "create_connection", create_connection)
    monkeypatch.setattr(asyncio.base_events.BaseEventLoop, "create_connection",
                        loop_create_connection)
    monkeypatch.setattr(asyncio.selector_events.BaseSelectorEventLoop, "sock_connect",
                        loop_sock_connect)
    monkeypatch.setattr(asyncio.proactor_events.BaseProactorEventLoop, "sock_connect",
                        loop_sock_connect)
    try:
        import psycopg
    except ImportError:  # pragma: no cover - psycopg is a chaos dependency
        psycopg = None
    if psycopg is not None:
        def pg_connect(*a, **k):
            _blocked("psycopg.connect", a[1:] or k.get("conninfo"), attempts)

        async def pg_connect_async(*a, **k):
            _blocked("psycopg.AsyncConnection.connect", a[1:] or k.get("conninfo"),
                     attempts)

        monkeypatch.setattr(psycopg.Connection, "connect", classmethod(pg_connect))
        monkeypatch.setattr(psycopg, "connect", lambda *a, **k: pg_connect(None, *a, **k))
        monkeypatch.setattr(psycopg.AsyncConnection, "connect",
                            classmethod(pg_connect_async))
    yield attempts
    if attempts:
        pytest.fail("network access attempted outside a live test: " + "; ".join(attempts))
