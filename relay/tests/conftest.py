import asyncio
import base64
import hashlib
import json
import os
import sys
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace

import httpx
import psycopg
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from psycopg import sql
from witness_core.sealed import Recipient
from witness_relay.app import create_app
from witness_relay.config import RelayConfig
from witness_relay.keys import did_key

PG = os.environ.get("WITNESS_TEST_PG")
HORNET = "http://hornet.test:14265"
BLOCKS_URL = HORNET + "/api/core/v2/blocks"
VECTORS = Path(__file__).resolve().parents[2] / "core" / "tests" / "vectors"


def pytest_asyncio_loop_factories(config, item):
    # psycopg async and aiomqtt need a selector loop; Windows defaults to Proactor.
    if sys.platform == "win32":
        return {"selector": asyncio.SelectorEventLoop}
    return {"default": asyncio.new_event_loop}


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _identity(key: Ed25519PrivateKey) -> SimpleNamespace:
    did = did_key(key.public_key().public_bytes_raw())
    return SimpleNamespace(key=key, did=did, kid=did + "#" + did.split(":")[-1])


@pytest.fixture
def ids():
    """Throwaway relay, producer, outsider and recipient identities."""
    kex = X25519PrivateKey.generate()
    return SimpleNamespace(
        relay=_identity(Ed25519PrivateKey.generate()),
        producer=_identity(Ed25519PrivateKey.generate()),
        outsider=_identity(Ed25519PrivateKey.generate()),
        kex=kex,
        kex_kid="did:example:domain#kex-1",
        search_key=os.urandom(32),
    )


@pytest.fixture
def pg_schema():
    if not PG:
        pytest.skip("WITNESS_TEST_PG is unset; run `bash scripts/test-db.sh` and export it")
    schema = f"t_{uuid.uuid4().hex[:12]}"
    yield schema
    with psycopg.connect(PG, autocommit=True) as conn:
        conn.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema)))


@pytest.fixture
def make_cfg(tmp_path, ids, pg_schema):
    def make(**overrides) -> RelayConfig:
        key_path = tmp_path / "relay.pem"
        key_path.write_bytes(
            ids.relay.key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        policy = overrides.pop("policy", None) or {
            "version": 1,
            "tags": {
                "trust.score": {
                    "allowed": [ids.producer.did, ids.relay.did],
                    "require_signature": False,
                    "legacy_grace": True,
                },
                "locked": {
                    "allowed": [ids.producer.did, ids.relay.did],
                    "require_signature": True,
                    "legacy_grace": False,
                },
            },
            "default": {"allowed": ["*"], "require_signature": False, "legacy_grace": True},
        }
        policy_path = tmp_path / "policy.json"
        policy_path.write_text(json.dumps(policy))
        search_path = tmp_path / "search.key"
        search_path.write_text(b64u(ids.search_key))
        args = {
            "allowed_nodes": {"iota-hornet": HORNET},
            "relay_did": ids.relay.did,
            "relay_kid": ids.relay.kid,
            "relay_key_path": str(key_path),
            "policy_path": str(policy_path),
            "encrypt_tags": [],
            "recipients": [Recipient(ids.kex_kid, ids.kex.public_key().public_bytes_raw())],
            "search_key_path": str(search_path),
            "keycloak_jwks_url": None,
            "db_url": PG,
            "db_schema": pg_schema,
            "mqtt_url": None,
            "explorer_url": None,
            "forward_drain_s": 0.2,
        }
        args.update(overrides)
        return RelayConfig(**args)

    return make


def fake_block_id(content: bytes) -> str:
    return "0x" + hashlib.blake2b(content, digest_size=32).hexdigest()


@pytest.fixture
def hornet():
    """respx-mocked HORNET: records every block request and answers like HORNET 2."""
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        sent: list[dict] = []
        state = SimpleNamespace(status=201, error=None)

        def handler(request: httpx.Request) -> httpx.Response:
            if state.error is not None:
                raise state.error
            sent.append(json.loads(request.content))
            if state.status >= 400:
                return httpx.Response(
                    state.status,
                    text='{"error":{"code":"400","message":"invalid block"}}\n',
                    headers={"content-type": "application/json"},
                )
            body = json.dumps({"blockId": fake_block_id(request.content)}, separators=(",", ":"))
            return httpx.Response(
                state.status, text=body + "\n", headers={"content-type": "application/json"}
            )

        route = router.post(BLOCKS_URL).mock(side_effect=handler)
        yield SimpleNamespace(router=router, route=route, sent=sent, state=state)


def sent_data(block_request: dict) -> bytes:
    return bytes.fromhex(block_request["payload"]["data"][2:])


def sent_envelope(block_request: dict) -> dict:
    return json.loads(sent_data(block_request))


class RecordingForwarder:
    """Forwarder test double: keeps every record it is handed."""

    def __init__(self, name: str = "recording"):
        self.name = name
        self.records: list[dict] = []

    async def send(self, record: dict) -> None:
        self.records.append(record)

    async def aclose(self) -> None:
        pass


@pytest.fixture
def recorder():
    return RecordingForwarder()


@asynccontextmanager
async def running(cfg: RelayConfig, forwarders=None):
    app = create_app(cfg, forwarders=forwarders)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://relay.test") as client:
            client.app = app
            yield client


@pytest.fixture
def relay():
    return running


async def wait_for(predicate, timeout: float = 3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("condition not met in time")


@pytest.fixture
def eventually():
    return wait_for


@pytest.fixture
def helpers():
    return SimpleNamespace(
        sent_data=sent_data,
        sent_envelope=sent_envelope,
        fake_block_id=fake_block_id,
        b64u=b64u,
        Recording=RecordingForwarder,
        vectors=VECTORS,
    )
