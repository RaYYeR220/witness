"""End to end against the local stack: HORNET on :14265 and Mosquitto on :1883.

The broker takes logins only (deploy/compose/mosquitto.acl): the relay publishes with the
`relay` login, the probe subscribes with the read-only `observer` login. WITNESS_LIVE_MQTT is
the broker (default mqtt://127.0.0.1:1883); the passwords are read from
WITNESS_LIVE_MQTT_SECRETS/<user>.password (default: secrets/mosquitto of this checkout, as
deploy/compose/setup-secrets.sh writes them). Without a password file the login is left out.
"""

import asyncio
import json
import os
import uuid
from pathlib import Path
from urllib.parse import quote, urlsplit

import aiomqtt
import httpx
import pytest
from witness_core import envelope, verdicts
from witness_core.envelope import KeyInfo

LIVE_HORNET = os.environ.get("WITNESS_LIVE_HORNET", "http://127.0.0.1:14265")
LIVE_MQTT = os.environ.get("WITNESS_LIVE_MQTT", "mqtt://127.0.0.1:1883")
LIVE_MQTT_SECRETS = Path(os.environ.get(
    "WITNESS_LIVE_MQTT_SECRETS", Path(__file__).resolve().parents[2] / "secrets" / "mosquitto"))


def mqtt_login(user: str) -> tuple[str | None, str | None]:
    path = LIVE_MQTT_SECRETS / f"{user}.password"
    if not path.is_file():
        return None, None
    return user, path.read_text(encoding="utf-8").strip()


def mqtt_url(user: str) -> str:
    parts = urlsplit(LIVE_MQTT)
    name, password = mqtt_login(user)
    host = f"{parts.hostname}:{parts.port or 1883}"
    if name is None:
        return f"{parts.scheme}://{host}"
    return f"{parts.scheme}://{quote(name, safe='')}:{quote(password, safe='')}@{host}"

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(os.environ.get("WITNESS_LIVE") != "1", reason="set WITNESS_LIVE=1"),
]


async def test_live_submit_reaches_hornet_and_broker(make_cfg, relay, ids):
    cfg = make_cfg(
        allowed_nodes={"iota-hornet": LIVE_HORNET},
        mqtt_url=mqtt_url("relay"),
    )
    marker = uuid.uuid4().hex
    message = {"score": 0.5, "id": "MyDomain:aabbccddeeff", "probe": marker}

    broker = urlsplit(LIVE_MQTT)
    user, password = mqtt_login("observer")
    async with aiomqtt.Client(broker.hostname, broker.port or 1883, username=user,
                              password=password, identifier=f"probe-{marker[:8]}") as sub:
        await sub.subscribe("aerios/iota/submissions/#", qos=1)
        async with relay(cfg) as client:
            resp = await client.post(
                "/upload",
                params={"node": "iota-hornet"},
                json={"tag": "trust.score", "message": message},
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["status_code"] == 201
            block_id = body["witness"]["blockId"]
            assert json.loads(body["return_payload"]) == {"blockId": block_id}

            async def first_matching():
                async for msg in sub.messages:
                    rec = json.loads(msg.payload)
                    if rec.get("message", {}).get("probe") == marker:
                        return str(msg.topic), rec

            topic, record = await asyncio.wait_for(first_matching(), timeout=10)

    assert topic == "aerios/iota/submissions/trust.score"
    assert record["blockId"] == block_id
    assert record["hornetStatus"] == 201
    assert record["relay"]["verdict"] == verdicts.RELAY_ATTESTED

    async with httpx.AsyncClient(base_url=LIVE_HORNET, timeout=10) as node:
        block = (await node.get(f"/api/core/v2/blocks/{block_id}")).json()
    assert block["payload"]["type"] == 5
    assert block["payload"]["tag"] == "0x" + b"trust.score".hex()
    assert block["payload"]["data"] == record["dataHex"]

    env = json.loads(bytes.fromhex(record["dataHex"][2:]))
    info = KeyInfo(ids.relay.kid, ids.relay.key.public_key().public_bytes_raw(), None, None)
    check = envelope.verify(env, "trust.score", lambda kid: info if kid == info.kid else None)
    assert check.verdict == verdicts.RELAY_ATTESTED
    assert env["body"] == message
