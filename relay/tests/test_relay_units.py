"""Pure units: did:key, key resolution, config parsing (no database)."""

import base64
import json

import httpx
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from witness_relay.config import RelayConfig
from witness_relay.keys import KeyResolver, did_key, did_key_public


def _b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def test_did_key_round_trip():
    pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    did = did_key(pub)
    assert did.startswith("did:key:z6Mk")
    assert did_key_public(did) == pub
    assert did_key_public("did:key:zNotBase58!!") is None
    assert did_key_public("did:iota:0xabc") is None


async def test_resolver_did_key_offline():
    pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    did = did_key(pub)
    msid = did.split(":")[-1]
    resolver = KeyResolver()
    info = await resolver.resolve(f"{did}#{msid}")
    assert info.ed25519_public == pub
    assert await resolver.resolve(f"{did}#other") is None


async def test_resolver_static_keys(tmp_path):
    pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    path = tmp_path / "keys.json"
    path.write_text(
        json.dumps(
            [
                {"kid": "did:iota:x#sig-1", "kty": "OKP", "crv": "Ed25519", "x": _b64u(pub)},
                {"kid": "did:iota:x#kex-1", "kty": "OKP", "crv": "X25519", "x": _b64u(pub)},
            ]
        )
    )
    resolver = KeyResolver.from_files(str(path))
    assert (await resolver.resolve("did:iota:x#sig-1")).ed25519_public == pub
    assert await resolver.resolve("did:iota:x#kex-1") is None


async def test_resolver_http_document():
    pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    did = "did:iota:testnet:0xabc"
    doc = {
        "id": did,
        "verificationMethod": [
            {
                "id": "#sig-1",
                "type": "JsonWebKey2020",
                "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": _b64u(pub)},
            },
        ],
    }
    with respx.mock() as router:
        route = router.get(f"http://anchor.test/resolve/{did}").mock(
            return_value=httpx.Response(
                200,
                json={
                    "doc": doc,
                    "version": 3,
                    "revokedMethods": [{"kid": did + "#sig-1", "revokedAtMs": 123}],
                },
            )
        )
        async with httpx.AsyncClient() as http:
            resolver = KeyResolver(resolver_url="http://anchor.test", http=http)
            info = await resolver.resolve(did + "#sig-1")
            again = await resolver.resolve(did + "#sig-1")
    assert info.ed25519_public == pub
    assert info.revoked_at_ms == 123
    assert again == info
    assert route.call_count == 1


def test_config_from_env(tmp_path):
    env = {
        "RELAY_ALLOWED_NODES": '{"iota-hornet": "http://iota-hornet:14265"}',
        "RELAY_DID": "did:key:z6Mk",
        "RELAY_KID": "did:key:z6Mk#z6Mk",
        "RELAY_KEY_PATH": "secrets/relay/sig.pem",
        "RELAY_POLICY_PATH": "secrets/policy.json",
        "RELAY_DB_URL": "postgresql://postgres:witness@postgres:5432/postgres",
        "RELAY_ENCRYPT_TAGS": "trust.score, self-security ,",
        "RELAY_MQTT_URL": "",
        "EXPLORER_URL": "http://witness-api:8080",
        "EXPLORER_TOKEN": "tok",
        "RELAY_PORT": "5556",
    }
    cfg = RelayConfig.from_env(env)
    assert cfg.allowed_nodes == {"iota-hornet": "http://iota-hornet:14265"}
    assert cfg.encrypt_tags == ["trust.score", "self-security"]
    assert cfg.mqtt_url is None
    assert cfg.explorer_url == "http://witness-api:8080"
    assert cfg.explorer_token == "tok"
    assert cfg.port == 5556
    assert cfg.max_block_bytes == 32768
    assert cfg.db_schema == "relay"

    defaults = RelayConfig.from_env({k: v for k, v in env.items() if k != "RELAY_MQTT_URL"})
    assert defaults.mqtt_url == "mqtt://127.0.0.1:1883"

    recipients = tmp_path / "recipients.json"
    pub = b"\x01" * 32
    recipients.write_text(
        json.dumps([{"kid": "did:x#kex-1", "kty": "OKP", "crv": "X25519", "x": _b64u(pub)}])
    )
    cfg = RelayConfig.from_env({**env, "RELAY_RECIPIENTS_PATH": str(recipients)})
    assert [(r.kid, r.x25519_public) for r in cfg.recipients] == [("did:x#kex-1", pub)]

    with pytest.raises(ValueError):
        RelayConfig.from_env({k: v for k, v in env.items() if k != "RELAY_DID"})
