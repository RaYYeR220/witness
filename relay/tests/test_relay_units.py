"""Pure units: did:key, key resolution, config parsing (no database)."""

import base64
import json
from urllib.parse import quote

import httpx
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from witness_core import envelope, policy, verdicts
from witness_relay.config import RelayConfig
from witness_relay.keys import KeyResolver, KeysUnavailable, did_key, did_key_public
from witness_relay.policy_gate import PolicyGate


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


async def test_resolver_caches_resolution():
    did = "did:iota:testnet:0xabc"
    pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    with respx.mock() as router:
        route = router.get(f"http://anchor.test/resolve/{quote(did, safe='')}").mock(
            return_value=httpx.Response(200, json=_resolve_body(did, (did + "#sig-1", pub, 123)))
        )
        async with httpx.AsyncClient() as http:
            resolver = KeyResolver(resolver_url="http://anchor.test", http=http)
            info = await resolver.resolve(did + "#sig-1")
            again = await resolver.resolve(did + "#sig-1")
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


def test_config_passthrough_tags():
    env = {
        "RELAY_ALLOWED_NODES": "{}",
        "RELAY_DID": "did:key:z6Mk",
        "RELAY_KID": "did:key:z6Mk#z6Mk",
        "RELAY_KEY_PATH": "k.pem",
        "RELAY_POLICY_PATH": "p.json",
        "RELAY_DB_URL": "postgresql://x",
        "RELAY_PASSTHROUGH_TAGS": "trust.score, LLO-K8s",
    }
    assert RelayConfig.from_env(env).passthrough_tags == ["trust.score", "LLO-K8s"]
    assert RelayConfig.from_env({**env, "RELAY_PASSTHROUGH_TAGS": ""}).passthrough_tags == []


async def test_resolver_rejects_bad_did_syntax_without_lookup():
    with respx.mock(assert_all_called=False) as router:
        route = router.get(url__startswith="http://anchor.test/").mock(
            return_value=httpx.Response(404)
        )
        async with httpx.AsyncClient() as http:
            resolver = KeyResolver(resolver_url="http://anchor.test", http=http)
            for kid in (
                "did:iota:../../admin#sig-1",
                "did:web:evil.example#k",
                "did:iota:a b#k",
                "did:iota:#k",
                "not-a-did",
            ):
                assert await resolver.resolve(kid) is None
    assert route.call_count == 0


async def test_resolver_cache_is_bounded():
    with respx.mock() as router:
        route = router.get(url__startswith="http://anchor.test/resolve/").mock(
            return_value=httpx.Response(404)
        )
        async with httpx.AsyncClient() as http:
            resolver = KeyResolver(resolver_url="http://anchor.test", http=http, cache_size=2)
            for n in (1, 2, 3, 1):
                await resolver.resolve(f"did:iota:testnet:0x{n}#sig-1")
    # did 1 was evicted by did 3, so it is fetched twice.
    assert route.call_count == 4


async def test_gate_resolves_only_well_formed_envelopes():
    class SpyResolver:
        def __init__(self):
            self.asked = []

        async def resolve(self, kid):
            self.asked.append(kid)

    key = Ed25519PrivateKey.generate()
    did = "did:iota:testnet:0xabc"
    good = envelope.seal(
        "t", {"a": 1}, iss=did, kid=did + "#sig-1", sign_key=key, seq=1, att_mode="producer"
    )
    spy = SpyResolver()
    gate = PolicyGate(policy.load({"version": 1}), spy, "did:key:zRelay")

    malformed = {k: v for k, v in good.items() if k != "nonce"}
    assert (await gate.check_envelope("t", malformed)).verdict == verdicts.MALFORMED
    wrong_tag = await gate.check_envelope("other", good)
    assert wrong_tag.verdict == verdicts.FORGED
    foreign_kid = {**good, "kid": "did:iota:testnet:0xdef#sig-1"}
    assert (await gate.check_envelope("t", foreign_kid)).verdict == verdicts.FORGED
    assert spy.asked == []

    assert (await gate.check_envelope("t", good)).verdict == verdicts.FORGED  # unknown key
    assert spy.asked == [did + "#sig-1"]


def _resolve_body(did, *entries):
    """Shape of the anchor service's GET /resolve/:did reply."""
    return {
        "doc": {"id": did, "verificationMethod": []},
        "version": 5,
        "keys": [
            {
                "kid": kid,
                "type": "Ed25519",
                "publicKeyHex": pub.hex(),
                "revokedAtMs": revoked,
            }
            for kid, pub, revoked in entries
        ],
        "historyComplete": True,
    }


async def _resolve_with(body, kid):
    did = kid.partition("#")[0]
    with respx.mock() as router:
        router.get(f"http://anchor.test/resolve/{quote(did, safe='')}").mock(
            return_value=httpx.Response(200, json=body)
        )
        async with httpx.AsyncClient() as http:
            resolver = KeyResolver(resolver_url="http://anchor.test", http=http)
            return await resolver.resolve(kid)


async def test_resolver_reads_anchor_keys_list():
    did = "did:iota:testnet:0xabc"
    kid = did + "#sig-1"
    pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    x25519 = bytes(range(32))
    body = _resolve_body(did, (kid, pub, None), (did + "#kex-1", x25519, None))
    body["keys"][1]["type"] = "X25519"
    info = await _resolve_with(body, kid)
    assert info.ed25519_public == pub
    assert info.revoked_at_ms is None
    assert await _resolve_with(body, did + "#kex-1") is None
    assert await _resolve_with(body, did + "#missing") is None


async def test_resolver_picks_key_valid_now_when_kid_was_replaced():
    did = "did:iota:testnet:0xabc"
    kid = did + "#sig-1"
    old = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    new = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    body = _resolve_body(did, (kid, new, None), (kid, old, 1_000))
    info = await _resolve_with(body, kid)
    assert info.ed25519_public == new and info.revoked_at_ms is None
    # order must not matter
    body["keys"].reverse()
    assert (await _resolve_with(body, kid)).ed25519_public == new


async def test_resolver_revoked_only_key_reports_revocation():
    did = "did:iota:testnet:0xabc"
    kid = did + "#sig-1"
    old = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    info = await _resolve_with(_resolve_body(did, (kid, old, 1_000)), kid)
    assert info.ed25519_public == old and info.revoked_at_ms == 1_000


async def test_resolver_ignores_malformed_revocation_time():
    did = "did:iota:testnet:0xabc"
    kid = did + "#sig-1"
    good = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    bad = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    for junk in ("123", 1.5, True):
        body = _resolve_body(did, (kid, bad, junk))
        assert await _resolve_with(body, kid) is None
        body = _resolve_body(did, (kid, good, None), (kid, bad, junk))
        assert (await _resolve_with(body, kid)).ed25519_public == good


async def test_resolver_prefers_last_live_entry():
    did = "did:iota:testnet:0xabc"
    kid = did + "#sig-1"
    first = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    last = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    info = await _resolve_with(_resolve_body(did, (kid, first, None), (kid, last, None)), kid)
    assert info.ed25519_public == last


DID = "did:iota:testnet:0xabc"
RESOLVE_URL = f"http://anchor.test/resolve/{quote(DID, safe='')}"


@pytest.mark.parametrize("status", [400, 404, 410, 414, 422, 431])
async def test_resolver_caches_definitive_refusals(status):
    with respx.mock() as router:
        route = router.get(RESOLVE_URL).mock(return_value=httpx.Response(status))
        async with httpx.AsyncClient() as http:
            resolver = KeyResolver(resolver_url="http://anchor.test", http=http)
            assert await resolver.resolve(DID + "#sig-1") is None
            assert await resolver.resolve(DID + "#sig-1") is None
    assert route.call_count == 1


@pytest.mark.parametrize(
    "failure",
    [
        httpx.Response(401),
        httpx.Response(403),
        httpx.Response(407),
        httpx.Response(408),
        httpx.Response(429),
        httpx.Response(500),
        httpx.Response(503),
        httpx.Response(200, text="not json"),
        httpx.Response(200, json={"doc": {"id": "did:iota:testnet:0xother"}, "keys": []}),
        httpx.ConnectError("refused"),
        httpx.ReadTimeout("slow"),
    ],
)
async def test_resolver_outage_is_not_an_answer(failure):
    """Neither cached nor turned into "no key": the next request asks again."""
    pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    with respx.mock() as router:
        route = router.get(RESOLVE_URL)
        if isinstance(failure, httpx.Response):
            route.mock(return_value=failure)
        else:
            route.mock(side_effect=failure)
        async with httpx.AsyncClient() as http:
            resolver = KeyResolver(resolver_url="http://anchor.test", http=http)
            with pytest.raises(KeysUnavailable):
                await resolver.resolve(DID + "#sig-1")
            route.mock(return_value=httpx.Response(
                200, json=_resolve_body(DID, (DID + "#sig-1", pub, None))))
            assert (await resolver.resolve(DID + "#sig-1")).ed25519_public == pub
    assert route.call_count == 2


async def test_gate_lets_resolver_outages_through():
    class DownResolver:
        async def resolve(self, kid):
            raise KeysUnavailable("DID resolver answered HTTP 503")

    key = Ed25519PrivateKey.generate()
    env = envelope.seal(
        "t", {"a": 1}, iss=DID, kid=DID + "#sig-1", sign_key=key, seq=1, att_mode="producer"
    )
    gate = PolicyGate(policy.load({"version": 1}), DownResolver(), "did:key:zRelay")
    with pytest.raises(KeysUnavailable):
        await gate.check_envelope("t", env)



def _deep(levels: int) -> object:
    v: object = "leaf"
    for _ in range(levels):
        v = {"n": v}
    return v


@pytest.mark.parametrize(
    "deep",
    [
        lambda pub: httpx.Response(200, json={
            **_resolve_body(DID, (DID + "#sig-1", pub, None)), "x": _deep(600)}),
        lambda pub: httpx.Response(200, content=b'{"doc":' + b"[" * 2500 + b"]" * 2500 + b"}"),
    ],
)
async def test_resolver_treats_hostile_documents_as_naming_no_key(deep):
    pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    with respx.mock() as router:
        route = router.get(RESOLVE_URL).mock(return_value=deep(pub))
        async with httpx.AsyncClient() as http:
            resolver = KeyResolver(resolver_url="http://anchor.test", http=http)
            assert await resolver.resolve(DID + "#sig-1") is None
            assert await resolver.resolve(DID + "#sig-1") is None
    assert route.call_count == 1
