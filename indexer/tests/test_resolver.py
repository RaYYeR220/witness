from urllib.parse import quote

import httpx
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from witness_indexer.resolver import DidResolver, ResolverUnavailable, did_key

BASE = "http://anchor.test"
DID = "did:iota:testnet:0x5e1f"
KID = DID + "#sig-1"
NEW = Ed25519PrivateKey.from_private_bytes(b"\x31" * 32)
OLD = Ed25519PrivateKey.from_private_bytes(b"\x32" * 32)
URL = f"{BASE}/resolve/{quote(DID, safe='')}"


def pub(k: Ed25519PrivateKey) -> bytes:
    return k.public_key().public_bytes_raw()


def entry(k: Ed25519PrivateKey, revoked: int | None, kid: str = "#sig-1") -> dict:
    return {"kid": kid, "type": "Ed25519", "publicKeyHex": pub(k).hex(), "revokedAtMs": revoked}


def reply(*keys: dict, did: str = DID) -> dict:
    return {"doc": {"id": did}, "version": "7", "keys": list(keys), "historyComplete": True}


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


@respx.mock(assert_all_called=False)
def test_did_key_resolves_offline():
    k = Ed25519PrivateKey.from_private_bytes(b"\x33" * 32)
    did = did_key(pub(k))
    msid = did[len("did:key:"):]
    r = DidResolver(None)
    for kid in (did, f"{did}#{msid}"):
        info = r.resolve_kid(kid)
        assert info is not None and info.ed25519_public == pub(k) and info.revoked_at_ms is None
    assert r.resolve_kid(f"{did}#other") is None
    assert r.resolve_kid("did:key:zNotAKey#x") is None
    assert r.doc(did)["doc"]["id"] == did
    assert not respx.calls


@respx.mock
def test_http_called_once_within_ttl():
    route = respx.get(URL).mock(return_value=httpx.Response(200, json=reply(entry(NEW, None))))
    clock = Clock()
    r = DidResolver(BASE, cache_ttl_s=60, clock=clock)
    assert r.resolve_kid(KID).ed25519_public == pub(NEW)
    clock.t += 59
    assert r.resolve_kid(KID).ed25519_public == pub(NEW)
    assert r.doc(DID)["version"] == "7"
    assert route.call_count == 1
    clock.t += 2
    r.resolve_kid(KID)
    assert route.call_count == 2
    assert r.status == "ok"


@respx.mock
async def test_async_lookup_shares_the_cache():
    route = respx.get(URL).mock(return_value=httpx.Response(200, json=reply(entry(NEW, None))))
    r = DidResolver(BASE)
    assert (await r.aresolve_kid(KID)).ed25519_public == pub(NEW)
    assert r.resolve_kid(KID).ed25519_public == pub(NEW)
    assert (await r.adoc(DID))["doc"]["id"] == DID
    assert route.call_count == 1


@respx.mock
def test_replaced_key_is_chosen_by_time():
    # The anchor lists the current key first, then the one it replaced.
    respx.get(URL).mock(
        return_value=httpx.Response(200, json=reply(entry(NEW, None), entry(OLD, 5000)))
    )
    r = DidResolver(BASE)
    assert r.resolve_kid(KID).ed25519_public == pub(NEW)
    old = r.resolve_kid(KID, at_ms=4000)
    assert (old.ed25519_public, old.revoked_at_ms) == (pub(OLD), 5000)
    assert r.resolve_kid(KID, at_ms=6000).ed25519_public == pub(NEW)
    # Full kids and fragment kids in the reply are treated alike.
    assert r.resolve_kid(DID + "#sig-2") is None


@respx.mock
def test_key_replaced_inside_the_second_is_not_picked():
    """Milestone times have second precision: a key replaced anywhere in the second holding
    at_ms was not in force for all of it, so its successor is picked."""
    respx.get(URL).mock(
        return_value=httpx.Response(200, json=reply(entry(NEW, None), entry(OLD, 4500)))
    )
    r = DidResolver(BASE)
    for at_ms in (4000, 4499, 4999):
        assert r.resolve_kid(KID, at_ms=at_ms).ed25519_public == pub(NEW), at_ms
    old = r.resolve_kid(KID, at_ms=3999)
    assert (old.ed25519_public, old.revoked_at_ms) == (pub(OLD), 4500)


@respx.mock
def test_only_revoked_entries_report_the_revocation():
    respx.get(URL).mock(
        return_value=httpx.Response(200, json=reply(entry(OLD, 10, kid=KID), entry(NEW, 20)))
    )
    info = DidResolver(BASE).resolve_kid(KID, at_ms=30)
    assert (info.ed25519_public, info.revoked_at_ms) == (pub(NEW), 20)


@respx.mock
def test_unreachable_raises_and_is_not_cached():
    route = respx.get(URL).mock(side_effect=httpx.ConnectError("refused"))
    r = DidResolver(BASE)
    with pytest.raises(ResolverUnavailable):
        r.resolve_kid(KID)
    assert r.status == "unreachable"
    route.mock(return_value=httpx.Response(200, json=reply(entry(NEW, None))))
    assert r.resolve_kid(KID).ed25519_public == pub(NEW)
    assert r.status == "ok"


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(500, json={"error": "boom"}),
        httpx.Response(200, text="not json"),
        httpx.Response(200, json={"doc": {"id": DID}}),
        httpx.Response(200, json=reply(entry(NEW, None), did="did:iota:testnet:0xother")),
    ],
)
@respx.mock
def test_non_answers_decide_nothing(response):
    respx.get(URL).mock(return_value=response)
    with pytest.raises(ResolverUnavailable):
        DidResolver(BASE).resolve_kid(KID)


@respx.mock
def test_unknown_did_is_an_answer():
    route = respx.get(URL).mock(return_value=httpx.Response(404, json={"error": "not found"}))
    r = DidResolver(BASE)
    assert r.resolve_kid(KID) is None
    assert r.doc(DID) is None
    assert route.call_count == 1


@respx.mock(assert_all_called=False)
def test_offline_docs_and_unsupported_ids():
    r = DidResolver(None, offline_docs={DID: reply(entry(NEW, None))})
    assert r.resolve_kid(KID).ed25519_public == pub(NEW)
    for kid in ("did:web:example.com#k", "not-a-did", "", None):
        assert r.resolve_kid(kid) is None
    # No registry configured: resolution is disabled, the DID is unknown, never an outage.
    assert r.resolve_kid("did:iota:testnet:0xabc#sig-1") is None
    assert r.can_resolve(DID) and not r.can_resolve("did:iota:testnet:0xabc")
    assert not respx.calls


@pytest.mark.parametrize("status", [400, 403, 404, 410, 414, 431])
@respx.mock
def test_definitive_refusals_are_answers(status):
    route = respx.get(URL).mock(return_value=httpx.Response(status))
    r = DidResolver(BASE)
    assert r.resolve_kid(KID) is None
    assert r.resolve_kid(KID) is None
    assert route.call_count == 1  # cached like a 404
    assert r.status == "ok"


@pytest.mark.parametrize("status", [408, 429, 500, 502, 503])
@respx.mock
def test_temporary_refusals_decide_nothing(status):
    respx.get(URL).mock(return_value=httpx.Response(status))
    r = DidResolver(BASE)
    with pytest.raises(ResolverUnavailable):
        r.resolve_kid(KID)
    assert r.status == "unreachable"


async def test_oversized_did_is_unknown_without_asking():
    did = "did:iota:" + ":" * 6000
    async with respx.mock(assert_all_called=False) as router:
        route = router.get(url__startswith=BASE).mock(return_value=httpx.Response(503))
        r = DidResolver(BASE)
        assert r.resolve_kid(did + "#sig-1") is None
        assert await r.aresolve_kid(did + "#sig-1") is None
        assert r.doc(did) is None and not r.can_resolve(did)
        assert r.can_resolve("did:iota:" + "a" * (128 - len("did:iota:")))
        assert not r.can_resolve("did:iota:" + "a" * (129 - len("did:iota:")))
        assert route.call_count == 0
