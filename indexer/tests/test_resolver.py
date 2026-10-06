from urllib.parse import quote

import httpx
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from witness_indexer.resolver import DidResolver, ResolverUnavailable, did_key

BASE = "http://anchor.test"
DID = "did:iota:testnet:0x" + "5e1f" * 16
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


WALL0 = 1_790_000_000.0  # wall clock (epoch s) when Clock.t == 0


class Clock:
    """Monotonic clock for the resolver; `wall` is the wall clock moving with it."""

    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def wall(self) -> float:
        return WALL0 + self.t

    def wall_ms(self) -> int:
        return int(self.wall() * 1000)


def clocked(**kw) -> tuple[DidResolver, Clock]:
    clock = Clock()
    return DidResolver(BASE, clock=clock, wall_clock=clock.wall, **kw), clock


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
def test_historical_lookups_reuse_a_complete_document_for_the_ttl():
    route = respx.get(URL).mock(return_value=httpx.Response(200, json=reply(entry(NEW, None))))
    r, clock = clocked(cache_ttl_s=60)
    past = clock.wall_ms() - 3_600_000  # an hour before the fetch: catching up
    assert r.resolve_kid(KID, at_ms=past).ed25519_public == pub(NEW)
    clock.t += 59
    assert r.resolve_kid(KID, at_ms=past).ed25519_public == pub(NEW)
    assert r.doc(DID, at_ms=past)["version"] == "7"
    assert route.call_count == 1
    clock.t += 2
    r.resolve_kid(KID, at_ms=past)
    assert route.call_count == 2
    assert r.status == "ok"


@respx.mock
@pytest.mark.parametrize("live", ["now", "at_fetch", "skewed", "window_edge", "future"])
def test_lookups_near_the_live_tip_refetch_after_3s(live):
    route = respx.get(URL).mock(return_value=httpx.Response(200, json=reply(entry(NEW, None))))
    r, clock = clocked(cache_ttl_s=60)
    fetched = clock.wall_ms()
    # The window is 30 s wide so a node clock running behind ours still counts as the tip.
    at_ms = {"now": None, "at_fetch": fetched, "skewed": fetched - 25_000,
             "window_edge": fetched - 30_000, "future": fetched + 5000}[live]
    r.resolve_kid(KID, at_ms=at_ms)
    clock.t += 2.9
    r.resolve_kid(KID, at_ms=at_ms)
    assert route.call_count == 1
    clock.t += 0.2
    r.resolve_kid(KID, at_ms=at_ms)
    assert route.call_count == 2


@respx.mock
def test_a_historical_fetch_does_not_serve_the_live_tip_for_long():
    """Fetched while catching up, then asked about the tip: older than 3 s is a miss."""
    route = respx.get(URL).mock(return_value=httpx.Response(200, json=reply(entry(NEW, None))))
    r, clock = clocked(cache_ttl_s=60)
    r.resolve_kid(KID, at_ms=clock.wall_ms() - 3_600_000)
    clock.t += 1
    r.resolve_kid(KID, at_ms=clock.wall_ms() - 2500)  # 1.5 s before the fetch: live
    assert route.call_count == 1
    clock.t += 2.5
    r.resolve_kid(KID, at_ms=clock.wall_ms() - 1000)
    assert route.call_count == 2
    second = clock.wall_ms()
    # Just outside the 30 s window of the new fetch, a complete document is historical.
    clock.t += 30
    r.resolve_kid(KID, at_ms=second - 30_001)
    assert route.call_count == 2
    r.resolve_kid(KID, at_ms=second - 30_000)
    assert route.call_count == 3


@respx.mock
def test_revocation_near_the_tip_is_seen_promptly():
    tip_ms = int(WALL0 * 1000) + 1_000_000
    route = respx.get(URL).mock(return_value=httpx.Response(200, json=reply(entry(NEW, None))))
    r, clock = clocked(cache_ttl_s=60)
    clock.t = (tip_ms - int(WALL0 * 1000)) / 1000  # the wall clock reads the tip's time
    assert r.resolve_kid(KID, at_ms=tip_ms).revoked_at_ms is None
    route.mock(return_value=httpx.Response(200, json=reply(entry(NEW, tip_ms + 1500))))
    clock.t += 3.5
    info = r.resolve_kid(KID, at_ms=tip_ms + 1000)
    assert info.revoked_at_ms == tip_ms + 1500
    assert route.call_count == 2


@respx.mock
@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(404, json={"error": "not found"}),
        httpx.Response(200, json={**reply(entry(NEW, None)), "historyComplete": False}),
        httpx.Response(200, json={k: v for k, v in reply(entry(NEW, None)).items()
                                  if k != "historyComplete"}),
    ],
)
def test_negative_and_incomplete_answers_live_5s(response):
    route = respx.get(URL).mock(return_value=response)
    r, clock = clocked(cache_ttl_s=60)
    past = clock.wall_ms() - 3_600_000
    r.resolve_kid(KID, at_ms=past)
    clock.t += 4.9
    r.resolve_kid(KID, at_ms=past)
    assert route.call_count == 1
    clock.t += 0.2
    r.resolve_kid(KID, at_ms=past)
    assert route.call_count == 2


@respx.mock
def test_cache_entry_is_stamped_when_the_request_is_sent():
    """A slow reply is as old as its request: it may miss what was published meanwhile."""
    r, clock = clocked(cache_ttl_s=60)

    def slow(_request):
        clock.t += 2.5
        return httpx.Response(200, json=reply(entry(NEW, None)))

    route = respx.get(URL).mock(side_effect=slow)
    r.resolve_kid(KID)
    clock.t += 0.6  # 0.6 s after the reply, 3.1 s after the request
    r.resolve_kid(KID)
    assert route.call_count == 2


@respx.mock
async def test_async_lookup_shares_the_cache():
    route = respx.get(URL).mock(return_value=httpx.Response(200, json=reply(entry(NEW, None))))
    r, clock = clocked()
    assert (await r.aresolve_kid(KID)).ed25519_public == pub(NEW)
    assert r.resolve_kid(KID).ed25519_public == pub(NEW)
    assert (await r.adoc(DID))["doc"]["id"] == DID
    assert route.call_count == 1
    clock.t += 10  # too old for the live tip, fine for an hour ago
    past = clock.wall_ms() - 3_600_000
    await r.aresolve_kid(KID, at_ms=past)
    assert r.resolve_kid(KID, at_ms=past) is not None
    assert route.call_count == 1
    await r.adoc(DID)
    assert route.call_count == 2


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
    other = "did:iota:testnet:0x" + "ab" * 32
    assert r.resolve_kid(other + "#sig-1") is None
    assert r.can_resolve(DID) and not r.can_resolve(other)
    assert not respx.calls


@pytest.mark.parametrize("status", [400, 404, 410, 414, 422, 431])
@respx.mock
def test_definitive_refusals_are_answers(status):
    route = respx.get(URL).mock(return_value=httpx.Response(status))
    r = DidResolver(BASE)
    assert r.resolve_kid(KID) is None
    assert r.resolve_kid(KID) is None
    assert route.call_count == 1  # cached like a 404
    assert r.status == "ok"


@pytest.mark.parametrize("status", [401, 403, 405, 407, 408, 421, 429, 500, 502, 503, 301])
@respx.mock
def test_temporary_refusals_decide_nothing(status):
    """Auth and proxy refusals (401/403/407) are about the indexer, not the DID: like an
    outage they decide nothing and are not cached."""
    route = respx.get(URL).mock(return_value=httpx.Response(status))
    r = DidResolver(BASE)
    with pytest.raises(ResolverUnavailable):
        r.resolve_kid(KID)
    assert r.status == "unreachable"
    route.mock(return_value=httpx.Response(200, json=reply(entry(NEW, None))))
    assert r.resolve_kid(KID).ed25519_public == pub(NEW)
    assert route.call_count == 2


async def test_oversized_did_is_unknown_without_asking():
    did = "did:iota:" + ":" * 6000
    async with respx.mock(assert_all_called=False) as router:
        route = router.get(url__startswith=BASE).mock(return_value=httpx.Response(503))
        r = DidResolver(BASE)
        assert r.resolve_kid(did + "#sig-1") is None
        assert await r.aresolve_kid(did + "#sig-1") is None
        assert r.doc(did) is None and not r.can_resolve(did)
        # The length limit (did:iota DIDs must also be canonical, see below).
        assert r.can_resolve("did:key:" + "a" * (128 - len("did:key:")))
        assert not r.can_resolve("did:key:" + "a" * (129 - len("did:key:")))
        assert route.call_count == 0


def _nested(levels: int) -> dict:
    v: object = "leaf"
    for _ in range(levels):
        v = {"n": v}
    return v  # type: ignore[return-value]


@pytest.mark.parametrize(
    "response",
    [
        # Past nesting.MAX_DOC_DEPTH (64): copy.deepcopy alone would recurse ~1800 frames.
        httpx.Response(200, json={**reply(entry(NEW, None)), "doc": {"id": DID, "x": _nested(600)}}),
        # Past the JSON cap itself.
        httpx.Response(200, content=b'{"doc":' + b"[" * 2500 + b"]" * 2500 + b"}"),
    ],
)
@respx.mock
def test_hostile_documents_are_unusable_answers_not_outages(response):
    route = respx.get(URL).mock(return_value=response)
    r, clock = clocked()
    assert r.resolve_kid(KID) is None
    assert r.doc(DID) is None
    assert r.status == "ok"
    assert route.call_count == 1  # cached like "no such DID"
    clock.t += 6
    r.resolve_kid(KID)
    assert route.call_count == 2  # with the short TTL of a negative answer


@respx.mock
def test_document_at_the_depth_limit_still_resolves():
    doc = reply(entry(NEW, None))
    doc["doc"]["x"] = _nested(62)  # reply 0, doc 1, x 2, leaf at 64
    respx.get(URL).mock(return_value=httpx.Response(200, json=doc))
    assert DidResolver(BASE).resolve_kid(KID).ed25519_public == pub(NEW)


@respx.mock
def test_callers_cannot_change_the_cached_reply():
    route = respx.get(URL).mock(return_value=httpx.Response(200, json=reply(entry(NEW, None))))
    r, _ = clocked()
    first = r.doc(DID)
    first["keys"][0]["publicKeyHex"] = pub(OLD).hex()
    first["keys"].append({"kid": "#evil"})
    first["version"] = "x"
    again = r.doc(DID)
    assert (again["version"], len(again["keys"])) == ("7", 1)
    assert r.resolve_kid(KID).ed25519_public == pub(NEW)
    assert route.call_count == 1


@pytest.mark.parametrize(
    "did",
    [
        "did:iota:testnet:0x" + "5E1F" * 16,  # upper-case hex
        "did:iota:testnet:0x" + "5e1f" * 15,  # too short
        "did:iota:testnet:0x" + "5e1f" * 16 + "00",  # too long
        "did:iota:testnet:" + "5e1f" * 16,  # no 0x
        "did:iota:Testnet:0x" + "5e1f" * 16,  # network not lower-case
    ],
)
async def test_non_canonical_iota_dids_are_never_looked_up(did):
    async with respx.mock(assert_all_called=False) as router:
        route = router.get(url__startswith=BASE).mock(return_value=httpx.Response(503))
        r = DidResolver(BASE, offline_docs={did: reply(entry(NEW, None), did=did)})
        assert r.resolve_kid(did + "#sig-1") is None
        assert await r.aresolve_kid(did + "#sig-1") is None
        assert r.doc(did) is None and not r.can_resolve(did)
        assert route.call_count == 0
    assert r.can_resolve("did:iota:testnet:0x" + "5e1f" * 16)
    assert r.can_resolve("did:iota:0x" + "5e1f" * 16)  # mainnet DIDs carry no network
