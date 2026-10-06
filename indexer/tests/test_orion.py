import json

import httpx
import pytest
import respx
from witness_indexer.orion import IE, OrionClient, OrionUnavailable

BASE = "http://orion.test"
ENTITIES = f"{BASE}/ngsi-ld/v1/entities"
URN = "urn:ngsi-ld:InfrastructureElement:"


def entity(ie: str, score=None, *, normalized: bool = True, prefix: str = URN) -> dict:
    e: dict = {"id": prefix + ie, "type": "InfrastructureElement"}
    if score is not None:
        e["trustScore"] = {"type": "Property", "value": score} if normalized else score
    return e


@respx.mock
async def test_ie_entities_maps_ids_and_scores():
    body = json.dumps([
        entity("MyDomain:fa163e5e25ef", 0.74),
        entity("MyDomain:fa163e5e25f0", 0.5, normalized=False),
        entity("Edge:001122334455"),
        entity("Edge:001122334456", "0.9"),
        entity("Edge:001122334457", True),
        entity("Edge:001122334458", "INF", normalized=False),
        entity("Plain:aabbccddeeff", 1, prefix=""),
        {"type": "InfrastructureElement"},
        "junk",
    ]).replace('"INF"', "1e400")  # parses as infinity
    route = respx.get(ENTITIES).mock(return_value=httpx.Response(200, text=body))
    ies = await OrionClient(BASE).ie_entities()
    assert ies == [
        IE(URN + "MyDomain:fa163e5e25ef", "MyDomain:fa163e5e25ef", "MyDomain", 0.74),
        IE(URN + "MyDomain:fa163e5e25f0", "MyDomain:fa163e5e25f0", "MyDomain", 0.5),
        IE(URN + "Edge:001122334455", "Edge:001122334455", "Edge", None),
        IE(URN + "Edge:001122334456", "Edge:001122334456", "Edge", None),
        IE(URN + "Edge:001122334457", "Edge:001122334457", "Edge", None),
        IE(URN + "Edge:001122334458", "Edge:001122334458", "Edge", None),
        IE("Plain:aabbccddeeff", "Plain:aabbccddeeff", "Plain", 1.0),
    ]
    req = route.calls[0].request
    assert req.url.params["type"] == "InfrastructureElement"
    assert req.headers["accept"] == "application/json"


@respx.mock
async def test_ie_entities_pages_through_results():
    pages = [[entity(f"D:00000000000{i}", 0.1 * i) for i in range(n, n + 2)] for n in (0, 2)]
    pages.append([entity("D:000000000004", 0.4)])

    def answer(request: httpx.Request) -> httpx.Response:
        offset = int(request.url.params.get("offset", "0"))
        assert request.url.params["limit"] == "2"
        return httpx.Response(200, json=pages[offset // 2])

    route = respx.get(ENTITIES).mock(side_effect=answer)
    ies = await OrionClient(BASE, page_size=2).ie_entities()
    assert [i.ie_id for i in ies] == [f"D:00000000000{i}" for i in range(5)]
    assert route.call_count == 3


@respx.mock
async def test_context_link_header():
    route = respx.get(ENTITIES).mock(return_value=httpx.Response(200, json=[]))
    ctx = "https://aerios.example/context.jsonld"
    assert await OrionClient(BASE, context_url=ctx).ie_entities() == []
    link = route.calls[0].request.headers["link"]
    assert ctx in link and 'rel="http://www.w3.org/ns/json-ld#context"' in link


@pytest.mark.parametrize("failure", [
    httpx.ConnectError("refused"),
    httpx.ReadTimeout("slow"),
    httpx.Response(500, json={"title": "boom"}),
    httpx.Response(200, text="<html>"),
    httpx.Response(200, json={"not": "a list"}),
])
@respx.mock
async def test_unreachable_is_never_an_empty_list(failure):
    if isinstance(failure, httpx.Response):
        respx.get(ENTITIES).mock(return_value=failure)
    else:
        respx.get(ENTITIES).mock(side_effect=failure)
    client = OrionClient(BASE)
    with pytest.raises(OrionUnavailable):
        await client.ie_entities()
    assert await client.status() == "unreachable"


@respx.mock
async def test_status_ok_and_default_timeout():
    respx.get(ENTITIES).mock(return_value=httpx.Response(200, json=[entity("D:000000000001")]))
    client = OrionClient(BASE)
    assert client.timeout_s == 2.0
    assert await client.status() == "ok"


@respx.mock
async def test_service_component_hosts_follow_the_relationship():
    sc = "urn:ngsi-ld:Service:0a1b:Component:"
    body = [
        {"id": sc + "web", "type": "ServiceComponent",
         "infrastructureElement": URN + "MyDomain:fa163e5e25ef"},
        {"id": sc + "db", "type": "ServiceComponent",
         "infrastructureElement": {"type": "Relationship", "object": URN + "Edge:001122334455"}},
        {"id": sc + "cache", "type": "ServiceComponent",
         "infrastructureElement": {"id": URN + "Edge:001122334456", "type": "InfrastructureElement"}},
        {"id": sc + "pending", "type": "ServiceComponent"},  # not allocated yet
        {"id": sc + "bad", "infrastructureElement": 7},
        {"type": "ServiceComponent"},
        "junk",
    ]
    route = respx.get(ENTITIES).mock(return_value=httpx.Response(200, json=body))
    hosts = await OrionClient(BASE).service_component_hosts()
    assert hosts == {sc + "web": "MyDomain:fa163e5e25ef", sc + "db": "Edge:001122334455",
                     sc + "cache": "Edge:001122334456"}
    assert route.calls[0].request.url.params["type"] == "ServiceComponent"


@respx.mock
async def test_oversized_listing_is_refused():
    body = json.dumps([entity(f"MyDomain:{n:012x}", 0.5) for n in range(50)])
    respx.get(ENTITIES).mock(return_value=httpx.Response(200, text=body))
    with pytest.raises(OrionUnavailable, match="larger than 1000 bytes"):
        await OrionClient(BASE, max_reply_bytes=1000).ie_entities()
    assert len(await OrionClient(BASE).ie_entities(max_bytes=len(body))) == 50
    with pytest.raises(OrionUnavailable, match=f"larger than {len(body) - 1} bytes"):
        await OrionClient(BASE).ie_entities(max_bytes=len(body) - 1)
    with pytest.raises(OrionUnavailable):
        await OrionClient(BASE).service_component_hosts(max_bytes=10)


@respx.mock
async def test_listing_budget_spans_pages():
    page = json.dumps([entity(f"MyDomain:{n:012x}", 0.5) for n in range(2)])
    respx.get(ENTITIES).mock(return_value=httpx.Response(200, text=page))
    with pytest.raises(OrionUnavailable, match=f"larger than {len(page) * 3} bytes"):
        # every page is full (2 of 2), so it keeps paging until the budget runs out
        await OrionClient(BASE, page_size=2, max_reply_bytes=len(page) * 3).ie_entities()


@respx.mock
async def test_service_component_hosts_unreachable():
    respx.get(ENTITIES).mock(side_effect=httpx.ConnectError("refused"))
    with pytest.raises(OrionUnavailable):
        await OrionClient(BASE).service_component_hosts()
