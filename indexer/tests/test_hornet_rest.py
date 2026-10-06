import httpx
import pytest
import respx
from witness_core.codec import serialize_tagged_block
from witness_core.ids import blake2b256
from witness_indexer.hornet_rest import RAW_MEDIA_TYPE, HornetRest, HornetUnavailable

BASE = "http://hornet.test"
RAW = serialize_tagged_block([b"\x11" * 32], b"trust.score", b'{"score": 0.5}')
BID = blake2b256(RAW)
BLOCK_URL = f"{BASE}/api/core/v2/blocks/0x{BID.hex()}"


@pytest.fixture
async def hornet():
    h = HornetRest(BASE + "/")
    try:
        yield h
    finally:
        await h.close()


@respx.mock
async def test_block_json(hornet):
    route = respx.get(BLOCK_URL).mock(
        return_value=httpx.Response(200, json={"protocolVersion": 2}))
    assert await hornet.block(BID) == {"protocolVersion": 2}
    assert route.calls.last.request.headers["accept"] == "application/json"


def binary(raw):
    return httpx.Response(200, content=raw, headers={"Content-Type": RAW_MEDIA_TYPE})


@respx.mock
async def test_block_raw_asks_for_binary(hornet):
    route = respx.get(BLOCK_URL).mock(return_value=binary(RAW))
    assert await hornet.block_raw(BID) == RAW
    assert route.calls.last.request.headers["accept"] == RAW_MEDIA_TYPE


@respx.mock
@pytest.mark.parametrize("answer", [
    httpx.Response(200, json={"protocolVersion": 2}),  # node ignored Accept
    httpx.Response(200, text="<html>maintenance</html>"),  # proxy page
    httpx.Response(200, content=RAW),  # no content type at all
], ids=["json", "html", "untyped"])
async def test_block_raw_rejects_non_binary_answer(hornet, answer):
    respx.get(BLOCK_URL).mock(return_value=answer)
    with pytest.raises(HornetUnavailable):
        await hornet.block_raw(BID)


@respx.mock
async def test_block_raw_accepts_media_type_parameters(hornet):
    respx.get(BLOCK_URL).mock(return_value=httpx.Response(
        200, content=RAW, headers={"Content-Type": RAW_MEDIA_TYPE.upper() + "; charset=x"}))
    assert await hornet.block_raw(BID) == RAW


@respx.mock
async def test_metadata(hornet):
    meta = {"blockId": "0x" + BID.hex(), "isSolid": True, "referencedByMilestoneIndex": 7}
    respx.get(BLOCK_URL + "/metadata").mock(return_value=httpx.Response(200, json=meta))
    assert await hornet.block_metadata(BID) == meta


@respx.mock
async def test_not_found_is_none(hornet):
    respx.get(BLOCK_URL).mock(return_value=httpx.Response(404, json={"error": {}}))
    respx.get(BLOCK_URL + "/metadata").mock(return_value=httpx.Response(404))
    assert await hornet.block(BID) is None
    assert await hornet.block_raw(BID) is None
    assert await hornet.block_metadata(BID) is None


@respx.mock
async def test_network_error_raises_unavailable(hornet):
    respx.get(BLOCK_URL + "/metadata").mock(side_effect=httpx.ConnectError("refused"))
    with pytest.raises(HornetUnavailable):
        await hornet.block_metadata(BID)


@respx.mock
@pytest.mark.parametrize("status", [500, 503])
async def test_server_error_raises_unavailable(hornet, status):
    respx.get(BLOCK_URL).mock(return_value=httpx.Response(status, text="busy"))
    with pytest.raises(HornetUnavailable) as e:
        await hornet.block_raw(BID)
    assert e.value.status == status


@respx.mock
async def test_garbage_json_raises_unavailable(hornet):
    respx.get(BLOCK_URL + "/metadata").mock(return_value=httpx.Response(200, text="<html>"))
    with pytest.raises(HornetUnavailable):
        await hornet.block_metadata(BID)


@respx.mock
async def test_errors_name_the_path_not_the_node(hornet):
    """Error text ends up in alert evidence and API answers; the node's address stays out."""
    respx.get(BLOCK_URL + "/metadata").mock(side_effect=httpx.ConnectError("refused"))
    respx.get(BLOCK_URL).mock(return_value=httpx.Response(503, text="busy"))
    for call in (hornet.block_metadata, hornet.block_raw):
        with pytest.raises(HornetUnavailable) as e:
            await call(BID)
        assert "hornet.test" not in str(e.value)
        assert f"/api/core/v2/blocks/0x{BID.hex()}" in str(e.value)


async def test_rejects_bad_block_id(hornet):
    with pytest.raises(ValueError):
        await hornet.block(b"\x00" * 31)
