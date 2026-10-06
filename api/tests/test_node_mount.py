import asyncio
import logging
from dataclasses import replace

import grpc
import httpx
import pytest
from witness_api import node_mount
from witness_api.app import create_app
from witness_api.node_mount import NodeRoute, encode_route_request


def test_route_request_encoding():
    # protobuf wire format of inx.APIRouteRequest{route=1, host=2, port=3 (uint32), path=4}
    assert encode_route_request("witness/v1", "host.docker.internal", 7200) == (
        b"\x0a\x0awitness/v1" + b"\x12\x14host.docker.internal" + b"\x18\xa0\x38")
    assert encode_route_request("r", "", 0, "/p") == b"\x0a\x01r" + b"\x22\x02/p"
    assert encode_route_request("witness/v1") == b"\x0a\x0awitness/v1"
    with pytest.raises(ValueError):
        encode_route_request("r", "h", 70_000)


def test_encoding_matches_generated_stubs():
    pb = pytest.importorskip("witness_indexer.inx_proto.inx_pb2")
    msg = pb.APIRouteRequest(route="witness/v1", host="host.docker.internal", port=7200, path="")
    assert encode_route_request("witness/v1", "host.docker.internal", 7200) == (
        msg.SerializeToString())


class FakeInx:
    """Just enough of the INX gRPC service to see route (un)registration requests."""

    def __init__(self, reject: bool = False):
        self.calls: list[tuple[str, bytes]] = []
        self.server = grpc.aio.server()

        def handler(name):
            async def fn(request: bytes, context) -> bytes:
                self.calls.append((name, request))
                if reject:
                    await context.abort(grpc.StatusCode.INVALID_ARGUMENT,
                                        "secret internal detail")
                return b""  # inx.NoParams
            return grpc.unary_unary_rpc_method_handler(fn)

        self.server.add_generic_rpc_handlers([grpc.method_handlers_generic_handler(
            "inx.INX", {n: handler(n) for n in ("RegisterAPIRoute", "UnregisterAPIRoute")})])
        self.port = self.server.add_insecure_port("127.0.0.1:0")

    async def __aenter__(self):
        await self.server.start()
        return self

    async def __aexit__(self, *exc):
        await self.server.stop(None)


async def test_register_and_unregister_against_inx():
    async with FakeInx() as inx:
        route = NodeRoute(f"127.0.0.1:{inx.port}", "witness/v1", "host.docker.internal", 7200)
        assert await route.register() is True
        assert route.registered and route.error is None
        await route.unregister()
        assert not route.registered
    assert inx.calls == [
        ("RegisterAPIRoute", encode_route_request("witness/v1", "host.docker.internal", 7200)),
        ("UnregisterAPIRoute", encode_route_request("witness/v1")),
    ]


async def test_registration_failure_is_logged_not_raised(caplog):
    route = NodeRoute("127.0.0.1:1", "witness/v1", "host.docker.internal", 7200,
                      timeout_s=0.5)
    with caplog.at_level(logging.WARNING, logger="witness_api.node_mount"):
        assert await route.register() is False
    assert not route.registered and route.error == "unreachable"
    assert "witness/v1" in caplog.text
    await route.unregister()  # nothing registered: a no-op


async def test_rejected_registration_reports_a_code_only(caplog):
    async with FakeInx(reject=True) as inx:
        route = NodeRoute(f"127.0.0.1:{inx.port}", "witness/v1", "h", 7200)
        with caplog.at_level(logging.WARNING, logger="witness_api.node_mount"):
            assert await route.register() is False
    assert route.error == "rejected"
    assert "secret internal detail" in caplog.text  # the detail goes to the log only


async def test_route_is_registered_again_periodically():
    """The node forgets routes when it restarts; registering again simply overrides."""
    async with FakeInx() as inx:
        route = NodeRoute(f"127.0.0.1:{inx.port}", "witness/v1", "h", 7200, refresh_s=0.1)
        route.start()
        for _ in range(100):
            if len(inx.calls) >= 3:
                break
            await asyncio.sleep(0.05)
        await route.stop()
    names = [name for name, _ in inx.calls]
    assert names[:3] == ["RegisterAPIRoute"] * 3 and names[-1] == "UnregisterAPIRoute"


async def test_registration_skipped_without_grpc(monkeypatch, caplog):
    def missing():
        raise ImportError("No module named 'grpc'")
    monkeypatch.setattr(node_mount, "_import_grpc", missing)
    route = NodeRoute("127.0.0.1:9029", "witness/v1", "h", 1)
    with caplog.at_level(logging.WARNING, logger="witness_api.node_mount"):
        assert await route.register() is False
    assert "grpc" in caplog.text and route.error == "grpc_missing"


async def test_app_mounts_route_on_the_node(store, settings):
    async with FakeInx() as inx:
        app = create_app(replace(settings, inx_addr=f"127.0.0.1:{inx.port}", port=7311,
                                 route_host="host.docker.internal"), store=store)
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://w.test") as c:
                for _ in range(50):
                    status = (await c.get("/stats")).json()["nodeRoute"]
                    if status["registered"]:
                        break
                    await asyncio.sleep(0.05)
        assert status == {"enabled": True, "route": "witness/v1", "registered": True,
                          "error": None}
        assert [name for name, _ in inx.calls] == ["RegisterAPIRoute", "UnregisterAPIRoute"]
        assert inx.calls[0][1] == encode_route_request("witness/v1", "host.docker.internal",
                                                       7311)
