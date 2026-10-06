import asyncio
import contextlib
import json


def parse_sse(text: str) -> list[dict]:
    """Events of an SSE body as {id, event, data}; comment lines (pings) are skipped."""
    out = []
    for chunk in text.replace("\r\n", "\n").split("\n\n"):
        ev: dict = {}
        for line in chunk.split("\n"):
            if not line or line.startswith(":"):
                continue
            field, _, value = line.partition(":")
            value = value.removeprefix(" ")
            if field == "data":
                ev["data"] = ev.get("data", "") + value
            else:
                ev[field] = value
        if "data" in ev:
            ev["data"] = json.loads(ev["data"])
            out.append(ev)
    return out


async def emit_n(store, n: int, start: int = 0) -> list[int]:
    return [await store.emit("message", {"n": start + i}) for i in range(n)]


async def test_sse_resume(client, store):
    first = await emit_n(store, 5)

    r = await client.get("/stream", params={"after": 0, "limit": 3})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/event-stream")
    got = parse_sse(r.text)
    assert [int(e["id"]) for e in got] == first[:3]
    assert [e["event"] for e in got] == ["message"] * 3
    assert got[0]["data"]["payload"] == {"n": 0}
    assert got[0]["data"]["type"] == "message" and got[0]["data"]["at"].endswith("Z")

    # reconnect where the client stopped: the backlog first, then live events, no gap or dup
    async def reconnect():
        return await client.get("/stream", params={"limit": 4},
                                headers={"Last-Event-ID": got[-1]["id"]})

    task = asyncio.create_task(reconnect())
    await asyncio.sleep(0.3)  # the stream has drained the backlog and waits for NOTIFY
    live = await emit_n(store, 2, start=5)
    r2 = await asyncio.wait_for(task, 10)
    resumed = [int(e["id"]) for e in parse_sse(r2.text)]
    assert resumed == first[3:] + live
    assert [e["data"]["payload"]["n"] for e in parse_sse(r2.text)] == [3, 4, 5, 6]


async def test_sse_starts_at_head_and_filters_types(client, store):
    await emit_n(store, 3)

    async def listen():
        return await client.get("/stream", params={"limit": 2, "types": "alert,anchor"})

    task = asyncio.create_task(listen())
    await asyncio.sleep(0.3)
    await store.emit("message", {"skip": True})
    a = await store.emit("alert", {"rule": "FORGED"})
    await store.emit("lifecycle", {"skip": True})
    b = await store.emit("anchor", {"seq": 1})
    events = parse_sse((await asyncio.wait_for(task, 10)).text)
    assert [(int(e["id"]), e["event"]) for e in events] == [(a, "alert"), (b, "anchor")]


async def test_sse_rejects_bad_resume_point(client):
    r = await client.get("/stream", headers={"Last-Event-ID": "abc"})
    assert r.status_code == 400
    assert (await client.get("/stream", params={"types": "bogus"})).status_code == 422
    assert (await client.get("/stream", params={"after": -1})).status_code == 422


async def test_sse_subscriber_cap(app, client):
    hub = app.state.services.hub
    cap = app.state.services.settings.stream_max_subscribers
    held = [hub.subscribe() for _ in range(cap)]
    try:
        r = await client.get("/stream", params={"limit": 1})
        assert r.status_code == 503 and "retry-after" in r.headers
    finally:
        for ev in held:
            hub.unsubscribe(ev)


async def test_sse_client_disconnect_releases_the_subscription(app, store):
    """A client that goes away mid-stream leaves nothing subscribed behind."""
    hub = app.state.services.hub
    await store.emit("message", {"n": 1})
    gone = asyncio.Event()
    during = []

    async def receive():
        await gone.wait()
        return {"type": "http.disconnect"}

    async def send(message):
        if message["type"] == "http.response.body" and b"event: message" in message.get(
                "body", b""):
            during.append(hub.subscribers)
            gone.set()

    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
             "method": "GET", "scheme": "http", "path": "/stream", "raw_path": b"/stream",
             "query_string": b"after=0", "headers": [(b"host", b"w.test")],
             "client": ("127.0.0.1", 5000), "server": ("w.test", 80), "root_path": ""}
    await asyncio.wait_for(app(scope, receive, send), 10)
    assert during == [1]
    assert hub.subscribers == 0


async def test_sse_slots_are_reserved_atomically(store, settings):
    """Concurrent connects cannot all slip under the cap: with K slots, exactly K streams
    open and the rest get 503; every slot is free again once the streams end."""
    from dataclasses import replace

    import httpx
    from witness_api.app import create_app

    cap, tries = 2, 6
    app = create_app(replace(settings, stream_max_subscribers=cap), store=store)
    async with app.router.lifespan_context(app):
        hub = app.state.services.hub
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://w.test") as c:
            # no `after`: each request awaits the head event id before taking its slot
            tasks = [asyncio.create_task(c.get("/stream", params={"limit": 1}))
                     for _ in range(tries)]
            for _ in range(100):
                if hub.subscribers == cap and sum(t.done() for t in tasks) == tries - cap:
                    break
                await asyncio.sleep(0.05)
            assert hub.subscribers == cap
            await store.emit("alert", {"rule": "FORGED"})
            done = await asyncio.wait_for(asyncio.gather(*tasks), 10)
        assert sorted(r.status_code for r in done) == [200] * cap + [503] * (tries - cap)
        assert all(len(parse_sse(r.text)) == 1 for r in done if r.status_code == 200)
        assert hub.subscribers == 0


async def test_sse_slot_freed_when_client_leaves_before_streaming(app):
    """A client gone before the stream starts must not keep its reserved slot."""
    hub = app.state.services.hub

    async def receive():
        return {"type": "http.disconnect"}

    async def send(message):
        pass

    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
             "method": "GET", "scheme": "http", "path": "/stream", "raw_path": b"/stream",
             "query_string": b"", "headers": [(b"host", b"w.test")],
             "client": ("127.0.0.1", 5001), "server": ("w.test", 80), "root_path": ""}
    for _ in range(3):
        await asyncio.wait_for(app(scope, receive, send), 10)
    assert hub.subscribers == 0

    # the connection is already dead when the response starts: the stream never runs
    async def broken_send(message):
        raise OSError("connection reset")

    for _ in range(3):
        with contextlib.suppress(OSError):
            await asyncio.wait_for(app(scope, receive, broken_send), 10)
    assert hub.subscribers == 0
