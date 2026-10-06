import asyncio
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
