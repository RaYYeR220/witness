import asyncio
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fakechain import FakeChain, FakeSource, did_key, signed
from witness_core import checkpoint, policy
from witness_core.ids import to_hex
from witness_indexer.anchors import AnchorIngest, default_anchor_did
from witness_indexer.didkey import OfflineResolver
from witness_indexer.pipeline import Indexer
from witness_indexer.store import Store

ANCHOR = Ed25519PrivateKey.from_private_bytes(b"\x0a" * 32)
OTHER = Ed25519PrivateKey.from_private_bytes(b"\x0b" * 32)
POLICY = policy.load({"version": 1, "default": {"allowed": ["*"]}})
TRAIL = "0x" + "7a" * 32
TX = "8L3KZB5SN8Dd7UTorJ6sUqC3DFyuatJ6WPvuSQZummtu"


def _ids(first: int, n: int) -> list[bytes]:
    return [hashlib.blake2b(f"ms-{i}".encode(), digest_size=32).digest()
            for i in range(first, first + n)]


def mirror(seq: int, first: int = 1, n: int = 12, msgs: int = 3, record: int = 4) -> dict:
    ids = _ids(first, n)
    cp = checkpoint.build("private_tangle1", "MyDomain", (first, ids[0]),
                          (first + n - 1, ids[-1]), ids, msgs, b"\x01" * 32, None)
    return {"seq": seq, "checkpoint": cp, "checkpointHash": to_hex(checkpoint.hash(cp)),
            "rebased": {"network": "testnet", "trail": TRAIL, "record": record, "tx": TX}}


async def index(store: Store, payloads: list[tuple[str, bytes]], anchor_did: str | None):
    chain = FakeChain()
    chain.add(payloads)
    ix = Indexer(FakeSource(chain), store, policy=POLICY, resolve=OfflineResolver(),
                 anchor_did=anchor_did, sleep=lambda _s: asyncio.sleep(0))
    await ix.sync()
    return chain


async def anchor_rows(store: Store) -> list[dict]:
    return await store._fetch("SELECT * FROM anchors ORDER BY seq")


async def test_genuine_mirror_becomes_an_anchor(store: Store):
    body = mirror(1)
    chain = await index(store, [("witness.anchor", signed(ANCHOR, "witness.anchor", body, 1))],
                        did_key(ANCHOR))
    [row] = await anchor_rows(store)
    cp = body["checkpoint"]
    assert (row["seq"], row["from_ms"], row["to_ms"]) == (1, 1, 12)
    assert to_hex(bytes(row["ms_root"])) == cp["msRoot"]
    assert to_hex(bytes(row["checkpoint_hash"])) == body["checkpointHash"]
    assert row["checkpoint"] == cp
    assert (row["network"], row["tx"], row["record"], row["status"]) == ("testnet", TX, 4,
                                                                          "anchored")
    assert row["created_at_ms"] == chain.ms[1].timestamp * 1000
    [ev] = [e for e in await store.events_after(0, 1000) if e["type"] == "anchor"]
    assert ev["payload"]["seq"] == 1 and ev["payload"]["trail"] == TRAIL
    assert ev["payload"]["blockId"] == to_hex(chain.block_id(1, 0))


async def test_only_the_pinned_anchor_producer_signed_well_formed_counts(store: Store):
    good = mirror(1)
    malformed = {k: v for k, v in mirror(2, first=13).items() if k != "seq"}
    await index(store, [
        ("witness.anchor", signed(OTHER, "witness.anchor", good, 1)),  # foreign issuer
        ("witness.anchor", signed(ANCHOR, "witness.anchor", mirror(3, first=25), 2,
                                  mode="relay")),  # RELAY_ATTESTED, even by the anchor DID
        ("witness.anchor", signed(ANCHOR, "witness.anchor", malformed, 3)),  # no seq
        ("witness.anchor", json.dumps(mirror(4, first=37)).encode()),  # unsigned
        ("other.tag", signed(ANCHOR, "other.tag", mirror(5, first=49), 4)),  # wrong tag
    ], did_key(ANCHOR))
    assert await anchor_rows(store) == []


async def test_without_a_pinned_did_nothing_is_ingested(store: Store):
    await index(store, [("witness.anchor", signed(ANCHOR, "witness.anchor", mirror(1), 1))],
                None)
    assert await anchor_rows(store) == []
    ingest = AnchorIngest(None)
    await ingest.publish_status(store)
    status = (await store.service_status())["anchor-mirror"]
    assert status["status"] == "off" and "--anchor-did" in status["detail"]


async def test_same_seq_twice_same_checkpoint_is_quiet_different_is_critical(store: Store):
    first, again = mirror(1), mirror(1)
    forged = mirror(1, msgs=99)  # same seq, another checkpoint
    chain = await index(store, [
        ("witness.anchor", signed(ANCHOR, "witness.anchor", first, 1)),
        ("witness.anchor", signed(ANCHOR, "witness.anchor", again, 2)),
        ("witness.anchor", signed(ANCHOR, "witness.anchor", forged, 3)),
    ], did_key(ANCHOR))
    [row] = await anchor_rows(store)
    assert to_hex(bytes(row["checkpoint_hash"])) == first["checkpointHash"]
    alerts = await store.alerts({"rule": "ANCHOR_MISMATCH"})
    assert len(alerts) == 1
    a = alerts[0]
    assert a["severity"] == "critical"
    assert bytes(a["block_id"]) == chain.block_id(1, 2)
    assert a["evidence"]["storedCheckpointHash"] == first["checkpointHash"]
    assert a["evidence"]["mirrorCheckpointHash"] == forged["checkpointHash"]
    assert "alert" in [e["type"] for e in await store.events_after(0, 1000)]


def test_default_anchor_did_from_the_identity_file(tmp_path):
    (tmp_path / "testnet.json").write_text(json.dumps({"identities": [
        {"name": "relay", "did": "did:iota:testnet:0x01"},
        {"name": "anchor", "did": "did:iota:testnet:0x02"},
    ]}))
    assert default_anchor_did("testnet", tmp_path) == "did:iota:testnet:0x02"
    assert default_anchor_did("mainnet", tmp_path) is None
    (tmp_path / "broken.json").write_text("{")
    assert default_anchor_did("broken", tmp_path) is None
    # The repository's own testnet identities name an anchor DID.
    assert (default_anchor_did("testnet") or "").startswith("did:iota:testnet:0x")
