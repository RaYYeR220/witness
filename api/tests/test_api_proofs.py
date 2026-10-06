import httpx
import respx
from apiseed import ISS, KID, SIGNER_PUBLIC, put_signed, sealed_score, seed_chain, signed_block
from conftest import ANCHOR, TRAIL
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from witness_core import bundle, checkpoint, codec, merkle
from witness_core.ids import blake2b256, from_hex, to_hex

IE = "MyDomain:fa163e5e25ef"
B371_1 = "0x32b2ce5c"  # prefix of the trust.score block in milestone 371


def cfg(vectors) -> bundle.VerifierConfig:
    keys = {from_hex(k) for k in vectors("coordinator_keys")["publicKeys"]}
    return bundle.VerifierConfig(network="private_tangle1", trusted_coordinator_keys=keys,
                                 threshold=2, rebased_network="testnet", trail_id=TRAIL)


def steps(ladder: bundle.Ladder) -> dict:
    return {s.name: s.ok for s in ladder.steps}


async def test_proof_bundle_verifies(client, store, vectors):
    tagged = await seed_chain(store, vectors)
    with respx.mock(assert_all_called=False) as mock:
        resolve = mock.get(url__startswith=f"{ANCHOR}/resolve/")
        for bid in tagged:
            r = await client.get(f"/proofs/{bid}")
            assert r.status_code == 200, r.text
            b = r.json()
            assert b["v"] == 1 and b["network"] == "private_tangle1"
            assert b["block"]["id"] == bid
            s = steps(bundle.verify(b, cfg(vectors)))
            assert (s["block_hash"], s["inclusion"], s["milestone_signatures"]) == (
                True, True, True), (bid, s)
            assert b["envelope"]["verdict"] in ("UNSIGNED_LEGACY", "MALFORMED")
            assert b["envelope"]["didDoc"] is None
            assert b["anchor"] is None
        assert not resolve.called  # unsigned messages name no issuer to resolve

    # a block without a message: the milestone block that milestone 371 references first
    ms_block = next(b["blockId"] for b in vectors("blocks") if b["kind"] == "milestone")
    b = (await client.get(f"/proofs/{ms_block}")).json()
    assert b["envelope"] is None
    s = steps(bundle.verify(b, cfg(vectors)))
    assert (s["block_hash"], s["inclusion"], s["milestone_signatures"]) == (True, True, True)


async def test_proof_bundle_carries_anchor(client, store, vectors):
    tagged = await seed_chain(store, vectors)
    bid = next(b for b in tagged if b.startswith(B371_1))
    mids = [from_hex(m["milestoneId"]) for m in vectors("milestones")]
    cp = checkpoint.build("private_tangle1", "MyDomain", (370, mids[0]), (373, mids[-1]), mids,
                          10, b"\x01" * 32, None)
    await store.put_anchor(seq=1, from_ms=370, to_ms=373, ms_root=from_hex(cp["msRoot"]),
                           checkpoint=cp, checkpoint_hash=checkpoint.hash(cp), network="testnet",
                           created_at_ms=1, status="pending")
    assert (await client.get(f"/proofs/{bid}")).json()["anchor"] is None  # not on chain yet

    await store.set_anchor_status(1, "anchored", tx="5xGp7rWq2Tz9", record=3)
    b = (await client.get(f"/proofs/{bid}")).json()
    assert b["anchor"]["checkpoint"] == cp
    assert b["anchor"]["rebased"] == {"network": "testnet", "trail": TRAIL, "record": 3,
                                      "tx": "5xGp7rWq2Tz9"}
    onchain = {"checkpointHash": to_hex(checkpoint.hash(cp))}
    s = steps(bundle.verify(b, cfg(vectors), fetch_anchor_record=lambda a: onchain))
    assert s == {"block_hash": True, "inclusion": True, "milestone_signatures": True,
                 "envelope": None, "anchor": True}


async def test_proof_bundle_signed_message_full_ladder(client, store, vectors):
    """A signed message in a (synthetic) milestone signed by the test coordinator keys: with
    the DID snapshot from the anchor service, steps 1-4 all pass."""
    ts = 1_791_283_600
    env = sealed_score({"id": IE, "score": 0.5}, seq=7)
    raw, bid, _ = signed_block(env)
    await put_signed(store, env, ms_index=900, ts=ts, wf_index=0)
    root = merkle.root([bid])
    prev = b"\x44" * 32
    essence = codec.serialize_milestone_essence(codec.MilestoneEssence(
        900, ts, 2, prev, [b"\x55" * 32], root, b"\x00" * 32, b"", b""))
    mid = codec.milestone_id(essence)
    sigs = []
    for k in vectors("coordinator_keys")["privateKeys"]:
        sk = Ed25519PrivateKey.from_private_bytes(from_hex(k)[:32])
        sigs.append({"pk": to_hex(sk.public_key().public_bytes_raw()), "sig": to_hex(sk.sign(mid))})
    await store.put_milestone(900, mid, ts, essence, sigs, root, prev)
    await store.put_block(bid, 900, 0, raw, codec.PAYLOAD_TAGGED_DATA)

    snapshot = {"doc": {"id": ISS}, "version": "4", "historyComplete": True, "keys": [
        {"kid": KID, "type": "Ed25519", "publicKeyHex": to_hex(SIGNER_PUBLIC),
         "revokedAtMs": None}]}
    with respx.mock() as mock:
        mock.get(f"{ANCHOR}/resolve/{ISS}").respond(200, json=snapshot)
        b = (await client.get(f"/proofs/{to_hex(bid)}")).json()
    assert b["envelope"] == {"verdict": "PRODUCER_SIGNED", "didDoc": snapshot, "didVersion": "4"}
    s = steps(bundle.verify(b, cfg(vectors), resolve_did=lambda d: snapshot if d == ISS else None))
    assert s == {"block_hash": True, "inclusion": True, "milestone_signatures": True,
                 "envelope": True, "anchor": None}

    with respx.mock() as mock:
        mock.get(f"{ANCHOR}/resolve/{ISS}").mock(side_effect=httpx.ConnectError("down"))
        b = (await client.get(f"/proofs/{to_hex(bid)}")).json()
    assert b["envelope"] == {"verdict": "PRODUCER_SIGNED", "didDoc": None, "didVersion": None}


async def test_proof_inx_poi_format(client, store, vectors):
    await seed_chain(store, vectors)
    for entry in vectors("poi_create"):
        r = await client.get(f"/proofs/{entry['blockId']}", params={"format": "inx-poi"})
        assert r.status_code == 200, r.text
        assert r.json() == entry["body"], entry["blockId"]
    ms_block = next(b["blockId"] for b in vectors("blocks") if b["kind"] == "milestone")
    poi = (await client.get(f"/proofs/{ms_block}", params={"format": "inx-poi"})).json()
    assert poi["block"]["payload"]["type"] == 7
    assert set(poi) == {"milestone", "block", "proof"}
    bad = await client.get(f"/proofs/{ms_block}", params={"format": "xml"})
    assert bad.status_code == 422


async def test_proof_errors(client, store, vectors):
    await seed_chain(store, vectors)
    assert (await client.get("/proofs/0x" + "ab" * 32)).status_code == 404
    unconfirmed = await put_signed(store, sealed_score({"id": IE, "score": 0.1}, seq=1),
                                   ms_index=950, ts=1)
    r = await client.get(f"/proofs/{to_hex(unconfirmed)}")
    assert r.status_code == 404 and "milestone" in r.json()["detail"]
    assert (await client.get("/proofs/0x12")).status_code == 422

    # a stored block whose bytes no longer hash to its id: say so instead of failing
    uncaptured = vectors("cones")[0]["blockIdsWhiteFlagOrder"][0]  # seeded as b"\x00"
    for params in ({}, {"format": "inx-poi"}):
        r = await client.get(f"/proofs/{uncaptured}", params=params)
        assert r.status_code == 409 and "do not hash to its id" in r.json()["detail"]

    # a cone that no longer reproduces the milestone's inclusion root
    target = vectors("cones")[0]["blockIdsWhiteFlagOrder"][4]
    assert (await client.get(f"/proofs/{target}")).status_code == 200
    stray = b"\x00\x01"
    await store.put_block(blake2b256(stray), 370, 99, stray, -1)
    r = await client.get(f"/proofs/{target}")
    assert r.status_code == 409 and "inclusion" in r.json()["detail"]
