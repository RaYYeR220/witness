from witness_core import merkle, poi_compat
from witness_core.ids import from_hex


def test_inx_poi_roundtrip(vectors):
    cones = {c["index"]: c["blockIdsWhiteFlagOrder"] for c in vectors("cones")}
    roots = {m["index"]: from_hex(m["inclusionMerkleRoot"]) for m in vectors("milestones")}
    entries = vectors("poi_create")
    assert entries
    for entry in entries:
        assert entry["status"] == 200
        body = entry["body"]
        idx = body["milestone"]["index"]
        cone = cones[idx]
        value, path = poi_compat.from_inx_poi(body["proof"])
        assert value == from_hex(entry["blockId"])
        assert merkle.verify(value, path, roots[idx])
        values = [from_hex(b) for b in cone]
        pos = cone.index(entry["blockId"])
        assert poi_compat.to_inx_poi(values, pos) == body["proof"]


def test_single_leaf_proof():
    v = [b"\x01" * 32]
    proof = poi_compat.to_inx_poi(v, 0)
    assert proof == {"value": "0x" + "01" * 32}
    assert poi_compat.from_inx_poi(proof) == (v[0], [])
