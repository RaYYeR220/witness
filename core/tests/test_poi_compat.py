import pytest
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


H = "0x" + "ab" * 32
V = "0x" + "cd" * 32


@pytest.mark.parametrize(
    "bad",
    [
        {},
        {"l": {"h": H}},
        {"r": {"h": H}},
        {"l": 1, "r": 2},
        {"l": {"h": H}, "r": 2},
        {"value": 5},
        {"value": None},
        {"value": "0xzz"},
        {"value": V, "l": {"h": H}, "r": {"h": H}},
        {"l": {"value": V}, "r": {"value": V}},
        {"l": {"h": H}, "r": {"h": H}},
        {"l": {"h": 5}, "r": {"value": V}},
        {"l": {"h": "nothex"}, "r": {"value": V}},
        {"l": {"h": H}, "r": 7},
        [],
        "x",
        None,
    ],
)
def test_from_inx_poi_malformed(bad):
    with pytest.raises(ValueError):
        poi_compat.from_inx_poi(bad)


def test_to_inx_poi_index_errors():
    vals = [bytes([i]) * 32 for i in range(3)]
    for i in (-1, 3):
        with pytest.raises(IndexError):
            poi_compat.to_inx_poi(vals, i)
    with pytest.raises(IndexError):
        poi_compat.to_inx_poi([], 0)


@pytest.mark.parametrize("n", [1, 2, 3, 5])
def test_to_inx_poi_roundtrip_small(n):
    vals = [bytes([i + 1]) * 32 for i in range(n)]
    r = merkle.root(vals)
    for i in range(n):
        value, path = poi_compat.from_inx_poi(poi_compat.to_inx_poi(vals, i))
        assert value == vals[i]
        assert merkle.verify(value, path, r)
