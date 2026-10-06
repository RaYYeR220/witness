import os

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from witness_core import merkle
from witness_core.ids import blake2b256, from_hex


def synth(n: int) -> list[bytes]:
    return [blake2b256(bytes([i % 256, i // 256])) for i in range(n)]


def test_root_matches_milestones(vectors):
    roots = {m["index"]: from_hex(m["inclusionMerkleRoot"]) for m in vectors("milestones")}
    cones = vectors("cones")
    assert cones
    for cone in cones:
        values = [from_hex(b) for b in cone["blockIdsWhiteFlagOrder"]]
        assert merkle.root(values) == roots[cone["index"]]


def test_degenerate_sizes():
    assert merkle.root([]) == blake2b256(b"")
    v = synth(1)
    assert merkle.root(v) == merkle.leaf_hash(v[0])
    for n in (2, 3, 5):
        vals = synth(n)
        r = merkle.root(vals)
        for i in range(n):
            assert merkle.verify(vals[i], merkle.audit_path(vals, i), r)


def test_index_out_of_range():
    with pytest.raises(IndexError):
        merkle.audit_path(synth(3), 3)
    with pytest.raises(IndexError):
        merkle.audit_path([], 0)
    with pytest.raises(IndexError):
        merkle.audit_path(synth(3), -1)


@settings(max_examples=int(os.environ.get("HYP_EXAMPLES", "60")), deadline=None)
@given(st.lists(st.binary(min_size=32, max_size=32), min_size=1, max_size=300), st.data())
def test_path_verifies_property(values, data):
    i = data.draw(st.integers(0, len(values) - 1))
    assert merkle.verify(values[i], merkle.audit_path(values, i), merkle.root(values))


def test_negative_control_flip():
    vals = synth(7)
    r = merkle.root(vals)
    path = merkle.audit_path(vals, 4)
    assert merkle.verify(vals[4], path, r)

    def flip(b: bytes) -> bytes:
        return bytes([b[0] ^ 1]) + b[1:]

    for j, step in enumerate(path):
        bad = list(path)
        bad[j] = merkle.PathStep(step.side, flip(step.hash))
        assert not merkle.verify(vals[4], bad, r)
        swapped = list(path)
        swapped[j] = merkle.PathStep("L" if step.side == "R" else "R", step.hash)
        assert not merkle.verify(vals[4], swapped, r)
    assert not merkle.verify(flip(vals[4]), path, r)
