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


def test_hand_computed_roots_and_paths():
    L = merkle.leaf_hash
    N = merkle.node_hash
    S = merkle.PathStep
    v = synth(7)
    l = [L(x) for x in v]
    assert merkle.root(v[:3]) == N(N(l[0], l[1]), l[2])
    assert merkle.root(v[:5]) == N(N(N(l[0], l[1]), N(l[2], l[3])), l[4])
    assert merkle.root(v) == N(N(N(l[0], l[1]), N(l[2], l[3])), N(N(l[4], l[5]), l[6]))

    v3 = v[:3]
    assert merkle.audit_path(v3, 0) == [S("R", l[1]), S("R", l[2])]
    assert merkle.audit_path(v3, 1) == [S("L", l[0]), S("R", l[2])]
    assert merkle.audit_path(v3, 2) == [S("L", N(l[0], l[1]))]

    v5 = v[:5]
    left4 = N(N(l[0], l[1]), N(l[2], l[3]))
    assert merkle.audit_path(v5, 0) == [S("R", l[1]), S("R", N(l[2], l[3])), S("R", l[4])]
    assert merkle.audit_path(v5, 1) == [S("L", l[0]), S("R", N(l[2], l[3])), S("R", l[4])]
    assert merkle.audit_path(v5, 2) == [S("R", l[3]), S("L", N(l[0], l[1])), S("R", l[4])]
    assert merkle.audit_path(v5, 3) == [S("L", l[2]), S("L", N(l[0], l[1])), S("R", l[4])]
    assert merkle.audit_path(v5, 4) == [S("L", left4)]

    assert merkle.audit_path(v[:1], 0) == []


def test_verify_rejects_malformed_inputs():
    vals = synth(5)
    r = merkle.root(vals)
    path = merkle.audit_path(vals, 2)
    S = merkle.PathStep
    assert merkle.verify(vals[2], path, r)
    assert not merkle.verify(vals[2], [S(path[0].side, path[0].hash[:31]), *path[1:]], r)
    assert not merkle.verify(vals[2], [S("X", path[0].hash), *path[1:]], r)  # type: ignore[arg-type]
    assert not merkle.verify(vals[2], [*path, path[0]], r)
    assert not merkle.verify(vals[2][:31], path, r)
    assert not merkle.verify(vals[2], path, r[:31])
    assert not merkle.verify("x", path, r)  # type: ignore[arg-type]
    assert not merkle.verify(vals[2], [S("L", "ab")], r)  # type: ignore[arg-type]
