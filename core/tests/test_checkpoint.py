import copy
import hashlib

import pytest
from witness_core import canon, checkpoint, merkle
from witness_core.ids import from_hex, to_hex


def _h(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32).digest()


def _real_ids(vectors) -> list[bytes]:
    return [from_hex(m["milestoneId"]) for m in vectors("milestones")]


def _cp(ids: list[bytes], first: int = 370, prev: bytes | None = None) -> dict:
    return checkpoint.build(
        "private_tangle1",
        "MyDomain",
        (first, ids[0]),
        (first + len(ids) - 1, ids[-1]),
        ids,
        12,
        b"\x11" * 32,
        prev,
    )


def test_build_fields(vectors):
    ids = _real_ids(vectors)
    cp = _cp(ids, prev=b"\x22" * 32)
    assert cp == {
        "v": 1,
        "kind": "witness.checkpoint",
        "network": "private_tangle1",
        "domain": "MyDomain",
        "from": {"index": 370, "id": to_hex(ids[0])},
        "to": {"index": 373, "id": to_hex(ids[3])},
        "msRoot": to_hex(merkle.root(ids)),
        "msgCount": 12,
        "policyHash": "0x" + "11" * 32,
        "prev": "0x" + "22" * 32,
    }
    assert _cp(ids)["prev"] is None


def test_ms_root_independent_oracle(vectors):
    ids = _real_ids(vectors)
    leaves = [_h(b"\x00" + i) for i in ids]
    left = _h(b"\x01" + leaves[0] + leaves[1])
    right = _h(b"\x01" + leaves[2] + leaves[3])
    expected = _h(b"\x01" + left + right)
    assert from_hex(_cp(ids)["msRoot"]) == expected


def test_hash_is_canon_hash_and_order_free(vectors):
    cp = _cp(_real_ids(vectors))
    assert checkpoint.hash(cp) == canon.canon_hash(cp)
    assert checkpoint.hash(dict(reversed(list(cp.items())))) == checkpoint.hash(cp)
    assert checkpoint.hash(cp) == _h(canon.jcs(cp))


@pytest.mark.parametrize(
    "field,value",
    [("msgCount", 13), ("domain", "Other"), ("network", "x"), ("prev", "0x" + "33" * 32)],
)
def test_hash_binds_every_field(vectors, field, value):
    cp = _cp(_real_ids(vectors))
    other = {**cp, field: value}
    assert checkpoint.hash(other) != checkpoint.hash(cp)


def test_membership_path_verifies_each_position(vectors):
    ids = _real_ids(vectors) + [_h(b"extra")]
    root = merkle.root(ids)
    for i, mid in enumerate(ids):
        path = checkpoint.membership_path(ids, i)
        assert merkle.verify(mid, path, root)
        assert not merkle.verify(ids[(i + 1) % len(ids)], path, root)


def test_membership_path_out_of_range():
    with pytest.raises(IndexError):
        checkpoint.membership_path([b"\x00" * 32], 1)


def test_build_rejects_inconsistent_window(vectors):
    ids = _real_ids(vectors)
    policy = b"\x11" * 32
    with pytest.raises(ValueError):  # window length does not match index range
        checkpoint.build("n", "d", (370, ids[0]), (374, ids[3]), ids, 0, policy, None)
    with pytest.raises(ValueError):  # first id is not the from id
        checkpoint.build("n", "d", (370, ids[1]), (373, ids[3]), ids, 0, policy, None)
    with pytest.raises(ValueError):  # last id is not the to id
        checkpoint.build("n", "d", (370, ids[0]), (373, ids[2]), ids, 0, policy, None)
    with pytest.raises(ValueError):
        checkpoint.build("n", "d", (370, ids[0]), (370, ids[0]), [], 0, policy, None)
    with pytest.raises(ValueError):
        checkpoint.build("n", "d", (370, b"\x01"), (370, b"\x01"), [b"\x01"], 0, policy, None)
    with pytest.raises(ValueError):
        checkpoint.build("n", "d", (370, ids[0]), (370, ids[0]), ids[:1], 0, b"\x00", None)
    with pytest.raises(ValueError):
        checkpoint.build("n", "d", (370, ids[0]), (370, ids[0]), ids[:1], -1, policy, None)


def test_shape_error(vectors):
    cp = _cp(_real_ids(vectors))
    assert checkpoint.shape_error(cp) is None
    assert checkpoint.shape_error({**cp, "prev": "0x" + "ab" * 32}) is None
    bad = [
        None,
        [],
        {**cp, "kind": "other"},
        {**cp, "v": 2},
        {**cp, "v": True},
        {**cp, "extra": 1},
        {k: v for k, v in cp.items() if k != "msRoot"},
        {**cp, "msRoot": "0x12"},
        {**cp, "msRoot": cp["msRoot"].upper()},
        {**cp, "msgCount": -1},
        {**cp, "msgCount": 1.0},
        {**cp, "from": {"index": 374, "id": cp["from"]["id"]}},
        {**cp, "to": {"index": "373", "id": cp["to"]["id"]}},
        {**cp, "to": {"index": 373}},
        {**cp, "network": 5},
        {**cp, "prev": "nope"},
    ]
    for b in bad:
        assert isinstance(checkpoint.shape_error(b), str), b


def test_build_output_passes_shape_check(vectors):
    cp = _cp(_real_ids(vectors))
    assert checkpoint.shape_error(copy.deepcopy(cp)) is None
