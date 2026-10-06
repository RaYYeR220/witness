"""Step 5 against the pinned IOTA Rebased JSON-RPC, using responses recorded from testnet."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import httpx
import pytest
from witness_core import bundle, canon, checkpoint, rebased
from witness_core.ids import from_hex, to_hex

VECTORS = Path(__file__).parent / "vectors"
RPC = "https://rpc.example"
NOT_FOUND = {"jsonrpc": "2.0", "id": 1, "result": {"error": {
    "code": "dynamicFieldNotFound", "parent_object_id": "0x1"}}}


@pytest.fixture(scope="module")
def rec() -> dict:
    return json.loads((VECTORS / "rebased_record.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def package(rec) -> str:
    return rec["trailObject"]["result"]["data"]["type"].split("::")[0]


def _fields(doc: dict) -> dict:
    return doc["result"]["data"]["content"]["fields"]["value"]["fields"]["value"]["fields"]


def fake_post(trail: dict, record: dict | None = None, *, status: int = 200, calls: list | None = None):
    def post(url, *, json=None, timeout=None, follow_redirects=None):
        if calls is not None:
            calls.append((url, json, timeout, follow_redirects))
        body = trail if json["method"] == "iota_getObject" else record
        return httpx.Response(status, json=body, request=httpx.Request("POST", url))
    return post


def fetch(rec, package, *, trail=None, record=None, index=4, **kw):
    return rebased.fetch_record(
        RPC, rec["trail"], index, package_id=package,
        post=fake_post(trail or rec["trailObject"], record or rec["record"]), **kw)


def test_recorded_record_decodes_and_hash_matches_chain_metadata(rec, package):
    got = fetch(rec, package)
    meta = json.loads(_fields(rec["record"])["metadata"])
    assert got["checkpointHash"] == meta["checkpointHash"]
    assert to_hex(checkpoint.hash(got["checkpoint"])) == meta["checkpointHash"]
    assert got["checkpoint"]["kind"] == "witness.checkpoint"


def test_requests_are_the_two_read_only_rpc_calls(rec, package):
    calls: list = []
    rebased.fetch_record(RPC, rec["trail"], 4, package_id=package,
                         post=fake_post(rec["trailObject"], rec["record"], calls=calls))
    assert [c[1]["method"] for c in calls] == ["iota_getObject", "iotax_getDynamicFieldObject"]
    assert calls[0][1]["params"][0] == rec["trail"]
    assert calls[1][1]["params"][1] == {"type": "u64", "value": "4"}
    assert all(c[2] == 15 and c[3] is False for c in calls)


def test_missing_record_is_none(rec, package):
    assert fetch(rec, package, record=NOT_FOUND) is None


def test_wrong_object_type_is_an_error(rec, package):
    with pytest.raises(rebased.RebasedError, match="Audit Trail"):
        fetch(rec, "0x" + "ab" * 32)
    other = copy.deepcopy(rec["trailObject"])
    other["result"]["data"]["type"] = "0x2::coin::Coin<0x2::iota::IOTA>"
    with pytest.raises(rebased.RebasedError, match="Audit Trail"):
        fetch(rec, package, trail=other)


def test_rpc_error_and_http_error_raise(rec, package):
    err = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "x"}}
    with pytest.raises(rebased.RebasedError, match="RPC error"):
        fetch(rec, package, record=err)
    with pytest.raises(rebased.RebasedError, match="HTTP 503"):
        rebased.fetch_record(RPC, rec["trail"], 4, package_id=package,
                             post=fake_post(rec["trailObject"], rec["record"], status=503))
    unreadable = {"jsonrpc": "2.0", "id": 1, "result": {"error": {"code": "dynamicFieldDeleted"}}}
    with pytest.raises(rebased.RebasedError):
        fetch(rec, package, record=unreadable)


def test_https_only_unless_explicit(rec, package):
    with pytest.raises(rebased.RebasedError, match="https"):
        rebased.fetch_record("http://rpc.example", rec["trail"], 4, package_id=package,
                             post=fake_post(rec["trailObject"], rec["record"]))
    got = rebased.fetch_record("http://127.0.0.1:9000", rec["trail"], 4, package_id=package,
                               post=fake_post(rec["trailObject"], rec["record"]), allow_http=True)
    assert got is not None


def test_sequence_must_match_index(rec, package):
    with pytest.raises(rebased.RebasedError, match="sequence"):
        fetch(rec, package, index=5)


def test_bytes_variant_and_unknown_variant(rec, package):
    record = copy.deepcopy(rec["record"])
    f = _fields(record)
    text = f["data"]["fields"]["pos0"]
    f["data"] = {"variant": "Bytes", "fields": {"pos0": list(text.encode())}}
    assert fetch(rec, package, record=record) == fetch(rec, package)
    f["data"] = {"variant": "Other", "fields": {"pos0": text}}
    with pytest.raises(rebased.RebasedError, match="variant"):
        fetch(rec, package, record=record)


def test_metadata_must_agree_with_data(rec, package):
    record = copy.deepcopy(rec["record"])
    f = _fields(record)
    f["metadata"] = json.dumps({"kind": "witness.checkpoint", "seq": 1,
                                "checkpointHash": "0x" + "00" * 32})
    with pytest.raises(rebased.RebasedError, match="hash"):
        fetch(rec, package, record=record)
    f["metadata"] = None
    with pytest.raises(rebased.RebasedError, match="metadata"):
        fetch(rec, package, record=record)


# ---------------------------------------------------------------- the ladder's step 5

@pytest.fixture(scope="module")
def anchored() -> dict:
    vectors = json.loads((VECTORS / "bundles.json").read_text(encoding="utf-8"))
    return next(c for c in vectors["cases"] if c["name"] == "valid_anchored") | {
        "registry": vectors["resolvers"]["registry"]}


def _cfg(case: dict, package: str, **kw) -> bundle.VerifierConfig:
    c = case["config"]
    return bundle.VerifierConfig(
        network=c["network"], threshold=c["threshold"],
        trusted_coordinator_keys={from_hex(k) for k in c["trustedCoordinatorKeys"]},
        rebased_network=c["rebasedNetwork"], trail_id=c["trailId"], rebased_rpc=RPC,
        audit_trail_package=package, **kw)


def _record_for(rec: dict, cp: dict, index: int, *, meta_hash: str | None = None) -> dict:
    record = copy.deepcopy(rec["record"])
    f = _fields(record)
    f["data"]["fields"]["pos0"] = canon.jcs(cp).decode()
    f["sequence_number"] = str(index)
    f["metadata"] = json.dumps({"kind": "witness.checkpoint", "seq": 1, "checkpointHash":
                                meta_hash or to_hex(checkpoint.hash(cp))})
    return record


def _ladder(anchored, rec, package, record) -> bundle.Ladder:
    cfg = _cfg(anchored, package)
    fetcher = rebased.make_fetcher(
        cfg, post=fake_post(rec["trailObject"], record))
    did = next(iter(anchored["registry"]))
    return bundle.verify(anchored["bundle"], cfg, fetcher, lambda _d: anchored["registry"][did])


def test_matching_chain_record_turns_step_5_green(anchored, rec, package):
    a = anchored["bundle"]["anchor"]
    record = _record_for(rec, a["checkpoint"], a["rebased"]["record"])
    ladder = _ladder(anchored, rec, package, record)
    assert [s.ok for s in ladder.steps] == [True] * 5
    assert ladder.overall == "VALID"


def test_tampered_chain_checkpoint_fails_step_5(anchored, rec, package):
    a = anchored["bundle"]["anchor"]
    cp = copy.deepcopy(a["checkpoint"])
    cp["msgCount"] += 1
    ladder = _ladder(anchored, rec, package, _record_for(rec, cp, a["rebased"]["record"]))
    assert ladder.steps[4].ok is False
    assert ladder.overall == "INVALID"


def test_missing_wrong_type_and_rpc_error_are_partial(anchored, rec, package):
    a = anchored["bundle"]["anchor"]
    idx = a["rebased"]["record"]
    assert _ladder(anchored, rec, package, NOT_FOUND).overall == "PARTIAL"
    err = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "boom"}}
    assert _ladder(anchored, rec, package, err).overall == "PARTIAL"
    wrong = _ladder(anchored, rec, "0x" + "cd" * 32, _record_for(rec, a["checkpoint"], idx))
    assert wrong.steps[4].ok is None and wrong.overall == "PARTIAL"


def test_fetcher_needs_pins(anchored, rec, package):
    cfg = bundle.VerifierConfig(network="n", trusted_coordinator_keys=set(), threshold=1)
    with pytest.raises(rebased.RebasedError):
        rebased.make_fetcher(cfg)({"rebased": {"record": 1}})


WRITER = "0xd40892daf5c81e3d67ffe9806575970b973ecf6625eb8a88562afae0d8c940c8"


def _writer_ladder(anchored, rec, package, record, writer):
    cfg = _cfg(anchored, package, anchor_writer=writer)
    fetcher = rebased.make_fetcher(cfg, post=fake_post(rec["trailObject"], record))
    did = next(iter(anchored["registry"]))
    return bundle.verify(anchored["bundle"], cfg, fetcher, lambda _d: anchored["registry"][did])


def test_pinned_writer_must_match_record_writer(anchored, rec, package):
    a = anchored["bundle"]["anchor"]
    record = _record_for(rec, a["checkpoint"], a["rebased"]["record"])
    assert _fields(record)["added_by"] == WRITER
    assert _writer_ladder(anchored, rec, package, record, WRITER).overall == "VALID"
    other = _writer_ladder(anchored, rec, package, record, "0x" + "ee" * 32)
    assert other.steps[4].ok is False
    assert "writer" in other.steps[4].detail
    assert other.overall == "INVALID"


def test_bundle_naming_another_trail_fails_step_5(anchored, rec, package):
    """The trail comes from the pins; a bundle pointing at an attacker's trail is rejected."""
    a = anchored["bundle"]["anchor"]
    forged = copy.deepcopy(anchored["bundle"])
    forged["anchor"]["rebased"]["trail"] = "0x" + "ab" * 32
    cfg = _cfg(anchored, package)
    calls: list = []
    record = _record_for(rec, a["checkpoint"], a["rebased"]["record"])
    fetcher = rebased.make_fetcher(cfg, post=fake_post(rec["trailObject"], record, calls=calls))
    did = next(iter(anchored["registry"]))
    ladder = bundle.verify(forged, cfg, fetcher, lambda _d: anchored["registry"][did])
    assert ladder.steps[4].ok is False and "pinned trail" in ladder.steps[4].detail
    assert calls == []  # the attacker's trail id is never even queried


def test_fetcher_queries_the_pinned_trail_only(anchored, rec, package):
    a = anchored["bundle"]["anchor"]
    calls: list = []
    cfg = _cfg(anchored, package)
    record = _record_for(rec, a["checkpoint"], a["rebased"]["record"])
    rebased.make_fetcher(cfg, post=fake_post(rec["trailObject"], record, calls=calls))(a)
    assert calls[0][1]["params"][0] == cfg.trail_id
