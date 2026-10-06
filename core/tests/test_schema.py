import copy
import json
import os
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import given, settings
from hypothesis import strategies as st
from witness_core import canon, checkpoint, envelope, schema
from witness_core.ids import from_hex, to_hex

DID = "did:iota:testnet:0x5e1f"
KID = DID + "#sig-1"
KEY = Ed25519PrivateKey.from_private_bytes(b"\x05" * 32)
PREV = "0x" + "ab" * 32


def _j(obj) -> bytes:
    return json.dumps(obj).encode()


def _seal(tag: str, body: dict | None, **kw) -> dict:
    return envelope.seal(
        tag, body, iss=DID, kid=KID, sign_key=KEY, seq=3, att_mode="producer",
        now_ms=1_700_000_000_000, nonce=bytes(range(16)), **kw,
    )


def _checkpoint() -> dict:
    ids = [bytes([i]) * 32 for i in range(1, 4)]
    return checkpoint.build(
        "private_tangle1", "MyDomain", (10, ids[0]), (12, ids[-1]), ids, 4, b"\x11" * 32, None
    )


def _anchor_body() -> dict:
    cp = _checkpoint()
    return {
        "seq": 1,
        "checkpoint": cp,
        "checkpointHash": to_hex(checkpoint.hash(cp)),
        "rebased": {"network": "testnet", "trail": "0x" + "7a" * 32, "record": 3,
                    "tx": "8L3KZB5SN8Dd7UTorJ6sUqC3DFyuatJ6WPvuSQZummtu"},
    }


# aeriOS producers, field names as written by the upstream components.
SAMPLES = [
    (
        "trust.score",
        {"score": 0.74, "id": "MyDomain:fa163e5e25ef"},
        "trust.score",
        "MyDomain:fa163e5e25ef",
    ),
    (
        "trust.score",
        {"score": 1, "id": "MyDomain:FA163E5E25EF"},
        "trust.score",
        "MyDomain:FA163E5E25EF",
    ),
    (
        "LLO-K8s",
        {
            "event": "Service component deployed",
            "lloId": "urn:ngsi-ld:LowLevelOrchestrator:MyDomain:Kubernetes",
            "serviceComponentId": "nginx-sc",
        },
        "llo.k8s",
        None,
    ),
    (
        "LLO-Docker",
        {
            "event": "Service component failed",
            "lloId": "urn:ngsi-ld:LowLevelOrchestrator:MyDomain:Docker",
            "serviceComponentId": "redis-sc",
        },
        "llo.docker",
        None,
    ),
    (
        "self-orchestrator",
        {"infrastructureElementId": "MyDomain:fa163e32c6ee", "errorCode": "HIGH_CPU"},
        "self-orchestrator",
        "MyDomain:fa163e32c6ee",
    ),
    (
        "self-orchestrator",
        {
            "infrastructureElementId": "urn:ngsi-ld:InfrastructureElement:MyDomain:fa163e32c6ee",
            "errorCode": 3,
        },
        "self-orchestrator",
        "MyDomain:fa163e32c6ee",
    ),
    ("audit.report", {"reportHash": "0x" + "cd" * 32, "generatedAt": 1791283600000},
     "audit.report", None),
    ("audit.report", {"reportHash": "0x" + "cd" * 32, "generatedAt": 1791283600000,
                      "range": {"msFrom": 370, "msTo": 373}, "ie": "MyDomain:fa163e5e25ef"},
     "audit.report", None),
    ("audit.report", {"reportHash": "0x" + "cd" * 32, "generatedAt": 0, "range": {"msTo": 5}},
     "audit.report", None),
]


@pytest.mark.parametrize("tag,body,kind,ie_id", SAMPLES)
def test_classify_aerios_samples(tag, body, kind, ie_id):
    c = schema.classify(tag, _j(body))
    assert (c.kind, c.ie_id, c.schema_ok) == (kind, ie_id, True)
    assert c.json == body
    assert c.envelope is None
    assert (c.nonce, c.prev, c.corr) == (None, None, None)


def test_classify_field_order():
    fields = [f.name for f in schema.Classified.__dataclass_fields__.values()]
    assert fields == ["kind", "json", "ie_id", "envelope", "schema_ok", "nonce", "prev", "corr"]


@pytest.mark.parametrize(
    "tag,body",
    [
        ("trust.score", {"score": 1.5, "id": "MyDomain:fa163e5e25ef"}),
        ("trust.score", {"score": -0.1, "id": "MyDomain:fa163e5e25ef"}),
        ("trust.score", {"score": True, "id": "MyDomain:fa163e5e25ef"}),
        ("trust.score", {"score": "0.5", "id": "MyDomain:fa163e5e25ef"}),
        ("trust.score", {"id": "MyDomain:fa163e5e25ef"}),
        ("trust.score", {"score": 0.5, "id": "MyDomain:fa163e5e25"}),
        ("trust.score", {"score": 0.5, "id": "fa163e5e25ef"}),
        ("trust.score", {"score": 0.5}),
        ("LLO-K8s", {"event": "deploy", "service": "ngsi-ld-broker", "replicas": 2}),
        ("LLO-K8s", {"event": "x", "lloId": 5, "serviceComponentId": "s"}),
        ("LLO-Docker", {"event": "x", "lloId": "l"}),
        ("self-orchestrator", {"action": "migrate", "from": "a", "to": "b"}),
        ("self-orchestrator", {"infrastructureElementId": "", "errorCode": "E"}),
        ("self-orchestrator", {"infrastructureElementId": "MyDomain:aa", "errorCode": True}),
        ("audit.report", {"reportHash": "0x12"}),
        ("witness.anchor", {"checkpoint": {}, "checkpointHash": "0x" + "00" * 32}),
    ] + [("audit.report", body) for body in [
        {"reportHash": "0x12", "generatedAt": 1},
        {"reportHash": "0x" + "CD" * 32, "generatedAt": 1},  # hex must be lowercase
        {"reportHash": "0x" + "cd" * 32},  # generatedAt required
        {"reportHash": "0x" + "cd" * 32, "generatedAt": -1},
        {"reportHash": "0x" + "cd" * 32, "generatedAt": 2**53},
        {"reportHash": "0x" + "cd" * 32, "generatedAt": True},
        {"reportHash": "0x" + "cd" * 32, "generatedAt": 1.5},
        {"reportHash": "0x" + "cd" * 32, "generatedAt": 1, "extra": 1},
        {"reportHash": "0x" + "cd" * 32, "generatedAt": 1, "range": []},
        {"reportHash": "0x" + "cd" * 32, "generatedAt": 1, "range": {"from": 1}},
        {"reportHash": "0x" + "cd" * 32, "generatedAt": 1, "range": {"msFrom": -1}},
        {"reportHash": "0x" + "cd" * 32, "generatedAt": 1, "range": {"msFrom": 2**32}},
        {"reportHash": "0x" + "cd" * 32, "generatedAt": 1, "range": {"msFrom": 5, "msTo": 4}},
        {"reportHash": "0x" + "cd" * 32, "generatedAt": 1, "ie": "fa163e5e25ef"},
        {"reportHash": "0x" + "cd" * 32, "generatedAt": 1, "ie": 7},
    ]],
)
def test_classify_schema_violations(tag, body):
    c = schema.classify(tag, _j(body))
    assert c.kind == schema.KINDS[tag]
    assert c.schema_ok is False
    assert c.json == body


def test_trust_score_ie_id_kept_when_score_invalid():
    c = schema.classify("trust.score", _j({"score": 7, "id": "MyDomain:fa163e5e25ef"}))
    assert (c.schema_ok, c.ie_id) == (False, "MyDomain:fa163e5e25ef")
    c = schema.classify("trust.score", _j({"score": 0.5, "id": "not an ie"}))
    assert (c.schema_ok, c.ie_id) == (False, None)


@pytest.mark.parametrize(
    "data",
    [
        b"\x00\xff\xfe\x80\x01\xc3(\xa0\xa1\x00\x7f",
        b"plain text, not json",
        b"",
        b'{"score": NaN, "id": "MyDomain:fa163e5e25ef"}',
        b'{"score": Infinity}',
        b"\xef\xbb\xbf{}",
        b"[" * 100_000,
    ],
    ids=["binary", "text", "empty", "nan", "infinity", "bom", "deep-nesting"],
)
def test_classify_non_json_is_unknown(data):
    for tag in ("trust.score", "whatever"):
        c = schema.classify(tag, data)
        assert (c.kind, c.json, c.ie_id, c.envelope, c.schema_ok) == (
            "unknown", None, None, None, False
        )


def test_classify_json_array():
    data = b'[{"node": "a", "cpu": 12}, {"node": "b", "cpu": 80}]'
    c = schema.classify("LLO-K8s", data)
    assert (c.kind, c.schema_ok, c.ie_id) == ("llo.k8s", False, None)
    assert c.json == [{"node": "a", "cpu": 12}, {"node": "b", "cpu": 80}]
    c = schema.classify("trust.score", b"[0.5]")
    assert (c.kind, c.schema_ok) == ("trust.score", False)


def test_classify_unknown_tag_json():
    c = schema.classify("self.reorquestration", b'{"anything": [1, 2]}')
    assert (c.kind, c.schema_ok, c.json) == ("unknown", True, {"anything": [1, 2]})


def test_classify_envelope_wrapped_trust_score():
    body = {"score": 0.82, "id": "MyDomain:fa163e5e25ef"}
    env = _seal("trust.score", body, prev=PREV, corr="incident-7")
    c = schema.classify("trust.score", canon.jcs(env))
    assert (c.kind, c.ie_id, c.schema_ok) == ("trust.score", "MyDomain:fa163e5e25ef", True)
    assert c.json == body
    assert c.envelope == env
    assert (c.nonce, c.prev, c.corr) == (env["nonce"], PREV, "incident-7")


def test_classify_envelope_body_checked_against_tag_schema():
    env = _seal("trust.score", {"score": 3, "id": "MyDomain:fa163e5e25ef"})
    c = schema.classify("trust.score", canon.jcs(env))
    assert (c.kind, c.schema_ok, c.ie_id) == ("trust.score", False, "MyDomain:fa163e5e25ef")
    assert c.envelope == env
    assert c.nonce == env["nonce"]


def test_classify_sealed_envelope():
    jwe = {"protected": "e30", "ciphertext": "AA", "iv": "AA", "tag": "AA", "recipients": []}
    env = _seal("trust.score", None, enc=jwe, bix=["tok"], corr="c1")
    c = schema.classify("trust.score", canon.jcs(env))
    assert (c.kind, c.json, c.ie_id, c.schema_ok) == ("trust.score", None, None, True)
    assert c.envelope == env
    assert (c.nonce, c.corr, c.prev) == (env["nonce"], "c1", None)


def test_classify_envelope_without_body_or_enc():
    env = _seal("trust.score", {"score": 0.5, "id": "MyDomain:fa163e5e25ef"})
    del env["body"]
    c = schema.classify("trust.score", canon.jcs(env))
    assert (c.kind, c.json, c.schema_ok) == ("trust.score", None, False)
    assert c.envelope == env


def test_classify_witness_anchor():
    body = _anchor_body()
    env = _seal("witness.anchor", body)
    c = schema.classify("witness.anchor", canon.jcs(env))
    assert (c.kind, c.schema_ok, c.json) == ("witness.anchor", True, body)
    bad_hash = {**body, "checkpointHash": "0x" + "00" * 32}
    assert schema.classify("witness.anchor", _j(bad_hash)).schema_ok is False
    no_rebased = {k: v for k, v in body.items() if k != "rebased"}
    assert schema.classify("witness.anchor", _j(no_rebased)).schema_ok is False
    bad_record = {**body, "rebased": {**body["rebased"], "record": "3"}}
    assert schema.classify("witness.anchor", _j(bad_record)).schema_ok is False


@pytest.mark.parametrize(
    "change",
    [
        {"seq": None},
        {"seq": 0},
        {"seq": "1"},
        {"seq": True},
        {"seq": 2**53},
        {"extra": 1},
        {"rebased": {"network": "testnet", "trail": "0x" + "7a" * 32, "record": 3}},
        {"rebased": {"network": "", "trail": "0x" + "7a" * 32, "record": 3, "tx": "5xGp" * 8}},
        {"rebased": {"network": "testnet", "trail": "0x7a", "record": 3, "tx": "5xGp" * 8}},
        {"rebased": {"network": "testnet", "trail": "0x" + "7a" * 32, "record": -1,
                     "tx": "5xGp" * 8}},
        {"rebased": {"network": "testnet", "trail": "0x" + "7a" * 32, "record": 3, "tx": ""}},
        {"rebased": {"network": "testnet", "trail": "0x" + "7a" * 32, "record": 3,
                     "tx": "0OIl" * 8}},
        {"rebased": {"network": "testnet", "trail": "0x" + "7a" * 32, "record": 3,
                     "tx": "5xGp" * 8, "extra": 1}},
    ],
    ids=["no-seq", "seq-0", "seq-str", "seq-bool", "seq-huge", "extra-field", "no-tx",
         "empty-network", "short-trail", "negative-record", "empty-tx", "tx-not-base58",
         "rebased-extra"],
)
def test_witness_anchor_full_shape(change):
    body = {**_anchor_body(), **change}
    if change.get("seq", 1) is None:
        del body["seq"]
    assert schema.classify("witness.anchor", _j(body)).schema_ok is False


def test_classify_real_vector_blocks(vectors):
    expected = {
        "0x972a878cf06f2cf6b7d4a1443dbb5f12fdda376fa7537a82dad8e7257a477967": (
            "trust.score", "MyDomain:aabbccddeeff", True,
        ),
        "0x84c489e0874a80086617cc268ab26ac6569ec8fa5b98a71cff708f3c4e5e1c58": (
            "unknown", None, False,
        ),
        "0xdcdd4f45668c81cbe8634b53c1a2f1d28d9e47c8b6bd85df16360f02743679c3": (
            "unknown", None, False,
        ),
    }
    for b in vectors("blocks"):
        if b["kind"] != "tagged":
            continue
        c = schema.classify(b["tag"], from_hex(b["data"]))
        assert isinstance(c, schema.Classified)
        if b["blockId"] in expected:
            assert (c.kind, c.ie_id, c.schema_ok) == expected[b["blockId"]]
        if b["tag"] == "trust.score":
            assert c.schema_ok and c.ie_id is not None


# ---------------------------------------------------------------- hostile input


def test_huge_integer_score_does_not_crash():
    body = {"score": 10**400, "id": "MyDomain:fa163e5e25ef"}
    c = schema.classify("trust.score", _j(body))
    assert (c.kind, c.schema_ok, c.ie_id) == ("trust.score", False, "MyDomain:fa163e5e25ef")
    assert schema.classify("trust.score", _j({**body, "score": -(10**400)})).schema_ok is False


def test_uncanonicalizable_anchor_checkpoint_does_not_crash():
    body = _anchor_body()
    body["checkpoint"]["network"] = "\ud800"  # lone surrogate: JCS refuses it
    c = schema.classify("witness.anchor", _j(body))
    assert (c.kind, c.schema_ok) == ("witness.anchor", False)


_SURROGATES = st.characters(codec=None, min_codepoint=0xD800, max_codepoint=0xDFFF)
_ANY_TEXT = st.text(st.characters(codec=None) | _SURROGATES, max_size=8)
_ANY = st.recursive(
    st.none()
    | st.booleans()
    | st.integers()
    | st.integers(min_value=10**300, max_value=10**400)
    | st.integers(min_value=-(10**400), max_value=-(10**300))
    | st.floats()
    | _ANY_TEXT,
    lambda inner: st.lists(inner, max_size=3) | st.dictionaries(_ANY_TEXT, inner, max_size=3),
    max_leaves=10,
)


def _templates() -> list[tuple[str, Any]]:
    out = [(tag, body) for tag, body, _, _ in SAMPLES]
    out.append(("witness.anchor", _anchor_body()))
    return out


def _paths(obj: Any, prefix: tuple = ()) -> list[tuple]:
    out = [prefix] if prefix else []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out += _paths(v, (*prefix, k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out += _paths(v, (*prefix, i))
    return out


# Values that broke classify before: ints beyond float range, lone surrogates.
_HOSTILE = (
    st.integers(min_value=10**300, max_value=10**400)
    | st.integers(min_value=-(10**400), max_value=-(10**300))
    | st.text(_SURROGATES, min_size=1, max_size=3)
)
_EXAMPLES = int(os.environ.get("HYP_EXAMPLES", "60"))


@settings(max_examples=_EXAMPLES * 4, deadline=None)
@given(st.data())
def test_classify_never_raises(data):
    """One field of a well-formed message replaced by a hostile value."""
    tag, body = data.draw(st.sampled_from(_templates()))
    body = copy.deepcopy(body)
    path = data.draw(st.sampled_from(_paths(body)))
    target = body
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = data.draw(_HOSTILE | _ANY)
    obj: Any = body
    if data.draw(st.booleans()):
        obj = {"w": 1, "sig": "x", "nonce": data.draw(_ANY), "corr": data.draw(_ANY), "body": body}
    c = schema.classify(tag, json.dumps(obj).encode())
    assert isinstance(c, schema.Classified)
    assert isinstance(c.schema_ok, bool)


@settings(max_examples=_EXAMPLES, deadline=None)
@given(st.sampled_from(sorted(schema.KINDS)) | _ANY_TEXT, st.binary(max_size=64))
def test_classify_never_raises_on_raw_bytes(tag, data):
    assert isinstance(schema.classify(tag, data), schema.Classified)
