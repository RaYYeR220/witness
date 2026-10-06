import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
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
        "checkpoint": cp,
        "checkpointHash": to_hex(checkpoint.hash(cp)),
        "rebased": {"network": "testnet", "trail": "0x" + "7a" * 32, "record": 3, "tx": "5xGp"},
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
    ("audit.report", {"reportHash": "0x" + "cd" * 32}, "audit.report", None),
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
    ],
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
