"""did:key resolved locally, the same way here, in the indexer and in @witness/verify."""

import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from witness_core import didkey

VECTORS = Path(__file__).parent / "vectors" / "did_key.json"


def _pub(n: int) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(bytes([n]) * 32).public_key().public_bytes_raw()


def _did(prefix: bytes, key: bytes) -> str:
    return didkey.PREFIX + "z" + didkey._b58encode(prefix + key)


def _cases() -> list[dict]:
    good = didkey.from_public_key(_pub(5))
    dids = {
        "ed25519": good,
        "ed25519_zero_key": didkey.from_public_key(bytes(32)),  # leading base58 '1's
        "x25519_multicodec": _did(b"\xec\x01", _pub(6)),
        "short_key": _did(b"\xed\x01", _pub(5)[:31]),
        "long_key": _did(b"\xed\x01", _pub(5) + b"\0"),
        "not_base58": good[:-1] + "0",
        "no_multibase_z": good.replace(":z", ":f", 1),
        "too_long": good + "1" * (didkey.MAX_LENGTH + 1 - len(good)),
        "did_iota": "did:iota:testnet:0x" + "ab" * 32,
        "bare_prefix": "did:key:",
    }
    out = []
    for name, did in dids.items():
        pub = didkey.public_key(did)
        out.append({"name": name, "did": did,
                    "publicKeyHex": None if pub is None else "0x" + pub.hex(),
                    "document": didkey.document(did)})
    return out


def test_did_key_vectors(regen):
    data = {
        "description": (
            "did:key resolved locally. publicKeyHex: the Ed25519 key the DID encodes, or "
            "null. document: the resolve reply (anchor shape) for the DID, or null when it "
            "is not a did:key."
        ),
        "cases": _cases(),
    }
    if regen("did_key"):
        VECTORS.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8", newline="\n")
    assert json.loads(VECTORS.read_text(encoding="utf-8")) == json.loads(json.dumps(data))


def test_round_trip_and_rejections():
    key = _pub(9)
    did = didkey.from_public_key(key)
    assert did.startswith("did:key:z6Mk")
    assert didkey.public_key(did) == key
    doc = didkey.document(did)
    assert doc["doc"] == {"id": did}
    assert [k["kid"] for k in doc["keys"]] == [f"{did}#{did[len('did:key:'):]}", did]
    assert didkey.document("did:key:zzz")["keys"] == []  # a did:key, but no Ed25519 key
    assert didkey.document("did:iota:" + "0x" + "00" * 32) is None
    assert didkey.public_key(123) is None  # type: ignore[arg-type]


def test_with_did_key_answers_locally_and_forwards_the_rest():
    asked = []

    def registry(did):
        asked.append(did)
        return {"doc": {"id": did}, "keys": []}

    did = didkey.from_public_key(_pub(3))
    resolve = didkey.with_did_key(registry)
    assert resolve(did) == didkey.document(did)
    assert asked == []
    iota = "did:iota:testnet:0x" + "cd" * 32
    assert resolve(iota)["doc"]["id"] == iota and asked == [iota]
    alone = didkey.with_did_key(None)
    assert alone(did) == didkey.document(did) and alone(iota) is None
