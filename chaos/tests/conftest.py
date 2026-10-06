import json
import socket
from pathlib import Path

import pytest
import yaml
from witness_core import bundle, checkpoint
from witness_core.bundle import VerifierConfig
from witness_core.codec import Ed25519Sig
from witness_core.ids import blake2b256, from_hex

VECTORS = Path(__file__).resolve().parents[2] / "core" / "tests" / "vectors"
NETWORK = "private_tangle1"
TRAIL = "0x" + "7a" * 32
REBASED = {"network": "testnet", "trail": TRAIL, "record": 3, "tx": "5xGp7rWq2Tz9"}


def vec(name: str):
    return json.loads((VECTORS / f"{name}.json").read_text(encoding="utf-8"))


@pytest.fixture
def sample_keys() -> list[bytes]:
    return [from_hex(k) for k in vec("coordinator_keys")["privateKeys"]]


@pytest.fixture
def cfg() -> VerifierConfig:
    return VerifierConfig(
        network=NETWORK,
        trusted_coordinator_keys={from_hex(k) for k in vec("coordinator_keys")["publicKeys"]},
        threshold=2,
        rebased_network="testnet",
        trail_id=TRAIL,
    )


@pytest.fixture
def real_bundle() -> dict:
    """A genuine bundle for a tagged block of a captured milestone, anchored."""
    milestones, cones, blocks = vec("milestones"), vec("cones"), vec("blocks")
    raw_of = {b["blockId"]: b for b in blocks}
    target = next(
        (ms, cone, bid)
        for ms, cone in zip(milestones, cones, strict=True)
        for bid in cone["blockIdsWhiteFlagOrder"]
        if bid in raw_of and raw_of[bid]["kind"] != "milestone"
    )
    ms, cone, bid = target
    ids = [from_hex(m["milestoneId"]) for m in milestones]
    pos = milestones.index(ms)
    cp = checkpoint.build(
        NETWORK, "MyDomain",
        (milestones[0]["index"], ids[0]), (milestones[-1]["index"], ids[-1]),
        ids, 11, blake2b256(b"writer policy v1"), None,
    )
    return bundle.build(
        network=NETWORK,
        block_raw=from_hex(raw_of[bid]["raw"]),
        milestone_essence=from_hex(ms["essence"]),
        milestone_sigs=[Ed25519Sig(from_hex(s["pk"]), from_hex(s["sig"]))
                        for s in ms["signatures"]],
        cone_ids=[from_hex(i) for i in cone["blockIdsWhiteFlagOrder"]],
        envelope_check=None,
        did_doc_snapshot=None,
        anchor={"checkpoint": cp, "msPath": checkpoint.membership_path(ids, pos),
                "rebased": dict(REBASED)},
    )


@pytest.fixture
def no_network(monkeypatch):
    """Any attempt to open a socket or send an HTTP request fails the test."""
    import httpx

    def boom(*a, **k):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr(httpx.Client, "send", boom)
    monkeypatch.setattr(httpx.AsyncClient, "send", boom)


@pytest.fixture(scope="session")
def key():
    from witness_chaos import attacks

    return yaml.safe_load(
        Path(attacks.__file__).with_name("answer_key.yaml").read_text(encoding="utf-8"))
