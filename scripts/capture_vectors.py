"""Capture real protocol vectors from the local aeriOS IOTA stack.

Posts a batch of tagged messages, waits until they are confirmed, and writes the
JSON files under core/tests/vectors/ that the parser and verifier tests load.
Only needs httpx. Run from the repo root:

    uv run python scripts/capture_vectors.py

Environment: HORNET_URL (default http://localhost:14265), RELAY_URL (default
http://localhost:5555).
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "core" / "tests" / "vectors"
TANGLE_DIR = ROOT / "vendor" / "iota-tangle" / "docker"

HORNET = os.environ.get("HORNET_URL", "http://localhost:14265").rstrip("/")
RELAY = os.environ.get("RELAY_URL", "http://localhost:5555").rstrip("/")
RAW = {"Accept": "application/vnd.iota.serializer-v1"}
SIG_ENTRY_LEN = 1 + 32 + 64  # signature type, public key, signature


def blake2b256(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32).digest()


def hx(data: bytes) -> str:
    return "0x" + data.hex()


def unhex(s: str) -> bytes:
    return bytes.fromhex(s.removeprefix("0x"))


def merkle_root(leaves: list[bytes]) -> bytes:
    """White-flag inclusion tree: 0x00-prefixed leaves, 0x01-prefixed nodes."""
    if not leaves:
        return blake2b256(b"")
    if len(leaves) == 1:
        return blake2b256(b"\x00" + leaves[0])
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    return blake2b256(b"\x01" + merkle_root(leaves[:split]) + merkle_root(leaves[split:]))


class Node:
    def __init__(self) -> None:
        self.http = httpx.Client(timeout=30)

    def core(self, path: str, raw: bool = False) -> httpx.Response:
        return self.http.get(f"{HORNET}/api/core/v2{path}", headers=RAW if raw else None)

    def metadata(self, block_id: str) -> dict:
        r = self.core(f"/blocks/{block_id}/metadata")
        r.raise_for_status()
        return r.json()

    def milestone(self, index: int) -> tuple[dict, bytes]:
        js = self.core(f"/milestones/by-index/{index}")
        js.raise_for_status()
        raw = self.core(f"/milestones/by-index/{index}", raw=True)
        raw.raise_for_status()
        return js.json(), raw.content

    def raw_block(self, block_id: str) -> bytes:
        r = self.core(f"/blocks/{block_id}", raw=True)
        r.raise_for_status()
        return r.content

    def cone(self, block_id: str) -> list[str]:
        r = self.http.get(f"{HORNET}/api/debug/v1/block-cones/{block_id}")
        r.raise_for_status()
        return [e["blockId"] for e in r.json()["cone"]]


def milestone_block(ms_json: dict, ms_raw: bytes) -> tuple[str, bytes]:
    """Rebuild the block that wraps a milestone payload (nonce 0) and hash it."""
    parents = [unhex(p) for p in ms_json["parents"]]
    block = (
        bytes([2, len(parents)])
        + b"".join(parents)
        + len(ms_raw).to_bytes(4, "little")
        + ms_raw
        + (0).to_bytes(8, "little")
    )
    return hx(blake2b256(block)), block


def submit_messages(node: Node) -> list[dict]:
    """Submits 10 tagged blocks; returns blockId, tag and exact data bytes of each."""
    relay_msgs = [
        ("trust.score", {"score": 0.5, "id": "MyDomain:aabbccddeeff"}),
        ("trust.score", {"score": 0.91, "id": "MyDomain:fa163e5e25ef"}),
        ("trust.score", {"score": 0.07, "id": "MyDomain:fa163ed55867"}),
        ("LLO-K8s", {"event": "deploy", "service": "ngsi-ld-broker", "replicas": 2}),
        ("LLO-K8s", {"event": "scale", "service": "iota-api", "replicas": 3}),
        ("self-orchestrator", {"action": "migrate", "from": "fa163e5e25ef", "to": "fa163e32c6ee"}),
        ("self-orchestrator", {"action": "reschedule", "reason": "cpu>90%", "ok": True}),
        ("LLO-K8s", [{"node": "a", "cpu": 12}, {"node": "b", "cpu": 80}]),  # JSON array payload
    ]
    records: list[dict] = []
    for i, (tag, msg) in enumerate(relay_msgs):
        r = httpx.post(
            f"{RELAY}/upload?node=iota-hornet",
            json={"tag": tag, "message": msg},
            timeout=30,
        )
        r.raise_for_status()
        if i == 0:
            dump(
                "legacy_upload_response.json",
                {
                    "request": {"tag": tag, "message": msg},
                    "status": r.status_code,
                    "contentType": r.headers.get("content-type"),
                    "bodyUtf8": r.content.decode(),
                    "bodyHex": r.content.hex(),
                },
            )
        inner = json.loads(json.loads(r.content)["return_payload"])
        records.append(
            {
                "blockId": inner["blockId"],
                "tag": tag,
                "data": json.dumps(msg).encode(),  # the relay's default separators
            }
        )

    # Non-JSON payloads go straight to the node (the relay can only carry JSON).
    binary = bytes([0x00, 0xFF, 0xFE, 0x80, 0x01, 0xC3, 0x28, 0xA0, 0xA1, 0x00, 0x7F])
    for tag, data in [("witness.binary", binary), ("witness.text", b"plain text, not json")]:
        body = {
            "protocolVersion": 2,
            "payload": {"type": 5, "tag": hx(tag.encode()), "data": hx(data)},
        }
        r = node.http.post(f"{HORNET}/api/core/v2/blocks", json=body)
        r.raise_for_status()
        records.append({"blockId": r.json()["blockId"], "tag": tag, "data": data})
    return records


def wait_confirmed(node: Node, ids: list[str], timeout: float = 120) -> dict[str, dict]:
    deadline = time.time() + timeout
    done: dict[str, dict] = {}
    while time.time() < deadline and len(done) < len(ids):
        for b in ids:
            if b in done:
                continue
            md = node.metadata(b)
            if md.get("referencedByMilestoneIndex") and md.get("ledgerInclusionState"):
                done[b] = md
        time.sleep(1)
    if len(done) < len(ids):
        sys.exit(f"timeout: {len(ids) - len(done)} block(s) not confirmed")
    return done


def milestone_vector(index: int, ms_json: dict, ms_raw: bytes) -> dict:
    n = len(ms_json["signatures"])
    # Payload layout: u32 type | essence | u8 signature count | n * (type, pk, sig).
    # The milestone id is BLAKE2b-256 of the essence, and the coordinators sign that id.
    essence = ms_raw[4 : len(ms_raw) - 1 - n * SIG_ENTRY_LEN]
    return {
        "index": index,
        "milestoneId": hx(blake2b256(essence)),
        "timestamp": ms_json["timestamp"],
        "essence": hx(essence),
        "signatures": [
            {"pk": s["publicKey"], "sig": s["signature"]} for s in ms_json["signatures"]
        ],
        "inclusionMerkleRoot": ms_json["inclusionMerkleRoot"],
        "previousMilestoneId": ms_json["previousMilestoneId"],
    }


def coordinator_keys() -> dict:
    cfg = json.loads((TANGLE_DIR / "config_private_tangle.json").read_text())
    public: list[str] = []

    def walk(o) -> None:
        if isinstance(o, dict):
            if "publicKeyRanges" in o:
                public.extend("0x" + r["key"] for r in o["publicKeyRanges"])
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(cfg)
    compose = (TANGLE_DIR / "main" / "hornet-main.yaml").read_text()
    line = next(ln for ln in compose.splitlines() if "COO_PRV_KEYS=" in ln)
    private = ["0x" + k for k in line.split("COO_PRV_KEYS=")[1].strip('" ').split(",")]
    for pub, prv in zip(public, private):
        assert prv.endswith(pub[2:]), "private key does not end with matching public key"
    return {
        "_source": {
            "note": "Test-only data, already public in the eclipse-aerios/iota-tangle repository.",
            "public": "docker/config_private_tangle.json: protocol.publicKeyRanges[].key",
            "private": "docker/main/hornet-main.yaml: inx-coordinator COO_PRV_KEYS "
            "(same value in docker/main/startup.yaml); 64 bytes = seed || public key",
        },
        "publicKeys": public,
        "privateKeys": private,
    }


def dump(name: str, obj) -> None:
    (OUT / name).write_text(json.dumps(obj, indent=2) + "\n")
    print(f"wrote {name}")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    node = Node()
    records = submit_messages(node)
    ids = [r["blockId"] for r in records]

    rest_block, rest_meta = [], []
    for b in ids:
        rest_meta.append({"blockId": b, "label": "after_submit", "metadata": node.metadata(b)})
    confirmed = wait_confirmed(node, ids)
    for b in ids:
        rest_meta.append({"blockId": b, "label": "confirmed", "metadata": confirmed[b]})
        rest_block.append({"blockId": b, "block": node.core(f"/blocks/{b}").json()})

    blocks: list[dict] = []
    for r in records:
        raw = node.raw_block(r["blockId"])
        assert hx(blake2b256(raw)) == r["blockId"], "blockId != blake2b256(raw)"
        blocks.append(
            {
                "blockId": r["blockId"],
                "raw": hx(raw),
                "kind": "tagged",
                "tag": r["tag"],
                "data": hx(r["data"]),
            }
        )

    indexes = sorted({m["referencedByMilestoneIndex"] for m in confirmed.values()})
    milestones, cones = [], []
    for idx in indexes:
        ms_json, ms_raw = node.milestone(idx)
        block_id, block = milestone_block(ms_json, ms_raw)
        assert node.raw_block(block_id) == block, "rebuilt milestone block differs from node's"
        blocks.append(
            {"blockId": block_id, "raw": hx(block), "kind": "milestone", "tag": None, "data": None}
        )
        milestones.append(milestone_vector(idx, ms_json, ms_raw))

        # Blocks referenced by this milestone: union of its parents' cones, in parent order.
        order: list[str] = []
        for p in ms_json["parents"]:
            for b in node.cone(p):
                if b not in order:
                    order.append(b)
        root = merkle_root([unhex(b) for b in order])
        assert hx(root) == ms_json["inclusionMerkleRoot"], f"merkle mismatch at {idx}"
        for pos, b in enumerate(order):
            assert node.metadata(b)["whiteFlagIndex"] == pos, "whiteFlagIndex != cone position"
        cones.append({"index": idx, "blockIdsWhiteFlagOrder": order})

    # The id of milestone N must be the previousMilestoneId recorded by N+1.
    for m in milestones:
        while node.core(f"/milestones/by-index/{m['index'] + 1}").status_code == 404:
            time.sleep(1)  # N+1 not issued yet
        nxt_json, _ = node.milestone(m["index"] + 1)
        assert nxt_json["previousMilestoneId"] == m["milestoneId"], "milestoneId mismatch"

    poi = []
    for b in ids[:3] + ids[-1:]:
        r = node.http.get(f"{HORNET}/api/poi/v1/create/{b}")
        poi.append({"blockId": b, "status": r.status_code, "body": r.json()})

    dump("blocks.json", blocks)
    dump("milestones.json", milestones)
    dump("cones.json", cones)
    dump("poi_create.json", poi)
    dump("rest_block.json", rest_block)
    dump("rest_metadata.json", rest_meta)
    dump("coordinator_keys.json", coordinator_keys())
    print(f"{len(blocks)} blocks, {len(milestones)} milestones")


if __name__ == "__main__":
    main()
