"""Regenerate checkpoint.json from the Python reference (witness_core).

    uv run python anchor/test/vectors/make_checkpoint_vectors.py

The anchor's TypeScript checkpoint and policy hashing must match these bytes exactly.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from witness_core import canon, checkpoint, policy


def h(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32).digest()


POLICY = {
    "version": 3,
    "tags": {
        "trust.score": {"allowed": ["did:iota:testnet:0x01", "did:iota:testnet:0x02"], "require_signature": True},
        "witness.anchor": {"allowed": ["did:iota:testnet:0x03"], "require_signature": 1, "legacy_grace": []},
        "LLO-K8s": {},
    },
    "default": {"allowed": ["*"], "legacy_grace": True},
    "note": "ignored by the policy hash",
}


def window(first: int, count: int) -> list[bytes]:
    return [h(b"milestone:" + i.to_bytes(4, "little")) for i in range(first, first + count)]


def main() -> None:
    p_hash = policy.policy_hash(policy.load(POLICY))
    out = {"policy": {"input": POLICY, "normalized": policy.to_dict(policy.load(POLICY)), "hash": "0x" + p_hash.hex()}, "checkpoints": []}
    prev = None
    for first, count, msgs, domain in ((3601, 12, 37, "Domäne-東京 \u2028 \"q\""), (3613, 12, 0, "Domäne-東京 \u2028 \"q\""), (1, 1, 5, "MyDomain")):
        ids = window(first, count)
        cp = checkpoint.build("private_tangle1", domain, (first, ids[0]), (first + count - 1, ids[-1]), ids, msgs, p_hash, prev if first != 1 else None)
        digest = checkpoint.hash(cp)
        out["checkpoints"].append({
            "input": {
                "network": "private_tangle1", "domain": domain, "first": first,
                "milestoneIds": ["0x" + i.hex() for i in ids], "msgCount": msgs,
                "policyHash": "0x" + p_hash.hex(), "prevHash": None if (prev is None or first == 1) else "0x" + prev.hex(),
            },
            "checkpoint": cp,
            "jcs": canon.jcs(cp).decode("utf-8"),
            "hash": "0x" + digest.hex(),
        })
        prev = digest
    path = Path(__file__).with_name("checkpoint.json")
    path.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
