"""Convert between audit paths and the inx-poi proof JSON.

inx-poi nests `{"l": ..., "r": ...}`; subtrees off the proven path collapse to
`{"h": "0x.."}` and the proven leaf is `{"value": "0x.."}`.
"""

from __future__ import annotations

from typing import Any

from . import merkle
from .ids import from_hex, to_hex


def to_inx_poi(values: list[bytes], index: int) -> dict[str, Any]:
    n = len(values)
    if not 0 <= index < n:
        raise IndexError(f"index {index} out of range for {n} leaves")
    if n == 1:
        return {"value": to_hex(values[0])}
    k = merkle.split_point(n)
    if index < k:
        return {
            "l": to_inx_poi(values[:k], index),
            "r": {"h": to_hex(merkle.root(values[k:]))},
        }
    return {
        "l": {"h": to_hex(merkle.root(values[:k]))},
        "r": to_inx_poi(values[k:], index - k),
    }


def from_inx_poi(proof: dict[str, Any]) -> tuple[bytes, list[merkle.PathStep]]:
    """Return (leaf value, path leaf-to-root)."""
    steps: list[merkle.PathStep] = []
    node = proof
    while True:
        if not isinstance(node, dict):
            raise ValueError("inx-poi proof node must be an object")  # noqa: TRY004
        if "value" in node:
            if "l" in node or "r" in node:
                raise ValueError("proof node has both value and children")
            if not isinstance(node["value"], str):
                raise ValueError("leaf value must be a hex string")
            break
        if "l" not in node or "r" not in node:
            raise ValueError("malformed inx-poi proof node")
        left, right = node["l"], node["r"]
        if not isinstance(left, dict) or not isinstance(right, dict):
            raise ValueError("proof children must be objects")  # noqa: TRY004
        if "h" in right and "h" not in left:
            steps.append(merkle.PathStep("R", _hash(right["h"])))
            node = left
        elif "h" in left and "h" not in right:
            steps.append(merkle.PathStep("L", _hash(left["h"])))
            node = right
        else:
            raise ValueError("proof node must have exactly one hashed child")
    steps.reverse()
    return from_hex(node["value"]), steps


def _hash(h: object) -> bytes:
    if not isinstance(h, str):
        raise ValueError("hash must be a hex string")  # noqa: TRY004
    return from_hex(h)
