"""Fixed nesting caps for untrusted JSON, the same on every platform and call stack.

CPython's own limits move. `json.loads` gives up near 3000 levels on Windows and near
10000 on Linux, so a tagged payload 5000 levels deep parsed on one and not on the other.
`rfc8785` recurses one Python frame per level under the interpreter's 1000-frame limit,
so how deep it gets depends on how deep its caller already is (about 990 levels from a
bare script, 890 with 100 frames above it). A verdict must depend on neither, so these
caps are checked first. @witness/verify applies the same ones (`PY_JSON_MAX_DEPTH` in
json.ts, `JCS_MAX_DEPTH` in jcs.ts); keep both sides equal.
"""

from __future__ import annotations

import json
from typing import Any

# Deepest bracket nesting read from JSON text. Below the C json scanner's own limit on
# every supported platform, so json.loads never reaches it first.
MAX_JSON_DEPTH = 2500
# Deepest value the canonicalizer accepts (the top value is at depth 0). Leaves rfc8785
# about 500 frames of headroom for its caller's stack.
MAX_JCS_DEPTH = 500


def text_too_deep(text: str, limit: int = MAX_JSON_DEPTH) -> bool:
    """True when `[` / `{` outside strings ever nest more than `limit` deep.

    Purely lexical, so it decides the same way whether or not the text is valid JSON: a
    payload that is both hostile and broken still fails closed, and the result does not
    depend on where a parser would have stopped.
    """
    if text.count("[") + text.count("{") <= limit:
        return False
    depth = 0
    in_string = escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > limit:
                return True
        elif ch in "]}":
            depth -= 1
    return False



class JsonTooDeep(ValueError):
    """JSON text nested deeper than MAX_JSON_DEPTH, valid JSON or not."""

    def __init__(self, limit: int = MAX_JSON_DEPTH) -> None:
        super().__init__(f"JSON nested deeper than {limit} levels")


def loads(data: str | bytes | bytearray, **kw: Any) -> Any:
    """`json.loads` for untrusted input, behind the shared cap.

    Raises JsonTooDeep (a ValueError) when the text nests deeper than MAX_JSON_DEPTH, so
    every entry point refuses the same payloads on every platform; json's own
    RecursionError (which cannot occur below the cap) is turned into the same. Bytes are
    decoded the way json.loads decodes them (UTF-8/16/32 sniffing). Other errors are
    json.loads' own.
    """
    text = data.decode(json.detect_encoding(data), "surrogatepass") if isinstance(
        data, (bytes, bytearray)) else data
    if text_too_deep(text):
        raise JsonTooDeep
    try:
        return json.loads(text, **kw)
    except RecursionError:
        raise JsonTooDeep from None


def value_too_deep(value: Any, limit: int = MAX_JCS_DEPTH) -> bool:
    """True when any value inside `value` sits more than `limit` levels below it (list
    items and dict values count; `value` itself is at depth 0). Checked without recursion."""
    stack = [(value, 0)]
    while stack:
        v, depth = stack.pop()
        if depth > limit:
            return True
        if isinstance(v, dict):
            stack.extend((x, depth + 1) for x in v.values())
        elif isinstance(v, (list, tuple)):
            stack.extend((x, depth + 1) for x in v)
    return False
