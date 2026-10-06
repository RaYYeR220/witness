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
