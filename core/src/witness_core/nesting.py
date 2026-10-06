"""Fixed nesting caps for untrusted JSON, the same on every platform.

CPython's own limit moves: `json.loads` gives up near 3000 levels on Windows and near
10000 on Linux, so a tagged payload 5000 levels deep parsed on one and not on the other.
A verdict must not depend on that, so this cap is checked first. @witness/verify applies
the same one (`PY_JSON_MAX_DEPTH` in json.ts); keep both sides equal.
"""

from __future__ import annotations

# Deepest bracket nesting read from JSON text. Below the C json scanner's own limit on
# every supported platform, so json.loads never reaches it first.
MAX_JSON_DEPTH = 2500


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

