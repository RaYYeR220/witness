"""Fixed nesting caps for untrusted JSON, the same on every platform and call stack.

CPython's own limits move. `json.loads` gives up near 3000 levels on Windows and near
10000 on Linux, so a tagged payload 5000 levels deep parsed on one and not on the other.
`rfc8785` recurses one Python frame per level under the interpreter's 1000-frame limit,
so how deep it gets depends on how deep its caller already is (about 990 levels from a
bare script, 890 with 100 frames above it). A verdict must depend on neither, so these
caps are checked first. @witness/verify applies the same ones (`PY_JSON_MAX_DEPTH` in
json.ts, `JCS_MAX_DEPTH` in jcs.ts); keep both sides equal.

The JSON cap only decides if json.loads itself parses that deep. CPython 3.11 gives up at
about 994 levels, so Witness requires CPython 3.12.1 or later and checks at import time
that this interpreter parses MAX_JSON_DEPTH levels (RuntimeError otherwise).
"""

from __future__ import annotations

import json
from typing import Any

# Deepest bracket nesting read from JSON text. On the supported interpreters (CPython
# 3.12.1+) json.loads parses deeper than this on every platform, which the import-time
# check below confirms, so the cap decides and the interpreter never does.
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


CAP_EXCEEDED = f"JSON nested deeper than {MAX_JSON_DEPTH} levels"
PARSER_LIMIT = "JSON nested deeper than the parser's recursion limit"


class JsonTooDeep(ValueError):
    """JSON text too deep to read: past MAX_JSON_DEPTH (CAP_EXCEEDED), valid JSON or not, or,
    should it ever happen below the cap, past json.loads' own limit (PARSER_LIMIT)."""

    def __init__(self, message: str = CAP_EXCEEDED) -> None:
        super().__init__(message)


def loads(data: str | bytes | bytearray, **kw: Any) -> Any:
    """`json.loads` for untrusted input, behind the shared cap.

    Raises JsonTooDeep (a ValueError) when the text nests deeper than MAX_JSON_DEPTH, so
    every entry point refuses the same payloads on every platform; json's own
    RecursionError (which the import-time check rules out below the cap) is turned into
    JsonTooDeep too, with its own message. Bytes are decoded the way json.loads decodes
    them (UTF-8/16/32 sniffing). Other errors are json.loads' own.
    """
    text = data.decode(json.detect_encoding(data), "surrogatepass") if isinstance(
        data, (bytes, bytearray)) else data
    if text_too_deep(text):
        raise JsonTooDeep(CAP_EXCEEDED)
    try:
        return json.loads(text, **kw)
    except RecursionError:
        raise JsonTooDeep(PARSER_LIMIT) from None


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


def _check_interpreter() -> None:
    """The cap must be what decides: this json.loads has to parse MAX_JSON_DEPTH levels."""
    deepest = "[" * MAX_JSON_DEPTH + "]" * MAX_JSON_DEPTH
    try:
        json.loads(deepest)
    except RecursionError:
        raise RuntimeError(
            f"witness_core needs a json.loads that parses {MAX_JSON_DEPTH} levels of nesting; "
            "this Python gives up earlier, so verdicts on deep payloads would depend on the "
            "interpreter. Use CPython 3.12.1 or later."
        ) from None


_check_interpreter()
