import json

import pytest
from witness_core import canon, nesting

CAP = nesting.MAX_JSON_DEPTH


def nest(n: int) -> str:
    return "[" * n + "]" * n


def test_cap_is_shared_with_the_ts_port():
    assert CAP == 2500  # packages/verify/src/json.ts PY_JSON_MAX_DEPTH


@pytest.mark.parametrize("n", [CAP + 1, CAP + 100, 2900])
def test_valid_json_past_the_cap_parses_natively_but_is_too_deep(n):
    """Depths json.loads accepts on every platform (its own limit is near 3000 on Windows,
    10000 on Linux): the verdict comes from the cap alone, not from the interpreter."""
    json.loads(nest(n))
    assert nesting.text_too_deep(nest(n))


def test_boundary():
    assert not nesting.text_too_deep(nest(CAP))
    assert nesting.text_too_deep(nest(CAP + 1))
    mixed = '{"a":' * (CAP - 1) + "[1]" + "}" * (CAP - 1)
    assert not nesting.text_too_deep(mixed)
    assert nesting.text_too_deep("[" + mixed + "]")


@pytest.mark.parametrize(
    "text",
    [
        "[" * (CAP + 1),  # never closed
        "[" * (CAP + 1) + "x",  # broken after the cap
        "﻿" + nest(CAP + 1),  # BOM in front: not JSON to json.loads either
        '{"a":1 ' + "[" * (CAP + 1),  # broken before the cap: still fails closed
    ],
)
def test_broken_json_is_judged_on_its_brackets_alone(text):
    assert nesting.text_too_deep(text)


def test_brackets_inside_strings_do_not_count():
    deep_string = json.dumps("[" * (CAP * 2))
    assert not nesting.text_too_deep("[" + deep_string + "]")
    escaped = json.dumps('\\"' + "{" * (CAP * 2))  # an escaped quote does not end it
    assert not nesting.text_too_deep(escaped)
    # A string left open swallows the rest of the text, brackets included.
    assert not nesting.text_too_deep('["' + "[" * (CAP * 2))


def _lists(levels: int) -> list:
    v: list = []
    for _ in range(levels - 1):
        v = [v]
    return v


def test_jcs_cap_is_shared_with_the_ts_port():
    assert nesting.MAX_JCS_DEPTH == 500  # packages/verify/src/jcs.ts JCS_MAX_DEPTH


def test_jcs_cap_counts_every_value_from_depth_zero():
    cap = nesting.MAX_JCS_DEPTH
    assert canon.jcs(_lists(cap + 1)) == b"[" * (cap + 1) + b"]" * (cap + 1)
    with pytest.raises(RecursionError):
        canon.jcs(_lists(cap + 2))
    # A scalar counts as a level of its own, dict values like list items.
    assert not nesting.value_too_deep([_lists(cap - 1)])
    assert not nesting.value_too_deep({"a": _lists(cap)})
    assert nesting.value_too_deep({"a": _lists(cap + 1)})
    inner: object = 1
    for _ in range(cap):
        inner = [inner]
    assert not nesting.value_too_deep(inner)
    assert nesting.value_too_deep([inner])


def test_jcs_cap_does_not_depend_on_the_callers_stack():
    def at(frames: int) -> bytes:
        return at(frames - 1) if frames else canon.jcs(_lists(nesting.MAX_JCS_DEPTH + 1))

    assert at(0) == at(350)
