import hashlib
import json
import struct

import pytest
from witness_core import canon

# RFC 8785 Appendix B: IEEE-754 bit pattern -> expected serialization.
NUMBERS = [
    (0x0000000000000000, "0"),
    (0x8000000000000000, "0"),
    (0x0000000000000001, "5e-324"),
    (0x8000000000000001, "-5e-324"),
    (0x7FEFFFFFFFFFFFFF, "1.7976931348623157e+308"),
    (0xFFEFFFFFFFFFFFFF, "-1.7976931348623157e+308"),
    (0x4340000000000000, "9007199254740992"),
    (0xC340000000000000, "-9007199254740992"),
    (0x4430000000000000, "295147905179352830000"),
    (0x44B52D02C7E14AF5, "9.999999999999997e+22"),
    (0x44B52D02C7E14AF6, "1e+23"),
    (0x44B52D02C7E14AF7, "1.0000000000000001e+23"),
    (0x444B1AE4D6E2EF4E, "999999999999999700000"),
    (0x444B1AE4D6E2EF4F, "999999999999999900000"),
    (0x444B1AE4D6E2EF50, "1e+21"),
    (0x3EB0C6F7A0B5ED8C, "9.999999999999997e-7"),
    (0x3EB0C6F7A0B5ED8D, "0.000001"),
]


@pytest.mark.parametrize("bits,expected", NUMBERS)
def test_jcs_rfc8785_numbers(bits, expected):
    value = struct.unpack(">d", struct.pack(">Q", bits))[0]
    assert canon.jcs(value) == expected.encode()


def test_jcs_rfc8785_examples():
    # RFC 8785 section 3.2.3: keys sort by UTF-16 code units.
    sample = {
        "€": "Euro Sign",
        "\r": "Carriage Return",
        "דּ": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "\U0001f600": "Emoji: Grinning Face",
        "\u0080": "Control",
        "ö": "Latin Small Letter O With Diaeresis",
    }
    expected = (
        '{"\\r":"Carriage Return","1":"One","\u0080":"Control",'
        '"ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign",'
        '"\U0001f600":"Emoji: Grinning Face",'
        '"דּ":"Hebrew Letter Dalet With Dagesh"}'
    )
    assert canon.jcs(sample) == expected.encode("utf-8")
    assert canon.jcs({"b": [1, 2, {"z": None, "a": True}], "a": "x"}) == (
        b'{"a":"x","b":[1,2,{"a":true,"z":null}]}'
    )


def test_jcs_python_json_dumps_equivalence():
    obj = {"score": 0.745, "id": "D:x"}
    spaced = json.loads(json.dumps(obj))
    compact = json.loads(json.dumps(obj, separators=(",", ":")))
    assert canon.canon_hash(spaced) == canon.canon_hash(compact)
    assert canon.canon_hash(obj) == hashlib.blake2b(
        b'{"id":"D:x","score":0.745}', digest_size=32
    ).digest()
