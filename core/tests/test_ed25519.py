import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from witness_core import ed25519

P = 2**255 - 19
IDENTITY = (1).to_bytes(32, "little")
ZERO_SIG = IDENTITY + bytes(32)  # R = identity, S = 0
# The eight points of small order (canonical encodings), identity first.
TORSION = [
    IDENTITY,
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000080"),
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    (P - 1).to_bytes(32, "little"),
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
    bytes(32),
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
]
# Non-canonical encodings of small-order points: y >= p, and x = 0 with the sign bit set.
ALIASES = [(n).to_bytes(32, "little") for n in (P + 1, 1 | 1 << 255, P, (P - 1) | 1 << 255)]


def test_openssl_alone_accepts_the_identity_key():
    """Why the screen exists: plain verification takes this for any message."""
    Ed25519PublicKey.from_public_bytes(IDENTITY).verify(ZERO_SIG, b"anything")


@pytest.mark.parametrize("public", TORSION + ALIASES)
def test_small_order_keys_are_weak(public):
    assert ed25519.is_weak_public_key(public)
    assert not ed25519.verify(public, ZERO_SIG, b"anything")


def test_strict_decoding():
    assert ed25519.is_weak_public_key((2).to_bytes(32, "little"))  # not on the curve
    assert not ed25519.is_weak_public_key((3).to_bytes(32, "little"))  # on it, large order
    assert ed25519.is_weak_public_key((P + 3).to_bytes(32, "little"))  # same point, y >= p
    for bad in (bytes(31), bytes(33), None, "01" * 32):
        assert ed25519.is_weak_public_key(bad)


def test_real_keys_verify():
    for _ in range(20):
        key = Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes_raw()
        msg = os.urandom(20)
        assert not ed25519.is_weak_public_key(public)
        assert ed25519.verify(public, key.sign(msg), msg)
        assert not ed25519.verify(public, key.sign(msg), msg + b"x")


def test_torsion_component_is_not_small_order():
    """Matches the TS port: A + T (T of order 8) stays usable."""
    public = Ed25519PrivateKey.from_private_bytes(b"\x09" * 32).public_key().public_bytes_raw()
    a, t = ed25519._decode(public), ed25519._decode(TORSION[1])
    x, y = ed25519._add(a, t)
    mixed = (y | (x & 1) << 255).to_bytes(32, "little")
    assert not ed25519.is_weak_public_key(mixed)
