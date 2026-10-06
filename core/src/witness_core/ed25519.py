"""Ed25519 verification with weak public keys refused.

Signatures are checked by OpenSSL: cofactorless equation, S < L, R compared by
encoding. OpenSSL decodes public keys leniently and accepts keys of small order, and
under such a key a crafted signature verifies for every message (the identity key
with R = identity, S = 0 is the classic one). Every signature the verifier checks goes
through `verify`, which refuses those keys first:

- the key must decode strictly (RFC 8032 5.1.3: y < p, no x = 0 with the sign bit set,
  and a point on the curve);
- the point must not be of small order (8*A is not the identity).

The TypeScript port (`packages/verify/src/ed25519.ts`) applies the same rule.
"""

from __future__ import annotations

from functools import lru_cache

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_P = 2**255 - 19
_D = -121665 * pow(121666, -1, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)
_IDENTITY = (0, 1)

Point = tuple[int, int]


def _decode(public_key: object) -> Point | None:
    """Affine point of a strictly encoded key, or None."""
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
        return None
    n = int.from_bytes(public_key, "little")
    sign, y = n >> 255, n & ((1 << 255) - 1)
    if y >= _P:
        return None
    u = (y * y - 1) % _P
    v = (_D * y * y + 1) % _P  # never 0: d is not a square
    x2 = u * pow(v, -1, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
        if (x * x - x2) % _P:
            return None  # not on the curve
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = _P - x
    return x, y


def _add(a: Point, b: Point) -> Point:
    """Twisted Edwards addition (a = -1); complete, so it also doubles."""
    (x1, y1), (x2, y2) = a, b
    t = _D * x1 * x2 * y1 * y2 % _P
    return (
        (x1 * y2 + y1 * x2) * pow(1 + t, -1, _P) % _P,
        (y1 * y2 + x1 * x2) * pow(1 - t, -1, _P) % _P,
    )


def is_weak_public_key(public_key: object) -> bool:
    """True for a key that must not verify anything: not a strict 32-byte encoding of a
    curve point, or a point of small order (one of the 8 torsion points, identity
    included). Memoized: the same few keys sign every message."""
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
        return True
    return _weak(bytes(public_key))


@lru_cache(maxsize=1024)
def _weak(public_key: bytes) -> bool:
    point = _decode(public_key)
    if point is None:
        return True
    for _ in range(3):
        point = _add(point, point)
    return point == _IDENTITY


def verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """OpenSSL Ed25519 verification; always False under a weak key."""
    if is_weak_public_key(public_key):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes(public_key)).verify(signature, message)
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True
