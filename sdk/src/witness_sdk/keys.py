"""Component signing keys: create new ones, or load the ones the anchor service wrote."""

from __future__ import annotations

import base64
import json
import os
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _jwk(crv: str, public: bytes) -> dict[str, str]:
    return {"kty": "OKP", "crv": crv, "x": _b64u(public)}


def _write_private(path: str, pem: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)


def generate(component: str, out_dir: str) -> dict[str, Any]:
    """Create `<out_dir>/<component>/{sig,kex}.pem` and return the public JWKs."""
    target = os.path.join(out_dir, component)
    os.makedirs(target, exist_ok=True)
    sig, kex = Ed25519PrivateKey.generate(), X25519PrivateKey.generate()
    for name, key in (("sig", sig), ("kex", kex)):
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        _write_private(os.path.join(target, f"{name}.pem"), pem)
    return {
        "component": component,
        "sig": _jwk("Ed25519", sig.public_key().public_bytes_raw()),
        "kex": _jwk("X25519", kex.public_key().public_bytes_raw()),
    }


def load_key_file(path: str) -> tuple[Ed25519PrivateKey, str | None]:
    """Read an Ed25519 private key from a PEM or an OKP JWK; also return the JWK's `kid`."""
    with open(path, "rb") as f:
        raw = f.read()
    if raw.lstrip().startswith(b"{"):
        jwk = json.loads(raw)
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or "d" not in jwk:
            raise ValueError(f"{path} is not an Ed25519 private JWK")
        return Ed25519PrivateKey.from_private_bytes(_b64u_decode(jwk["d"])), jwk.get("kid")
    key = serialization.load_pem_private_key(raw, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"{path} is not an Ed25519 key")
    return key, None


def load_component(
    component: str, secrets_dir: str, name: str = "sig-1.jwk.json"
) -> tuple[str, str, Ed25519PrivateKey]:
    """Load `<secrets_dir>/<component>/sig-1.jwk.json`; return (iss DID, kid, private key)."""
    key, kid = load_key_file(os.path.join(secrets_dir, component, name))
    if not kid:
        raise ValueError(f"{component} key file has no kid")
    return kid.partition("#")[0], kid, key
