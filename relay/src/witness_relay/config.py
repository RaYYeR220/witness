"""Relay configuration, read from the environment (see relay/.env.example)."""

from __future__ import annotations

import base64
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field

from witness_core.sealed import Recipient

DEFAULT_MQTT_URL = "mqtt://127.0.0.1:1883"


@dataclass(frozen=True)
class RelayConfig:
    allowed_nodes: dict[str, str]  # node name accepted in ?node= -> HORNET base URL
    relay_did: str
    relay_kid: str
    relay_key_path: str  # Ed25519 private key, PKCS#8 PEM
    policy_path: str  # writer policy JSON (witness_core.policy format)
    db_url: str  # PostgreSQL DSN; receipts and per-issuer sequence live in `db_schema`
    encrypt_tags: list[str] = field(default_factory=list)
    # Legacy messages on these tags are posted unsigned, byte for byte as the original API.
    passthrough_tags: list[str] = field(default_factory=list)
    recipients: list[Recipient] = field(default_factory=list)
    search_key_path: str | None = None  # blind-index key, base64url text
    keycloak_jwks_url: str | None = None
    jwt_audience: str | None = None
    jwt_issuer: str | None = None
    trusted_keys_path: str | None = None  # JSON list of public Ed25519 JWKs with `kid`
    resolver_url: str | None = None  # anchor service; GET {url}/resolve/{did}
    db_schema: str = "relay"
    mqtt_url: str | None = None
    explorer_url: str | None = None
    explorer_token: str | None = None
    max_block_bytes: int = 32768
    hornet_timeout_s: float = 10.0
    forward_queue_size: int = 1000
    forward_drain_s: float = 2.0
    host: str = "0.0.0.0"
    port: int = 5555

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> RelayConfig:
        env = os.environ if env is None else env

        def opt(*names: str) -> str | None:
            for name in names:
                value = env.get(name, "").strip()
                if value:
                    return value
            return None

        def tags(name: str) -> list[str]:
            return [t.strip() for t in env.get(name, "").split(",") if t.strip()]

        def req(name: str) -> str:
            value = opt(name)
            if value is None:
                raise ValueError(f"{name} is required")
            return value

        nodes = json.loads(req("RELAY_ALLOWED_NODES"))
        if not isinstance(nodes, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in nodes.items()
        ):
            raise ValueError("RELAY_ALLOWED_NODES must be a JSON object of name -> base URL")
        recipients_path = opt("RELAY_RECIPIENTS_PATH")
        mqtt_url = env.get("RELAY_MQTT_URL", DEFAULT_MQTT_URL).strip() or None
        return cls(
            allowed_nodes=nodes,
            relay_did=req("RELAY_DID"),
            relay_kid=req("RELAY_KID"),
            relay_key_path=req("RELAY_KEY_PATH"),
            policy_path=req("RELAY_POLICY_PATH"),
            db_url=req("RELAY_DB_URL"),
            db_schema=opt("RELAY_DB_SCHEMA") or "relay",
            encrypt_tags=tags("RELAY_ENCRYPT_TAGS"),
            passthrough_tags=tags("RELAY_PASSTHROUGH_TAGS"),
            recipients=load_recipients(recipients_path) if recipients_path else [],
            search_key_path=opt("RELAY_SEARCH_KEY_PATH"),
            keycloak_jwks_url=opt("RELAY_KEYCLOAK_JWKS_URL"),
            jwt_audience=opt("RELAY_JWT_AUDIENCE"),
            jwt_issuer=opt("RELAY_JWT_ISSUER"),
            trusted_keys_path=opt("RELAY_TRUSTED_KEYS_PATH"),
            resolver_url=opt("RELAY_RESOLVER_URL"),
            mqtt_url=mqtt_url,
            explorer_url=opt("RELAY_EXPLORER_URL", "EXPLORER_URL"),
            explorer_token=opt("RELAY_EXPLORER_TOKEN", "EXPLORER_TOKEN"),
            max_block_bytes=int(opt("RELAY_MAX_BLOCK_BYTES") or 32768),
            hornet_timeout_s=float(opt("RELAY_HORNET_TIMEOUT_S") or 10.0),
            forward_queue_size=int(opt("RELAY_FORWARD_QUEUE_SIZE") or 1000),
            host=opt("RELAY_HOST") or "0.0.0.0",
            port=int(opt("RELAY_PORT") or 5555),
        )


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def load_recipients(path: str) -> list[Recipient]:
    """JSON list of public X25519 JWKs (`kid`, `kty: OKP`, `crv: X25519`, `x`)."""
    with open(path, encoding="utf-8") as f:
        entries = json.load(f)
    out = []
    for jwk in entries:
        if jwk.get("crv") != "X25519" or not isinstance(jwk.get("kid"), str):
            raise ValueError(f"recipient is not an X25519 JWK with kid: {jwk!r}")
        pub = _b64u_decode(jwk["x"])
        if len(pub) != 32:
            raise ValueError(f"recipient {jwk['kid']}: X25519 key must be 32 bytes")
        out.append(Recipient(jwk["kid"], pub))
    return out


def load_search_key(path: str) -> bytes:
    """Blind-index key stored as base64url text."""
    with open(path, encoding="utf-8") as f:
        key = _b64u_decode(f.read().strip())
    if len(key) < 16:
        raise ValueError("search key must be at least 16 bytes")
    return key
