"""API configuration, read from `WITNESS_*` environment variables (see `api/.env.example`)."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field

_KEY = re.compile(r"0x[0-9a-f]{64}")
_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off", ""}


@dataclass(frozen=True)
class Settings:
    db: str
    schema: str = "witness"
    # What a verifier pins: the private Tangle's network label, its coordinator keys and
    # signature threshold, the IOTA Rebased network and Audit Trail holding the anchors.
    network: str = "private_tangle1"
    coordinator_keys: list[str] = field(default_factory=list)
    threshold: int = 1
    rebased_network: str | None = None
    trail_id: str | None = None
    # Upstreams; each is optional and the API says so when one is missing or down.
    hornet_url: str | None = "http://127.0.0.1:14265"
    orion_url: str | None = None
    orion_context: str | None = None
    anchor_url: str | None = None
    # Mounting on the node: the node proxies /api/<node_route>/* to route_host:port.
    inx_addr: str | None = None
    node_route: str = "witness/v1"
    route_host: str = "host.docker.internal"
    host: str = "127.0.0.1"
    port: int = 7200
    public_base_url: str | None = None
    cors_origins: list[str] = field(default_factory=list)
    ingest_token: str | None = None
    policy_path: str | None = None
    # Run the validation worker here (HTTP-ingested blocks are checked at once). Turn off when
    # the indexer runs with --validate, so a single process works through the backlog.
    validate: bool = True
    verify_timeout_s: float = 10.0
    upstream_timeout_s: float = 2.0
    drift_epsilon: float = 0.01
    stream_poll_s: float = 1.0
    stream_ping_s: float = 15.0

    def __post_init__(self) -> None:
        keys = [k.lower() for k in self.coordinator_keys]
        for k in keys:
            if not _KEY.fullmatch(k):
                raise ValueError(f"coordinator key {k!r} is not 0x followed by 64 hex digits")
        object.__setattr__(self, "coordinator_keys", keys)
        if self.threshold < 1:
            raise ValueError("threshold must be at least 1")
        if keys and self.threshold > len(keys):
            raise ValueError(f"threshold {self.threshold} exceeds the {len(keys)} trusted keys")
        if self.ingest_token is not None and len(self.ingest_token) < 16:
            raise ValueError("WITNESS_INGEST_TOKEN must be at least 16 characters")
        if not 0 < self.port < 65536:
            raise ValueError("port must be between 1 and 65535")

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        env = os.environ if env is None else env

        def get(name: str) -> str | None:
            value = env.get(name)
            value = value.strip() if value is not None else None
            return value or None

        def number(name: str, default: float, kind: type = float) -> float:
            raw = get(name)
            try:
                return kind(raw) if raw is not None else default
            except ValueError:
                raise ValueError(f"{name} must be a number, got {raw!r}") from None

        def flag(name: str, default: bool) -> bool:
            raw = get(name)
            if raw is None:
                return default
            if raw.lower() in _TRUE:
                return True
            if raw.lower() in _FALSE:
                return False
            raise ValueError(f"{name} must be 0 or 1, got {raw!r}")

        def items(name: str) -> list[str]:
            return [p.strip() for p in (get(name) or "").split(",") if p.strip()]

        db = get("WITNESS_DB")
        if db is None:
            raise ValueError("WITNESS_DB (PostgreSQL DSN) is required")
        keys = items("WITNESS_COORDINATOR_KEYS")
        hornet = get("WITNESS_HORNET_URL")
        return cls(
            db=db,
            schema=get("WITNESS_SCHEMA") or "witness",
            network=get("WITNESS_NETWORK") or "private_tangle1",
            coordinator_keys=keys,
            threshold=int(number("WITNESS_THRESHOLD", max(len(keys), 1), int)),
            rebased_network=get("WITNESS_REBASED_NETWORK"),
            trail_id=get("WITNESS_TRAIL_ID"),
            hornet_url=hornet if hornet is not None else cls.hornet_url,
            orion_url=get("WITNESS_ORION_URL"),
            orion_context=get("WITNESS_ORION_CONTEXT"),
            anchor_url=get("WITNESS_ANCHOR_URL"),
            inx_addr=get("WITNESS_INX_ADDR"),
            node_route=get("WITNESS_NODE_ROUTE") or "witness/v1",
            route_host=get("WITNESS_ROUTE_HOST") or "host.docker.internal",
            host=get("WITNESS_HOST") or "127.0.0.1",
            port=int(number("WITNESS_PORT", 7200, int)),
            public_base_url=get("WITNESS_PUBLIC_BASE_URL"),
            cors_origins=items("WITNESS_CORS_ORIGINS"),
            ingest_token=get("WITNESS_INGEST_TOKEN"),
            policy_path=get("WITNESS_POLICY"),
            validate=flag("WITNESS_VALIDATE", True),
            verify_timeout_s=number("WITNESS_VERIFY_TIMEOUT_S", 10.0),
            drift_epsilon=number("WITNESS_DRIFT_EPSILON", 0.01),
        )
