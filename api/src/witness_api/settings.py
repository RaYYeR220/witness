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
    # Upstreams; each is optional and the API says so when one is missing or down. No
    # hornet_url (WITNESS_HORNET_URL set to "") means no node calls at all.
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
    # The indexer (`--validate`) owns validation and re-verification. Turn this on only when
    # no indexer validates: the API then runs the worker for HTTP-ingested blocks itself.
    validate: bool = False
    # POST /messages/{id}/verify: optional bearer token, checks running at once, and how long
    # a stored answer from the node is served instead of asking again.
    verify_token: str | None = None
    verify_concurrency: int = 4
    verify_cooldown_s: float = 20.0
    verify_timeout_s: float = 10.0
    upstream_timeout_s: float = 2.0
    # Node posture scanner (GET /posture, POST /posture/scan). It scans `hornet_url`/`inx_addr`
    # plus an optional dashboard; active probes run only against loopback or allow-listed hosts.
    posture_token: str | None = None
    posture_dashboard_url: str | None = None
    posture_allow_active_hosts: list[str] = field(default_factory=list)
    posture_timeout_s: float = 5.0
    # Signed audit reports (POST /reports). The hash is posted as `audit.report` through the
    # relay, signed with a component DID key loaded from `report_signer_key` (never logged).
    report_token: str | None = None
    relay_url: str | None = "http://127.0.0.1:5556"
    report_relay_node: str = "iota-hornet"
    report_signer_key: str | None = None
    drift_epsilon: float = 0.01
    stream_poll_s: float = 1.0
    stream_ping_s: float = 15.0
    stream_max_subscribers: int = 200
    stats_cache_s: float = 5.0
    node_refresh_s: float = 180.0

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
        for name, token in (("WITNESS_INGEST_TOKEN", self.ingest_token),
                            ("WITNESS_VERIFY_TOKEN", self.verify_token),
                            ("WITNESS_POSTURE_TOKEN", self.posture_token),
                            ("WITNESS_REPORT_TOKEN", self.report_token)):
            if token is not None and len(token) < 16:
                raise ValueError(f"{name} must be at least 16 characters")
        if self.verify_concurrency < 1:
            raise ValueError("verify_concurrency must be at least 1")
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
        # Unset: the local node. Set but empty: no node at all.
        hornet = cls.hornet_url if env.get("WITNESS_HORNET_URL") is None \
            else get("WITNESS_HORNET_URL")
        return cls(
            db=db,
            schema=get("WITNESS_SCHEMA") or "witness",
            network=get("WITNESS_NETWORK") or "private_tangle1",
            coordinator_keys=keys,
            threshold=int(number("WITNESS_THRESHOLD", max(len(keys), 1), int)),
            rebased_network=get("WITNESS_REBASED_NETWORK"),
            trail_id=get("WITNESS_TRAIL_ID"),
            hornet_url=hornet,
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
            validate=flag("WITNESS_VALIDATE", False),
            verify_token=get("WITNESS_VERIFY_TOKEN"),
            verify_concurrency=int(number("WITNESS_VERIFY_CONCURRENCY", 4, int)),
            verify_cooldown_s=number("WITNESS_VERIFY_COOLDOWN_S", 20.0),
            verify_timeout_s=number("WITNESS_VERIFY_TIMEOUT_S", 10.0),
            posture_token=get("WITNESS_POSTURE_TOKEN"),
            posture_dashboard_url=get("WITNESS_POSTURE_DASHBOARD_URL"),
            posture_allow_active_hosts=items("WITNESS_POSTURE_ALLOW_ACTIVE_HOSTS"),
            posture_timeout_s=number("WITNESS_POSTURE_TIMEOUT_S", 5.0),
            report_token=get("WITNESS_REPORT_TOKEN"),
            relay_url=get("WITNESS_RELAY_URL") or "http://127.0.0.1:5556",
            report_relay_node=get("WITNESS_REPORT_RELAY_NODE") or "iota-hornet",
            report_signer_key=get("WITNESS_REPORT_SIGNER_KEY"),
            stream_max_subscribers=int(number("WITNESS_STREAM_MAX_SUBSCRIBERS", 200, int)),
            drift_epsilon=number("WITNESS_DRIFT_EPSILON", 0.01),
        )
