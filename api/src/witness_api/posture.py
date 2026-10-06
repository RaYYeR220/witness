"""Node security posture: constructive findings about a HORNET deployment (spec §4.8).

Each check produces a `Finding` with an id, a severity, evidence and a concrete fix. Passive
checks (default) only read: `GET`/`HEAD`/`OPTIONS`, a TCP connect to INX and nothing else.
Active checks — a `POST` to a protected route with an invalid body (never prunes anything)
and a dashboard default-credentials login — run only with `active=True` and only against a
loopback host, or one explicitly allowed, so the scanner never probes someone else's node.

Nothing here logs or returns a secret: the dashboard probe reports only whether the default
password was accepted, never the token it would receive.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx

log = logging.getLogger(__name__)

# The IOTA sample coordinator public keys shipped with every private tangle. Source:
# iotaledger/hornet `private_tangle/private_tangle_keys.md` and
# `private_tangle/config_private_tangle.json`, mirrored by eclipse-aerios
# `iota-tangle/docker/config_private_tangle.json` `protocol.publicKeyRanges`. A node that
# signs milestones with these keys can be forged by anyone who reads the public repo.
SAMPLE_COORDINATOR_KEYS: frozenset[str] = frozenset({
    "ed3c3f1a319ff4e909cf2771d79fece0ac9bd9fd2ee49ea6c0885c9cb3b1248c",
    "f6752f5f46a53364e2ee9c4d662d762a81efd51010282a75cd6bd03f28ef349c",
})

PEERS_PATH = "/api/core/v2/peers"
PRUNE_PATH = "/api/core/v2/control/database/prune"
DEBUG_PATH = "/api/debug/v1/requests"

# A request that reached the route without credentials: anything other than the node's
# "you need a token" answers. HORNET's auth middleware runs before method dispatch, so a
# protected route answers 401/403 even for a wrong method or body.
_AUTH_STATUSES = frozenset({401, 403})
_LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1", "[::1]", ""})

Severity = str  # "high" | "medium" | "low" | "info"


@dataclass(frozen=True)
class Finding:
    id: str
    severity: Severity
    title: str
    evidence: dict
    fix: str


def _norm_key(key: str) -> str:
    return key.strip().lower().removeprefix("0x")


def _host(url_or_addr: str) -> str:
    """Host of a URL (`http://h:p/…`) or a bare `host:port`."""
    if "://" in url_or_addr:
        return (urlsplit(url_or_addr).hostname or "").lower()
    host, _, _ = url_or_addr.rpartition(":")
    return (host or url_or_addr).lower().strip("[]")


def host_allowed(host: str, allow: frozenset[str] | set[str] | tuple[str, ...]) -> bool:
    host = host.lower()
    return host in _LOOPBACK or host in {h.lower() for h in allow}


async def tcp_reachable(addr: str, timeout_s: float) -> bool | None:
    """Open and immediately close a TCP connection to `host:port`. None if `addr` is unusable."""
    host, _, port = addr.rpartition(":")
    if not host or not port.isdigit():
        return None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host.strip("[]"), int(port)), timeout_s)
    except (TimeoutError, OSError):
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return True


TcpProbe = Callable[[str, float], Awaitable[bool | None]]


@dataclass
class ScanContext:
    http: httpx.AsyncClient
    node_url: str | None
    inx_addr: str | None
    dashboard_url: str | None
    config_keys: list[str]
    plaintext: dict | None = None
    active: bool = False
    allow_active_hosts: frozenset[str] = frozenset()
    timeout_s: float = 5.0
    tcp_probe: TcpProbe = tcp_reachable
    calls: list[str] = field(default_factory=list)

    async def _request(self, method: str, url: str, **kw) -> httpx.Response:
        self.calls.append(f"{method} {url}")
        return await self.http.request(method, url, timeout=self.timeout_s, **kw)


def check_sample_keys(config_keys: list[str]) -> Finding | None:
    matched = sorted({_norm_key(k) for k in config_keys} & SAMPLE_COORDINATOR_KEYS)
    if not matched:
        return None
    return Finding(
        id="sample-coordinator-keys",
        severity="high",
        title="Milestones are signed with public IOTA sample coordinator keys",
        evidence={
            "matchedKeys": ["0x" + k for k in matched],
            "sampleKeyCount": len(SAMPLE_COORDINATOR_KEYS),
            "source": "iotaledger/hornet private_tangle_keys.md; "
                      "eclipse-aerios iota-tangle config_private_tangle.json",
        },
        fix="Run `hornet tool ed25519-key` to generate a fresh coordinator key pair, set "
            "`protocol.publicKeyRanges` to the new public keys and `COO_PRV_KEYS` to the "
            "private keys, then bootstrap a new private tangle. Never ship the sample keys: "
            "anyone can forge milestones that your nodes will accept as genuine.",
    )


async def check_admin_routes(ctx: ScanContext, active_ok: bool) -> Finding | None:
    if not ctx.node_url:
        return None
    base = ctx.node_url.rstrip("/")
    peers = await _probe(ctx, "GET", base + PEERS_PATH)
    if active_ok:
        prune = await _probe(ctx, "POST", base + PRUNE_PATH, json={})
    else:
        prune = await _probe(ctx, "GET", base + PRUNE_PATH)
    reachable = [p for p in (peers, prune) if p.get("status") is not None]
    open_routes = [p for p in reachable if p["status"] not in _AUTH_STATUSES]
    if not open_routes:
        return None
    return Finding(
        id="unauthenticated-admin-routes",
        severity="high",
        title="Administrative REST routes answer without authentication",
        evidence={"peers": peers, "prune": prune,
                  "note": "Status 401/403 would mean the route requires a token; any other "
                          "answer means it was reached without one."},
        fix="In the node config set `restAPI.publicRoutes` to only the routes clients need "
            "(health, info, blocks, …) and move `/api/core/v2/control/*` and "
            "`/api/core/v2/peers` into `restAPI.protectedRoutes`, then issue JWT tokens with "
            "`hornet tool jwt-api`. As shipped, `publicRoutes: [\"/api/*\"]` exposes database "
            "pruning and peer management to anyone who can reach the port.",
    )


async def check_inx(ctx: ScanContext) -> Finding | None:
    if not ctx.inx_addr:
        return None
    reachable = await ctx.tcp_probe(ctx.inx_addr, ctx.timeout_s)
    ctx.calls.append(f"TCP {ctx.inx_addr}")
    if not reachable:
        return None
    _, _, port = ctx.inx_addr.rpartition(":")
    return Finding(
        id="inx-unauthenticated",
        severity="medium",
        title="INX gRPC port is reachable and has no authentication",
        evidence={"port": int(port) if port.isdigit() else None, "probe": "tcp-connect"},
        fix="INX speaks an unauthenticated gRPC protocol with full node access. Bind "
            "`--inx.bindAddress` to a private interface or `127.0.0.1`, keep the port off "
            "any public network, and front it with network policy so only your own INX "
            "extensions can reach it.",
    )


async def check_debug_api(ctx: ScanContext) -> Finding | None:
    if not ctx.node_url:
        return None
    probe = await _probe(ctx, "GET", ctx.node_url.rstrip("/") + DEBUG_PATH)
    if probe.get("status") != 200:
        return None
    return Finding(
        id="debug-api-enabled",
        severity="low",
        title="The debug REST API is enabled",
        evidence={"endpoint": DEBUG_PATH, "status": probe["status"]},
        fix="Set `restAPI.debugRequestLoggerEnabled` off and remove `/api/debug/v1/*` from "
            "`restAPI.publicRoutes` (or run the node without `--debug.enabled`). The debug "
            "API exposes internal node state that is useful for reconnaissance.",
    )


async def check_dashboard(ctx: ScanContext, active_ok: bool) -> Finding | None:
    if not ctx.dashboard_url or not active_ok:
        return None
    accepted = await _dashboard_default_login(ctx)
    if not accepted:
        return None
    return Finding(
        id="dashboard-default-credentials",
        severity="high",
        title="The node dashboard accepts the default admin/admin credentials",
        evidence={"endpoint": "/dashboard/auth", "username": "admin", "result": "accepted",
                  "note": "The issued session token is not recorded."},
        fix="Generate a new hash with `hornet tool pwd-hash` and set "
            "`--dashboard.auth.passwordHash` and `--dashboard.auth.passwordSalt` to the new "
            "values (and change `--dashboard.auth.username`). The inx-dashboard image ships "
            "with admin/admin, which grants full dashboard control to anyone.",
    )


def check_relay_ssrf() -> Finding:
    """An informational finding about the upstream aeriOS Messages API (always reported)."""
    return Finding(
        id="legacy-relay-ssrf",
        severity="medium",
        title="The aeriOS Messages API builds its upstream URL from the client's `node` "
              "parameter",
        evidence={
            "component": "eclipse-aerios/iota-messages-api",
            "code": 'node = "http://" + request.args.get("node") + ":14265/api/core/v2/blocks"',
            "file": "send_data.py",
            "impact": "A caller chooses the host the server connects to (SSRF).",
        },
        fix="Validate `node` against an allow-list of known node names that map to fixed "
            "base URLs, and reject anything else with 400 — exactly what the Witness relay "
            "does (`RELAY_ALLOWED_NODES`), so an attacker can never steer the server at an "
            "arbitrary host.",
    )


def check_plaintext(plaintext: dict | None) -> Finding | None:
    if not plaintext or plaintext.get("total", 0) == 0 or plaintext.get("plaintext", 0) == 0:
        return None
    ratio = plaintext["ratio"]
    return Finding(
        id="plaintext-payloads",
        severity="info",
        title="Message payloads are written to the Tangle in plaintext",
        evidence={"total": plaintext["total"], "plaintext": plaintext["plaintext"],
                  "encrypted": plaintext["encrypted"], "plaintextRatio": round(ratio, 4)},
        fix="Tagged-data payloads are world-readable forever. For tags that carry sensitive "
            "detail, enable the relay's envelope encryption (`RELAY_ENCRYPT_TAGS` with "
            "recipient X25519 keys); the blind index still allows lookup without disclosing "
            "the content.",
    )


async def _probe(ctx: ScanContext, method: str, url: str, **kw) -> dict:
    """One HTTP probe reduced to `{method, status}` (or `{error}` when the node is down)."""
    try:
        resp = await ctx._request(method, url, **kw)
    except httpx.HTTPError as e:
        return {"method": method, "status": None, "error": type(e).__name__}
    return {"method": method, "status": resp.status_code}


async def _dashboard_default_login(ctx: ScanContext) -> bool:
    """Try admin/admin against inx-dashboard. True only when the login is accepted (200)."""
    base = ctx.dashboard_url.rstrip("/")
    try:
        ctx.calls.append(f"GET {base}/dashboard/")
        seed = await ctx.http.get(base + "/dashboard/", timeout=ctx.timeout_s)
        csrf = seed.cookies.get("_csrf")
        headers = {"X-CSRF-Token": csrf} if csrf else {}
        ctx.calls.append(f"POST {base}/dashboard/auth")
        # The client persists the `_csrf` cookie from the seed request; echo it as the header
        # the dashboard requires.
        resp = await ctx.http.post(base + "/dashboard/auth", timeout=ctx.timeout_s,
                                   headers=headers,
                                   json={"user": "admin", "password": "admin"})
    except httpx.HTTPError as e:
        log.info("dashboard probe could not reach %s: %s", base, type(e).__name__)
        return False
    return resp.status_code == 200


async def scan(*, http: httpx.AsyncClient, node_url: str | None, inx_addr: str | None,
               dashboard_url: str | None, config_keys: list[str],
               plaintext: dict | None = None, active: bool = False,
               allow_active_hosts: frozenset[str] | set[str] | tuple[str, ...] = (),
               timeout_s: float = 5.0, tcp_probe: TcpProbe = tcp_reachable) -> list[Finding]:
    """Run every posture check and return the findings that fired, highest severity first."""
    allow = frozenset(allow_active_hosts)
    targets = [u for u in (node_url, dashboard_url) if u]
    active_ok = active and all(host_allowed(_host(t), allow) for t in targets) and bool(targets)
    if active and not active_ok:
        log.info("active posture probes skipped: a target host is not loopback or allow-listed")
    ctx = ScanContext(http=http, node_url=node_url, inx_addr=inx_addr,
                      dashboard_url=dashboard_url, config_keys=config_keys, plaintext=plaintext,
                      active=active, allow_active_hosts=allow, timeout_s=timeout_s,
                      tcp_probe=tcp_probe)
    findings = [
        check_sample_keys(config_keys),
        await check_admin_routes(ctx, active_ok),
        await check_inx(ctx),
        await check_debug_api(ctx),
        await check_dashboard(ctx, active_ok),
        check_relay_ssrf(),
        check_plaintext(plaintext),
    ]
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    return sorted((f for f in findings if f is not None),
                  key=lambda f: (order.get(f.severity, 9), f.id))
