"""`witness-chaos`: run the pre-registered fault-injection evaluation against a local stack.

    witness-chaos keys --out secrets/chaos      # once: run-only producer + eval policy
    witness-chaos run --api http://127.0.0.1:7200 --relay http://127.0.0.1:5557 \\
        --orion http://127.0.0.1:1026 --hornet http://127.0.0.1:14265 \\
        --secrets-dir secrets --trials 20 --out results/

The run signs with its own producer key (a did:key from `keys`), never a live component's:
two signers sharing a key interleave their seq/prev chains and turn genuine messages into
chain gaps. The stack must run with the eval policy `keys` writes, which allows that
producer on trust.score.

Phases, in this order:

1. preflight: API, relay, HORNET and Orion answer; the producer is no live component's DID,
   the stack's writer policy allows it on trust.score, and nobody else signs as it;
2. trap: genuine traffic only (`traffic.py`), then every alert on a trap block or trap IE
   is a false positive and every verdict outside the answer key's list counts as one too;
3. attacks: for every class of the answer key, `trials` injections through its attack
   function in `attacks.py`, each followed by polling the explorer API until the class's
   expectation holds or its `timeout_s` runs out. Bundle classes are checked offline by
   `witness_core.bundle.verify` and by the TS verifier CLI; the two must agree on every
   step, or the trial fails. The C01 control follows the classes;
4. a late sweep for alerts that arrived on injected blocks after their trial ended, and
   the rows A19 rewrote are restored;
5. `scorecard.json`, `scorecard.md`, `trials.jsonl`, `trap.jsonl` and `run.json` in `--out`.

Seeds make the IE ids, scores, tamper positions and identities of the outsider and the
attacker reproducible; nonces and timestamps are fresh. `run.json` records the git commit,
a hash of the configuration (secrets excluded) and of the answer key.

`witness-chaos score <out>` rebuilds the scorecard from a results directory.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import dataclasses
import hashlib
import json
import logging
import os
import random
import subprocess
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from witness_core import bundle, checkpoint
from witness_core.bundle import VerifierConfig
from witness_core.codec import Ed25519Sig
from witness_core.ids import blake2b256, from_hex, to_hex

from . import attacks, forge, scorecard, traffic
from .attacks import AttackContext, Identity, InjectionRecord

log = logging.getLogger("witness_chaos")

# Classes whose trial IEs must exist in Orion before the trial (registered per class, then
# given the trial's baseline score by the begin_trial hook, then deleted after the trial).
NEEDS_ORION = frozenset({"A06", "A13", "A14", "A16", "A17", "A20", "C01"})
HORNET_DIRECT = "hornet-direct"
OFFLINE = "bundle-offline"
VECTOR_NETWORK = "private_tangle1"
VECTOR_TRAIL = "0x" + "7a" * 32
VECTOR_REBASED = {"network": "testnet", "trail": VECTOR_TRAIL, "record": 3, "tx": "5xGp7rWq2Tz9"}
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class PreflightError(RuntimeError):
    """The stack is not in a state the evaluation can run against."""


class NoLiveBundle(RuntimeError):
    """No anchored proof bundle could be taken from the live explorer."""


# ---------------------------------------------------------------------------------- config


@dataclass
class RunConfig:
    api: str = "http://127.0.0.1:7200"
    relay: str = "http://127.0.0.1:5557"
    relay_node: str = "iota-hornet"
    hornet: str = "http://127.0.0.1:14265"
    orion: str = "http://127.0.0.1:1026"
    anchor: str | None = "http://127.0.0.1:7300"
    out: str = "results"
    repo: str = "."
    trials: int | None = None  # None: as the answer key says (20)
    classes: list[str] | None = None
    seed: int = 1
    poll_s: float = 1.0
    parallel: int = 1
    trap: bool = True
    trap_minutes: float | None = None  # None: the answer key's duration_min
    trap_messages: int | None = None  # None: the answer key's min_messages
    trap_rate_per_min: float = 20.0
    trap_ies: int = 4
    trap_settle_s: float = 70.0
    controls: bool = True
    secrets_dir: str = "secrets"
    # Private JWK (with kid) of the run's own producer; `witness-chaos keys` writes it.
    # Default: <secrets_dir>/chaos/producer/sig-1.jwk.json. Never a live component's key.
    producer_key: str | None = None
    outsider_key: str | None = None  # private JWK with kid; default: a did:key from the seed
    revoked_key: str | None = None  # private JWK with the kid of a revoked method
    search_key_file: str | None = None
    ingest_via: str = "http"
    bundle_source: str = "auto"  # auto | api | vectors
    vectors_dir: str | None = None
    verify_cli: str | None = None
    node: str = "node"
    db_schema: str = "witness"
    orion_settle_s: float = 6.0
    drift_keepalive_s: float = 45.0
    wait_indexed_s: float = 30.0
    exclusive_window_s: float = 120.0
    allow_concurrent_producer: bool = False
    cleanup_orion: bool = True
    # Secrets: never written to run.json, never part of the config hash.
    ingest_token: str | None = field(default=None, repr=False)
    mqtt_url: str | None = field(default=None, repr=False)
    db_dsn: str | None = field(default=None, repr=False)

    SECRET_FIELDS = ("ingest_token", "mqtt_url", "db_dsn")

    def public(self) -> dict:
        d = dataclasses.asdict(self)
        for k in self.SECRET_FIELDS:
            d[k] = None if d[k] is None else "<set>"
        return d


def config_hash(cfg: RunConfig, key_text: str) -> str:
    """SHA-256 over the public configuration and the answer key text."""
    d = cfg.public()
    for k in cfg.SECRET_FIELDS:
        d.pop(k, None)
    d.pop("out", None)
    blob = json.dumps({"config": d, "answerKey": hashlib.sha256(key_text.encode()).hexdigest()},
                      sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


def git_info(repo: str) -> dict:
    def git(*args: str) -> str | None:
        try:
            out = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True,
                                 timeout=10, check=True)
        except (OSError, subprocess.SubprocessError):
            return None
        return out.stdout.strip()

    status = git("status", "--porcelain", "--untracked-files=no")
    return {"commit": git("rev-parse", "HEAD"), "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
            "dirty": None if status is None else bool(status)}


def read_search_key(path: str) -> bytes:
    """The relay's blind-index key file: base64url text (same format as the relay reads)."""
    text = Path(path).read_text(encoding="utf-8").strip()
    key = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if len(key) < 16:
        raise ValueError("search key must be at least 16 bytes")
    return key


def read_env_file(path: str) -> dict[str, str]:
    """KEY=VALUE lines (comments and blanks skipped, optional quotes removed)."""
    out: dict[str, str] = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
                v = v[1:-1]
            out[k.strip().removeprefix("export ").strip()] = v
    return out


# ---------------------------------------------------------------------------------- identities


def b58(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + s


def did_key_identity(key: Ed25519PrivateKey) -> Identity:
    """A did:key identity: resolvable by anyone, offline, and on no writer policy."""
    did = "did:key:z" + b58(b"\xed\x01" + key.public_key().public_bytes_raw())
    return Identity(did, f"{did}#{did[len('did:key:'):]}", key)


def seeded_key(seed: int, purpose: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(f"witness-chaos/{seed}/{purpose}".encode()).digest())


def identity_from_file(path: str) -> Identity:
    from witness_sdk.keys import load_key_file

    key, kid = load_key_file(path)
    if not kid:
        raise ValueError(f"{path}: the key file names no kid")
    return Identity(kid.partition("#")[0], kid, key)


def producer_key_path(cfg: RunConfig) -> str:
    return cfg.producer_key or str(Path(cfg.secrets_dir) / "chaos" / "producer" / "sig-1.jwk.json")


def private_jwk(key: Ed25519PrivateKey, kid: str) -> dict:
    def b64u(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    return {"kty": "OKP", "crv": "Ed25519", "kid": kid,
            "x": b64u(key.public_key().public_bytes_raw()), "d": b64u(key.private_bytes_raw())}


def eval_policy(base: dict, producer_did: str) -> dict:
    """The writer policy of a run: `base` with the run's producer allowed on trust.score."""
    out = json.loads(json.dumps(base))
    rule = out["tags"][attacks.TRUST_TAG]
    if producer_did not in rule["allowed"]:
        rule["allowed"] = [*rule["allowed"], producer_did]
    return out


def write_keys(out_dir: str, base_policy: str, *, force: bool = False) -> dict:
    """`witness-chaos keys`: a fresh did:key producer for the run (private JWK, 0600) and
    the eval policy that allows it on trust.score. Refuses to overwrite a key."""
    key_path = Path(out_dir) / "producer" / "sig-1.jwk.json"
    if key_path.exists() and not force:
        raise FileExistsError(f"{key_path} exists (use --force to replace it)")
    ident = did_key_identity(Ed25519PrivateKey.generate())
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if key_path.exists():
        key_path.unlink()
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(private_jwk(ident.key, ident.kid), f)
    policy_path = Path(out_dir) / "eval-policy.json"
    base = json.loads(Path(base_policy).read_text(encoding="utf-8"))
    policy_path.write_text(json.dumps(eval_policy(base, ident.iss), indent=2) + "\n",
                           encoding="utf-8")
    return {"producer": ident.iss, "key": str(key_path), "policy": str(policy_path)}


def live_dids(repo: str) -> set[str]:
    """Every DID the repository's identity files name (current and retired)."""
    out: set[str] = set()
    for f in (Path(repo) / "deploy" / "identity").glob("*.json"):
        with contextlib.suppress(OSError, ValueError):
            doc = json.loads(f.read_text(encoding="utf-8"))
            for i in [*doc.get("identities", []), *doc.get("previous", [])]:
                if isinstance(i, dict) and isinstance(i.get("did"), str):
                    out.add(i["did"])
    return out


# ---------------------------------------------------------------------------------- explorer API


class ExplorerApi:
    """The explorer endpoints the runner reads (camelCase JSON, as served)."""

    def __init__(self, base_url: str, http: httpx.AsyncClient) -> None:
        self.base = base_url.rstrip("/")
        self.http = http

    async def _get(self, path: str, params: dict | None = None) -> httpx.Response:
        return await self.http.get(self.base + path, params=params)

    async def json(self, path: str, params: dict | None = None) -> Any:
        resp = await self._get(path, params)
        resp.raise_for_status()
        return resp.json()

    async def message(self, block_id: str) -> dict | None:
        resp = await self._get(f"/messages/{block_id}")
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()

    async def alerts(self, *, block_id: str | None = None, ie: str | None = None,
                     since_ms: int | None = None, limit: int = 500) -> list[dict]:
        params: dict[str, Any] = {"limit": limit}
        if block_id:
            params["block_id"] = block_id
        if ie:
            params["ie"] = ie
        if since_ms is not None:
            params["since"] = str(int(since_ms))
        return list((await self.json("/alerts", params)).get("items", []))

    async def blind(self, tokens: list[str]) -> list[str]:
        resp = await self.http.post(self.base + "/lookup/blind", json={"tokens": tokens})
        resp.raise_for_status()
        return [m.get("blockId") for m in resp.json().get("matches", []) if m.get("blockId")]

    async def recent(self, *, tag: str, iss: str, limit: int = 20) -> list[dict]:
        page = await self.json("/messages", {"tag": tag, "iss": iss, "limit": limit})
        return list(page.get("items", []))


# ---------------------------------------------------------------------------------- observing


def alert_label(cls: dict, alert: dict) -> str:
    """The rule of an alert, or `RULE@severity` when it is the expected rule with another
    severity than the answer key pre-registered (then it is not the expected alert)."""
    rule = alert.get("rule") or "?"
    e = cls.get("expect", {})
    if rule == e.get("alert") and e.get("severity") and alert.get("severity") != e["severity"]:
        return f"{rule}@{alert.get('severity')}"
    return rule


def stored_envelope(msg: dict | None) -> Any:
    """The stored message as bytes on the Tangle, parsed (None when unreadable)."""
    if not msg or not isinstance(msg.get("dataHex"), str):
        return None
    try:
        return json.loads(bytes.fromhex(msg["dataHex"][2:]).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None


@dataclass
class Observation:
    verdict: str | None = None
    alerts: dict[int, dict] = field(default_factory=dict)  # alert id -> alert
    sealed: bool | None = None
    sealed_why: str | None = None
    blind_search: bool | None = None
    indexed: bool = False
    polls: int = 0
    detected: bool = False
    detected_at_ms: int | None = None
    errors: list[str] = field(default_factory=list)

    def labels(self, cls: dict) -> list[str]:
        rows = sorted(self.alerts.values(), key=lambda a: (a.get("atMs") or 0, a.get("id") or 0))
        return [alert_label(cls, a) for a in rows]

    def as_obs(self, cls: dict) -> dict:
        return {"verdict": self.verdict, "alerts": self.labels(cls), "sealed": self.sealed,
                "blind_search": self.blind_search}


async def snapshot(api: ExplorerApi, cls: dict, rec: InjectionRecord, o: Observation, *,
                   since_ms: int, by_ie: bool) -> None:
    """One poll: verdict of the injected block, alerts on it (and on the trial IE), and the
    A11 assertions."""
    e = cls.get("expect", {})
    msg = None
    if rec.block_id:
        msg = await api.message(rec.block_id)
        if msg is not None:
            o.indexed = bool(msg.get("indexed", True))
            o.verdict = msg.get("verdict")
        for a in await api.alerts(block_id=rec.block_id):
            o.alerts[a["id"]] = a
    if by_ie and rec.ie_id:
        for a in await api.alerts(ie=rec.ie_id, since_ms=since_ms):
            o.alerts[a["id"]] = a
    if e.get("sealed") and msg is not None:
        stored = stored_envelope(msg)
        if stored is not None:
            o.sealed, o.sealed_why = attacks.check_sealed(stored, rec.detail.get("plaintext", {}))
    if e.get("blind_search") and o.indexed and rec.detail.get("blindToken"):
        o.blind_search = attacks.check_blind_search(
            await api.blind([rec.detail["blindToken"]]), rec.block_id)


async def observe(api: ExplorerApi, cls: dict, rec: InjectionRecord, *, trial_start_ms: int,
                  timeout_s: float, poll_s: float, by_ie: bool, stop_on_detect: bool = True,
                  clock_ms: Callable[[], int], sleep: Callable[[float], Awaitable[None]],
                  keepalive: Callable[[], Awaitable[None]] | None = None,
                  keepalive_s: float = 0.0) -> Observation:
    """Poll until the class's expectation holds (or, without `stop_on_detect`, until the
    timeout), and no longer than `timeout_s` after the injection."""
    o = Observation()
    deadline = rec.injected_at_ms + int(timeout_s * 1000)
    next_keepalive = clock_ms() + int(keepalive_s * 1000) if keepalive else None
    while True:
        try:
            await snapshot(api, cls, rec, o, since_ms=trial_start_ms, by_ie=by_ie)
        except (httpx.HTTPError, ValueError) as exc:
            o.errors.append(f"{type(exc).__name__}: {exc}"[:200])
        o.polls += 1
        if not o.detected and scorecard.evaluate_trial(cls, o.as_obs(cls))["detected"]:
            o.detected, o.detected_at_ms = True, clock_ms()
        if (o.detected and stop_on_detect) or clock_ms() >= deadline:
            return o
        if next_keepalive is not None and clock_ms() >= next_keepalive:
            try:
                await keepalive()  # type: ignore[misc]
            except (httpx.HTTPError, ValueError) as exc:
                o.errors.append(f"keepalive {type(exc).__name__}: {exc}"[:200])
            next_keepalive = clock_ms() + int(keepalive_s * 1000)
        await sleep(max(0.0, min(poll_s, (deadline - clock_ms()) / 1000)))


def latency(cls: dict, rec: InjectionRecord, o: Observation) -> tuple[int | None, str | None]:
    """Insertion -> detection: the server's alert time for alert classes, else the poll
    that first saw the expected state (an upper bound, within one poll interval)."""
    if not o.detected:
        return None, None
    rule = cls["expect"].get("alert")
    if rule:
        times = [a.get("atMs") for a in o.alerts.values()
                 if alert_label(cls, a) == rule and a.get("atMs") is not None]
        if times:
            return max(0, min(times) - rec.injected_at_ms), "alert.atMs"
    return max(0, (o.detected_at_ms or rec.injected_at_ms) - rec.injected_at_ms), "poll"


def trial_row(cls: dict, t: int, rec: InjectionRecord | None, o: Observation | None, *,
              trial_start_ms: int, error: str | None = None) -> dict:
    """One line of trials.jsonl; also the scorecard's trial result."""
    row: dict[str, Any] = {"class": cls["id"], "trial": t, "startedAtMs": trial_start_ms}
    if error is not None:
        row.update(status="error", error=error, detected=False, observed=None)
        return row
    assert rec is not None and o is not None
    ev = scorecard.evaluate_trial(cls, o.as_obs(cls))
    lat, source = latency(cls, rec, o)
    row.update(
        status="ok", detected=ev["detected"], observed=ev["observed"], alerts=ev["alerts"],
        latency_ms=lat, latency_source=source, blockId=rec.block_id, ieId=rec.ie_id,
        injectedAtMs=rec.injected_at_ms, verdict=o.verdict, indexed=o.indexed,
        sealed=o.sealed, sealedWhy=o.sealed_why, blindSearch=o.blind_search, polls=o.polls,
        alertIds=sorted(o.alerts), alertRows=[
            {k: a.get(k) for k in ("id", "rule", "severity", "blockId", "ieId", "atMs")}
            for a in o.alerts.values()],
        detail={k: v for k, v in rec.detail.items() if k not in ("bundle", "plaintext")},
        pollErrors=o.errors[:5])
    return row


# ---------------------------------------------------------------------------------- bundles


def vector_bundle(vectors_dir: Path) -> tuple[dict, VerifierConfig, list[bytes]]:
    """A genuine bundle from the captured private-Tangle vectors (the one the chaos tests
    use), the matching verifier config and the public sample coordinator keys."""

    def vec(name: str) -> Any:
        return json.loads((vectors_dir / f"{name}.json").read_text(encoding="utf-8"))

    milestones, cones, blocks = vec("milestones"), vec("cones"), vec("blocks")
    keys = vec("coordinator_keys")
    raw_of = {b["blockId"]: b for b in blocks}
    ms, cone, bid = next(
        (ms, cone, bid)
        for ms, cone in zip(milestones, cones, strict=True)
        for bid in cone["blockIdsWhiteFlagOrder"]
        if bid in raw_of and raw_of[bid]["kind"] != "milestone")
    ids = [from_hex(m["milestoneId"]) for m in milestones]
    pos = milestones.index(ms)
    cp = checkpoint.build(
        VECTOR_NETWORK, "MyDomain",
        (milestones[0]["index"], ids[0]), (milestones[-1]["index"], ids[-1]),
        ids, 11, blake2b256(b"writer policy v1"), None)
    b = bundle.build(
        network=VECTOR_NETWORK,
        block_raw=from_hex(raw_of[bid]["raw"]),
        milestone_essence=from_hex(ms["essence"]),
        milestone_sigs=[Ed25519Sig(from_hex(s["pk"]), from_hex(s["sig"]))
                        for s in ms["signatures"]],
        cone_ids=[from_hex(i) for i in cone["blockIdsWhiteFlagOrder"]],
        envelope_check=None, did_doc_snapshot=None,
        anchor={"checkpoint": cp, "msPath": checkpoint.membership_path(ids, pos),
                "rebased": dict(VECTOR_REBASED)})
    cfg = VerifierConfig(
        network=VECTOR_NETWORK,
        trusted_coordinator_keys={from_hex(k) for k in keys["publicKeys"]},
        threshold=2, rebased_network="testnet", trail_id=VECTOR_TRAIL)
    return b, cfg, [from_hex(k) for k in keys["privateKeys"]]


async def live_bundle(api: ExplorerApi, http: httpx.AsyncClient, anchor_url: str | None
                      ) -> tuple[dict, VerifierConfig, dict, dict]:
    """(bundle, verifier config, on-chain record, info) for an anchored block of the live
    explorer. The record comes from the anchor service, which reads it on IOTA Rebased."""
    if not anchor_url:
        raise NoLiveBundle("no anchor service URL")
    c = await api.json("/config/verifier")
    if not c.get("trailId"):
        raise NoLiveBundle("the explorer pins no Audit Trail (trailId)")
    cfg = VerifierConfig(network=c["network"],
                         trusted_coordinator_keys={from_hex(k) for k in
                                                   c["trustedCoordinatorKeys"]},
                         threshold=int(c["threshold"]), rebased_network=c.get("rebasedNetwork"),
                         trail_id=c["trailId"])
    anchored = [a for a in (await api.json("/anchors")).get("items", [])
                if a.get("status") == "anchored"]
    if not anchored:
        raise NoLiveBundle("no anchored checkpoint yet")
    for a in anchored:
        page = await api.json("/messages", {"ms_from": a["fromMilestone"],
                                            "ms_to": a["toMilestone"], "limit": 20})
        for m in page.get("items", []):
            if m.get("msIndex") is None:
                continue
            resp = await api._get(f"/proofs/{m['blockId']}")
            if resp.status_code != 200:
                continue
            b = resp.json()
            if not b.get("anchor"):
                continue
            rec_resp = await http.get(f"{anchor_url.rstrip('/')}/checkpoints/{a['seq']}")
            if rec_resp.status_code != 200:
                raise NoLiveBundle(f"anchor service has no record for checkpoint {a['seq']} "
                                   f"(HTTP {rec_resp.status_code})")
            record = rec_resp.json()
            want = to_hex(checkpoint.hash(b["anchor"]["checkpoint"]))
            got = str(record.get("checkpointHash", "")).lower()
            if got != want:
                raise NoLiveBundle(f"on-chain record of checkpoint {a['seq']} does not match "
                                   "the bundle's checkpoint")
            return b, cfg, record, {"blockId": m["blockId"], "anchorSeq": a["seq"],
                                    "msIndex": m["msIndex"]}
    raise NoLiveBundle("no message of an anchored window has an anchored proof bundle")


def ts_config(cfg: VerifierConfig) -> dict:
    return {"network": cfg.network,
            "trustedCoordinatorKeys": sorted(to_hex(k) for k in cfg.trusted_coordinator_keys),
            "threshold": cfg.threshold, "rebasedNetwork": cfg.rebased_network,
            "trailId": cfg.trail_id}


def ts_verify(node: str, cli: Path, b: dict, cfg: dict, record: dict | None,
              timeout_s: float = 60.0) -> dict:
    """Run the TS verifier CLI on `b`; {"overall", "steps": {name: ok}, "ms"} or {"error"}."""
    with tempfile.TemporaryDirectory(prefix="witness-chaos-") as d:
        paths = {}
        for name, value in (("bundle", b), ("config", cfg), ("record", record)):
            p = Path(d) / f"{name}.json"
            p.write_text(json.dumps(value), encoding="utf-8")
            paths[name] = str(p)
        argv = [node, str(cli), paths["bundle"], "--config", paths["config"]]
        if record is not None:
            argv += ["--anchor-record", paths["record"]]
        t0 = time.perf_counter()
        try:
            out = subprocess.run(argv, capture_output=True, text=True, timeout=timeout_s,
                                 check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            return {"error": f"{type(exc).__name__}: {exc}"}
        ms = round((time.perf_counter() - t0) * 1000, 1)
    if out.returncode not in (0, 1, 2):
        return {"error": f"exit {out.returncode}: {out.stderr.strip()[:300]}", "ms": ms}
    try:
        ladder = json.loads(out.stdout)
    except ValueError:
        return {"error": f"unreadable output: {out.stdout[:200]!r}", "ms": ms}
    return {"overall": ladder.get("overall"),
            "steps": {s["name"]: s["ok"] for s in ladder.get("steps", [])},
            "details": {s["name"]: s.get("detail") for s in ladder.get("steps", [])}, "ms": ms}


def parity(py: dict, ts: dict) -> tuple[bool, list[str]]:
    """Do the Python and TS ladders agree on the overall result and on every step?"""
    if "error" in ts:
        return False, [f"TS verifier failed: {ts['error']}"]
    diffs = [f"{n}: py {py['steps'].get(n)!r} ts {ts['steps'].get(n)!r}"
             for n in bundle.STEP_NAMES if py["steps"].get(n) is not ts["steps"].get(n)]
    if py.get("overall") != ts.get("overall"):
        diffs.append(f"overall: py {py.get('overall')} ts {ts.get('overall')}")
    return not diffs, diffs


def py_ladder(b: dict, cfg: VerifierConfig, record: dict | None) -> dict:
    lad = bundle.verify(b, cfg, (lambda _a: record) if record is not None else None)
    return {"overall": lad.overall, "steps": {s.name: s.ok for s in lad.steps},
            "details": {s.name: s.detail for s in lad.steps}}


# ---------------------------------------------------------------------------------- trap


async def collect_trap(api: ExplorerApi, sent: list[traffic.Sent], ies: list[str], *,
                       start_ms: int, end_ms: int, window_end_ms: int,
                       concurrency: int = 8) -> tuple[dict, list[dict]]:
    """Score the trap: verdict of every block it put on the Tangle and every alert on those
    blocks or on the trap IEs raised before `window_end_ms`. Also returns one row per sent
    message for trap.jsonl."""
    on_tangle = [s for s in sent if s.block_id]
    sem = asyncio.Semaphore(concurrency)
    rows: list[dict] = []
    attributable: dict[int, dict] = {}

    async def one(s: traffic.Sent) -> None:
        async with sem:
            msg = await api.message(s.block_id)  # type: ignore[arg-type]
            alerts = await api.alerts(block_id=s.block_id)
        mine = [a for a in alerts if (a.get("atMs") or 0) <= window_end_ms]
        for a in mine:
            attributable[a["id"]] = a
        rows.append({**dataclasses.asdict(s), "verdict": None if msg is None else msg.get("verdict"),
                     "indexed": bool(msg and msg.get("indexed", True) and msg.get("verdict")),
                     "alerts": [a["rule"] for a in mine]})

    await asyncio.gather(*(one(s) for s in on_tangle))
    for ie in ies:
        for a in await api.alerts(ie=ie, since_ms=start_ms):
            if (a.get("atMs") or 0) <= window_end_ms:
                attributable[a["id"]] = a
    background = [a for a in await api.alerts(since_ms=start_ms)
                  if (a.get("atMs") or 0) <= window_end_ms]
    verdicts = Counter(r["verdict"] for r in rows if r["indexed"])
    trap = {
        "messages": len(on_tangle),
        "duration_s": round((end_ms - start_ms) / 1000, 1),
        "alerts": len(attributable),
        "verdicts": dict(verdicts),
        "not_indexed": sum(1 for r in rows if not r["indexed"]),
        "failed_sends": sum(1 for s in sent if not s.block_id),
        "alert_rules": dict(Counter(a["rule"] for a in attributable.values())),
        "alert_ids": sorted(attributable),
        "by_tag": dict(Counter(s.tag for s in on_tangle)),
        "window_end_ms": window_end_ms,
        # Every alert in the window, whatever it is about: context, not scored.
        "all_alerts_in_window": dict(Counter(a["rule"] for a in background)),
        "all_alerts_truncated": len(background) >= 500,
    }
    rows.sort(key=lambda r: r["n"])
    return trap, rows


# ---------------------------------------------------------------------------------- runner


@dataclass
class Trial:
    cls: dict
    t: int
    start_ms: int
    rec: InjectionRecord | None = None
    ies: tuple[str | None, str | None] = (None, None)
    error: str | None = None
    row: dict | None = None
    obs: Observation | None = None


class Runner:
    def __init__(self, cfg: RunConfig, *, http: httpx.AsyncClient | None = None,
                 clock_ms: Callable[[], int] | None = None,
                 sleep: Callable[[float], Awaitable[None]] | None = None) -> None:
        self.cfg = cfg
        self.key = attacks.answer_key()
        self.key_text = (Path(attacks.__file__).with_name("answer_key.yaml")
                         .read_text(encoding="utf-8"))
        self.http = http or httpx.AsyncClient(timeout=15.0)
        self.api = ExplorerApi(cfg.api, self.http)
        self.clock_ms = clock_ms or (lambda: int(time.time() * 1000))
        self.sleep = sleep or asyncio.sleep
        self.out = Path(cfg.out)
        self.rng_ies = random.Random(f"{cfg.seed}:ies")
        self.orion = traffic.OrionAdmin(cfg.orion, http=self.http)
        self.ctx: AttackContext | None = None
        self.registered: set[str] = set()
        self.not_run: list[dict] = []
        self.results: list[dict] = []
        self.controls: list[dict] = []
        self.trials: list[Trial] = []
        self.meta: dict = {}
        self.bundle_info: dict | None = None
        self._bundle_ready: bool | None = None
        self._ts_cfg: dict | None = None
        self._record: dict | None = None

    # -- setup ---------------------------------------------------------------------------

    def classes(self) -> list[dict]:
        if self.cfg.classes is None:
            return list(self.key["classes"])
        wanted = set(self.cfg.classes)
        return [c for c in self.key["classes"] if c["id"] in wanted]

    def n_trials(self, c: dict) -> int:
        return self.cfg.trials if self.cfg.trials is not None else int(c.get("trials", 20))

    def build_context(self) -> AttackContext:
        cfg = self.cfg
        rng = random.Random(cfg.seed)
        producer = identity_from_file(producer_key_path(cfg))
        outsider = (identity_from_file(cfg.outsider_key) if cfg.outsider_key
                    else did_key_identity(seeded_key(cfg.seed, "outsider")))
        revoked = identity_from_file(cfg.revoked_key) if cfg.revoked_key else None
        search_key = None
        if cfg.search_key_file:
            search_key = read_search_key(cfg.search_key_file)
        dsn = None
        if cfg.db_dsn:
            from psycopg.conninfo import make_conninfo

            dsn = make_conninfo(cfg.db_dsn, options=f"-c search_path={cfg.db_schema}")
        ctx = AttackContext(
            hornet_url=cfg.hornet, relay_url=cfg.relay, relay_node=cfg.relay_node,
            ingest_url=cfg.api.rstrip("/") + "/ingest", ingest_token=cfg.ingest_token,
            ingest_via=cfg.ingest_via, mqtt_url=cfg.mqtt_url, orion_url=cfg.orion,
            db_dsn=dsn, producer=producer, outsider=outsider, revoked=revoked,
            attacker_key=seeded_key(cfg.seed, "attacker"), search_key=search_key,
            http=self.http, rng=rng, clock_ms=self.clock_ms, live=True,
            on_trial=self._on_trial, wait_indexed=self._wait_indexed)
        self.meta["identities"] = {"producer": producer.iss, "outsider": outsider.iss,
                                   "revoked": None if revoked is None else revoked.iss}
        return ctx

    def _on_trial(self, ctx: AttackContext) -> None:
        """begin_trial hook: the trial IEs get the trial's score in Orion, as the Trust
        Manager writes it before uploading."""
        if ctx.ie_id in self.registered:
            self.orion.set_score_sync(ctx.ie_id, ctx.baseline_score)
        if ctx.stale_ie_id in self.registered:
            self.orion.set_score_sync(ctx.stale_ie_id, 0.5)

    async def _wait_indexed(self, block_id: str) -> None:
        deadline = self.clock_ms() + int(self.cfg.wait_indexed_s * 1000)
        while self.clock_ms() < deadline:
            try:
                msg = await self.api.message(block_id)
            except httpx.HTTPError:
                msg = None
            if msg is not None and msg.get("indexed", True) and msg.get("verdict"):
                return
            await self.sleep(self.cfg.poll_s)
        log.warning("block %s not indexed after %.0f s; sending the next block anyway",
                    block_id, self.cfg.wait_indexed_s)

    async def register_ies(self, n: int) -> tuple[list[str], list[str]]:
        ies = [attacks.random_ie_id(self.rng_ies) for _ in range(n)]
        stale = [attacks.random_ie_id(self.rng_ies) for _ in range(n)]
        await self.orion.upsert(ies + stale, 0.5)
        self.registered.update(ies + stale)
        await self.sleep(self.cfg.orion_settle_s)  # past the rules' Orion cache refresh
        return ies, stale

    async def cleanup_ies(self, *ids: str | None) -> None:
        if not self.cfg.cleanup_orion:
            return
        for ie in ids:
            if ie and ie in self.registered:
                with contextlib.suppress(httpx.HTTPError):
                    await self.orion.delete(ie)
                self.registered.discard(ie)

    # -- preflight -------------------------------------------------------------------------

    async def preflight(self) -> dict:
        cfg = self.cfg
        report: dict[str, Any] = {}

        async def probe(name: str, url: str, required: bool) -> Any:
            try:
                resp = await self.http.get(url)
                ok = resp.status_code == 200
                body = resp.json() if ok and "json" in resp.headers.get("content-type", "") \
                    else None
            except (httpx.HTTPError, ValueError) as exc:
                ok, body = False, f"{type(exc).__name__}: {exc}"
            report[name] = {"ok": ok, "url": url}
            if required and not ok:
                raise PreflightError(f"{name} at {url} does not answer: {body}")
            return body

        health = await probe("api", cfg.api.rstrip("/") + "/healthz", True)
        report["api"]["health"] = health
        relay = await probe("relay", cfg.relay.rstrip("/") + "/healthz", True)
        report["relay"]["did"] = relay.get("relay") if isinstance(relay, dict) else None
        await probe("hornet", cfg.hornet.rstrip("/") + "/api/core/v2/info", True)
        await probe("orion", cfg.orion.rstrip("/") + "/ngsi-ld/ex/v1/version", False)
        with contextlib.suppress(httpx.HTTPError, ValueError):
            report["stats"] = await self.api.json("/stats")
        return report

    async def check_identity(self, iss: str) -> dict:
        """The producer is the run's own: no live component's DID, and the stack's writer
        policy (as the API reports it) allows it on trust.score."""
        live = live_dids(self.cfg.repo)
        ident = await self.api.json("/identity")
        anchor = ident.get("anchor") or {}
        for i in [*(anchor.get("identities") or []), *(anchor.get("previous") or [])]:
            if isinstance(i, dict) and isinstance(i.get("did"), str):
                live.add(i["did"])
        if iss in live:
            raise PreflightError(
                f"the producer {iss} is a live component's DID; the run signs with its own "
                "key (`witness-chaos keys`), never a live one")
        rule = ((ident.get("policy") or {}).get("tags") or {}).get(attacks.TRUST_TAG) or {}
        allowed = rule.get("allowed") or []
        if iss not in allowed and "*" not in allowed:
            raise PreflightError(
                f"the stack's writer policy does not allow {iss} on trust.score; run the stack "
                "with the eval policy `witness-chaos keys` wrote (WITNESS_POLICY_FILE)")
        return {"producer": iss, "policyHash": (ident.get("policy") or {}).get("hash"),
                "trustScoreWriters": allowed}

    async def check_exclusive(self, iss: str) -> dict:
        """Nobody else may be signing as the producer while the harness does."""
        now = self.clock_ms()
        recent = [m for m in await self.api.recent(tag=attacks.TRUST_TAG, iss=iss)
                  if (m.get("dateMs") or 0) >= now - self.cfg.exclusive_window_s * 1000]
        info = {"recentProducerBlocks": len(recent),
                "latest": recent[0].get("blockId") if recent else None}
        if recent and not self.cfg.allow_concurrent_producer:
            raise PreflightError(
                f"{len(recent)} trust.score block(s) signed as {iss} in the last "
                f"{self.cfg.exclusive_window_s:.0f} s (latest {info['latest']}): another "
                "producer (trust-manager-witness?) signs with the harness's key. Stop it for "
                "the run, or pass --allow-concurrent-producer and expect chain alerts.")
        return info

    # -- trap ------------------------------------------------------------------------------

    async def run_trap(self) -> dict:
        cfg, spec = self.cfg, self.key["traps"]
        minutes = cfg.trap_minutes if cfg.trap_minutes is not None else spec["duration_min"]
        messages = cfg.trap_messages if cfg.trap_messages is not None else spec["min_messages"]
        from witness_sdk.signer import WitnessSigner

        rng = random.Random(f"{cfg.seed}:trap")
        ies = traffic.trap_ie_ids(rng, cfg.trap_ies)
        await self.orion.upsert(ies, None)
        plan = traffic.TrafficPlan(rng, ies)
        for ie in ies:
            await self.orion.set_score(ie, plan.scores[ie])
        await self.sleep(cfg.orion_settle_s)
        self.out.mkdir(parents=True, exist_ok=True)
        state = self.out / "trap-signer-state.json"
        traffic.seed_signer_state(str(state), self.clock_ms())
        key_path = producer_key_path(cfg)
        producer = self.ctx.producer  # type: ignore[union-attr]
        signer = WitnessSigner(producer.iss, producer.kid, key_path, str(state))
        log_path = self.out / "trap-sent.jsonl"
        log_file = log_path.open("w", encoding="utf-8")

        def on_sent(s: traffic.Sent) -> None:
            log_file.write(json.dumps(dataclasses.asdict(s)) + "\n")
            log_file.flush()
            if s.error:
                log.warning("trap message %d (%s) failed: %s", s.n, s.tag, s.error)

        gen = traffic.TrafficGenerator(
            relay_url=cfg.relay, relay_node=cfg.relay_node, plan=plan,
            upload_score=traffic.sdk_uploader(
                signer, str(self.out / "trap-disclosures.jsonl")),
            orion=self.orion, http=self.http, rate_per_min=cfg.trap_rate_per_min,
            clock_ms=self.clock_ms, sleep=self.sleep, on_sent=on_sent)
        start = self.clock_ms()
        log.info("trap: genuine traffic for %.1f min / %d messages at %.0f/min", minutes,
                 messages, cfg.trap_rate_per_min)
        try:
            sent = await gen.run(duration_s=minutes * 60, min_messages=messages)
        finally:
            log_file.close()
        end = self.clock_ms()
        log.info("trap: %d sent; settling %.0f s before scoring", len(sent), cfg.trap_settle_s)
        await self.sleep(cfg.trap_settle_s)
        trap, rows = await collect_trap(self.api, sent, ies, start_ms=start, end_ms=end,
                                        window_end_ms=self.clock_ms())
        trap["ies"] = ies
        trap["profile"] = {"minutes": minutes, "messages": messages,
                           "ratePerMin": cfg.trap_rate_per_min}
        with (self.out / "trap.jsonl").open("w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        if cfg.cleanup_orion:
            for ie in ies:
                with contextlib.suppress(httpx.HTTPError):
                    await self.orion.delete(ie)
        return trap

    # -- attacks ---------------------------------------------------------------------------

    def missing_setup(self, c: dict) -> str | None:
        """Why a class cannot run with this configuration, or None."""
        cid, ctx = c["id"], self.ctx
        assert ctx is not None
        if cid == "A05" and ctx.revoked is None:
            return "no revoked identity configured (--revoked-key)"
        if cid == "A11" and ctx.search_key is None:
            return "no blind-index search key (--search-key-file)"
        if cid == "A19" and not ctx.db_dsn:
            return "no database DSN (--db-dsn / WITNESS_CHAOS_DB)"
        if cid in ("A16", "A18"):
            if ctx.ingest_via in ("http", "both") and not ctx.ingest_token:
                return "no ingest token (--ingest-token / WITNESS_INGEST_TOKEN)"
            if ctx.ingest_via in ("mqtt", "both") and not ctx.mqtt_url:
                return "no MQTT URL (--mqtt)"
        if c.get("channel") == OFFLINE and self._bundle_ready is False:
            return f"no usable genuine bundle ({(self.bundle_info or {}).get('error')})"
        return None

    async def prepare_bundles(self) -> None:
        """Pick the genuine bundle the offline classes tamper with and check that both
        verifiers accept it (steps 1-3 and 5 green)."""
        if self._bundle_ready is not None:
            return
        cfg, ctx = self.cfg, self.ctx
        assert ctx is not None
        vectors = Path(cfg.vectors_dir) if cfg.vectors_dir else \
            Path(cfg.repo) / "core" / "tests" / "vectors"
        info: dict[str, Any] = {"requested": cfg.bundle_source}
        b = None
        if cfg.bundle_source in ("auto", "api"):
            try:
                b, vcfg, record, extra = await live_bundle(self.api, self.http, cfg.anchor)
                info.update(source="api", **extra)
            except (NoLiveBundle, httpx.HTTPError, ValueError, KeyError) as exc:
                info["apiError"] = f"{type(exc).__name__}: {exc}"
                if cfg.bundle_source == "api":
                    self.bundle_info, self._bundle_ready = {**info, "error": info["apiError"]}, False
                    return
        _, _, sample_keys = vector_bundle(vectors)
        if b is None:
            b, vcfg, _ = vector_bundle(vectors)
            record = forge.real_anchor_record(b)
            info["source"] = "vectors"
        ctx.real_bundle, ctx.verifier, ctx.sample_private_keys = b, vcfg, sample_keys
        ctx.anchor_fetch = lambda _anchor: record
        self._record, self._ts_cfg = record, ts_config(vcfg)
        py = py_ladder(b, vcfg, record)
        ts = await asyncio.to_thread(ts_verify, cfg.node, self.verify_cli(), b, self._ts_cfg,
                                     record)
        same, diffs = parity(py, ts)
        green = all(py["steps"][n] is True for n in
                    ("block_hash", "inclusion", "milestone_signatures", "anchor"))
        info.update(baseline={"py": py["steps"], "pyOverall": py["overall"],
                              "ts": ts.get("steps"), "tsOverall": ts.get("overall"),
                              "parity": same, "diffs": diffs})
        if not green or not same:
            info["error"] = ("baseline bundle not green" if not green
                             else f"verifiers disagree on the baseline: {diffs}")
        self.bundle_info, self._bundle_ready = info, green and same

    def verify_cli(self) -> Path:
        return Path(self.cfg.verify_cli) if self.cfg.verify_cli else \
            Path(self.cfg.repo) / "packages" / "verify" / "dist" / "cli.js"

    async def bundle_trial(self, c: dict, t: int) -> dict:
        ctx = self.ctx
        assert ctx is not None
        start = self.clock_ms()
        fn = getattr(attacks, c["inject"])
        try:
            rec = await fn(ctx)
        except Exception as exc:  # noqa: BLE001 - a harness failure, recorded as such
            return trial_row(c, t, None, None, trial_start_ms=start,
                             error=f"{type(exc).__name__}: {exc}")
        t0 = time.perf_counter()
        py = {"overall": rec.detail["overall"], "steps": rec.detail["steps"]}
        ts = await asyncio.to_thread(ts_verify, self.cfg.node, self.verify_cli(),
                                     rec.detail["bundle"], self._ts_cfg or {}, self._record)
        same, diffs = parity(py, ts)
        obs = {"ladder": py["steps"], "overall": py["overall"], "parses": rec.detail.get("parses")}
        ev = scorecard.evaluate_trial(c, obs)
        detected = ev["detected"] and same
        return {"class": c["id"], "trial": t, "startedAtMs": start, "status": "ok",
                "detected": detected,
                "observed": ev["observed"] if same else "PARITY_MISMATCH",
                "alerts": [], "latency_ms": None, "blockId": rec.block_id,
                "injectedAtMs": rec.injected_at_ms, "py": py, "ts": ts, "parity": same,
                "parityDiffs": diffs, "parses": rec.detail.get("parses"),
                "pyDetails": rec.detail.get("details"),
                "verifyMs": round((time.perf_counter() - t0) * 1000, 1)}

    async def inject(self, c: dict, t: int, fn: Callable[[AttackContext], Awaitable[Any]]
                     ) -> Trial:
        ctx = self.ctx
        assert ctx is not None
        trial = Trial(c, t, self.clock_ms())
        try:
            trial.rec = await fn(ctx)
        except Exception as exc:  # noqa: BLE001 - a harness failure, recorded as such
            trial.error = f"{type(exc).__name__}: {exc}"[:500]
            log.warning("%s trial %d: injection failed: %s", c["id"], t, trial.error)
        trial.ies = (ctx.ie_id, ctx.stale_ie_id) if c["id"] in NEEDS_ORION else (None, None)
        return trial

    def _keepalive(self, c: dict, trial: Trial) -> Callable[[], Awaitable[None]] | None:
        """A06 waits minutes for DRIFT; meanwhile the producer keeps scoring the IE with the
        same (ledger) score, as the Trust Manager would, so the IE does not go STALE."""
        if c["expect"].get("alert") != "DRIFT" or self.cfg.drift_keepalive_s <= 0:
            return None
        rec, ctx = trial.rec, self.ctx
        assert rec is not None and ctx is not None
        score = rec.detail.get("ledgerScore")
        if score is None or rec.ie_id is None:
            return None

        async def again() -> None:
            env = attacks.seal_as(ctx.need("producer"), ctx, attacks.score_body(rec.ie_id, score))
            await attacks._post_relay(ctx, attacks.TRUST_TAG, env)

        return again

    async def observe_trial(self, c: dict, trial: Trial, *, control: bool = False) -> None:
        if trial.error is not None or trial.rec is None:
            error = trial.error or "no injection record"
            if control:  # a control that could not run fails the run, it is not skipped
                trial.row = {"control": c["id"], "trial": trial.t, "status": "error",
                             "startedAtMs": trial.start_ms, "error": error, "passed": False}
            else:
                trial.row = trial_row(c, trial.t, None, None, trial_start_ms=trial.start_ms,
                                      error=error)
            return
        by_ie = bool(c.get("per_trial_ie")) or control
        o = await observe(self.api, c, trial.rec, trial_start_ms=trial.start_ms,
                          timeout_s=float(c.get("timeout_s", 15)), poll_s=self.cfg.poll_s,
                          by_ie=by_ie, stop_on_detect=not control, clock_ms=self.clock_ms,
                          sleep=self.sleep, keepalive=self._keepalive(c, trial),
                          keepalive_s=self.cfg.drift_keepalive_s)
        trial.obs = o
        if control:
            row = {"control": c["id"], "trial": trial.t, "startedAtMs": trial.start_ms,
                   "status": "ok", "blockId": trial.rec.block_id, "ieId": trial.rec.ie_id,
                   "verdict": o.verdict, "indexed": o.indexed, "alerts": o.labels(c),
                   "alertIds": sorted(o.alerts), "detail": trial.rec.detail, "polls": o.polls}
            row["passed"], row["why"] = scorecard.control_row_passed(c, row)
            trial.row = row
        else:
            trial.row = trial_row(c, trial.t, trial.rec, o, trial_start_ms=trial.start_ms)
        await self.cleanup_ies(*trial.ies)

    async def run_class(self, c: dict, *, control: bool = False,
                        emit: Callable[[dict], None]) -> None:
        n = self.n_trials(c)
        why = None if control else self.missing_setup(c)
        if why is None and c.get("channel") == OFFLINE:
            await self.prepare_bundles()
            why = self.missing_setup(c)
        if why is not None:
            log.warning("%s: not run (%s)", c["id"], why)
            self.not_run.append({"class": c["id"], "trials": n, "reason": why})
            return
        log.info("%s %s: %d trial(s)", c["id"], c.get("name"), n)
        if c.get("channel") == OFFLINE:
            for t in range(n):
                emit(await self.bundle_trial(c, t))
            return
        fn = attacks.CONTROLS[c["id"]] if control else getattr(attacks, c["inject"])
        concurrent = self.cfg.parallel if (c.get("per_trial_ie") or control) else 1
        if c["id"] in NEEDS_ORION:
            ies, stale = await self.register_ies(n)
            assert self.ctx is not None
            self.ctx.ie_pool, self.ctx.stale_pool = ies, stale
        for lo in range(0, n, max(1, concurrent)):
            batch = [await self.inject(c, t, fn) for t in range(lo, min(n, lo + concurrent))]
            await asyncio.gather(*(self.observe_trial(c, tr, control=control) for tr in batch))
            for tr in batch:
                self.trials.append(tr)
                emit(tr.row or {})

    async def restore_tampered(self) -> list[str]:
        """Undo A19 once the run is over: the bit flip is its own inverse. The alerts it
        raised stay."""
        ctx = self.ctx
        if ctx is None or not ctx.tampered or not ctx.db_dsn:
            return []
        import psycopg

        done = []
        async with await psycopg.AsyncConnection.connect(ctx.db_dsn, autocommit=True) as conn:
            for bid in ctx.tampered:
                await conn.execute(attacks.TAMPER_SQL, (bid,))
                done.append(to_hex(bid))
        ctx.tampered.clear()
        return done

    async def late_sweep(self) -> dict[str, dict[str, int]]:
        """Alerts on injected blocks (and trial IEs) that arrived after their trial ended:
        reported per class, not scored."""
        late: dict[str, Counter] = {}
        for tr in self.trials:
            if tr.rec is None or tr.obs is None or tr.row is None:
                continue
            by_ie = bool(tr.cls.get("per_trial_ie")) or "control" in tr.row
            seen = set(tr.obs.alerts)
            rows: dict[int, dict] = {}
            with contextlib.suppress(httpx.HTTPError, ValueError):
                if tr.rec.block_id:
                    for a in await self.api.alerts(block_id=tr.rec.block_id):
                        rows[a["id"]] = a
                if by_ie and tr.rec.ie_id:
                    for a in await self.api.alerts(ie=tr.rec.ie_id, since_ms=tr.start_ms):
                        rows[a["id"]] = a
            new = [alert_label(tr.cls, a) for i, a in rows.items() if i not in seen]
            tr.row["lateAlerts"] = new
            late.setdefault(tr.cls["id"], Counter()).update(new)
        return {k: dict(v) for k, v in late.items() if v}

    # -- whole run -------------------------------------------------------------------------

    async def run(self) -> dict:
        cfg = self.cfg
        self.out.mkdir(parents=True, exist_ok=True)
        started = self.clock_ms()
        self.meta.update(schema="witness-chaos/run/v1", startedAtMs=started,
                         git=git_info(cfg.repo), configHash=config_hash(cfg, self.key_text),
                         answerKeySha256=hashlib.sha256(self.key_text.encode()).hexdigest(),
                         config=cfg.public(), python=sys.version.split()[0])
        self.meta["preflight"] = await self.preflight()
        self.ctx = self.build_context()
        producer = self.ctx.producer
        assert producer is not None
        self.meta["identity"] = await self.check_identity(producer.iss)
        self.meta["exclusive"] = await self.check_exclusive(producer.iss)
        self._write_meta()
        trap = None
        if cfg.trap:
            trap = await self.run_trap()
            (self.out / "trap.json").write_text(json.dumps(trap, indent=2), encoding="utf-8")
        trials_log = (self.out / "trials.jsonl").open("w", encoding="utf-8")

        def emit(row: dict) -> None:
            trials_log.write(json.dumps(row, default=str) + "\n")
            trials_log.flush()
            if "class" in row:
                self.results.append(row)
            else:
                self.controls.append(row)

        try:
            for c in self.classes():
                await self.run_class(c, emit=emit)
            if cfg.controls:
                for ctl in self.key.get("controls", []):
                    await self.run_class(ctl, control=True, emit=emit)
        finally:
            trials_log.close()
        late = await self.late_sweep()
        self.meta["restored"] = await self.restore_tampered()
        self._rewrite_trials()
        self.meta["finishedAtMs"] = self.clock_ms()
        self.meta["bundles"] = self.bundle_info
        self._write_meta()
        card = self.scorecard(trap, late)
        return card

    def scorecard(self, trap: dict | None, late: dict | None = None) -> dict:
        return write_scorecard(self.out, self.key, self.results, trap, self.controls,
                               self.not_run, self.meta, late or {})

    def _write_meta(self) -> None:
        (self.out / "run.json").write_text(json.dumps(self.meta, indent=2, default=str),
                                           encoding="utf-8")

    def _rewrite_trials(self) -> None:
        with (self.out / "trials.jsonl").open("w", encoding="utf-8") as f:
            for row in [*self.results, *self.controls]:
                f.write(json.dumps(row, default=str) + "\n")

    async def aclose(self) -> None:
        await self.orion.aclose()
        await self.http.aclose()


# ---------------------------------------------------------------------------------- scorecard


def scored_rows(results: Iterable[dict]) -> tuple[list[dict], list[dict]]:
    """(trials that ran, not-run entries for trials whose injection failed)."""
    ran, failed = [], Counter()
    errors: dict[str, str] = {}
    for r in results:
        if r.get("status") == "error":
            failed[r["class"]] += 1
            errors.setdefault(r["class"], r.get("error") or "")
        else:
            ran.append(r)
    skipped = [{"class": k, "trials": n, "reason": f"injection failed: {errors[k]}"}
               for k, n in failed.items()]
    return ran, skipped


def write_scorecard(out: Path, key: dict, results: list[dict], trap: dict | None,
                    controls: list[dict], not_run: list[dict], meta: dict,
                    late: dict) -> dict:
    ran, failed = scored_rows(results)
    card = scorecard.build_scorecard(ran, trap, key, controls or None, [*not_run, *failed])
    parity_rows = [r for r in ran if "parity" in r]
    card["parity"] = {"bundleTrials": len(parity_rows),
                      "agreed": sum(1 for r in parity_rows if r["parity"]),
                      "bundleSource": (meta.get("bundles") or {}).get("source")}
    card["late_alerts"] = late
    card["run"] = {k: meta.get(k) for k in ("git", "configHash", "answerKeySha256",
                                            "startedAtMs", "finishedAtMs")}
    card["run"]["trialsPerClass"] = (meta.get("config") or {}).get("trials")
    md = scorecard.render_markdown(card)
    extra = ["", (f"Bundle classes: {card['parity']['agreed']}/"
                  f"{card['parity']['bundleTrials']} trials where core `bundle.verify` and "
                  "the TS verifier CLI agreed on every step (genuine bundle: "
                  f"{card['parity']['bundleSource']}).")]
    if late:
        extra += ["", "Alerts that arrived after a trial ended (not scored):", ""]
        extra += [f"- {k}: " + ", ".join(f"{r} x{n}" for r, n in sorted(v.items()))
                  for k, v in sorted(late.items())]
    run = card["run"]
    git = run.get("git") or {}
    dirty = " (dirty)" if git.get("dirty") else ""
    extra += ["", (f"Commit {git.get('commit')}{dirty}, config "
                   f"{str(run.get('configHash'))[:16]}, answer key "
                   f"{str(run.get('answerKeySha256'))[:16]}.")]
    md += "\n".join(extra) + "\n"
    out.mkdir(parents=True, exist_ok=True)
    (out / "scorecard.json").write_text(json.dumps(card, indent=2, default=str),
                                        encoding="utf-8")
    (out / "scorecard.md").write_text(md, encoding="utf-8")
    return card


def rescore(out: Path) -> dict:
    """Rebuild the scorecard from a results directory."""
    key = attacks.answer_key()
    rows = [json.loads(line) for line in (out / "trials.jsonl").read_text(encoding="utf-8")
            .splitlines() if line.strip()]
    meta = json.loads((out / "run.json").read_text(encoding="utf-8"))
    trap_path = out / "trap.json"
    trap = json.loads(trap_path.read_text(encoding="utf-8")) if trap_path.exists() else None
    old = out / "scorecard.json"
    previous = json.loads(old.read_text(encoding="utf-8")) if old.exists() else {}
    late: dict[str, Counter] = {}
    for r in rows:
        if r.get("lateAlerts") and "class" in r:
            late.setdefault(r["class"], Counter()).update(r["lateAlerts"])
    not_run = [s for s in previous.get("not_run", [])
               if not str(s.get("reason", "")).startswith("injection failed")]
    return write_scorecard(out, key, [r for r in rows if "class" in r], trap,
                           [r for r in rows if "control" in r], not_run, meta,
                           {k: dict(v) for k, v in late.items()})


# ---------------------------------------------------------------------------------- CLI


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="witness-chaos", description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("run", "trap"):
        r = sub.add_parser(name, help="run the evaluation" if name == "run"
                           else "genuine traffic only (the trap), then score it")
        r.add_argument("--api", default=RunConfig.api)
        r.add_argument("--relay", default=RunConfig.relay)
        r.add_argument("--relay-node", default=RunConfig.relay_node)
        r.add_argument("--hornet", default=RunConfig.hornet)
        r.add_argument("--orion", default=RunConfig.orion)
        r.add_argument("--anchor", default=RunConfig.anchor,
                       help="anchor service (on-chain checkpoint records); empty: none")
        r.add_argument("--out", default="results")
        r.add_argument("--repo", default=".", help="repository root (git commit, vectors, "
                                                   "TS verifier)")
        r.add_argument("--seed", type=int, default=1)
        r.add_argument("--poll-s", type=float, default=1.0)
        r.add_argument("--secrets-dir", default="secrets")
        r.add_argument("--producer-key",
                       help="private JWK of the run's producer (default: "
                            "<secrets-dir>/chaos/producer/sig-1.jwk.json, see `keys`)")
        r.add_argument("--env-file", action="append", default=[],
                       help="KEY=VALUE file read for WITNESS_INGEST_TOKEN, WITNESS_CHAOS_MQTT, "
                            "WITNESS_CHAOS_DB (repeatable; the process environment wins)")
        r.add_argument("--trap-minutes", type=float)
        r.add_argument("--trap-messages", type=int)
        r.add_argument("--trap-rate", type=float, default=20.0, help="messages per minute")
        r.add_argument("--trap-settle-s", type=float, default=70.0)
        r.add_argument("--allow-concurrent-producer", action="store_true")
        r.add_argument("--keep-orion", action="store_true",
                       help="leave the harness's IEs in Orion")
        r.add_argument("-v", "--verbose", action="store_true")
        if name == "run":
            r.add_argument("--trials", type=int, help="trials per class (default: the answer "
                                                      "key's, 20)")
            r.add_argument("--classes", help="comma-separated class ids (default: all)")
            r.add_argument("--no-trap", action="store_true")
            r.add_argument("--no-controls", action="store_true")
            r.add_argument("--parallel", type=int, default=1,
                           help="observe up to N trials of a per-trial-IE class at once")
            r.add_argument("--outsider-key")
            r.add_argument("--revoked-key")
            r.add_argument("--search-key-file")
            r.add_argument("--ingest-via", choices=attacks.INGEST_ROUTES, default=None)
            r.add_argument("--ingest-token")
            r.add_argument("--mqtt", help="broker URL for forged submission records "
                                          "(default: $WITNESS_CHAOS_MQTT, else RELAY_MQTT_URL "
                                          "from an --env-file)")
            r.add_argument("--mqtt-host", help="replace the broker URL's host (host[:port])")
            r.add_argument("--db-dsn")
            r.add_argument("--db-schema", default="witness")
            r.add_argument("--bundle-source", choices=("auto", "api", "vectors"),
                           default="auto")
            r.add_argument("--vectors-dir")
            r.add_argument("--verify-cli")
            r.add_argument("--node", default="node")
            r.add_argument("--drift-keepalive-s", type=float, default=45.0)
    s = sub.add_parser("score", help="rebuild the scorecard from a results directory")
    s.add_argument("out")
    k = sub.add_parser("keys", help="create the run's own producer key and eval policy")
    k.add_argument("--out", default="secrets/chaos")
    k.add_argument("--base-policy", default=str(Path(__file__).resolve().parents[2]
                                               / "demo-policy.json"))
    k.add_argument("--force", action="store_true")
    return p


def with_host(url: str, host: str) -> str:
    """`url` with its host (and port, when given as host:port) replaced, credentials kept:
    the relay's broker URL names the broker by its compose service name."""
    parts = urlsplit(url)
    creds = parts.netloc.rpartition("@")[0]
    netloc = host if ":" in host or parts.port is None else f"{host}:{parts.port}"
    return urlunsplit(parts._replace(netloc=f"{creds}@{netloc}" if creds else netloc))


def config_from_args(a: argparse.Namespace, environ: dict[str, str] | None = None) -> RunConfig:
    env: dict[str, str] = {}
    for path in a.env_file:
        env.update(read_env_file(path))
    env.update(os.environ if environ is None else environ)
    run = a.cmd == "run"

    def opt(name: str, var: str) -> str | None:
        value = getattr(a, name, None)
        return value or env.get(var) or None

    mqtt = opt("mqtt", "WITNESS_CHAOS_MQTT") or env.get("RELAY_MQTT_URL") or None
    if mqtt and getattr(a, "mqtt_host", None):
        mqtt = with_host(mqtt, a.mqtt_host)
    token = opt("ingest_token", "WITNESS_INGEST_TOKEN")
    via = getattr(a, "ingest_via", None) or ("both" if mqtt and token else
                                             "mqtt" if mqtt else "http")
    return RunConfig(
        api=a.api, relay=a.relay, relay_node=a.relay_node, hornet=a.hornet, orion=a.orion,
        anchor=a.anchor or None, out=a.out, repo=a.repo, seed=a.seed, poll_s=a.poll_s,
        secrets_dir=a.secrets_dir, producer_key=a.producer_key,
        trap=not getattr(a, "no_trap", False), trap_minutes=a.trap_minutes,
        trap_messages=a.trap_messages, trap_rate_per_min=a.trap_rate,
        trap_settle_s=a.trap_settle_s, allow_concurrent_producer=a.allow_concurrent_producer,
        cleanup_orion=not a.keep_orion,
        trials=getattr(a, "trials", None),
        classes=[c.strip() for c in a.classes.split(",")] if getattr(a, "classes", None)
        else ([] if not run else None),
        controls=run and not getattr(a, "no_controls", False),
        parallel=getattr(a, "parallel", 1), outsider_key=getattr(a, "outsider_key", None),
        revoked_key=getattr(a, "revoked_key", None),
        search_key_file=getattr(a, "search_key_file", None), ingest_via=via,
        ingest_token=token, mqtt_url=mqtt, db_dsn=opt("db_dsn", "WITNESS_CHAOS_DB"),
        db_schema=getattr(a, "db_schema", "witness"),
        bundle_source=getattr(a, "bundle_source", "auto"),
        vectors_dir=getattr(a, "vectors_dir", None), verify_cli=getattr(a, "verify_cli", None),
        node=getattr(a, "node", "node"),
        drift_keepalive_s=getattr(a, "drift_keepalive_s", 45.0))


async def amain(cfg: RunConfig) -> dict:
    runner = Runner(cfg)
    try:
        return await runner.run()
    finally:
        await runner.aclose()


def main(argv: list[str] | None = None) -> int:
    a = _parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if getattr(a, "verbose", False) else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    if a.cmd == "score":
        card = rescore(Path(a.out))
        print(card["headline"])
        return 0 if card["valid"] else 1
    if a.cmd == "keys":
        try:
            made = write_keys(a.out, a.base_policy, force=a.force)
        except FileExistsError as exc:
            print(f"witness-chaos: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(made, indent=2))
        print("Run the stack with WITNESS_POLICY_FILE pointing at this policy for the "
              "evaluation only.", file=sys.stderr)
        return 0
    cfg = config_from_args(a)
    # psycopg's async driver and aiomqtt need a selector loop; Windows defaults to proactor.
    factory = asyncio.SelectorEventLoop if sys.platform == "win32" else None
    try:
        with asyncio.Runner(loop_factory=factory) as r:
            card = r.run(amain(cfg))
    except PreflightError as exc:
        print(f"witness-chaos: preflight failed: {exc}", file=sys.stderr)
        return 2
    print(card["headline"])
    if a.cmd == "run" and not card["valid"]:
        return 1  # the positive control failed or did not run: no number may be quoted
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
