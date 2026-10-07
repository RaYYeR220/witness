"""Genuine traffic for the trap runs: what the patched Trust Manager and the LLOs send.

- `trust.score`: signed with the trust-manager key by the SDK's `WitnessSigner`, the code the
  patched Trust Manager runs, so every message carries `prev` (the block id of the signer's
  previous upload) and salted commitments to its rel/sec/rep sub-scores. As the Trust
  Manager does, the score is written to Orion's `trustScore` first, then uploaded. Scores
  move by small steps and every trap IE is scored at least once a minute.
- `LLO-K8s` / `LLO-Docker`: legacy, unsigned deployment events (never "failed"), which the
  relay attests.
- `self-orchestrator`: legacy status reports with `errorCode` 0 about the trap IEs. On the
  relay's pass-through list they stay unsigned (UNSIGNED_LEGACY), otherwise the relay
  attests them.

Everything goes through the witness relay (`POST /upload`). The trap IEs live in their own
domain and are registered in Orion without `internalIpAddress`, so the stock Trust Manager,
which only scores entities that have one, leaves them alone. Nothing here is an attack: the
pre-registered expectation is zero alerts and only the verdicts of the answer key's `traps`.
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import time
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass, field
from typing import Any

import httpx

TRUST_TAG = "trust.score"
LLO_TAGS = ("LLO-K8s", "LLO-Docker")
SELF_ORCH_TAG = "self-orchestrator"
IE_TYPE = "InfrastructureElement"
IE_URN = "urn:ngsi-ld:InfrastructureElement:"
ENTITIES = "/ngsi-ld/v1/entities"
UPSERT = "/ngsi-ld/v1/entityOperations/upsert/"
CORE_CONTEXT = ('<https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld>; '
                'rel="http://www.w3.org/ns/json-ld#context"; type="application/ld+json"')

# Share of each kind of message in the trap traffic.
MIX: tuple[tuple[str, float], ...] = (
    (TRUST_TAG, 0.5), ("LLO-K8s", 0.2), ("LLO-Docker", 0.15), (SELF_ORCH_TAG, 0.15))
LLO_EVENTS = ("Service component deployed", "Service component running",
              "Service component scaled", "Service component updated")
MAX_STEP = 0.03  # a genuine score moves slowly; the ANOMALY threshold is 0.3
SCORE_EVERY_MS = 30_000  # longest gap between two scores of one trap IE


# ---------------------------------------------------------------------------------------- Orion


def ie_urn(ie_id: str) -> str:
    return IE_URN + ie_id


def ie_entity(ie_id: str, score: float | None) -> dict:
    """An InfrastructureElement as the trap registers it: no internalIpAddress, so the
    stock Trust Manager does not score it."""
    e: dict[str, Any] = {"id": ie_urn(ie_id), "type": IE_TYPE}
    if score is not None:
        e["trustScore"] = {"type": "Property", "value": score}
    return e


class OrionAdmin:
    """The few Orion-LD writes the harness makes about its own IEs."""

    def __init__(self, base_url: str, *, http: httpx.AsyncClient | None = None,
                 sync_http: httpx.Client | None = None, timeout_s: float = 5.0) -> None:
        self.base_url = base_url.rstrip("/")
        self._http = http
        self._sync = sync_http
        self._timeout = timeout_s

    def _a(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=self._timeout)
        return self._http

    def _s(self) -> httpx.Client:
        if self._sync is None:
            self._sync = httpx.Client(timeout=self._timeout)
        return self._sync

    @staticmethod
    def _headers() -> dict[str, str]:
        return {"Content-Type": "application/json", "Link": CORE_CONTEXT}

    async def upsert(self, ie_ids: list[str], score: float | None = 0.5) -> None:
        if not ie_ids:
            return
        resp = await self._a().post(self.base_url + UPSERT, headers=self._headers(),
                                    content=json.dumps([ie_entity(i, score) for i in ie_ids]))
        resp.raise_for_status()

    async def set_score(self, ie_id: str, score: float) -> None:
        resp = await self._a().patch(
            f"{self.base_url}{ENTITIES}/{ie_urn(ie_id)}/attrs", headers=self._headers(),
            content=json.dumps({"trustScore": {"type": "Property", "value": score}}))
        resp.raise_for_status()

    def set_score_sync(self, ie_id: str, score: float) -> None:
        resp = self._s().patch(
            f"{self.base_url}{ENTITIES}/{ie_urn(ie_id)}/attrs", headers=self._headers(),
            content=json.dumps({"trustScore": {"type": "Property", "value": score}}))
        resp.raise_for_status()

    async def delete(self, ie_id: str) -> bool:
        resp = await self._a().delete(f"{self.base_url}{ENTITIES}/{ie_urn(ie_id)}")
        if resp.status_code == 404:
            return False
        resp.raise_for_status()
        return True

    async def aclose(self) -> None:
        if self._http is not None:
            await self._http.aclose()
        if self._sync is not None:
            self._sync.close()


# ---------------------------------------------------------------------------------------- plan


@dataclass
class Planned:
    """One message of the trap, decided before it is sent."""

    tag: str
    message: dict
    ie_id: str | None = None
    commitments: dict | None = None


@dataclass
class Sent:
    """What happened to one trap message."""

    n: int
    tag: str
    ie_id: str | None
    at_ms: int
    http_status: int | None
    block_id: str | None
    relay_verdict: str | None
    error: str | None = None


def trap_ie_ids(rng: random.Random, n: int, domain: str = "TrapDomain") -> list[str]:
    return [f"{domain}:{rng.getrandbits(48):012x}" for _ in range(n)]


@dataclass
class TrafficPlan:
    """Deterministic message plan: same seed, same messages (nonces and times aside)."""

    rng: random.Random
    ies: list[str]
    scores: dict[str, float] = field(default_factory=dict)
    _next_ie: int = 0
    components: tuple[str, ...] = ("frontend", "api", "broker", "worker")

    def __post_init__(self) -> None:
        for ie in self.ies:
            self.scores.setdefault(ie, round(self.rng.uniform(0.55, 0.85), 4))

    def _tag(self) -> str:
        x = self.rng.random()
        acc = 0.0
        for tag, share in MIX:
            acc += share
            if x < acc:
                return tag
        return MIX[-1][0]

    def score_message(self) -> Planned:
        ie = self.ies[self._next_ie % len(self.ies)]
        self._next_ie += 1
        step = self.rng.uniform(-MAX_STEP, MAX_STEP)
        score = round(min(0.95, max(0.05, self.scores[ie] + step)), 4)
        self.scores[ie] = score
        # Plausible sub-scores; only their salted commitments leave the producer.
        commitments = {k: round(min(1.0, max(0.0, score + self.rng.uniform(-0.1, 0.1))), 4)
                       for k in ("rel", "sec", "rep")}
        return Planned(TRUST_TAG, {"score": score, "id": ie}, ie, commitments)

    def next(self, *, score_due: bool = False) -> Planned:
        tag = TRUST_TAG if score_due else self._tag()
        if tag == TRUST_TAG:
            return self.score_message()
        if tag in LLO_TAGS:
            llo = "llo-k8s-1" if tag == "LLO-K8s" else "llo-docker-1"
            comp = self.rng.choice(self.components)
            return Planned(tag, {"event": self.rng.choice(LLO_EVENTS), "lloId": llo,
                                 "serviceComponentId":
                                     f"urn:ngsi-ld:ServiceComponent:TrapDomain:{comp}"})
        ie = self.rng.choice(self.ies)
        return Planned(SELF_ORCH_TAG, {"infrastructureElementId": ie_urn(ie), "errorCode": 0,
                                       "status": "running"}, ie)


# ---------------------------------------------------------------------------------------- sending


ScoreUploader = Callable[[str, str, str, dict, dict | None], dict]


def seed_signer_state(state_path: str, seq: int) -> None:
    """Start the signer's chain at `seq` (epoch ms): above any seq the producer DID has
    used, so the relay's first answer is not a REPLAY refusal, and with no `prev`."""
    os.makedirs(os.path.dirname(os.path.abspath(state_path)), exist_ok=True)
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump({"seq": seq, "prev": None}, f)


class TrafficGenerator:
    """Sends the planned trap traffic through the relay at a steady rate."""

    def __init__(
        self,
        *,
        relay_url: str,
        relay_node: str,
        plan: TrafficPlan,
        upload_score: ScoreUploader,
        orion: OrionAdmin | None,
        http: httpx.AsyncClient,
        rate_per_min: float = 20.0,
        relay_token: str | None = None,
        clock_ms: Callable[[], int] = lambda: int(time.time() * 1000),
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        on_sent: Callable[[Sent], None] | None = None,
    ) -> None:
        if rate_per_min <= 0:
            raise ValueError("rate_per_min must be positive")
        self.relay_url = relay_url.rstrip("/")
        self.relay_node = relay_node
        self.plan = plan
        self.upload_score = upload_score
        self.orion = orion
        self.http = http
        self.interval_s = 60.0 / rate_per_min
        self.relay_token = relay_token
        self.clock_ms = clock_ms
        self.sleep = sleep
        self.on_sent = on_sent
        self.sent: list[Sent] = []
        self._last_score_ms: dict[str, int] = {}

    def _score_due(self, now_ms: int) -> bool:
        """True when some IE has gone SCORE_EVERY_MS without a score: every IE stays well
        inside the STALE threshold (2 x 60 s), as with a Trust Manager scoring every minute,
        and still does so for a while after the traffic stops (the trap's settle time)."""
        return any(now_ms - self._last_score_ms.get(ie, now_ms) > SCORE_EVERY_MS
                   for ie in self.plan.ies)

    async def _legacy(self, p: Planned) -> tuple[int, dict]:
        headers = {"Content-Type": "application/json"}
        if self.relay_token:
            headers["Authorization"] = f"Bearer {self.relay_token}"
        resp = await self.http.post(f"{self.relay_url}/upload",
                                    params={"node": self.relay_node},
                                    json={"tag": p.tag, "message": p.message}, headers=headers)
        try:
            body = resp.json()
        except ValueError:
            body = {"error": resp.text[:200]}
        return resp.status_code, body if isinstance(body, dict) else {"error": body}

    async def send(self, n: int, p: Planned) -> Sent:
        at = self.clock_ms()
        try:
            if p.tag == TRUST_TAG:
                if self.orion is not None and p.ie_id is not None:
                    await self.orion.set_score(p.ie_id, p.message["score"])
                reply = await asyncio.to_thread(
                    self.upload_score, self.relay_url, self.relay_node, p.tag, p.message,
                    p.commitments)
                status = reply.get("http_status")
                self._last_score_ms[p.ie_id or ""] = at
            else:
                status, reply = await self._legacy(p)
        except (httpx.HTTPError, OSError) as exc:
            s = Sent(n, p.tag, p.ie_id, at, None, None, None, f"{type(exc).__name__}: {exc}")
        else:
            w = reply.get("witness") or {}
            err = None if status == 200 else str(reply.get("error") or reply)[:300]
            s = Sent(n, p.tag, p.ie_id, at, status, w.get("blockId"), w.get("verdict"), err)
        self.sent.append(s)
        if self.on_sent is not None:
            self.on_sent(s)
        return s

    async def run(self, *, duration_s: float, min_messages: int,
                  max_messages: int | None = None) -> list[Sent]:
        """Send until at least `duration_s` have passed and `min_messages` were sent."""
        start = self.clock_ms()
        for ie in self.plan.ies:
            self._last_score_ms.setdefault(ie, start - 60_000)  # score every IE early on
        n = 0
        while True:
            now = self.clock_ms()
            if (now - start >= duration_s * 1000 and n >= min_messages) or \
                    (max_messages is not None and n >= max_messages):
                return self.sent
            await self.send(n, self.plan.next(score_due=self._score_due(now)))
            n += 1
            spent = (self.clock_ms() - now) / 1000
            await self.sleep(max(0.0, self.interval_s - spent))


def sdk_uploader(signer: Any, disclosures_path: str | None = None) -> ScoreUploader:
    """Adapt `witness_sdk.signer.WitnessSigner.upload` to the generator."""

    def upload(relay_url: str, node: str, tag: str, body: dict,
               commitments: dict | None) -> dict:
        return signer.upload(relay_url, node, tag, body, commitments,
                             disclosures_path=disclosures_path, meta={"id": body.get("id")})

    return upload


def sent_rows(sent: list[Sent]) -> list[dict]:
    return [asdict(s) for s in sent]
