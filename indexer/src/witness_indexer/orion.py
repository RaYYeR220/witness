"""Read-only client for the aeriOS Orion-LD context broker (NGSI-LD).

The Trust Manager writes each Infrastructure Element's score to Orion (`trustScore`) and,
through Witness, to the Tangle. The rules engine compares the two (R5 DRIFT) and checks that
scored IEs exist in Orion (R6 UNKNOWN_IE). Orion entity ids look like
`urn:ngsi-ld:InfrastructureElement:<domain>:<id>`; the Trust Manager's ledger ids are
`<domain>:<id>`, so the prefix is stripped to line the two up. ServiceComponent entities name
the IE they were allocated to (`infrastructureElement`), which lets the incident engine tie
an LLO report about a component to the IE it runs on.

An Orion that cannot be asked raises `OrionUnavailable`; it is never reported as an empty
entity list, which would make every IE look unknown. So does a listing larger than
`max_reply_bytes` (all pages together): it is read as a stream and abandoned at the limit.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx

ENTITY_TYPE = "InfrastructureElement"
COMPONENT_TYPE = "ServiceComponent"
IE_URN = f"urn:ngsi-ld:{ENTITY_TYPE}:"
ENTITIES_PATH = "/ngsi-ld/v1/entities"
MAX_PAGES = 1000
MAX_REPLY_BYTES = 16 * 1024 * 1024


class OrionUnavailable(Exception):
    """Orion could not be asked, or answered with something that is not an entity list."""


class _Missing:
    def __repr__(self) -> str:
        return "<missing>"


MISSING: Any = _Missing()  # an entity without a trustScore attribute


@dataclass(frozen=True)
class IE:
    entity_id: str
    ie_id: str
    domain: str
    trust_score: float | None
    # The `trustScore` attribute as Orion sent it (MISSING when absent), for evidence when it
    # cannot be read as a number.
    raw_trust_score: Any = field(default=MISSING, compare=False, repr=False)


def ie_id_of(entity_id: str) -> str:
    """`urn:ngsi-ld:InfrastructureElement:<domain>:<id>` -> `<domain>:<id>`."""
    if entity_id.startswith(IE_URN) and len(entity_id) > len(IE_URN):
        return entity_id[len(IE_URN):]
    return entity_id


def _score(attr: Any) -> float | None:
    """`trustScore` in normalized (`{"type": "Property", "value": x}`) or keyValues form."""
    value = attr.get("value") if isinstance(attr, dict) else attr
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    value = float(value)
    return value if math.isfinite(value) else None


def _relationship(attr: Any) -> str | None:
    """A relationship target in keyValues (`"urn:..."`) or normalized form
    (`{"type": "Relationship", "object": "urn:..."}`); an embedded entity gives its id."""
    if isinstance(attr, dict):
        attr = attr.get("object", attr.get("value", attr.get("id")))
        if isinstance(attr, dict):
            attr = attr.get("id")
    return attr if isinstance(attr, str) and attr else None


def _ie(e: Any) -> IE | None:
    if not isinstance(e, dict) or not isinstance(e.get("id"), str) or not e["id"]:
        return None
    ie_id = ie_id_of(e["id"])
    raw = e.get("trustScore", MISSING)
    return IE(e["id"], ie_id, ie_id.split(":", 1)[0] if ":" in ie_id else "",
              _score(None if raw is MISSING else raw), raw)


class OrionClient:
    def __init__(self, base_url: str, timeout_s: float = 2.0, *, context_url: str | None = None,
                 page_size: int = 1000, http: httpx.AsyncClient | None = None,
                 max_reply_bytes: int = MAX_REPLY_BYTES) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self._context_url = context_url
        self._page_size = page_size
        self._http = http
        self._max_reply_bytes = max_reply_bytes

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self._context_url:
            headers["Link"] = (f'<{self._context_url}>; rel="http://www.w3.org/ns/json-ld#context"; '
                               f'type="application/ld+json"')
        return headers

    async def _page(self, offset: int, limit: int, type_: str = ENTITY_TYPE,
                    budget: int | None = None) -> tuple[list, int]:
        """One page of entities and its size in bytes; more than `budget` bytes is an error."""
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=self.timeout_s)
        budget = self._max_reply_bytes if budget is None else budget
        params = {"type": type_, "limit": str(limit), "offset": str(offset)}
        buf = bytearray()
        try:
            async with self._http.stream("GET", self.base_url + ENTITIES_PATH, params=params,
                                         headers=self._headers(),
                                         timeout=self.timeout_s) as resp:
                if resp.status_code != 200:
                    raise OrionUnavailable(f"Orion answered HTTP {resp.status_code}")
                async for chunk in resp.aiter_bytes():
                    buf += chunk
                    if len(buf) > budget:
                        raise OrionUnavailable(
                            f"Orion {type_} listing larger than {self._max_reply_bytes} bytes")
        except httpx.HTTPError as exc:
            raise OrionUnavailable(f"Orion unreachable: {exc}") from exc
        try:
            body = json.loads(bytes(buf))
        except (ValueError, RecursionError) as exc:
            raise OrionUnavailable("Orion sent no JSON") from exc
        if not isinstance(body, list):
            raise OrionUnavailable("Orion reply is not an entity list")
        return body, len(buf)

    async def _all(self, type_: str, max_bytes: int | None = None) -> list:
        out: list = []
        budget = self._max_reply_bytes if max_bytes is None else max_bytes
        for page in range(MAX_PAGES):
            batch, size = await self._page(page * self._page_size, self._page_size, type_,
                                           budget)
            budget -= size
            out.extend(batch)
            if len(batch) < self._page_size:
                return out
        raise OrionUnavailable(f"more than {MAX_PAGES} pages of {type_} entities")

    async def ie_entities(self, *, max_bytes: int | None = None) -> list[IE]:
        """Every InfrastructureElement entity, all pages. Raises OrionUnavailable."""
        return [ie for ie in map(_ie, await self._all(ENTITY_TYPE, max_bytes))
                if ie is not None]

    async def service_component_hosts(self, *, max_bytes: int | None = None) -> dict[str, str]:
        """ServiceComponent entity id -> id of the IE it is allocated to (`<domain>:<id>`),
        for every component that names one. Raises OrionUnavailable."""
        out: dict[str, str] = {}
        for e in await self._all(COMPONENT_TYPE, max_bytes):
            if not isinstance(e, dict) or not isinstance(e.get("id"), str) or not e["id"]:
                continue
            host = _relationship(e.get("infrastructureElement"))
            if host:
                out[e["id"]] = ie_id_of(host)
        return out

    async def status(self) -> Literal["ok", "unreachable"]:
        try:
            await self._page(0, 1)
        except OrionUnavailable:
            return "unreachable"
        return "ok"

    async def aclose(self) -> None:
        if self._http is not None:
            await self._http.aclose()
