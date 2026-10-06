"""Read-only client for the aeriOS Orion-LD context broker (NGSI-LD).

The Trust Manager writes each Infrastructure Element's score to Orion (`trustScore`) and,
through Witness, to the Tangle. The rules engine compares the two (R5 DRIFT) and checks that
scored IEs exist in Orion (R6 UNKNOWN_IE). Orion entity ids look like
`urn:ngsi-ld:InfrastructureElement:<domain>:<id>`; the Trust Manager's ledger ids are
`<domain>:<id>`, so the prefix is stripped to line the two up.

An Orion that cannot be asked raises `OrionUnavailable`; it is never reported as an empty
entity list, which would make every IE look unknown.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Literal

import httpx

ENTITY_TYPE = "InfrastructureElement"
IE_URN = f"urn:ngsi-ld:{ENTITY_TYPE}:"
ENTITIES_PATH = "/ngsi-ld/v1/entities"
MAX_PAGES = 1000


class OrionUnavailable(Exception):
    """Orion could not be asked, or answered with something that is not an entity list."""


@dataclass(frozen=True)
class IE:
    entity_id: str
    ie_id: str
    domain: str
    trust_score: float | None


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


def _ie(e: Any) -> IE | None:
    if not isinstance(e, dict) or not isinstance(e.get("id"), str) or not e["id"]:
        return None
    ie_id = ie_id_of(e["id"])
    return IE(e["id"], ie_id, ie_id.split(":", 1)[0] if ":" in ie_id else "",
              _score(e.get("trustScore")))


class OrionClient:
    def __init__(self, base_url: str, timeout_s: float = 2.0, *, context_url: str | None = None,
                 page_size: int = 1000, http: httpx.AsyncClient | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self._context_url = context_url
        self._page_size = page_size
        self._http = http

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self._context_url:
            headers["Link"] = (f'<{self._context_url}>; rel="http://www.w3.org/ns/json-ld#context"; '
                               f'type="application/ld+json"')
        return headers

    async def _page(self, offset: int, limit: int) -> list:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=self.timeout_s)
        params = {"type": ENTITY_TYPE, "limit": str(limit), "offset": str(offset)}
        try:
            resp = await self._http.get(self.base_url + ENTITIES_PATH, params=params,
                                        headers=self._headers(), timeout=self.timeout_s)
        except httpx.HTTPError as exc:
            raise OrionUnavailable(f"Orion unreachable: {exc}") from exc
        if resp.status_code != 200:
            raise OrionUnavailable(f"Orion answered HTTP {resp.status_code}")
        try:
            body = resp.json()
        except ValueError as exc:
            raise OrionUnavailable("Orion sent no JSON") from exc
        if not isinstance(body, list):
            raise OrionUnavailable("Orion reply is not an entity list")
        return body

    async def ie_entities(self) -> list[IE]:
        """Every InfrastructureElement entity, all pages. Raises OrionUnavailable."""
        out: list[IE] = []
        for page in range(MAX_PAGES):
            batch = await self._page(page * self._page_size, self._page_size)
            out.extend(ie for ie in map(_ie, batch) if ie is not None)
            if len(batch) < self._page_size:
                return out
        raise OrionUnavailable(f"more than {MAX_PAGES} pages of {ENTITY_TYPE} entities")

    async def status(self) -> Literal["ok", "unreachable"]:
        try:
            await self._page(0, 1)
        except OrionUnavailable:
            return "unreachable"
        return "ok"

    async def aclose(self) -> None:
        if self._http is not None:
            await self._http.aclose()
