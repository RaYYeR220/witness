"""Thin async client for the HORNET core REST API (v2) used by the validator.

Only the two endpoints the brief names: `GET /api/core/v2/blocks/{id}` (JSON, or the raw
serialized block with `Accept: application/vnd.iota.serializer-v1`) and
`GET /api/core/v2/blocks/{id}/metadata`. A 404 is an answer ("the node does not know this
block") and comes back as None; anything that is not an answer raises HornetUnavailable.
"""

from __future__ import annotations

import httpx

RAW_MEDIA_TYPE = "application/vnd.iota.serializer-v1"
BLOCKS_PATH = "/api/core/v2/blocks"


class HornetUnavailable(Exception):
    """The node could not be asked: network error, timeout, 5xx or an unreadable answer."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


def block_path(block_id: bytes) -> str:
    if len(block_id) != 32:
        raise ValueError(f"block id must be 32 bytes, got {len(block_id)}")
    return f"{BLOCKS_PATH}/0x{block_id.hex()}"


class HornetRest:
    def __init__(self, base_url: str, timeout_s: float = 5.0, *,
                 client: httpx.AsyncClient | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = client or httpx.AsyncClient(timeout=timeout_s)
        self._owns_client = client is None

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def _get(self, path: str, accept: str) -> httpx.Response | None:
        url = self.base_url + path
        try:
            resp = await self._client.get(url, headers={"Accept": accept})
        except httpx.HTTPError as e:
            raise HornetUnavailable(f"GET {url}: {type(e).__name__}: {e}") from e
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            raise HornetUnavailable(
                f"GET {url}: HTTP {resp.status_code} {resp.text[:200]}", resp.status_code)
        return resp

    async def _get_json(self, path: str) -> dict | None:
        resp = await self._get(path, "application/json")
        if resp is None:
            return None
        try:
            body = resp.json()
        except ValueError as e:
            raise HornetUnavailable(f"GET {path}: response is not JSON", resp.status_code) from e
        if not isinstance(body, dict):
            raise HornetUnavailable(f"GET {path}: expected a JSON object", resp.status_code)
        return body

    async def block(self, block_id: bytes) -> dict | None:
        """The block as HORNET renders it in JSON."""
        return await self._get_json(block_path(block_id))

    async def block_raw(self, block_id: bytes) -> bytes | None:
        """The block exactly as serialized on the Tangle; its BLAKE2b-256 is the block id.

        A 200 that is not the binary serialization (an HTML page from a proxy, JSON from a
        node ignoring Accept) is not an answer about the block: HornetUnavailable.
        """
        resp = await self._get(block_path(block_id), RAW_MEDIA_TYPE)
        if resp is None:
            return None
        media = resp.headers.get("content-type", "").split(";")[0].strip().lower()
        if media != RAW_MEDIA_TYPE:
            raise HornetUnavailable(
                f"GET {block_path(block_id)}: expected {RAW_MEDIA_TYPE}, got {media or 'none'}",
                resp.status_code)
        return resp.content

    async def block_metadata(self, block_id: bytes) -> dict | None:
        """Solidity and confirmation state: isSolid, referencedByMilestoneIndex, ..."""
        return await self._get_json(block_path(block_id) + "/metadata")
