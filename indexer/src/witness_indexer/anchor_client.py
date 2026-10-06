"""Client for the anchor service's checkpoint records on IOTA Rebased.

`GET {base}/checkpoints/{seq}` answers `{seq, checkpoint, checkpointHash, tx, record,
network}` as read from the Audit Trail on Rebased, never from the private-Tangle mirror
(`witness.anchor` messages). That record is the reference R11 ANCHOR_MISMATCH compares the
indexed milestones against.
"""

from __future__ import annotations

import httpx


class AnchorUnavailable(Exception):
    """The anchor service could not be asked, or did not answer about the checkpoint."""


class AnchorClient:
    def __init__(self, base_url: str, timeout_s: float = 2.0, *,
                 http: httpx.AsyncClient | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self._http = http

    async def checkpoint(self, seq: int) -> dict | None:
        """The on-chain record of checkpoint `seq`; None when there is none (yet)."""
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=self.timeout_s)
        try:
            resp = await self._http.get(f"{self.base_url}/checkpoints/{int(seq)}",
                                        timeout=self.timeout_s)
        except httpx.HTTPError as exc:
            raise AnchorUnavailable(f"anchor service unreachable: {exc}") from exc
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            raise AnchorUnavailable(f"anchor service answered HTTP {resp.status_code}")
        try:
            body = resp.json()
        except ValueError as exc:
            raise AnchorUnavailable("anchor service sent no JSON") from exc
        if not isinstance(body, dict) or not isinstance(body.get("checkpoint"), dict):
            raise AnchorUnavailable(f"anchor reply for checkpoint {seq} carries no checkpoint")
        return body

    async def aclose(self) -> None:
        if self._http is not None:
            await self._http.aclose()
