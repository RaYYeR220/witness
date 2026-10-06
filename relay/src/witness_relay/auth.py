"""Caller identity for legacy (unsigned) uploads: the `sub` of a Keycloak access token.

No `Authorization: Bearer` header, or no JWKS configured, means `anonymous`. A bearer
token that is present but does not verify is an error, never a silent downgrade.
"""

from __future__ import annotations

import time

import httpx
import jwt

ANONYMOUS = "anonymous"


class AuthError(Exception):
    """The presented bearer token is not acceptable."""


class AuthUnavailable(AuthError):
    """The JWKS could not be fetched, so no token can be checked right now."""


class CallerAuth:
    def __init__(
        self,
        jwks_url: str | None,
        http: httpx.AsyncClient,
        *,
        audience: str | None = None,
        issuer: str | None = None,
        cache_ttl_s: float = 300.0,
        min_refresh_s: float = 10.0,
    ):
        self._url = jwks_url
        self._http = http
        self._audience = audience
        self._issuer = issuer
        self._ttl = cache_ttl_s
        self._min_refresh = min_refresh_s
        self._keys: dict[str | None, jwt.PyJWK] = {}
        self._fetched_at = float("-inf")

    async def caller(self, authorization: str | None) -> str:
        if not self._url or not authorization:
            return ANONYMOUS
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer":
            return ANONYMOUS
        token = token.strip()
        if not token:
            raise AuthError("empty bearer token")
        try:
            kid = jwt.get_unverified_header(token).get("kid")
        except jwt.PyJWTError as exc:
            raise AuthError(f"malformed bearer token: {exc}") from exc
        key = await self._key(kid)
        if key is None:
            raise AuthError("bearer token signed by an unknown key")
        try:
            claims = jwt.decode(
                token,
                key.key,
                algorithms=[key.algorithm_name],
                audience=self._audience,
                issuer=self._issuer,
                options={"require": ["exp", "sub"], "verify_aud": self._audience is not None},
            )
        except jwt.PyJWTError as exc:
            raise AuthError(f"invalid bearer token: {exc}") from exc
        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub:
            raise AuthError("bearer token has no subject")
        return sub

    async def _key(self, kid: str | None) -> jwt.PyJWK | None:
        now = time.monotonic()
        stale = now - self._fetched_at > self._ttl
        unknown = self._lookup(kid) is None and now - self._fetched_at > self._min_refresh
        if stale or unknown:
            await self._refresh()
        return self._lookup(kid)

    def _lookup(self, kid: str | None) -> jwt.PyJWK | None:
        if kid is None and len(self._keys) == 1:
            return next(iter(self._keys.values()))
        return self._keys.get(kid)

    async def _refresh(self) -> None:
        try:
            resp = await self._http.get(self._url, timeout=5.0)
            resp.raise_for_status()
            entries = resp.json().get("keys", [])
        except (httpx.HTTPError, ValueError, AttributeError) as exc:
            raise AuthUnavailable(f"cannot fetch JWKS: {exc}") from exc
        keys: dict[str | None, jwt.PyJWK] = {}
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("use", "sig") != "sig":
                continue
            try:
                key = jwt.PyJWK(entry)
            except jwt.PyJWTError:
                continue  # unsupported algorithm or key type
            if key.algorithm_name.startswith("HS") or key.algorithm_name == "none":
                continue  # only asymmetric signatures
            keys[entry.get("kid")] = key
        self._keys = keys
        self._fetched_at = time.monotonic()
