from __future__ import annotations

from typing import Any

import httpx

from .errors import APIError, ConfigurationError, ConnectionError

VERSION = "0.1.0"


class HTTP:
    """JSON over HTTP. Pass `transport` (an httpx transport) to test or proxy."""

    def __init__(self, base_url: str, *, timeout: float = 10.0, retries: int = 1,
                 transport: httpx.BaseTransport | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self._retries = retries
        self._client = httpx.Client(timeout=timeout, transport=transport)

    def request(self, method: str, path: str, *, bearer: str | None = None, headers: dict[str, str] | None = None,
                public: bool = False, body: Any = None, idempotent: bool | None = None) -> Any:
        extra = dict(headers or {})
        if not bearer and not extra and not public:
            raise ConfigurationError("No credentials for this Scute call")
        sent = {"Accept": "application/json", "User-Agent": f"scute-python/{VERSION}", **extra}
        if bearer:
            sent["Authorization"] = f"Bearer {bearer}"
        idempotent = method.upper() == "GET" if idempotent is None else idempotent

        attempts = 0
        while True:
            try:
                res = self._client.request(method.upper(), f"{self.base_url}{path}", headers=sent,
                                           json=body if body is not None else None)
                break
            except httpx.TransportError as e:
                attempts += 1
                if idempotent and attempts <= self._retries:
                    continue
                raise ConnectionError(f"Couldn't reach Scute: {type(e).__name__}: {e}") from e

        data: Any = None
        if res.content:
            try:
                data = res.json()
            except ValueError:
                data = None
        if 200 <= res.status_code < 300:
            return data
        info = data if isinstance(data, dict) else {}
        raise APIError(info.get("error") or info.get("say") or f"Scute answered {res.status_code}",
                       status=res.status_code, code=info.get("error_code"), body=data)

    def close(self) -> None:
        self._client.close()
