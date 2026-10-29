from __future__ import annotations

import copy
import os
from typing import Any
from urllib.parse import quote

import httpx

from ._client_ip import HEADER as CLIENT_IP_HEADER
from ._client_ip import client_ip_argument
from ._http import HTTP
from .agents import Agents
from .authz import Authz
from .errors import ConfigurationError
from .sessions import Sessions
from .tokens import Tokens
from .users import Users


class Scute:
    """Your backend's handle on Scute, with the app's secret key.

        scute = Scute()  # SCUTE_APP_ID, SCUTE_SECRET, SCUTE_BASE_URL
        session = scute.tokens.verify(token)
        scute.authz.check(user_id=session.user_id, action="refund", resource="invoice:42").allowed

    `client_ip` is the address of the person the calls are made for. Calls with
    the secret key send it as X-Scute-Client-IP, so Scute checks server-started
    sign-ins against the workspace's IP rules and records it on sessions and
    audit events. Per request, use `scute.with_client_ip(ip)`.
    """

    def __init__(self, app_id: str | None = None, secret: str | None = None, base_url: str | None = None, *,
                 timeout: float = 10.0, transport: httpx.BaseTransport | None = None,
                 client_ip: str | None = None) -> None:
        app_id = app_id or os.environ.get("SCUTE_APP_ID")
        if not app_id:
            raise ConfigurationError("Scute needs an app id: pass app_id or set SCUTE_APP_ID")
        self.app_id = str(app_id)
        self._secret = secret or os.environ.get("SCUTE_SECRET")
        self._client_ip = client_ip_argument(client_ip)
        self.http = HTTP(base_url or os.environ.get("SCUTE_BASE_URL") or "https://api.scute.io", timeout=timeout,
                         transport=transport)
        self.tokens = Tokens(self)
        self._bind()

    def _bind(self) -> None:
        self.users = Users(self)
        self.sessions = Sessions(self)
        self.authz = Authz(self)
        self.agents = Agents(self)

    @property
    def has_secret(self) -> bool:
        return bool(self._secret)

    @property
    def client_ip(self) -> str | None:
        """The end user's address this client sends on secret-key calls."""
        return self._client_ip

    def with_client_ip(self, client_ip: str | None) -> Scute:
        """A copy of this client that sends `client_ip` (None sends none). It
        shares the connection pool and the cached signing keys, so make one
        per request; close the original, not the copies.

            scute.with_client_ip(request.remote_addr).users.create("ada@example.com")
        """
        other = copy.copy(self)
        other._client_ip = client_ip_argument(client_ip)
        other._bind()
        return other

    def request(self, method: str, path: str, body: Any = None, idempotent: bool | None = None, *,
                client_ip: str | None = None) -> Any:
        """A call with the secret key. `client_ip` overrides the client's for this call."""
        if not self._secret:
            raise ConfigurationError("This call needs the app's secret key: pass secret or set SCUTE_SECRET")
        ip = client_ip_argument(client_ip) or self._client_ip
        headers = {CLIENT_IP_HEADER: ip} if ip else None
        return self.http.request(method, path, bearer=self._secret, headers=headers, body=body, idempotent=idempotent)

    def user_request(self, method: str, path: str, *, access: str | None = None, refresh: str | None = None,
                     body: Any = None) -> Any:
        """A call with the user's own session (or a public read)."""
        headers = {k: v for k, v in {"X-Authorization": access, "X-Refresh-Token": refresh}.items() if v}
        return self.http.request(method, path, headers=headers, public=not headers, body=body)

    def esc(self, value: object) -> str:
        return quote(str(value), safe="")

    def apps_path(self, rest: str = "") -> str:
        return f"/v1/apps/{self.esc(self.app_id)}{rest}"

    def auth_path(self, rest: str = "") -> str:
        return f"/v1/auth/{self.esc(self.app_id)}{rest}"

    def app_path(self, rest: str = "") -> str:
        """The API-key user routes (/v1/:app_id/users...)."""
        return f"/v1/{self.esc(self.app_id)}{rest}"

    def close(self) -> None:
        self.http.close()
