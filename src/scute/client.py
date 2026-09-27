from __future__ import annotations

import os
from typing import Any
from urllib.parse import quote

import httpx

from ._http import HTTP
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
    """

    def __init__(self, app_id: str | None = None, secret: str | None = None, base_url: str | None = None, *,
                 timeout: float = 10.0, transport: httpx.BaseTransport | None = None) -> None:
        app_id = app_id or os.environ.get("SCUTE_APP_ID")
        if not app_id:
            raise ConfigurationError("Scute needs an app id: pass app_id or set SCUTE_APP_ID")
        self.app_id = str(app_id)
        self._secret = secret or os.environ.get("SCUTE_SECRET")
        self.http = HTTP(base_url or os.environ.get("SCUTE_BASE_URL") or "https://api.scute.io", timeout=timeout,
                         transport=transport)
        self.tokens = Tokens(self)
        self.users = Users(self)
        self.sessions = Sessions(self)
        self.authz = Authz(self)

    @property
    def has_secret(self) -> bool:
        return bool(self._secret)

    def request(self, method: str, path: str, body: Any = None, idempotent: bool | None = None) -> Any:
        """A call with the secret key."""
        if not self._secret:
            raise ConfigurationError("This call needs the app's secret key: pass secret or set SCUTE_SECRET")
        return self.http.request(method, path, bearer=self._secret, body=body, idempotent=idempotent)

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
