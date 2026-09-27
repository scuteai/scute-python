from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .client import Scute


class Sessions:
    """A user's sessions. With the user's own tokens: who they are, refresh,
    sign out. With the secret key: list and revoke."""

    def __init__(self, client: Scute) -> None:
        self._c = client

    def current_user(self, access_token: str) -> Any:
        """The signed-in user (and "impersonation" in a session someone started as them). Asks Scute."""
        return self._c.user_request("GET", self._c.auth_path("/current_user"), access=access_token)

    def refresh(self, refresh_token: str) -> Any:
        return self._c.user_request("POST", self._c.auth_path("/tokens/refresh"), refresh=refresh_token)

    def sign_out(self, access_token: str) -> None:
        """Ends this session (the user's other sessions stay)."""
        self._c.user_request("DELETE", self._c.auth_path("/current_user"), access=access_token)

    def list(self, user_id: str) -> Any:
        return self._c.request("GET", self._c.app_path(f"/users/{self._c.esc(user_id)}/sessions"))

    def revoke(self, user_id: str, session_id: str) -> Any:
        return self._c.request("DELETE", self._c.app_path(f"/users/{self._c.esc(user_id)}/sessions/{self._c.esc(session_id)}"))
