from __future__ import annotations

import builtins
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

if TYPE_CHECKING:
    from .client import Scute


class Users:
    """The app's users, from your backend (secret key). Answers are the API's JSON."""

    def __init__(self, client: Scute) -> None:
        self._c = client

    def list(self, **params: Any) -> Any:
        query = f"?{urlencode({k: v for k, v in params.items() if v is not None})}" if params else ""
        return self._c.request("GET", self._c.app_path(f"/users{query}"))

    def get(self, user_id: str) -> Any:
        return self._c.request("GET", self._c.app_path(f"/users/{self._c.esc(user_id)}"))

    def find_by_identifier(self, identifier: str) -> dict[str, Any] | None:
        """By email or phone; None when nobody by that identifier uses the app."""
        data = self._c.request("GET", self._c.auth_path(f"/users?identifier={self._c.esc(identifier)}"))
        return (data or {}).get("user")

    def create(self, identifier: str, meta: dict[str, Any] | None = None) -> Any:
        return self._c.request("POST", self._c.auth_path("/users"), {"identifier": identifier, **({"user_meta": meta} if meta else {})})

    def invite(self, identifier: str, meta: dict[str, Any] | None = None) -> Any:
        """Sends an invitation (magic link) as well."""
        return self._c.request("POST", self._c.app_path("/users/invite"),
                               {"identifier": identifier, **({"user_meta": meta} if meta else {})})

    def update(self, user_id: str, **attributes: Any) -> Any:
        return self._c.request("PATCH", self._c.app_path(f"/users/{self._c.esc(user_id)}"), attributes, idempotent=True)

    def activate(self, user_id: str) -> Any:
        return self._c.request("POST", self._c.app_path(f"/users/{self._c.esc(user_id)}/activate"))

    def deactivate(self, user_id: str) -> Any:
        return self._c.request("POST", self._c.app_path(f"/users/{self._c.esc(user_id)}/deactivate"))

    def delete(self, user_id: str) -> Any:
        return self._c.request("DELETE", self._c.app_path(f"/users/{self._c.esc(user_id)}"))

    # ── Signing in as a user (support access) ──
    # Off until the app turns it on. The session is short, never refreshed,
    # and its token names who is really acting (Session.actor).

    def impersonate(self, user_id: str, *, reason: str, minutes: int | None = None, actor_user_id: str | None = None,
                    actor: dict[str, str] | None = None, challenge: str | None = None, approval: str | None = None) -> Any:
        body = {"reason": reason, "minutes": minutes, "actor_user_id": actor_user_id, "actor": actor,
                "challenge": challenge, "approval": approval}
        return self._c.request("POST", self._c.apps_path(f"/users/{self._c.esc(user_id)}/impersonate"),
                               {k: v for k, v in body.items() if v is not None})

    def impersonations(self, user_id: str) -> builtins.list[dict[str, Any]]:
        return list(self._c.request("GET", self._c.apps_path(f"/users/{self._c.esc(user_id)}/impersonations"))["impersonations"])

    def stop_impersonating(self, user_id: str, session_id: str | None = None) -> Any:
        query = f"?session_id={self._c.esc(session_id)}" if session_id else ""
        return self._c.request("DELETE", self._c.apps_path(f"/users/{self._c.esc(user_id)}/impersonate{query}"))
