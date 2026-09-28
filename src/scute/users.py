from __future__ import annotations

import builtins
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

if TYPE_CHECKING:
    from .client import Scute


def _digits(value: object) -> str:
    return "".join(c for c in str(value or "") if c.isdigit())


class Users:
    """The app's users, from your backend (secret key). Answers are the API's JSON."""

    def __init__(self, client: Scute) -> None:
        self._c = client

    def list(self, **params: Any) -> Any:
        query = f"?{urlencode({k: v for k, v in params.items() if v is not None})}" if params else ""
        return self._c.request("GET", self._c.app_path(f"/users{query}"))

    def get(self, user_id: str) -> Any:
        return self._c.request("GET", self._c.app_path(f"/users/{self._c.esc(user_id)}"))

    FIND_PAGE_SIZE = 100
    FIND_MAX_PAGES = 10

    def find_by_identifier(self, identifier: str) -> dict[str, Any] | None:
        """The app's user with this email (any case) or phone number (compared as
        digits, so include the country code), as users.get shows it; None when
        nobody by that identifier uses the app. Never creates a user.

        Searches the app's users with the secret key (list, q=...: a loose search
        over email, phone and name) and keeps only an exact match.
        """
        wanted = identifier.strip()
        if "@" in wanted:
            query = wanted.lower()

            def same(user: dict[str, Any]) -> bool:
                return str(user.get("email") or "").strip().lower() == query
        else:
            query = _digits(wanted)

            def same(user: dict[str, Any]) -> bool:
                return _digits(user.get("phone")) == query

        if not query:
            return None
        for page in range(1, self.FIND_MAX_PAGES + 1):
            data = self.list(q=query, limit=self.FIND_PAGE_SIZE, page=page) or {}
            for user in data.get("users") or []:
                if same(user):
                    return dict(user)
            if not data.get("next_page"):
                break
        return None

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

    # ── Previous accounts ──
    # Someone deleted who signs in again gets a fresh account (a new id). Their
    # earlier accounts stay deleted, and can be merged into the live one.

    def previous_accounts(self, user_id: str) -> builtins.list[dict[str, Any]]:
        """The person's earlier, deleted accounts in this app, newest first: id,
        status, created_at, deleted_at, merged_into (once merged), and what each
        still holds (roles and passkeys counted, mfa_methods listed)."""
        data = self._c.request("GET", self._c.app_path(f"/users/{self._c.esc(user_id)}/previous_accounts"))
        return list((data or {}).get("previous_accounts") or [])

    def merge(self, user_id: str, from_id: str) -> dict[str, Any]:
        """Merge a previous (deleted) account of the same person into this live
        one. Roles, resource roles, passkeys, MFA methods and unused backup codes
        move over; meta and attributes are combined, the live account winning;
        history stays on the old account. Answers {user_id, merged, moved: {roles,
        resource_roles, passkeys, mfa_methods, backup_codes}} (counts moved).

        Once per account: merging it again raises APIError (422, code
        "already_merged")."""
        return dict(self._c.request("POST", self._c.app_path(f"/users/{self._c.esc(user_id)}/merge"), {"from": from_id}))

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
