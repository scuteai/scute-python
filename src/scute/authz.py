from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

if TYPE_CHECKING:
    from .client import Scute


@dataclass(frozen=True)
class Decision:
    """An answer from Scute's engine. `allowed` is True only for a plain allow:
    a step-up or approval answer isn't allowed yet."""

    decision: str
    reason: str | None = None
    permission: str | None = None
    roles: list[str] = field(default_factory=list)
    explanation: str | None = None
    step_up: dict[str, Any] | None = None
    approval: dict[str, Any] | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)
    say: str | None = None  # a line for the person, on an agent's checks

    @classmethod
    def from_api(cls, data: dict[str, Any] | None) -> Decision:
        d = data or {}
        return cls(decision=str(d.get("decision")), reason=d.get("reason"), permission=d.get("permission"),
                   roles=list(d.get("roles") or []), explanation=d.get("explanation"), step_up=d.get("step_up"),
                   approval=d.get("approval"), raw=d, say=d.get("say"))

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"

    @property
    def needs_step_up(self) -> bool:
        return self.decision == "allow_with_step_up"

    @property
    def needs_approval(self) -> bool:
        return self.decision == "allow_with_approval"


class Authz:
    """Authorization for your app's users, from your backend (secret key)."""

    BATCH_LIMIT = 100

    def __init__(self, client: Scute) -> None:
        self._c = client

    def check(self, *, user_id: str, action: str, resource: Any = None, context: dict[str, Any] | None = None,
              challenge: str | None = None, approval: str | None = None) -> Decision:
        """May this user do this? Pass the session's authz_context() in `context`
        so "not while impersonating" permissions are refused."""
        body = {"user_id": user_id, "action": action, "resource": resource, "context": context or None,
                "challenge": challenge, "approval": approval}
        data = self._c.request("POST", self._c.auth_path("/authz/check"), {k: v for k, v in body.items() if v is not None},
                               idempotent=True)
        return Decision.from_api(data)

    def check_batch(self, checks: list[dict[str, Any]]) -> list[Decision]:
        if len(checks) > self.BATCH_LIMIT:
            raise ValueError(f"Send at most {self.BATCH_LIMIT} checks")
        data = self._c.request("POST", self._c.auth_path("/authz/check-batch"),
                               {"checks": [{k: v for k, v in c.items() if v is not None} for c in checks]}, idempotent=True)
        return [Decision.from_api(r) for r in (data or {}).get("results", [])]

    def permissions(self, user_id: str, resource: str | None = None) -> Any:
        query = f"?resource={self._c.esc(resource)}" if resource else ""
        return self._c.request("GET", self._c.auth_path(f"/authz/users/{self._c.esc(user_id)}/permissions{query}"))

    def authorized_users(self, *, action: str, resource: str | None = None, limit: int | None = None,
                         offset: int | None = None) -> Any:
        query = urlencode({k: v for k, v in {"action": action, "resource": resource, "limit": limit, "offset": offset}.items()
                           if v is not None})
        return self._c.request("GET", self._c.auth_path(f"/authz/authorized-users?{query}"))
