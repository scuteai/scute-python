from __future__ import annotations

import builtins
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .client import Scute


class Agents:
    """Register the agents you build and start tasks for them (secret key).
    The agent itself runs with a task token: see scute.harness.

        scute.agents.create("support-bot", roles=["support"])
        task = scute.agents.start_task("support-bot", acts_for=user_id, actions=["invoice:read"])
        task["token"]  # once: hand it to the agent, never to the model
    """

    def __init__(self, client: Scute) -> None:
        self._c = client

    def list(self) -> builtins.list[dict[str, Any]]:
        return list((self._c.request("GET", self._path()) or {}).get("agents") or [])

    def get(self, slug: str) -> Any:
        return self._c.request("GET", self._path(f"/{self._c.esc(slug)}"))

    def create(self, slug: str, *, name: str | None = None, description: str | None = None, roles: builtins.list[str] | None = None,
               owner_user_id: str | None = None, team_role: str | None = None, settings: dict[str, Any] | None = None) -> Any:
        """roles: role slugs from your policy, the agent's ceiling. owner_user_id: a
        person who can reach the app's workspace, answerable for the agent.
        settings: safety rails, e.g. {"budget": {"max_actions": 50, "window_minutes": 60}}."""
        body = {"slug": slug, "name": name, "description": description, "roles": roles, "owner_user_id": owner_user_id,
                "team_role": team_role, "settings": settings}
        return self._c.request("POST", self._path(), {k: v for k, v in body.items() if v is not None})

    def update(self, slug: str, **attributes: Any) -> Any:
        return self._c.request("PATCH", self._path(f"/{self._c.esc(slug)}"), attributes, idempotent=True)

    def delete(self, slug: str) -> None:
        self._c.request("DELETE", self._path(f"/{self._c.esc(slug)}"))

    def suspend(self, slug: str, reason: str | None = None) -> Any:
        """The kill switch: every open task of the agent ends at once."""
        return self._c.request("POST", self._path(f"/{self._c.esc(slug)}/suspend"), {"reason": reason} if reason else None)

    def resume(self, slug: str) -> Any:
        return self._c.request("POST", self._path(f"/{self._c.esc(slug)}/resume"))

    def tasks(self, slug: str, status: str | None = None) -> builtins.list[dict[str, Any]]:
        """status: "open" for live tasks only."""
        query = f"?status={self._c.esc(status)}" if status else ""
        return list((self._c.request("GET", self._path(f"/{self._c.esc(slug)}/tasks{query}")) or {}).get("tasks") or [])

    def start_task(self, slug: str, *, acts_for: str | None = None, actions: builtins.list[str] | None = None,
                   resources: builtins.list[str] | None = None, requester: dict[str, Any] | None = None, ttl: int | None = None,
                   ref: str | None = None, parent_task_id: str | None = None) -> Any:
        """Start a task. The answer carries the task token once (`token`); hand it
        to the agent and never to the model. actions / resources narrow what the
        task may do (an empty list means nothing, None means everything the
        agent and the person may)."""
        body = {"acts_for": acts_for, "actions": actions, "resources": resources, "requester": requester,
                "ttl_seconds": ttl, "ref": ref, "parent_task_id": parent_task_id}
        return self._c.request("POST", self._path(f"/{self._c.esc(slug)}/tasks"), {k: v for k, v in body.items() if v is not None})

    def complete_task(self, slug: str, task_id: str) -> Any:
        return self._c.request("POST", self._task_path(slug, task_id, "/complete"))

    def revoke_task(self, slug: str, task_id: str) -> Any:
        return self._c.request("POST", self._task_path(slug, task_id, "/revoke"))

    def assertion(self, slug: str, task_id: str) -> Any:
        """The delegation as a signed JWT (sub: the person, act: the agent chain, RFC 8693)."""
        return self._c.request("GET", self._task_path(slug, task_id, "/assertion"))

    def _path(self, rest: str = "") -> str:
        return self._c.apps_path(f"/authz/agents{rest}")

    def _task_path(self, slug: str, task_id: str, rest: str) -> str:
        return self._path(f"/{self._c.esc(slug)}/tasks/{self._c.esc(task_id)}{rest}")
