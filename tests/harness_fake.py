"""A small stand-in for the agent API the harness calls, as an httpx transport."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

import httpx

from scute.harness import Harness

AUTH = "/v1/auth/app1"
AGENTS = "/v1/apps/app1/authz/agents"
MINT = f"{AGENTS}/support-bot/tasks"
CHECK = f"{AUTH}/agent/check"


@dataclass(frozen=True)
class Seen:
    method: str
    path: str
    body: Any
    auth: str | None
    query: str


Decide = Callable[[dict[str, Any]], dict[str, Any] | None]


@dataclass
class FakeAgentAPI:
    decide: Decide | None = None
    ceiling: list[str] = field(default_factory=lambda: ["invoice:read", "invoice:refund"])
    request_status: str = "pending"
    ttl: int = 1800
    down: bool = False
    revoked: bool = False  # every agent call answers 401 invalid_task_token
    verification_status: str = "pending"
    seen: list[Seen] = field(default_factory=list)
    tasks: int = 0

    def paths(self, path: str) -> list[Seen]:
        return [s for s in self.seen if s.path == path]

    def handler(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            raise httpx.ConnectError("fake is down", request=request)
        url = urlparse(str(request.url))
        body = json.loads(request.content) if request.content else None
        auth = request.headers.get("authorization")
        self.seen.append(Seen(request.method, url.path, body, auth, url.query))
        return self.route(request.method, url.path, body or {}, auth or "")

    @staticmethod
    def json(data: Any, status: int = 200) -> httpx.Response:
        return httpx.Response(status, json=data)

    def route(self, method: str, path: str, body: dict[str, Any], auth: str) -> httpx.Response:
        secret = auth == "Bearer sk_test"
        task = auth.startswith("Bearer sct_")
        ok = self.json
        if path.startswith(f"{AUTH}/agent/"):
            if not task:
                return ok({"error": "Task token missing, expired or revoked", "error_code": "invalid_task_token"}, 401)
            if self.revoked:
                return ok({"error": "Task token missing, expired or revoked", "error_code": "invalid_task_token"}, 401)
            return self.agent(method, path[len(f"{AUTH}/agent"):], body)
        if path == MINT and method == "POST":
            if not secret:
                return ok({"error": "Unauthorized"}, 401)
            self.tasks += 1
            expires = (datetime.now(timezone.utc) + timedelta(seconds=self.ttl)).isoformat().replace("+00:00", "Z")
            return ok({"id": f"task{self.tasks}", "token": f"sct_token{self.tasks}", "agent": "support-bot", "status": "open",
                       "acts_for": body.get("acts_for"), "expires_at": expires, "chain": ["support-bot"]}, 201)
        if path.startswith(f"{MINT}/") and method == "POST":
            return ok({"status": "done"})
        if path == AGENTS and method == "POST":
            return ok({"id": "agent1", "status": "active", **body}, 201) if secret else ok({"error": "Unauthorized"}, 401)
        if path == AGENTS and method == "GET":
            return ok({"agents": [{"slug": "support-bot"}]})
        if path.startswith(f"{AGENTS}/support-bot"):
            return ok({"slug": "support-bot", "path": path})
        return ok({"error": f"no route {method} {path}"}, 404)

    def agent(self, method: str, path: str, body: dict[str, Any]) -> httpx.Response:
        ok = self.json
        routes: dict[tuple[str, str], Callable[[], httpx.Response]] = {
            ("GET", "/whoami"): lambda: ok({"agent": "support-bot", "task": "task1", "acts_for": "user1", "permissions": [],
                                            "ceiling": self.ceiling}),
            ("POST", "/check"): lambda: self.check(body),
            ("POST", "/sessions"): lambda: ok({"id": "sess1", "task_id": "task1", "verified": False}, 201),
            ("POST", "/sessions/sess1/verified"): lambda: ok({"id": "sess1", "verified": True}) if body.get("challenge") == "ch_ok"
            else ok({"error": "That challenge doesn't verify this person", "error_code": "challenge_invalid"}, 422),
            ("POST", "/sessions/sess1/end"): lambda: ok({"id": "sess1"}),
            ("POST", "/verifications"): lambda: ok({"token": "ch_ok", "status": "pending", "method": body.get("method"),
                                                    "say": "I've emailed a code to a***@example.com. What's the code?"}, 201),
            ("GET", "/verifications/ch_ok"): lambda: ok({
                "token": "ch_ok", "status": self.verification_status,
                "say": "Thanks, you're verified." if self.verification_status == "completed" else "Approve it, then tell me."}),
            ("POST", "/verifications/ch_ok/code"): lambda: self.code(body),
            ("POST", "/approvals"): lambda: ok({"id": "req1", "status": self.request_status,
                                                "say": "I've asked for approval. I'll let you know when there's an answer."}, 201),
            ("GET", "/approvals/req1"): lambda: ok({"id": "req1", "status": self.request_status,
                                                    "say": "It's approved." if self.request_status == "approved" else "Still waiting."}),
            ("GET", "/properties/stripe"): lambda: ok({"name": "stripe", "value": "sk_live_123"}),
            ("GET", "/properties/locked"): lambda: ok({"error": "support-bot isn't allowed to use locked.",
                                                       "error_code": "agent_not_listed"}, 403),
            ("POST", "/properties/mandates/sign"): lambda: ok(
                {"jws": "h.b.s", "alg": "ES256", "kid": "prop_1"} if body.get("claims")
                else {"signature": "c2ln", "alg": "ES256", "kid": "prop_1"}),
        }
        route = routes.get((method, path))
        return route() if route else ok({"error": f"no route {method} {path}"}, 404)

    def check(self, body: dict[str, Any]) -> httpx.Response:
        d = (self.decide(body) if self.decide else None) or {"decision": "allow"}
        decision = d.get("decision", "allow")
        return self.json({"allowed": decision == "allow", "reason": "role_grant" if decision == "allow" else "no", **d})

    def code(self, body: dict[str, Any]) -> httpx.Response:
        if body.get("code") == "123456":
            self.verification_status = "completed"
            return self.json({"token": "ch_ok", "status": "completed", "say": "Thanks, you're verified."})
        return self.json({"token": "ch_ok", "status": "pending", "remaining_attempts": 2, "error": "Invalid code",
                          "say": "That code didn't work. Want to try again?"}, 422)


def harness(fake: FakeAgentAPI | None = None, *, secret: str | None = "sk_test", **options: Any) -> Harness:
    fake = fake or FakeAgentAPI()
    transport = options.pop("transport", None) or httpx.MockTransport(fake.handler)
    return Harness("support-bot", app_id="app1", secret=secret, base_url="https://scute.test", transport=transport,
                   **options)
