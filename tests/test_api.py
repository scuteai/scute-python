from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from scute import APIError, ConfigurationError, ConnectionError, Scute

from .conftest import FakeScute


def client(fake: FakeScute, secret: str | None = "sk_test") -> Scute:
    return Scute(app_id="app1", secret=secret, base_url="https://scute.test", transport=httpx.MockTransport(fake.handler))


def test_manages_users_with_the_secret_key(fake: FakeScute) -> None:
    c = client(fake)
    assert c.users.list(page=2)["query"] == "page=2"
    assert c.users.create("ada@example.com", meta={"plan": "pro"})["user"]["identifier"] == "ada@example.com"
    c.users.deactivate("user1")
    c.users.update("user1", user_meta={"plan": "team"})
    assert ("POST", "/v1/app1/users/user1/deactivate") in [(r.method, r.url.path) for r in fake.seen]
    assert fake.seen[-1].headers["authorization"] == "Bearer sk_test"


def test_finds_a_user_by_identifier_exactly(fake: FakeScute) -> None:
    c = client(fake)
    assert c.users.find_by_identifier(" ADA@example.com ")["id"] == "user1"  # on page 2 of the loose search
    assert c.users.find_by_identifier("+1 (415) 555-0100")["id"] == "user4"
    assert c.users.find_by_identifier("14155550101")["id"] == "user5"
    searches = [r for r in fake.seen if r.url.path == "/v1/app1/users"]
    assert [(r.url.params["q"], r.url.params["page"]) for r in searches] == [
        ("ada@example.com", "1"), ("ada@example.com", "2"), ("14155550100", "1"), ("14155550101", "1"), ("14155550101", "2")]
    assert all(r.headers["authorization"] == "Bearer sk_test" for r in searches)


def test_finds_nobody_without_making_anyone(fake: FakeScute) -> None:
    c = client(fake)
    assert c.users.find_by_identifier("ada@example.co") is None  # a near miss isn't a match
    assert c.users.find_by_identifier("+1 415 555 0199") is None
    assert [r.url.params["page"] for r in fake.seen] == ["1", "2", "3", "1", "2", "3"]  # every page, then stop
    assert c.users.find_by_identifier("  ") is None and c.users.find_by_identifier("n/a") is None
    assert len(fake.seen) == 6  # nothing to search for: no call
    assert not any(r.url.path.startswith("/v1/auth/") for r in fake.seen)


def test_the_search_stops_after_a_bounded_number_of_pages(fake: FakeScute) -> None:
    fake.people = [{"id": f"u{n}", "email": f"ada{n}@example.com", "phone": None} for n in range(40)]
    assert client(fake).users.find_by_identifier("ada@example.com") is None
    assert len(fake.seen) == client(fake).users.FIND_MAX_PAGES


def test_lists_and_merges_previous_accounts(fake: FakeScute) -> None:
    c = client(fake)
    previous = c.users.previous_accounts("user1")
    assert [(a["id"], a["roles"], a["mfa_methods"]) for a in previous] == [("old1", 1, ["totp"])]
    merged = c.users.merge("user1", "old1")
    assert (merged["merged"], merged["moved"]["roles"]) == ("old1", 1)
    assert (fake.seen[-1].method, fake.seen[-1].url.path) == ("POST", "/v1/app1/users/user1/merge")
    assert json.loads(fake.seen[-1].content) == {"from": "old1"}
    assert fake.seen[-1].headers["authorization"] == "Bearer sk_test"
    with pytest.raises(APIError) as again:
        c.users.merge("user1", "old1")
    assert (again.value.status, again.value.code) == (422, "already_merged")


def test_retries_reads_once_on_a_network_error_and_never_a_plain_write() -> None:
    attempts: list[str] = []

    def flaky(request: httpx.Request) -> httpx.Response:
        attempts.append(request.method)
        if len(attempts) == 1:
            raise httpx.ConnectError("reset", request=request)
        return httpx.Response(200, json={"ok": True})

    c = Scute(app_id="app1", secret="sk_test", base_url="https://scute.test", transport=httpx.MockTransport(flaky))
    assert c.users.get("user1") == {"ok": True}
    assert attempts == ["GET", "GET"]

    attempts.clear()
    with pytest.raises(ConnectionError, match="Couldn't reach Scute"):
        c.users.merge("user1", "old1")
    assert attempts == ["POST"]

    attempts.clear()  # an authorization check is a POST that's safe to repeat
    assert c.authz.check(user_id="user1", action="read", resource="invoice:1").reason is None
    assert attempts == ["POST", "POST"]


@pytest.mark.parametrize(("call", "method", "path", "body"), [
    (lambda c: c.authz.check_batch([{"user_id": "u1", "action": "read", "resource": None}]), "POST",
     "/v1/auth/app1/authz/check-batch", {"checks": [{"user_id": "u1", "action": "read"}]}),
    (lambda c: c.authz.permissions("u 1", resource="doc:1"), "GET", "/v1/auth/app1/authz/users/u%201/permissions", None),
    (lambda c: c.authz.authorized_users(action="read", limit=5), "GET", "/v1/auth/app1/authz/authorized-users", None),
    (lambda c: c.users.invite("ada@example.com", meta={"plan": "pro"}), "POST", "/v1/app1/users/invite",
     {"identifier": "ada@example.com", "user_meta": {"plan": "pro"}}),
    (lambda c: c.users.activate("user1"), "POST", "/v1/app1/users/user1/activate", None),
    (lambda c: c.users.delete("user1"), "DELETE", "/v1/app1/users/user1", None),
    (lambda c: c.sessions.revoke("user1", "ses/1"), "DELETE", "/v1/app1/users/user1/sessions/ses%2F1", None),
    (lambda c: c.agents.update("bot", name="Bot"), "PATCH", "/v1/apps/app1/authz/agents/bot", {"name": "Bot"}),
    (lambda c: c.agents.delete("bot"), "DELETE", "/v1/apps/app1/authz/agents/bot", None),
    (lambda c: c.agents.resume("bot"), "POST", "/v1/apps/app1/authz/agents/bot/resume", None),
    (lambda c: c.agents.tasks("bot", status="open"), "GET", "/v1/apps/app1/authz/agents/bot/tasks", None),
    (lambda c: c.agents.assertion("bot", "task1"), "GET", "/v1/apps/app1/authz/agents/bot/tasks/task1/assertion", None),
])
def test_thin_wrappers_send_the_right_request(call: Any, method: str, path: str, body: Any) -> None:
    seen: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={})

    call(Scute(app_id="app1", secret="sk_test", base_url="https://scute.test", transport=httpx.MockTransport(record)))
    assert len(seen) == 1
    (request,) = seen
    assert (request.method, request.url.raw_path.decode().split("?")[0]) == (method, path)
    assert request.headers["authorization"] == "Bearer sk_test"
    assert (json.loads(request.content) if request.content else None) == body


def test_starts_lists_and_ends_sessions_as_a_user(fake: FakeScute) -> None:
    c = client(fake)
    started = c.users.impersonate("user1", reason="Ticket 4411", actor={"email": "support@acme.test"}, minutes=15)
    assert started["session_id"] == "ses1"
    assert started["echo"] == {"reason": "Ticket 4411", "minutes": 15, "actor": {"email": "support@acme.test"}}
    assert c.users.impersonations("user1") == [{"session_id": "ses1"}]
    assert c.users.stop_impersonating("user1", session_id="ses1") == {"ended": 1}
    assert fake.seen[-1].url.query == b"session_id=ses1"


def test_uses_the_users_own_tokens_for_their_session(fake: FakeScute) -> None:
    c = client(fake)
    c.sessions.current_user("tok")
    assert fake.seen[-1].headers["x-authorization"] == "tok"
    assert "authorization" not in fake.seen[-1].headers
    assert c.sessions.refresh("r1")["seen_refresh"] == "r1"
    c.sessions.sign_out("tok")
    assert (fake.seen[-1].method, fake.seen[-1].url.path) == ("DELETE", "/v1/auth/app1/current_user")
    assert c.sessions.list("user1") == [{"id": "ses1"}]


def test_checks_with_the_impersonation_context(fake: FakeScute) -> None:
    d = client(fake).authz.check(user_id="user1", action="read", resource="invoice:1", context={"impersonated": True})
    assert d.allowed
    assert d.raw["echo"]["context"] == {"impersonated": True}


def test_errors(fake: FakeScute) -> None:
    with pytest.raises(ConfigurationError):
        client(fake, secret=None).users.list()
    with pytest.raises(APIError) as e:
        client(fake, secret="sk_wrong").users.get("user1")
    assert e.value.status == 401


def test_reads_each_kind_of_decision(fake: FakeScute) -> None:
    c = client(fake)
    allow = c.authz.check(user_id="user1", action="read", resource="invoice:1")
    assert (allow.allowed, allow.needs_step_up, allow.needs_approval) == (True, False, False)
    assert (allow.reason, allow.permission, allow.roles) == ("role_grant", "invoice:read", ["clerk"])
    deny = c.authz.check(user_id="user1", action="delete", resource="invoice:1")
    assert (deny.allowed, deny.explanation) == (False, "Ada can't delete invoices.")
    step_up = c.authz.check(user_id="user1", action="pay", resource="invoice:1")
    assert (step_up.allowed, step_up.needs_step_up, step_up.step_up) == (False, True, {"method": "any"})
    approval = c.authz.check(user_id="user1", action="approve", resource="invoice:1")
    assert (approval.allowed, approval.needs_approval, approval.approval) == (False, True, {"by": "reviewer"})
    assert fake.paths("/v1/auth/app1/authz/check")[-1].headers["authorization"] == "Bearer sk_test"


def test_checks_in_a_batch_and_keeps_the_order(fake: FakeScute) -> None:
    c = client(fake)
    got = c.authz.check_batch([{"user_id": "user1", "action": a, "resource": "invoice:1"} for a in ("read", "pay", "delete")])
    assert [d.decision for d in got] == ["allow", "allow_with_step_up", "deny"]
    with pytest.raises(ValueError, match="at most 100"):
        c.authz.check_batch([{"user_id": "user1", "action": "read"}] * (c.authz.BATCH_LIMIT + 1))
    assert len(fake.paths("/v1/auth/app1/authz/check-batch")) == 1  # the oversized batch wasn't sent


def test_reads_its_configuration_from_the_environment(fake: FakeScute, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ConfigurationError, match="SCUTE_APP_ID"):
        Scute()
    monkeypatch.setenv("SCUTE_APP_ID", "app1")
    monkeypatch.setenv("SCUTE_SECRET", "sk_test")
    monkeypatch.setenv("SCUTE_BASE_URL", "https://scute.test/")
    c = Scute(transport=httpx.MockTransport(fake.handler))
    assert (c.app_id, c.has_secret, repr(c)) == ("app1", True, "Scute(app_id='app1', secret=***)")
    c.users.get("user1")
    assert str(fake.seen[-1].url) == "https://scute.test/v1/app1/users/user1"
    assert fake.seen[-1].headers["authorization"] == "Bearer sk_test"
