from __future__ import annotations

import httpx
import pytest

from scute import APIError, ConfigurationError, Scute

from .conftest import FakeScute


def client(fake: FakeScute, secret: str | None = "sk_test") -> Scute:
    return Scute(app_id="app1", secret=secret, base_url="https://scute.test", transport=httpx.MockTransport(fake.handler))


def test_manages_users_with_the_secret_key(fake: FakeScute) -> None:
    c = client(fake)
    assert c.users.list(page=2)["query"] == "page=2"
    assert c.users.find_by_identifier("ada@example.com") == {"id": "user1"}
    assert c.users.find_by_identifier("bob@example.com") is None
    assert c.users.create("ada@example.com", meta={"plan": "pro"})["user"]["identifier"] == "ada@example.com"
    c.users.deactivate("user1")
    c.users.update("user1", user_meta={"plan": "team"})
    assert ("POST", "/v1/app1/users/user1/deactivate") in [(r.method, r.url.path) for r in fake.seen]
    assert fake.seen[-1].headers["authorization"] == "Bearer sk_test"


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
