"""6. Signing in as a user (support access): start (the `act` claim in the
token), list, stop, and a permission marked "not while impersonating" denied
inside the session. All SDK (scute.users.impersonate, scute.tokens,
Session.authz_context, scute.authz.check).
"""

from __future__ import annotations

from typing import Any

import pytest

from scute import InvalidToken, Scute

from .support import Cleanup, Names, Policy, SignedIn, Trail, redact

pytestmark = pytest.mark.live


def support_email(names: Names) -> str:
    return names.email(3)


@pytest.fixture(scope="module")
def started(scute: Scute, alice: SignedIn, names: Names, cleanup: Cleanup, app_settings: dict[str, Any]) -> dict[str, Any]:
    cleanup.add("stop signing in as alice", lambda: scute.users.stop_impersonating(alice.user_id), order=10)
    answer: dict[str, Any] = redact(scute.users.impersonate(
        alice.user_id, reason=f"{names.prefix} support ticket", minutes=10,
        actor={"email": support_email(names), "name": "Live support"}))
    return answer


def test_starts_a_session_as_the_user(scute: Scute, alice: SignedIn, names: Names, started: dict[str, Any]) -> None:
    assert started["session_id"]
    assert "refresh" not in started  # never refreshed: when it expires, it's over
    session = scute.tokens.verify(started["access"])
    assert session.user_id == alice.user_id
    assert session.impersonated
    who = support_email(names)
    assert session.actor == {"sub": who, "kind": "backend", "email": who, "name": "Live support"}
    assert session.claims["act"] == session.actor
    assert session.authz_context() == {"impersonated": True, "actor": session.actor}

    me = scute.sessions.current_user(started["access"])
    assert me["user"]["id"] == alice.user_id
    assert me["impersonation"]["actor"]["email"] == who
    assert me["impersonation"]["reason"] == f"{names.prefix} support ticket"


def test_lists_the_sessions_as_the_user(scute: Scute, alice: SignedIn, started: dict[str, Any]) -> None:
    assert started["session_id"] in [i["session_id"] for i in scute.users.impersonations(alice.user_id)]


def test_not_while_impersonating(scute: Scute, alice: SignedIn, policy: Policy, started: dict[str, Any],
                                 trail: Trail) -> None:
    session = scute.tokens.verify(started["access"])
    edit = f"{policy.doc}:1"
    inside = scute.authz.check(user_id=session.user_id, action="edit", resource=edit, context=session.authz_context())
    assert (inside.decision, inside.reason) == ("deny", "impersonating")
    assert not inside.allowed
    outside = scute.authz.check(user_id=alice.user_id, action="edit", resource=edit)
    assert outside.allowed
    trail.add(f"{policy.doc}:edit", "deny", user_id=alice.user_id)
    trail.add(f"{policy.doc}:edit", "allow", user_id=alice.user_id)


def test_stops(scute: Scute, alice: SignedIn, started: dict[str, Any]) -> None:
    assert scute.users.stop_impersonating(alice.user_id, session_id=started["session_id"]) == {"ended": 1}
    assert started["session_id"] not in [i["session_id"] for i in scute.users.impersonations(alice.user_id)]
    with pytest.raises(InvalidToken) as ended:
        scute.tokens.verify(started["access"], remote=True)
    assert ended.value.reason == "revoked"
    assert scute.tokens.verify(alice.access, remote=True).user_id == alice.user_id  # alice's own session is untouched
