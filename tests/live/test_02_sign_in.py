"""2. Sign-in with test identities: email OTP and SMS OTP. Then the user,
refresh, sign out, and listing and revoking sessions.

scute-python is a server SDK and has no sign-in client, so the OTP sign-ins go
through the HTTP helper (POST /otps/login, then /otps/verify with 424242).
Everything after that is the SDK (scute.sessions).
"""

from __future__ import annotations

import pytest

from scute import APIError, InvalidToken, Scute

from .support import Cleanup, LiveAPI, Names, SignedIn, delete_user_later, redact, same_secret, sign_in

pytestmark = pytest.mark.live


def digits(phone: object) -> str:
    return "".join(c for c in str(phone) if c.isdigit())


@pytest.fixture(scope="module")
def bob(api: LiveAPI, scute: Scute, names: Names, cleanup: Cleanup) -> SignedIn:
    """Signed in by SMS OTP with a test phone number (+1 415 555 01xx)."""
    user = sign_in(api, names.phone(1))
    delete_user_later(scute, cleanup, user.user_id)
    return user


def test_email_otp_sign_in(scute: Scute, alice: SignedIn) -> None:
    me = scute.sessions.current_user(alice.access)
    assert me["user"]["id"] == alice.user_id
    assert me["user"]["email"] == alice.identifier
    assert "impersonation" not in me


def test_sms_otp_sign_in(scute: Scute, bob: SignedIn) -> None:
    me = scute.sessions.current_user(bob.access)["user"]
    assert me["id"] == bob.user_id
    assert digits(me["phone"]) == digits(bob.identifier)
    assert scute.tokens.verify(bob.access).user_id == bob.user_id


def test_refresh(scute: Scute, bob: SignedIn) -> None:
    assert bob.refresh, "the app returns no refresh token (refresh_payload is off)"
    fresh = redact(scute.sessions.refresh(bob.refresh))
    assert fresh.get("access")
    assert not same_secret(fresh["access"], bob.access)
    assert scute.tokens.verify(fresh["access"], remote=True).user_id == bob.user_id


def test_lists_sessions(scute: Scute, bob: SignedIn) -> None:
    sessions = scute.sessions.list(bob.user_id)
    assert isinstance(sessions, list) and sessions
    assert all(s.get("id") for s in sessions)


def test_signs_out(api: LiveAPI, scute: Scute, bob: SignedIn) -> None:
    """A second sign-in, signed out; the first session stays."""
    second = sign_in(api, bob.identifier)
    assert second.user_id == bob.user_id
    scute.sessions.sign_out(second.access)
    with pytest.raises(InvalidToken) as ended:
        scute.tokens.verify(second.access, remote=True)
    assert ended.value.reason == "revoked"
    with pytest.raises(APIError) as refused:
        scute.sessions.current_user(second.access)
    assert refused.value.status == 401


def test_revokes_a_session(scute: Scute, bob: SignedIn) -> None:
    """From the backend. The session ids come from users.get, so this doesn't
    lean on sessions.list."""
    sessions = scute.users.get(bob.user_id)["user"]["sessions"]
    assert sessions, "users.get lists no session for a user signed in a moment ago"
    for session in sessions:
        scute.sessions.revoke(bob.user_id, str(session["id"]))
    assert scute.users.get(bob.user_id)["user"]["sessions"] == []
    with pytest.raises(APIError) as refused:
        scute.sessions.refresh(bob.refresh or "")
    assert refused.value.status == 401
