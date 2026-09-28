"""2. Sign-in with test identities: email OTP and SMS OTP. Then the user,
refresh, sign out, and listing and revoking sessions.

scute-python is a server SDK and has no sign-in client, so the OTP sign-ins go
through the HTTP helper (POST /otps/login, then /otps/verify with 424242).
Everything after that is the SDK (scute.sessions).
"""

from __future__ import annotations

from typing import Any

import pytest

from scute import APIError, InvalidToken, Scute

from .support import Cleanup, LiveAPI, Names, SignedIn, delete_user_later, redact, same_secret, sign_in

pytestmark = pytest.mark.live

# Confirmed against scute-api-v2 (v21); see the PR for the evidence.
REFRESHED_AID = ("API: a refreshed access token carries aid = the app's internal UUID (api token_session.rb:300, "
                 "jwt_session), a sign-in token the public id (token_session.rb:57), so tokens.verify refuses it: wrong_app")
SESSIONS_NEED_A_USER = ("API: /v1/:app_id/users/:id/sessions answers 401 Not authorized to the app's secret key alone; "
                        "it also wants a user session in X-Authorization (api sessions_controller.rb:6-8)")


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


@pytest.fixture(scope="module")
def refreshed(scute: Scute, bob: SignedIn, cleanup: Cleanup) -> dict[str, Any]:
    """bob's session, refreshed once (signed out at the end if it's still live)."""
    assert bob.refresh, "the app returns no refresh token (refresh_payload is off)"
    fresh: dict[str, Any] = redact(scute.sessions.refresh(bob.refresh))

    def sign_out() -> None:
        try:
            scute.sessions.sign_out(fresh["access"])
        except APIError as e:
            if e.status != 401:  # already ended (revoked) is fine
                raise

    cleanup.add("sign bob out", sign_out, order=35)
    return fresh


def test_refresh(scute: Scute, bob: SignedIn, refreshed: dict[str, Any]) -> None:
    assert refreshed.get("access")
    assert not same_secret(refreshed["access"], bob.access)
    assert scute.sessions.current_user(refreshed["access"])["user"]["id"] == bob.user_id  # Scute takes it


@pytest.mark.xfail(strict=True, raises=InvalidToken, reason=REFRESHED_AID)
def test_a_refreshed_token_verifies_locally(scute: Scute, bob: SignedIn, refreshed: dict[str, Any]) -> None:
    assert scute.tokens.verify(refreshed["access"]).user_id == bob.user_id


@pytest.mark.xfail(strict=True, raises=APIError, reason=SESSIONS_NEED_A_USER)
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


@pytest.mark.xfail(strict=True, raises=APIError, reason=SESSIONS_NEED_A_USER)
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
