"""3. Tokens: local verification against the app's JWKS (a tampered, an expired
and another audience's token refused), and the remote check (remote=True).
All of it is the SDK (scute.tokens); the tokens are real ones from this run.
"""

from __future__ import annotations

import time

import pytest

from scute import InvalidToken, Scute
from scute.tokens import Tokens

from .support import LiveAPI, LiveEnv, Secret, SignedIn, jws_parts, with_claims

pytestmark = pytest.mark.live


def reason(tokens: Tokens, token: str | None) -> str:
    with pytest.raises(InvalidToken) as refused:
        tokens.verify(token)
    return refused.value.reason


def test_verifies_locally_with_the_jwks(scute: Scute, live: LiveEnv, alice: SignedIn) -> None:
    session = scute.tokens.verify(alice.access)
    assert session.user_id == alice.user_id
    assert session.app_id == live.app_id
    assert session.workspace_id
    assert session.expires_at > time.time()
    assert not session.impersonated
    assert session.actor is None
    assert session.authz_context() == {}


def test_refuses_a_tampered_token(scute: Scute, alice: SignedIn, nobody: str) -> None:
    assert reason(scute.tokens, with_claims(alice.access, uuid=nobody)) == "signature"
    head, body, sig = str(alice.access).split(".")
    flipped = Secret(f"{head}.{body}.{'A' if sig[0] != 'A' else 'B'}{sig[1:]}")
    assert reason(scute.tokens, flipped) == "signature"


def test_refuses_an_expired_token(scute: Scute, alice: SignedIn) -> None:
    """The same real token, read by a clock past its expiry (and the leeway)."""
    _, claims, _, _ = jws_parts(alice.access)
    later = Tokens(scute, clock=lambda: float(claims["exp"]) + Tokens.LEEWAY + 1)
    assert reason(later, alice.access) == "expired"


def test_refuses_a_token_for_another_audience(api: LiveAPI, scute: Scute) -> None:
    """The policy snapshot is signed with the same key as sessions, but it's
    for another audience (no app id claim): not a session of this app."""
    snapshot = api.ok("GET", api.apps("/authz/snapshot"))["token"]
    assert reason(scute.tokens, snapshot) == "wrong_app"


def test_refuses_what_isnt_a_token(scute: Scute) -> None:
    assert reason(scute.tokens, None) == "missing"
    assert reason(scute.tokens, "not-a-jwt") == "malformed"


def test_remote_check(scute: Scute, alice: SignedIn) -> None:
    """remote=True also asks Scute (one call); the refusal of an ended session
    is in the sign-out and impersonation tests."""
    assert scute.tokens.verify(alice.access, remote=True).user_id == alice.user_id
