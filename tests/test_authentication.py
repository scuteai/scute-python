from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives import serialization

from scute import InvalidToken, Scute
from scute.tokens import Tokens

from .conftest import KEY, OTHER_KEY, FakeScute, b64, sign_jwt

NOW = 1_800_000_000.0


def client(fake: FakeScute, app_id: str = "app1") -> Scute:
    return Scute(app_id=app_id, secret="sk_test", base_url="https://scute.test", transport=httpx.MockTransport(fake.handler))


def tokens(fake: FakeScute, clock: Any = lambda: NOW, app_id: str = "app1") -> Tokens:
    return Tokens(client(fake, app_id), clock=clock)


def jwt(key: Any = KEY, header: dict[str, Any] | None = None, **claims: Any) -> str:
    body = {"uuid": "user1", "aid": "app1", "wid": "ws1", "exp": int(NOW) + 600, **claims}
    return sign_jwt({k: v for k, v in body.items() if v is not None}, key=key, header=header)


def reason(verifier: Tokens, token: Any) -> str | None:
    try:
        verifier.verify(token)
        return None
    except InvalidToken as e:
        return e.reason


def test_verifies_a_session_token(fake: FakeScute) -> None:
    session = tokens(fake).verify(jwt())
    assert (session.user_id, session.app_id, session.workspace_id, session.actor) == ("user1", "app1", "ws1", None)
    assert not session.impersonated
    assert session.authz_context() == {}
    assert len(fake.paths("/v1/auth/app1/.well-known/jwks.json")) == 1


def test_refuses_what_isnt_a_live_session_of_this_app(fake: FakeScute) -> None:
    t = tokens(fake)
    assert reason(t, None) == "missing"
    assert reason(t, "nope") == "malformed"
    assert reason(t, jwt(key=OTHER_KEY)) == "signature"
    assert reason(t, jwt(exp=int(NOW) - 31)) == "expired"
    assert reason(t, jwt(exp=None)) == "malformed"
    assert reason(t, jwt(aid="app_other")) == "wrong_app"
    assert reason(t, jwt(m2m=True)) == "not_a_user"
    assert reason(t, jwt(uuid=None)) == "not_a_user"
    assert reason(t, jwt(exp=int(NOW) - 10)) is None  # a little clock skew is fine


def test_only_rs256(fake: FakeScute) -> None:
    claims = b64(json.dumps({"uuid": "user1", "aid": "app1", "exp": int(NOW) + 600}).encode())
    none = f"{b64(json.dumps({'alg': 'none'}).encode())}.{claims}."
    assert reason(tokens(fake), none) in ("malformed", "algorithm")

    # HMAC signed with the public key as the secret (the classic confusion)
    head = b64(json.dumps({"alg": "HS256"}).encode())
    pem = KEY.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    mac = hmac.new(pem, f"{head}.{claims}".encode(), hashlib.sha256).digest()
    assert reason(tokens(fake), f"{head}.{claims}.{b64(mac)}") == "algorithm"


def test_doesnt_hammer_the_keys_on_unknown_signatures(fake: FakeScute) -> None:
    t = tokens(fake)
    t.verify(jwt())
    for _ in range(3):
        assert reason(t, jwt(key=OTHER_KEY, header={"alg": "RS256", "kid": "k9"})) == "signature"
    assert len(fake.paths("/v1/auth/app1/.well-known/jwks.json")) == 1


def test_picks_up_rotated_keys_after_a_minute(fake: FakeScute) -> None:
    now = [NOW]
    t = tokens(fake, clock=lambda: now[0])
    t.verify(jwt())
    fake.keys = [(OTHER_KEY, "k2")]
    now[0] = NOW + 61
    assert t.verify(jwt(key=OTHER_KEY, exp=int(NOW) + 700)).user_id == "user1"


def test_reads_who_is_really_acting(fake: FakeScute) -> None:
    actor = {"kind": "backend", "email": "support@acme.test"}
    session = tokens(fake).verify(jwt(imp=True, act=actor))
    assert session.impersonated
    assert session.actor == actor
    assert session.authz_context() == {"impersonated": True, "actor": actor}


def test_remote_catches_a_revoked_session(fake: FakeScute) -> None:
    t = tokens(fake)
    token = jwt()
    assert t.verify(token, remote=True).user_id == "user1"
    fake.revoked.add(token)
    with pytest.raises(InvalidToken) as e:
        t.verify(token, remote=True)
    assert e.value.reason == "revoked"
    assert t.verify(token).user_id == "user1"  # locally it still verifies until it expires


def test_learns_the_public_app_id(fake: FakeScute) -> None:
    t = tokens(fake, app_id="7f1c-uuid")
    assert t.verify(jwt()).app_id == "app1"
    assert t.public_app_id == "app1"


def test_real_clock_default() -> None:
    assert Tokens.__init__.__defaults__ == (time.time,)
