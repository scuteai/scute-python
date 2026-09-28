"""7 (glue). The FastAPI and Flask integrations, driven with their test clients
and real sessions from this run: a protected route lets the signed-in user in,
turns away a missing or forged token, and require(action, resource) follows the
live policy, including "not while impersonating".
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated, Any

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from flask import Flask, g

from scute import Scute, Session
from scute.contrib.fastapi import ScuteAuth as FastAPIAuth
from scute.contrib.flask import ScuteAuth as FlaskAuth

from .support import Cleanup, LiveEnv, Names, Policy, Secret, SignedIn, redact, with_claims

pytestmark = pytest.mark.live

NOBODY = "00000000-0000-0000-0000-000000000000"


@pytest.fixture(scope="module")
def as_alice(scute: Scute, alice: SignedIn, names: Names, cleanup: Cleanup, app_settings: dict[str, Any]) -> Iterator[Secret]:
    """An access token of a session as alice (support access)."""
    cleanup.add("stop signing in as alice (glue)", lambda: scute.users.stop_impersonating(alice.user_id), order=10)
    started = redact(scute.users.impersonate(alice.user_id, reason=f"{names.prefix} glue test", minutes=10,
                                             actor={"email": names.email(3)}))
    yield started["access"]
    scute.users.stop_impersonating(alice.user_id, session_id=str(started["session_id"]))


def fastapi_app(scute: Scute, policy: Policy) -> FastAPI:
    app = FastAPI()
    auth = FastAPIAuth(scute)

    @app.get("/me")
    def me(session: Annotated[Session, Depends(auth.session)]) -> dict[str, Any]:
        return {"user_id": session.user_id, "impersonated": session.impersonated}

    @app.get("/invoices/{key}", dependencies=[Depends(auth.require("read", policy.invoice + ":{key}"))])
    def read_invoice(key: str) -> dict[str, str]:
        return {"read": key}

    @app.post("/invoices/{key}/refund", dependencies=[Depends(auth.require("refund", policy.invoice + ":{key}"))])
    def refund(key: str) -> dict[str, str]:
        return {"refunded": key}

    @app.post("/docs/{key}/edit", dependencies=[Depends(auth.require("edit", policy.doc + ":{key}"))])
    def edit(key: str) -> dict[str, str]:
        return {"edited": key}

    return app


def flask_app(scute: Scute, policy: Policy) -> Flask:
    app = Flask(__name__)
    auth = FlaskAuth(scute)

    @app.get("/me")
    @auth.required
    def me() -> dict[str, Any]:
        session: Session = g.scute_session
        return {"user_id": session.user_id, "impersonated": session.impersonated}

    @app.get("/invoices/<key>")
    @auth.permission("read", policy.invoice + ":{key}")
    def read_invoice(key: str) -> dict[str, str]:
        return {"read": key}

    @app.post("/invoices/<key>/refund")
    @auth.permission("refund", policy.invoice + ":{key}")
    def refund(key: str) -> dict[str, str]:
        return {"refunded": key}

    @app.post("/docs/<key>/edit")
    @auth.permission("edit", policy.doc + ":{key}")
    def edit(key: str) -> dict[str, str]:
        return {"edited": key}

    return app


def headers(name: str, value: str) -> dict[str, str]:
    """Header values stay Secret, so a failing assert can't print them."""
    return {name: Secret(value)}


def test_fastapi(scute: Scute, live: LiveEnv, alice: SignedIn, policy: Policy, as_alice: Secret) -> None:
    web = TestClient(fastapi_app(scute, policy))
    mine = headers("X-Authorization", alice.access)

    assert web.get("/me").status_code == 401
    forged = web.get("/me", headers=headers("X-Authorization", with_claims(alice.access, uuid=NOBODY)))
    assert forged.status_code == 401 and forged.json()["detail"]["reason"] == "signature"
    assert web.get("/me", headers=mine).json() == {"user_id": alice.user_id, "impersonated": False}
    bearer = headers("Authorization", f"Bearer {alice.access}")
    assert web.get("/me", headers=bearer).status_code == 200
    web.cookies.set(f"sc-access-token__{live.app_id}", alice.access)
    assert web.get("/me").status_code == 200
    web.cookies.clear()

    assert web.get("/invoices/1", headers=mine).json() == {"read": "1"}
    refused = web.post("/invoices/1/refund", headers=mine)
    assert refused.status_code == 403
    assert refused.json()["detail"]["decision"]["reason"] == "no_role_grants_permission"
    assert web.post("/docs/1/edit", headers=mine).status_code == 200

    theirs = headers("X-Authorization", as_alice)
    assert web.get("/me", headers=theirs).json() == {"user_id": alice.user_id, "impersonated": True}
    assert web.get("/invoices/1", headers=theirs).status_code == 200
    blocked = web.post("/docs/1/edit", headers=theirs)
    assert blocked.status_code == 403
    assert blocked.json()["detail"]["decision"]["reason"] == "impersonating"


def test_flask(scute: Scute, live: LiveEnv, alice: SignedIn, policy: Policy, as_alice: Secret) -> None:
    web = flask_app(scute, policy).test_client()
    mine = headers("X-Authorization", alice.access)

    assert web.get("/me").status_code == 401
    forged = web.get("/me", headers=headers("X-Authorization", with_claims(alice.access, uuid=NOBODY)))
    assert forged.status_code == 401 and forged.get_json()["reason"] == "signature"
    assert web.get("/me", headers=mine).get_json() == {"user_id": alice.user_id, "impersonated": False}
    bearer = headers("Authorization", f"Bearer {alice.access}")
    assert web.get("/me", headers=bearer).status_code == 200
    web.set_cookie(f"sc-access-token__{live.app_id}", alice.access)
    assert web.get("/me").status_code == 200
    web.delete_cookie(f"sc-access-token__{live.app_id}")

    assert web.get("/invoices/1", headers=mine).get_json() == {"read": "1"}
    refused = web.post("/invoices/1/refund", headers=mine)
    assert refused.status_code == 403
    assert refused.get_json()["decision"]["reason"] == "no_role_grants_permission"
    assert web.post("/docs/1/edit", headers=mine).status_code == 200

    theirs = headers("X-Authorization", as_alice)
    assert web.get("/me", headers=theirs).get_json() == {"user_id": alice.user_id, "impersonated": True}
    assert web.get("/invoices/1", headers=theirs).status_code == 200
    blocked = web.post("/docs/1/edit", headers=theirs)
    assert blocked.status_code == 403
    assert blocked.get_json()["decision"]["reason"] == "impersonating"
