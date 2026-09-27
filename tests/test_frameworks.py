from typing import Annotated, Any

import httpx
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from flask import Flask, g

from scute import Scute, Session
from scute.contrib.fastapi import ScuteAuth as FastAPIAuth
from scute.contrib.flask import ScuteAuth as FlaskAuth

from .conftest import FakeScute, sign_jwt


def scute(fake: FakeScute) -> Scute:
    return Scute(app_id="app1", secret="sk_test", base_url="https://scute.test", transport=httpx.MockTransport(fake.handler))


def token(**claims: Any) -> str:
    import time

    return sign_jwt({"uuid": "user1", "aid": "app1", "exp": int(time.time()) + 600, **claims})


def test_fastapi(fake: FakeScute) -> None:
    app = FastAPI()
    auth = FastAPIAuth(scute(fake))

    @app.get("/me")
    def me(session: Annotated[Session, Depends(auth.session)]) -> dict[str, Any]:
        return {"user": session.user_id}

    @app.post("/invoices/{id}/refund", dependencies=[Depends(auth.require("refund", "invoice:{id}"))])
    def refund(id: str) -> dict[str, str]:
        return {"refunded": id}

    @app.delete("/invoices/{id}", dependencies=[Depends(auth.require("delete", "invoice:{id}"))])
    def delete(id: str) -> dict[str, str]:
        return {"deleted": id}

    web = TestClient(app)
    assert web.get("/me").status_code == 401
    assert web.get("/me", headers={"X-Authorization": token()}).json() == {"user": "user1"}
    assert web.get("/me", headers={"Authorization": f"Bearer {token()}"}).status_code == 200
    web.cookies.set("sc-access-token__app1", token())
    assert web.get("/me").status_code == 200
    web.cookies.clear()

    imp = token(imp=True, act={"kind": "backend", "email": "s@acme.test"})
    res = web.post("/invoices/42/refund", headers={"X-Authorization": imp})
    assert res.json() == {"refunded": "42"}
    sent = fake.paths("/v1/auth/app1/authz/check")[-1]
    import json

    assert json.loads(sent.content) == {"user_id": "user1", "action": "refund", "resource": "invoice:42",
                                        "context": {"impersonated": True, "actor": {"kind": "backend", "email": "s@acme.test"}}}

    denied = web.delete("/invoices/42", headers={"X-Authorization": token()})
    assert denied.status_code == 403
    assert denied.json()["detail"]["error"] == "Ada can't delete invoices."


def test_flask(fake: FakeScute) -> None:
    app = Flask(__name__)
    auth = FlaskAuth(scute(fake))

    @app.get("/me")
    @auth.required
    def me() -> dict[str, str]:
        return {"user": g.scute_session.user_id}

    @app.delete("/invoices/<id>")
    @auth.permission("delete", "invoice:{id}")
    def delete(id: str) -> dict[str, str]:
        return {"deleted": id}

    @app.post("/invoices/<id>/refund")
    @auth.permission("refund", "invoice:{id}")
    def refund(id: str) -> dict[str, str]:
        return {"refunded": id}

    web = app.test_client()
    assert web.get("/me").status_code == 401
    assert web.get("/me", headers={"X-Authorization": token()}).get_json() == {"user": "user1"}
    assert web.post("/invoices/7/refund", headers={"X-Authorization": token()}).get_json() == {"refunded": "7"}
    assert web.delete("/invoices/7", headers={"X-Authorization": token()}).status_code == 403
    assert web.delete("/invoices/7").status_code == 401
