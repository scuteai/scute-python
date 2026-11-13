import json
import time
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


def test_a_step_up_or_approval_answer_is_a_403_not_an_allow(fake: FakeScute) -> None:
    fast = FastAPI()
    fauth = FastAPIAuth(scute(fake))

    @fast.post("/invoices/{id}/pay", dependencies=[Depends(fauth.require("pay", "invoice:{id}"))])
    def pay_fast(id: str) -> dict[str, str]:
        return {"paid": id}

    @fast.post("/invoices/{id}/approve", dependencies=[Depends(fauth.require("approve", "invoice:{id}"))])
    def approve(id: str) -> dict[str, str]:
        return {"approved": id}

    web = TestClient(fast)
    for action, decision in (("pay", "allow_with_step_up"), ("approve", "allow_with_approval")):
        res = web.post(f"/invoices/9/{action}", headers={"X-Authorization": token()})
        assert res.status_code == 403
        assert res.json()["detail"]["decision"]["decision"] == decision

    flask_app = Flask(__name__)
    lauth = FlaskAuth(scute(fake))

    @flask_app.post("/invoices/<id>/pay")
    @lauth.permission("pay", "invoice:{id}")
    def pay(id: str) -> dict[str, str]:
        return {"paid": id}

    res = flask_app.test_client().post("/invoices/9/pay", headers={"X-Authorization": token()})
    assert res.status_code == 403
    assert res.get_json()["decision"]["decision"] == "allow_with_step_up"


def test_flask_checks_carry_the_impersonation_context_and_read_every_token_source(fake: FakeScute) -> None:
    app = Flask(__name__)
    auth = FlaskAuth(scute(fake))

    @app.post("/invoices/<id>/refund")
    @auth.permission("refund", "invoice:{id}")
    def refund(id: str) -> dict[str, Any]:
        return {"refunded": id, "decision": g.scute_decision.decision}

    web = app.test_client()
    actor = {"kind": "backend", "email": "s@acme.test"}
    res = web.post("/invoices/7/refund", headers={"X-Authorization": token(imp=True, act=actor)})
    assert res.get_json() == {"refunded": "7", "decision": "allow"}
    sent = json.loads(fake.paths("/v1/auth/app1/authz/check")[-1].content)
    assert sent == {"user_id": "user1", "action": "refund", "resource": "invoice:7",
                    "context": {"impersonated": True, "actor": actor}}

    web.post("/invoices/8/refund", headers={"X-Authorization": token()})
    assert "context" not in json.loads(fake.paths("/v1/auth/app1/authz/check")[-1].content)

    assert web.post("/invoices/7/refund", headers={"Authorization": f"Bearer {token()}"}).status_code == 200
    web.set_cookie("sc-access-token__app1", token())
    assert web.post("/invoices/7/refund").status_code == 200
    web.delete_cookie("sc-access-token__app1")
    expired = web.post("/invoices/7/refund", headers={"X-Authorization": token(exp=int(time.time()) - 3600)})
    assert (expired.status_code, expired.get_json()["reason"]) == (401, "expired")


def test_remote_mode_refuses_a_revoked_session(fake: FakeScute) -> None:
    app = FastAPI()
    auth = FastAPIAuth(scute(fake), remote=True)

    @app.get("/me")
    def me(session: Annotated[Session, Depends(auth.session)]) -> dict[str, Any]:
        return {"user": session.user_id}

    web = TestClient(app)
    live = token()
    assert web.get("/me", headers={"X-Authorization": live}).status_code == 200
    fake.revoked.add(live)
    res = web.get("/me", headers={"X-Authorization": live})
    assert (res.status_code, res.json()["detail"]["reason"]) == (401, "revoked")
