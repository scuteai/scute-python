import time
from typing import Annotated, Any

import httpx
import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from flask import Flask

from scute import Scute
from scute.contrib.fastapi import ScuteAuth as FastAPIAuth
from scute.contrib.flask import ScuteAuth as FlaskAuth

from .conftest import FakeScute, sign_jwt

HEADER = "x-scute-client-ip"


def client(fake: FakeScute, **kwargs: Any) -> Scute:
    return Scute(app_id="app1", secret="sk_test", base_url="https://scute.test",
                 transport=httpx.MockTransport(fake.handler), **kwargs)


def sent_ip(fake: FakeScute) -> str | None:
    return fake.seen[-1].headers.get(HEADER)


def token() -> str:
    return sign_jwt({"uuid": "user1", "aid": "app1", "exp": int(time.time()) + 600})


def test_sends_the_client_ip_on_secret_key_calls(fake: FakeScute) -> None:
    c = client(fake, client_ip=" 203.0.113.24 ")
    assert c.client_ip == "203.0.113.24"
    c.users.create("ada@example.com")
    assert sent_ip(fake) == "203.0.113.24"
    c.authz.check(user_id="user1", action="refund", resource="invoice:42")
    assert sent_ip(fake) == "203.0.113.24"


def test_sends_nothing_without_one(fake: FakeScute) -> None:
    c = client(fake)
    assert c.client_ip is None
    c.users.create("ada@example.com")
    assert HEADER not in fake.seen[-1].headers
    assert client(fake, client_ip="  ").client_ip is None


def test_not_sent_on_calls_without_the_secret_key(fake: FakeScute) -> None:
    c = client(fake, client_ip="203.0.113.24")
    c.sessions.current_user("user.access")
    assert fake.seen[-1].url.path == "/v1/auth/app1/current_user"
    assert HEADER not in fake.seen[-1].headers


def test_with_client_ip_is_a_copy_for_one_person(fake: FakeScute) -> None:
    base = client(fake, client_ip="203.0.113.24")
    scoped = base.with_client_ip("2001:db8::1")
    scoped.users.create("ada@example.com")
    assert sent_ip(fake) == "2001:db8::1"
    base.users.create("ada@example.com")
    assert sent_ip(fake) == "203.0.113.24"  # the original is unchanged
    assert scoped.http is base.http and scoped.tokens is base.tokens  # one connection pool, one key cache
    base.with_client_ip(None).users.create("ada@example.com")
    assert HEADER not in fake.seen[-1].headers


def test_a_per_call_client_ip_wins(fake: FakeScute) -> None:
    c = client(fake, client_ip="203.0.113.24")
    c.request("POST", c.auth_path("/users"), {"identifier": "ada@example.com"}, client_ip="::ffff:198.51.100.7")
    assert sent_ip(fake) == "::ffff:198.51.100.7"
    c.request("POST", c.auth_path("/users"), {"identifier": "ada@example.com"})
    assert sent_ip(fake) == "203.0.113.24"


@pytest.mark.parametrize("bad", ["203.0.113.0/24", "203.0.113.24, 198.51.100.7", "example.com", "fe80::1%eth0", "999.1.1.1"])
def test_refuses_anything_but_one_address(fake: FakeScute, bad: str) -> None:
    with pytest.raises(ValueError, match="one IPv4 or IPv6 address"):
        client(fake, client_ip=bad)
    with pytest.raises(ValueError):
        client(fake).with_client_ip(bad)
    c = client(fake)
    with pytest.raises(ValueError):
        c.request("GET", c.app_path("/users"), client_ip=bad)
    assert fake.seen == []  # nothing was sent


def test_fastapi_fills_it_from_the_request(fake: FakeScute) -> None:
    app = FastAPI()
    auth = FastAPIAuth(client(fake))

    @app.post("/signup")
    def signup(scute: Annotated[Scute, Depends(auth.client)]) -> dict[str, Any]:
        return scute.users.create("ada@example.com")  # type: ignore[no-any-return]

    @app.post("/invoices/{id}/refund", dependencies=[Depends(auth.require("refund", "invoice:{id}"))])
    def refund(id: str) -> dict[str, str]:
        return {"refunded": id}

    web = TestClient(app, client=("203.0.113.24", 50000))
    assert web.post("/signup").status_code == 200
    assert sent_ip(fake) == "203.0.113.24"
    assert web.post("/invoices/42/refund", headers={"X-Authorization": token()}).json() == {"refunded": "42"}
    assert sent_ip(fake) == "203.0.113.24"

    # Not an address (the test client's default host, "testclient"): nothing is sent.
    assert TestClient(app).post("/signup").status_code == 200
    assert HEADER not in fake.seen[-1].headers
    # A forwarded-for header isn't read: only what the server says the peer is.
    web.post("/signup", headers={"X-Forwarded-For": "198.51.100.7"})
    assert sent_ip(fake) == "203.0.113.24"


def test_flask_fills_it_from_the_request(fake: FakeScute) -> None:
    app = Flask(__name__)
    auth = FlaskAuth(client(fake))

    @app.post("/signup")
    def signup() -> Any:
        return auth.client().users.create("ada@example.com")

    @app.post("/invoices/<id>/refund")
    @auth.permission("refund", "invoice:{id}")
    def refund(id: str) -> dict[str, str]:
        return {"refunded": id}

    web = app.test_client()
    web.post("/signup", environ_base={"REMOTE_ADDR": "203.0.113.24"})
    assert sent_ip(fake) == "203.0.113.24"
    res = web.post("/invoices/7/refund", headers={"X-Authorization": token(), "X-Forwarded-For": "198.51.100.7"},
                   environ_base={"REMOTE_ADDR": "2001:db8::1"})
    assert res.get_json() == {"refunded": "7"}
    assert sent_ip(fake) == "2001:db8::1"
    web.post("/signup", environ_base={"REMOTE_ADDR": "not-an-ip"})
    assert HEADER not in fake.seen[-1].headers
