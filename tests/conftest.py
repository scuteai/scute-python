from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwk(key: rsa.RSAPrivateKey, kid: str) -> dict[str, str]:
    pub = key.public_key().public_numbers()
    return {"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
            "n": b64(pub.n.to_bytes((pub.n.bit_length() + 7) // 8, "big")), "e": b64(pub.e.to_bytes(3, "big"))}


def sign_jwt(claims: dict[str, Any], key: rsa.RSAPrivateKey = KEY, header: dict[str, Any] | None = None) -> str:
    head = b64(json.dumps(header or {"alg": "RS256", "typ": "JWT"}).encode())
    body = b64(json.dumps(claims).encode())
    sig = key.sign(f"{head}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{head}.{body}.{b64(sig)}"


@dataclass
class FakeScute:
    """A stand-in for the Scute API endpoints the SDK calls, as an httpx transport."""

    keys: list[tuple[rsa.RSAPrivateKey, str]] = field(default_factory=lambda: [(KEY, "k1")])
    revoked: set[str] = field(default_factory=set)
    seen: list[httpx.Request] = field(default_factory=list)

    def paths(self, path: str) -> list[httpx.Request]:
        return [r for r in self.seen if r.url.path == path]

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.seen.append(request)
        path, method = request.url.path, request.method
        secret = request.headers.get("authorization") == "Bearer sk_test"
        session = request.headers.get("x-authorization")
        body = json.loads(request.content) if request.content else None

        def ok(data: Any, status: int = 200) -> httpx.Response:
            return httpx.Response(status, json=data)

        if path in ("/v1/auth/app1/.well-known/jwks.json", "/v1/auth/7f1c-uuid/.well-known/jwks.json"):
            return ok({"keys": [jwk(k, kid) for k, kid in self.keys]})
        if path in ("/v1/apps/7f1c-uuid", "/v1/apps/app1") and method == "GET":
            return ok({"id": "app1"})
        if path == "/v1/auth/app1/current_user":
            if method == "DELETE":
                return ok({"message": "ok"})
            if not session or session in self.revoked:
                return ok({"error": "Not authorized"}, 401)
            return ok({"user": {"id": "user1"}})
        if path == "/v1/auth/app1/tokens/refresh":
            return ok({"access": "new", "seen_refresh": request.headers.get("x-refresh-token")})
        if path == "/v1/auth/app1/authz/check":
            return ok({"decision": "allow", "reason": "role_grant", "permission": "invoice:read", "roles": ["clerk"], "echo": body})
        if not secret:
            return ok({"error": "Unauthorized"}, 401)
        if path == "/v1/app1/users" and method == "GET":
            return ok({"users": [{"id": "user1"}], "query": urlparse(str(request.url)).query})
        if path == "/v1/auth/app1/users" and method == "GET":
            return ok({"user": {"id": "user1"} if "ada" in str(request.url) else None})
        if path == "/v1/auth/app1/users" and method == "POST":
            return ok({"user": {"id": "user2", "identifier": body["identifier"]}}, 201)
        if path.startswith("/v1/app1/users/user1"):
            if path.endswith("/sessions"):
                return ok([{"id": "ses1"}])
            return ok({"ok": True})
        if path == "/v1/apps/app1/users/user1/impersonate" and method == "POST":
            return ok({"access": "imp.access", "session_id": "ses1", "echo": body}, 201)
        if path == "/v1/apps/app1/users/user1/impersonations":
            return ok({"impersonations": [{"session_id": "ses1"}]})
        if path == "/v1/apps/app1/users/user1/impersonate" and method == "DELETE":
            return ok({"ended": 1})
        return ok({"error": f"no route {method} {path}"}, 404)


@pytest.fixture
def fake() -> FakeScute:
    return FakeScute()
