"""Plumbing for the live suite: the environment, a small HTTP client for the API
calls the SDK doesn't wrap, sign-ins with test identities, TOTP, JWS checks and
cleanup.

Nothing here prints a secret: tokens, keys and codes are wrapped in `Secret`,
whose repr is masked, so a failing assertion shows `Secret(***)` instead.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import struct
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from scute import APIError, Scute

SUITE = "python"
CODE = "424242"  # what a test identity always gets
ENV_KEYS = ("SCUTE_LIVE_BASE_URL", "SCUTE_LIVE_APP_ID", "SCUTE_LIVE_SECRET")
# Outside the repo: <checkout>/../.sdk-live/python.env (never committed).
DEFAULT_ENV_FILE = Path(__file__).resolve().parents[3] / ".sdk-live" / f"{SUITE}.env"


class Secret(str):
    """A token, key or code. Behaves like the string, but its repr is masked."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "Secret(***)"


def same_secret(a: str | None, b: str | None) -> bool:
    """Compare two secrets without letting pytest diff (and print) them."""
    return a is not None and b is not None and hmac.compare_digest(str(a).encode(), str(b).encode())


# Keys whose values are credentials in the API's answers.
SENSITIVE = frozenset({"access", "refresh", "csrf", "token", "key", "secret", "value", "jws", "signature",
                       "backup_codes", "provisioning_uri", "assertion", "short_token", "access_token", "refresh_token"})


def redact(data: Any, sensitive: bool = False) -> Any:
    """Wrap every credential in an API answer in Secret."""
    if isinstance(data, dict):
        return {k: redact(v, sensitive or k in SENSITIVE) for k, v in data.items()}
    if isinstance(data, list):
        return [redact(v, sensitive) for v in data]
    if sensitive and isinstance(data, str):
        return Secret(data)
    return data


# ── environment ──


@dataclass(frozen=True)
class LiveEnv:
    base_url: str
    app_id: str
    secret: Secret = field(repr=False)
    source: str


def env_file() -> Path:
    return Path(os.environ.get("SCUTE_LIVE_ENV_FILE") or DEFAULT_ENV_FILE)


def parse_env_file(text: str) -> dict[str, str]:
    """KEY=VALUE lines (what `rake sdk_live:setup` prints); `export`, quotes and comments are fine."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.removeprefix("export ").partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        out[key.strip()] = value
    return out


def load_env() -> LiveEnv | None:
    """From the environment, else from the env file. None when anything is missing."""
    values = {k: os.environ.get(k, "").strip() for k in ENV_KEYS}
    source = "environment"
    if not all(values.values()):
        path = env_file()
        try:
            from_file = parse_env_file(path.read_text())
        except OSError:
            from_file = {}
        values = {k: values[k] or from_file.get(k, "").strip() for k in ENV_KEYS}
        source = str(path)
    if not all(values.values()):
        return None
    return LiveEnv(base_url=values["SCUTE_LIVE_BASE_URL"].rstrip("/"), app_id=values["SCUTE_LIVE_APP_ID"],
                   secret=Secret(values["SCUTE_LIVE_SECRET"]), source=source)


def skip_reason() -> str:
    return (f"scute live suite: no credentials (set {', '.join(ENV_KEYS)} or write them to {env_file()}; "
            f'see README "Live suite")')


# ── names: everything this run makes is prefixed live-<runid> ──


@dataclass(frozen=True)
class Names:
    run_id: str

    @property
    def prefix(self) -> str:
        return f"live-{self.run_id}"

    def slug(self, name: str) -> str:
        return f"{self.prefix}-{name}"

    def email(self, n: int) -> str:
        return f"live-{SUITE}-{self.run_id}-{n}+scute_test@example.com"

    def phone(self, n: int) -> str:
        """+1 415 555 01xx (the python suite's test range)."""
        return f"+141555501{(int(self.run_id, 16) + n) % 100:02d}"


# ── HTTP for what the SDK doesn't wrap ──


class APIFailure(AssertionError):
    """The API answered something the test didn't expect (no body, so no secrets)."""


@dataclass
class Reply:
    status: int
    data: Any
    headers: httpx.Headers = field(repr=False)

    @property
    def error_code(self) -> str | None:
        return self.data.get("error_code") if isinstance(self.data, dict) else None


_OPAQUE = re.compile(r"^(?![0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$)[A-Za-z0-9_\-]{24,}$")


def safe_path(path: str) -> str:
    """The path with anything token-like (a challenge token in the URL) masked."""
    head, _, query = path.partition("?")
    parts = ["***" if _OPAQUE.match(p) else p for p in head.split("/")]
    return "/".join(parts) + ("?..." if query else "")


class LiveAPI:
    """JSON over HTTP against the live API. Answers come back with credentials wrapped in Secret."""

    def __init__(self, env: LiveEnv) -> None:
        self.env = env
        self.http = httpx.Client(base_url=env.base_url, timeout=30.0,
                                 headers={"Accept": "application/json", "User-Agent": f"scute-python-live/{SUITE}"})

    def close(self) -> None:
        self.http.close()

    def apps(self, rest: str = "") -> str:
        return f"/v1/apps/{self.env.app_id}{rest}"

    def auth(self, rest: str = "") -> str:
        return f"/v1/auth/{self.env.app_id}{rest}"

    def call(self, method: str, path: str, body: Any = None, *, secret: bool = True, bearer: str | None = None,
             access: str | None = None, params: dict[str, Any] | None = None,
             headers: dict[str, str] | None = None) -> Reply:
        sent = dict(headers or {})
        token = bearer or (self.env.secret if secret else None)
        if token:
            sent["Authorization"] = f"Bearer {token}"
        if access:
            sent["X-Authorization"] = str(access)
        res = self.http.request(method, path, json=body, params=params, headers=sent)
        data: Any = None
        if res.content:
            try:
                data = res.json()
            except ValueError:
                data = None
        return Reply(status=res.status_code, data=redact(data), headers=res.headers)

    def ok(self, method: str, path: str, body: Any = None, **kw: Any) -> Any:
        """The answer's JSON, or APIFailure when it isn't a 2xx."""
        reply = self.call(method, path, body, **kw)
        if not 200 <= reply.status < 300:
            info = reply.data if isinstance(reply.data, dict) else {}
            raise APIFailure(f"{method} {safe_path(path)} answered {reply.status} "
                             f"({info.get('error_code') or '-'}): {info.get('error') or info.get('say') or ''}".rstrip())
        return reply.data

    def gone(self, method: str, path: str, body: Any = None, **kw: Any) -> None:
        """For cleanup: fine when it's already gone (404)."""
        reply = self.call(method, path, body, **kw)
        if reply.status != 404 and not 200 <= reply.status < 300:
            raise APIFailure(f"{method} {safe_path(path)} answered {reply.status} ({reply.error_code or '-'})")


# ── sign-in with a test identity (the SDK is server side: no client for this) ──

# The sign-in helper stands in for the browser SDK. The API lists a user's
# sessions (users.get) only for browser user agents, so it says it's one.
BROWSER = {"User-Agent": "Mozilla/5.0 (compatible; scute-python live suite)"}


@dataclass(frozen=True)
class SignedIn:
    identifier: str
    user_id: str
    access: Secret = field(repr=False)
    refresh: Secret | None = field(repr=False, default=None)


def send_code(api: LiveAPI, identifier: str) -> Secret:
    """POST /otps/login: a test identity gets 424242 and nothing is sent. Returns the challenge token."""
    data = api.ok("POST", api.auth("/otps/login"), {"identifier": identifier}, secret=False, headers=BROWSER)
    return Secret(data["user_id"])  # the challenge token, named user_id for old SDKs


def verify_code(api: LiveAPI, challenge: str, code: str = CODE) -> Any:
    """POST /otps/verify: tokens, or {mfa_required, mfa_challenge} when MFA is on for the user."""
    return api.ok("POST", api.auth("/otps/verify"), {"user_id": str(challenge), "otp": str(code)}, secret=False,
                  headers=BROWSER)


def signed_in(identifier: str, data: Any) -> SignedIn:
    if not isinstance(data, dict) or not data.get("access"):
        raise APIFailure(f"sign-in for {identifier} gave no access token (keys: {sorted(data or {})})")
    return SignedIn(identifier=identifier, user_id=str(data["user_id"]), access=data["access"], refresh=data.get("refresh"))


def sign_in(api: LiveAPI, identifier: str) -> SignedIn:
    return signed_in(identifier, verify_code(api, send_code(api, identifier)))


# ── TOTP (RFC 6238, SHA-1, 6 digits, 30 s) ──


def totp(secret_b32: str, at: float | None = None, *, digits: int = 6, step: int = 30) -> Secret:
    key = base64.b32decode(str(secret_b32).upper() + "=" * (-len(secret_b32) % 8))
    counter = int((time.time() if at is None else at) // step)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    number = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % 10**digits
    return Secret(f"{number:0{digits}d}")


def wrong_totp(secret_b32: str) -> Secret:
    """A code no drift window accepts right now."""
    now = time.time()
    near = {str(totp(secret_b32, now + d)) for d in (-60, -30, 0, 30, 60)}
    n = 0
    while f"{n:06d}" in near:
        n += 1
    return Secret(f"{n:06d}")


# ── JWS ──


def b64url(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jws_parts(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    head, body, sig = str(token).split(".")
    return json.loads(b64url(head)), json.loads(b64url(body)), f"{head}.{body}".encode(), b64url(sig)


def with_claims(token: str, **changes: Any) -> Secret:
    """The same token with its payload edited and the old signature kept (a forgery)."""
    head, body, sig = str(token).split(".")
    claims = json.loads(b64url(body))
    claims.update(changes)
    return Secret(f"{head}.{b64url_encode(json.dumps(claims).encode())}.{sig}")


def verify_jws(token: str, jwks: dict[str, Any]) -> dict[str, Any]:
    """RS256 or ES256 against a JWKS; the payload, or AssertionError."""
    header, payload, signed, signature = jws_parts(token)
    keys = [k for k in jwks.get("keys", []) if header.get("kid") in (None, k.get("kid"))]
    for jwk in keys:
        try:
            if header.get("alg") == "RS256" and jwk.get("kty") == "RSA":
                rsa_key = rsa.RSAPublicNumbers(int.from_bytes(b64url(jwk["e"]), "big"),
                                               int.from_bytes(b64url(jwk["n"]), "big")).public_key()
                rsa_key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
                return payload
            if header.get("alg") == "ES256" and jwk.get("kty") == "EC" and len(signature) == 64:
                ec_key = ec.EllipticCurvePublicNumbers(int.from_bytes(b64url(jwk["x"]), "big"),
                                                       int.from_bytes(b64url(jwk["y"]), "big"), ec.SECP256R1()).public_key()
                der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
                ec_key.verify(der, signed, ec.ECDSA(hashes.SHA256()))
                return payload
        except InvalidSignature:
            continue
    raise AssertionError(f"no key in the JWKS verifies this {header.get('alg')} JWS (kid {header.get('kid')})")


# ── auth MCP (JSON-RPC over Streamable HTTP, JSON answers) ──


class Mcp:
    """One conversation on the app's auth MCP server, as the platform holding an agent key."""

    PROTOCOL = "2025-06-18"

    def __init__(self, api: LiveAPI, key: str) -> None:
        self.api = api
        self.key = key
        self.session_id: str | None = None
        self._id = 0

    @property
    def path(self) -> str:
        return f"/v1/mcp/auth/{self.api.env.app_id}"

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": self.PROTOCOL}
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        return headers

    def send(self, method: str, params: dict[str, Any] | None = None, *, notify: bool = False) -> Reply:
        msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        if not notify:
            self._id += 1
            msg["id"] = self._id
        reply = self.api.call("POST", self.path, msg, bearer=self.key, headers=self._headers())
        self.session_id = reply.headers.get("Mcp-Session-Id") or self.session_id
        return reply

    def result(self, method: str, params: dict[str, Any] | None = None) -> Any:
        reply = self.send(method, params)
        if reply.status != 200 or not isinstance(reply.data, dict) or "result" not in reply.data:
            error = reply.data.get("error") if isinstance(reply.data, dict) else None
            raise APIFailure(f"MCP {method} answered {reply.status}: {error}")
        return reply.data["result"]

    def tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        """A tool's structuredContent (every Scute tool answers with one)."""
        result = self.result("tools/call", {"name": name, "arguments": arguments or {}})
        content: dict[str, Any] = dict(result.get("structuredContent") or {})
        content["_is_error"] = bool(result.get("isError"))
        return content

    def end(self) -> int:
        return self.api.call("DELETE", self.path, bearer=self.key, headers=self._headers()).status


# ── this run's policy (the SDK has no policy API: imported as a document) ──


@dataclass(frozen=True)
class Policy:
    """This run's slice of the app's policy (all slugs live-<runid>-...)."""

    invoice: str
    doc: str
    clerk: str
    editor: str
    assistant: str
    auditor: str
    cashier: str
    document: dict[str, Any] = field(repr=False)

    @property
    def roles(self) -> tuple[str, ...]:
        return (self.clerk, self.editor, self.assistant, self.auditor, self.cashier)

    @property
    def resources(self) -> tuple[str, ...]:
        return (self.invoice, self.doc)


def policy_for(n: Names) -> Policy:
    """invoice: read; approve under 5000; pay with a reviewer's approval; refund.
    doc: read; edit (not while someone is signed in as the user); delete after
    verifying. clerk and editor are for people, assistant and cashier for agents."""
    invoice, doc = n.slug("invoice"), n.slug("doc")
    clerk, editor, assistant, auditor = n.slug("clerk"), n.slug("editor"), n.slug("assistant"), n.slug("auditor")
    cashier = n.slug("cashier")
    document: dict[str, Any] = {
        "scute_policy": 1,
        "resources": {
            invoice: {"name": "Live invoice", "actions": ["approve", "pay", "read", "refund"]},
            doc: {"name": "Live doc", "actions": ["delete", "edit", "read"]},
        },
        "permissions": {
            f"{invoice}:pay": {"requires_approval": True},
            f"{doc}:edit": {"blocked_while_impersonating": True},
            f"{doc}:delete": {"requires_verification": True, "verification_method": "any"},
        },
        "roles": {
            clerk: {"name": "Live clerk", "permissions": [
                f"{invoice}:read", f"{invoice}:pay",
                {"permission": f"{invoice}:approve", "when": {"lt": [{"var": "resource.amount"}, 5000]}}]},
            editor: {"name": "Live editor", "permissions": [f"{doc}:read", f"{doc}:edit", f"{doc}:delete"]},
            assistant: {"name": "Live assistant", "permissions": [
                f"{invoice}:read", f"{invoice}:approve", f"{invoice}:refund", f"{doc}:delete"]},
            auditor: {"name": "Live auditor", "permissions": [f"{invoice}:read"]},
            cashier: {"name": "Live cashier", "permissions": [f"{invoice}:read", f"{invoice}:pay", f"{doc}:delete"]},
        },
    }
    return Policy(invoice=invoice, doc=doc, clerk=clerk, editor=editor, assistant=assistant, auditor=auditor,
                  cashier=cashier, document=document)


def assign_role(api: LiveAPI, cleanup: Cleanup, user_id: str, role: str) -> None:
    """POST /authz/users/:id/roles (the SDK has no role API), taken back at the end."""
    revoke_role_later(api, cleanup, user_id, role)
    api.ok("POST", api.apps(f"/authz/users/{user_id}/roles"), {"role": role})


def revoke_role_later(api: LiveAPI, cleanup: Cleanup, user_id: str, role: str) -> None:
    cleanup.add(f"revoke {role} from {user_id}",
                lambda: api.gone("DELETE", api.apps(f"/authz/users/{user_id}/roles/{role}")), order=30)


def delete_user_later(scute: Scute, cleanup: Cleanup, user_id: str) -> None:
    def undo() -> None:
        try:
            scute.users.delete(user_id)
        except APIError as e:
            if e.status != 404:
                raise

    cleanup.add(f"delete user {user_id}", undo, order=40)


# ── cleanup and the decision trail ──


class Cleanup:
    """Undo steps run at the end of the session, even after failures: lower
    `order` first, and within an order the last added first."""

    def __init__(self) -> None:
        self._steps: list[tuple[int, int, str, Callable[[], object]]] = []

    def add(self, label: str, undo: Callable[[], object], order: int = 50) -> None:
        self._steps.append((order, -len(self._steps), label, undo))

    def run(self) -> list[str]:
        failures = []
        for _, _, label, undo in sorted(self._steps, key=lambda s: (s[0], s[1])):
            try:
                undo()
            except Exception as e:  # noqa: BLE001 - every step runs; failures are reported together
                failures.append(f"{label}: {type(e).__name__}: {e}")
        self._steps.clear()
        return failures


@dataclass(frozen=True)
class Expected:
    """A check made earlier that the decision log should have a row for."""

    where: tuple[tuple[str, str], ...]  # the decisions query (user_id=... or agent_id=...)
    permission: str
    decision: str
    via: str | None = None


@dataclass
class Trail:
    expected: list[Expected] = field(default_factory=list)

    def add(self, permission: str, decision: str, *, user_id: str | None = None, agent_id: str | None = None,
            via: str | None = None) -> None:
        where = tuple((k, v) for k, v in (("user_id", user_id), ("agent_id", agent_id)) if v)
        self.expected.append(Expected(where=where, permission=permission, decision=decision, via=via))


def missing_rows(expected: Iterable[Expected], rows_for: Callable[[tuple[tuple[str, str], ...]], list[dict[str, Any]]]) -> list[Expected]:
    """The expected checks with no matching decision row yet."""
    cache: dict[tuple[tuple[str, str], ...], list[dict[str, Any]]] = {}
    missing = []
    for e in expected:
        rows = cache.setdefault(e.where, rows_for(e.where))
        if not any(r.get("permission") == e.permission and r.get("decision") == e.decision and
                   (e.via is None or (r.get("details") or {}).get("via") == e.via) for r in rows):
            missing.append(e)
    return missing
