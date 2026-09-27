from __future__ import annotations

import base64
import binascii
import json
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .errors import APIError, InvalidToken

if TYPE_CHECKING:
    from .client import Scute


@dataclass(frozen=True)
class Session:
    """A verified access token: who the user is, and whether someone else is
    signed in as them (support access)."""

    user_id: str
    app_id: str
    workspace_id: str | None
    expires_at: float
    actor: dict[str, Any] | None
    claims: dict[str, Any] = field(repr=False)

    @property
    def impersonated(self) -> bool:
        return self.claims.get("imp") is True

    def authz_context(self) -> dict[str, Any]:
        """Context for authorization checks made for this request: a
        permission marked "not while impersonating" is refused when someone is
        signed in as the user."""
        return {"impersonated": True, "actor": self.actor or "unknown"} if self.impersonated else {}


def _b64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class Tokens:
    """Verifies your users' access tokens locally with the app's signing keys
    (RS256, from the app's JWKS). Local verification can't see a session that
    was revoked a moment ago: pass remote=True where that matters (one call).

        session = scute.tokens.verify(token)   # raises InvalidToken
        session.user_id
    """

    KEYS_TTL = 600  # re-read the keys every 10 minutes
    REFETCH_AFTER = 60  # on an unknown key, re-read at most once a minute
    LEEWAY = 30  # seconds of clock skew allowed on exp
    ALGORITHMS = ("RS256",)

    def __init__(self, client: Scute, clock: Callable[[], float] = time.time) -> None:
        self._client = client
        self._clock = clock
        self._lock = threading.Lock()
        self._keys: dict[str, rsa.RSAPublicKey] | None = None
        self._fetched_at: float | None = None
        self._public_app_id: str | None = None

    def verify(self, token: str | None, *, remote: bool = False) -> Session:
        if not token:
            raise InvalidToken("No access token", "missing")
        header, claims, signed, signature = self._decode(token)
        if header.get("alg") not in self.ALGORITHMS:
            raise InvalidToken(f"Unexpected token algorithm {header.get('alg')!r}", "algorithm")
        self._verify_signature(header, signed, signature)
        session = self._check_claims(claims)
        if remote:
            self._confirm_live(token)
        return session

    @property
    def public_app_id(self) -> str:
        """The id the app's tokens carry (aid): the app's public id ("app_...")."""
        with self._lock:
            if self._public_app_id is None:
                if self._client.app_id.startswith("app_"):
                    self._public_app_id = self._client.app_id
                else:
                    self._public_app_id = str(self._client.user_request("GET", self._client.apps_path())["id"])
            return self._public_app_id

    # ── internals ──

    def _decode(self, token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
        parts = token.split(".")
        if len(parts) != 3:
            raise InvalidToken("Not a JWT", "malformed")
        try:
            header = json.loads(_b64(parts[0]))
            claims = json.loads(_b64(parts[1]))
            signature = _b64(parts[2])
        except (ValueError, binascii.Error) as e:
            raise InvalidToken("Not a JWT", "malformed") from e
        if not isinstance(header, dict) or not isinstance(claims, dict):
            raise InvalidToken("Not a JWT", "malformed")
        return header, claims, f"{parts[0]}.{parts[1]}".encode(), signature

    def _verify_signature(self, header: dict[str, Any], signed: bytes, signature: bytes) -> None:
        if any(self._ok(k, signed, signature) for k in self._matching(header)):
            return
        # The keys may have rotated since the last read.
        if self._refetch_allowed() and any(self._ok(k, signed, signature) for k in self._matching(header, refresh=True)):
            return
        raise InvalidToken("The token's signature doesn't match the app's keys", "signature")

    @staticmethod
    def _ok(key: rsa.RSAPublicKey, signed: bytes, signature: bytes) -> bool:
        try:
            key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
            return True
        except InvalidSignature:
            return False

    def _check_claims(self, claims: dict[str, Any]) -> Session:
        exp = claims.get("exp")
        if not isinstance(exp, (int, float)) or isinstance(exp, bool):
            raise InvalidToken("The token has no expiry", "malformed")
        if exp + self.LEEWAY < self._clock():
            raise InvalidToken("The token has expired", "expired")
        if claims.get("aid") != self.public_app_id:
            raise InvalidToken("The token is for another app", "wrong_app")
        if claims.get("m2m") or not claims.get("uuid"):
            raise InvalidToken("Not a user's session", "not_a_user")
        return Session(user_id=str(claims["uuid"]), app_id=str(claims["aid"]), workspace_id=claims.get("wid"),
                       expires_at=float(exp), actor=claims.get("act") if claims.get("imp") is True else None, claims=claims)

    def _confirm_live(self, token: str) -> None:
        try:
            self._client.sessions.current_user(token)
        except APIError as e:
            if e.status in (401, 403, 404):
                raise InvalidToken("The session has ended", "revoked") from e
            raise

    def _matching(self, header: dict[str, Any], refresh: bool = False) -> list[rsa.RSAPublicKey]:
        keys = self._signing_keys(refresh)
        kid = header.get("kid")
        if kid is None:
            return list(keys.values())
        return [keys[kid]] if kid in keys else []

    def _signing_keys(self, refresh: bool) -> dict[str, rsa.RSAPublicKey]:
        with self._lock:
            now = self._clock()
            stale = self._fetched_at is None or now - self._fetched_at > self.KEYS_TTL
            if refresh or stale or self._keys is None:
                self._keys = self._fetch_keys()
                self._fetched_at = now
            return self._keys

    def _refetch_allowed(self) -> bool:
        with self._lock:
            return self._fetched_at is None or self._clock() - self._fetched_at > self.REFETCH_AFTER

    def _fetch_keys(self) -> dict[str, rsa.RSAPublicKey]:
        data = self._client.user_request("GET", self._client.auth_path("/.well-known/jwks.json")) or {}
        out: dict[str, rsa.RSAPublicKey] = {}
        for i, jwk in enumerate(data.get("keys") or []):
            if jwk.get("kty") != "RSA" or (jwk.get("alg") not in (None, *self.ALGORITHMS)):
                continue
            n = int.from_bytes(_b64(jwk["n"]), "big")
            e = int.from_bytes(_b64(jwk["e"]), "big")
            out[jwk.get("kid") or f"key{i}"] = rsa.RSAPublicNumbers(e, n).public_key()
        return out
