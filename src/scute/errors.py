from __future__ import annotations

from typing import Any


class ScuteError(Exception):
    """Base for everything the SDK raises."""


class APIError(ScuteError):
    """Scute answered with an error. `code` is the API's error_code."""

    def __init__(self, message: str, status: int | None = None, code: str | None = None, body: Any = None) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.body = body


class ConnectionError(ScuteError):
    """Scute couldn't be reached."""


class ConfigurationError(ScuteError):
    """Something is missing to make the call (app id, secret key)."""


class InvalidToken(ScuteError):
    """An access token that isn't a live session of this app.

    `reason`: missing, malformed, algorithm, signature, expired, wrong_app,
    not_a_user, revoked.
    """

    def __init__(self, message: str, reason: str) -> None:
        super().__init__(message)
        self.reason = reason
