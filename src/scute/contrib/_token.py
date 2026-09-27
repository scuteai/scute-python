from __future__ import annotations

from collections.abc import Callable, Mapping


def access_token(header: Callable[[str], str | None], cookies: Mapping[str, str], app_ids: list[str]) -> str | None:
    """X-Authorization (what the Scute SDKs send), then Authorization: Bearer,
    then the browser SDK's cookie (sc-access-token__<app id>)."""
    token = (header("X-Authorization") or "").strip()
    if token:
        return token
    auth = header("Authorization") or ""
    if auth[:7].lower() == "bearer " and auth[7:].strip():
        return auth[7:].strip()
    for app_id in app_ids:
        value = cookies.get(f"sc-access-token__{app_id}")
        if value:
            return value
    return None
