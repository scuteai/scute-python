"""1. App: read the app's data.

The SDK has no app read of its own. It reads the app's public data once, when
it's configured with the app's UUID rather than its public id: tokens carry the
public id, so `scute.tokens.public_app_id` looks it up (GET /v1/apps/:id).
"""

from __future__ import annotations

import pytest

from scute import Scute

from .support import LiveAPI, LiveEnv, SignedIn

pytestmark = pytest.mark.live


def test_reads_the_apps_public_data(api: LiveAPI, live: LiveEnv) -> None:
    app = api.ok("GET", api.apps(), secret=False)
    assert app["id"] == live.app_id
    assert app["email_auth_type"] == "otp"  # sdk_live:setup: sign-in sends a code
    assert app["public_signup"] is True


def test_sdk_finds_the_public_id_from_the_apps_uuid(api: LiveAPI, live: LiveEnv, alice: SignedIn) -> None:
    uuid = str(api.ok("GET", api.apps("/authz/policy"))["app_id"])
    assert uuid != live.app_id
    by_uuid = Scute(app_id=uuid, secret=live.secret, base_url=live.base_url, timeout=30.0)
    try:
        assert by_uuid.tokens.public_app_id == live.app_id
        assert by_uuid.tokens.verify(alice.access).user_id == alice.user_id
    finally:
        by_uuid.close()
