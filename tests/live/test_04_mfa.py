"""4. MFA: enroll TOTP (the code computed from the enrollment secret, RFC 6238),
verify the enrollment; the next sign-in then needs MFA and is finished with
TOTP; backup codes; the method removed.

The SDK has no MFA API (MFA is the sign-in client's job; the SDK verifies the
session it ends in). So this goes through the HTTP helper, and the SDK checks
the session MFA produced.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field

import pytest

from scute import Scute

from .support import (
    BROWSER,
    Cleanup,
    LiveAPI,
    Names,
    Secret,
    SignedIn,
    delete_user_later,
    send_code,
    sign_in,
    signed_in,
    totp,
    verify_code,
    wrong_totp,
)

pytestmark = pytest.mark.live


@dataclass
class Carol:
    """The MFA user, filled in as the module goes."""

    first: SignedIn
    totp_secret: Secret | None = None
    enrollment_id: str | None = None
    backup_codes: list[Secret] = field(default_factory=list)
    mfa_session: SignedIn | None = None
    verification: Secret | None = None


@pytest.fixture(scope="module")
def mfa_on(api: LiveAPI, cleanup: Cleanup) -> Iterator[None]:
    """MFA optional (asked of users who set it up), TOTP and backup codes
    allowed. Put back after the module."""
    app = api.ok("GET", api.apps(), secret=False)
    before = {"mfa_policy": app["mfa_policy"], "mfa_methods_allowed": app["mfa_methods_allowed"]}
    methods = sorted(set(before["mfa_methods_allowed"] or []) | {"totp", "backup_codes"})

    def restore() -> None:
        api.ok("PATCH", api.apps(), {"app": before})

    cleanup.add("restore MFA settings", restore, order=90)
    api.ok("PATCH", api.apps(), {"app": {"mfa_policy": "optional", "mfa_methods_allowed": methods}})
    yield
    restore()


@pytest.fixture(scope="module")
def carol(api: LiveAPI, scute: Scute, names: Names, cleanup: Cleanup, mfa_on: None) -> Carol:
    first = sign_in(api, names.email(4))
    delete_user_later(scute, cleanup, first.user_id)
    return Carol(first=first)


def test_enrolls_totp(api: LiveAPI, carol: Carol) -> None:
    me = carol.first.access
    started = api.ok("POST", api.auth("/mfa/enroll"), {"method": "totp", "name": "live suite"}, secret=False, access=me)
    assert started["enrollment"]["verified"] is False
    assert started["provisioning_uri"].startswith("otpauth://totp/")
    carol.enrollment_id, carol.totp_secret = str(started["enrollment"]["id"]), started["secret"]

    body = {"enrollment_id": carol.enrollment_id, "code": wrong_totp(carol.totp_secret)}
    assert api.call("POST", api.auth("/mfa/enroll/verify"), body, secret=False, access=me).status == 422
    body["code"] = totp(carol.totp_secret)
    verified = api.ok("POST", api.auth("/mfa/enroll/verify"), body, secret=False, access=me)
    assert verified["enrollment"]["verified"] is True


def test_backup_codes(api: LiveAPI, carol: Carol) -> None:
    me = carol.first.access
    carol.backup_codes = list(api.ok("POST", api.auth("/mfa/backup-codes"), {}, secret=False, access=me)["backup_codes"])
    assert carol.backup_codes
    methods = api.ok("GET", api.auth("/mfa/methods"), secret=False, access=me)
    assert methods["mfa_enabled"] is True
    assert methods["backup_codes_available"] == len(carol.backup_codes)
    assert [m["method"] for m in methods["methods"] if m["verified"]] == ["totp"]


def test_sign_in_needs_mfa_and_finishes_with_totp(api: LiveAPI, scute: Scute, carol: Carol) -> None:
    assert carol.totp_secret, "needs the enrollment above"
    answer = verify_code(api, send_code(api, carol.first.identifier))
    assert answer.get("mfa_required") is True
    assert "access" not in answer
    challenge = answer["mfa_challenge"]
    assert challenge["method"] == "totp"
    path = Secret(api.auth(f"/challenges/{challenge['token']}/verify"))  # the token is in the path

    wrong = api.call("POST", path, {"code": wrong_totp(carol.totp_secret)}, headers=BROWSER)
    assert wrong.status == 422
    carol.mfa_session = signed_in(carol.first.identifier,
                                  api.ok("POST", path, {"code": totp(carol.totp_secret)}, headers=BROWSER))
    session = scute.tokens.verify(carol.mfa_session.access, remote=True)
    assert session.user_id == carol.first.user_id


def test_a_backup_code_works_once(api: LiveAPI, carol: Carol) -> None:
    assert carol.backup_codes, "needs the backup codes above"
    code = carol.backup_codes[0]

    def step_up() -> Secret:
        made = api.ok("POST", api.auth("/challenges"),
                      {"purpose": "step_up", "method": "backup_code", "app_user_id": carol.first.user_id})
        return Secret(made["challenge"]["token"])

    first = step_up()
    done = api.ok("POST", api.auth(f"/challenges/{first}/verify"), {"code": code})
    assert done["status"] == "completed"
    assert done["remaining_backup_codes"] == len(carol.backup_codes) - 1
    carol.verification = first
    reused = api.call("POST", api.auth(f"/challenges/{step_up()}/verify"), {"code": code})
    assert reused.status == 422


def test_removes_the_method(api: LiveAPI, carol: Carol) -> None:
    """Removing a method asks to re-verify once the session is older than the
    app's mfa_reverify_minutes (5 at least). This session is seconds old, so the
    API doesn't ask; the completed backup-code step-up is passed as `challenge`
    anyway, the way a client would later on. The refusal path isn't reachable
    within a run without waiting 5 minutes."""
    assert carol.mfa_session and carol.enrollment_id, "needs the MFA sign-in above"
    me = carol.mfa_session.access
    removed = api.call("DELETE", api.auth(f"/mfa/methods/{carol.enrollment_id}"), secret=False, access=me,
                       params={"challenge": carol.verification} if carol.verification else None)
    assert removed.status == 204
    status = api.ok("GET", api.auth("/mfa/status"), secret=False, access=me)
    assert status["mfa_enabled"] is False
