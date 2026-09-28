"""The live suite: real HTTP against a real Scute API, no mocks.

    pytest -m live

Credentials come from SCUTE_LIVE_BASE_URL, SCUTE_LIVE_APP_ID and
SCUTE_LIVE_SECRET, or from the file in SCUTE_LIVE_ENV_FILE (default:
.sdk-live/python.env next to this checkout). Without them every live test is
skipped with one reason, and the run still exits 0.

Everything a run makes is named live-<runid> and deleted at the end, also
when tests fail (the `cleanup` fixture).
"""

from __future__ import annotations

import functools
import secrets
from collections.abc import Iterator
from typing import Any

import pytest

from scute import Scute

from .support import (
    Cleanup,
    LiveAPI,
    LiveEnv,
    Names,
    Policy,
    SignedIn,
    Trail,
    assign_role,
    delete_user_later,
    load_env,
    policy_for,
    sign_in,
    skip_reason,
)

_ENV = load_env()


def _live_selected(config: pytest.Config) -> bool:
    expr = str(config.getoption("markexpr", "") or "")
    return "live" in expr and "not live" not in expr


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if _ENV is not None:
        return
    skip = pytest.mark.skip(reason=skip_reason())
    for item in items:
        if item.get_closest_marker("live"):
            item.add_marker(skip)


def pytest_terminal_summary(terminalreporter: Any, exitstatus: int, config: pytest.Config) -> None:
    if _live_selected(config):
        line = skip_reason() if _ENV is None else f"scute live suite: {_ENV.base_url}, app {_ENV.app_id} ({_ENV.source})"
        terminalreporter.write_line(line)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    # No credentials and nothing left to run is a skip, not a failure (exit 5).
    if _ENV is None and _live_selected(session.config) and exitstatus == pytest.ExitCode.NO_TESTS_COLLECTED:
        session.exitstatus = pytest.ExitCode.OK


# ── fixtures ──


@pytest.fixture(scope="session")
def live() -> LiveEnv:
    if _ENV is None:
        pytest.skip(skip_reason())
    return _ENV


@pytest.fixture(scope="session")
def names() -> Names:
    return Names(run_id=secrets.token_hex(3))


@pytest.fixture(scope="session")
def api(live: LiveEnv) -> Iterator[LiveAPI]:
    client = LiveAPI(live)
    yield client
    client.close()


@pytest.fixture(scope="session")
def scute(live: LiveEnv) -> Iterator[Scute]:
    client = Scute(app_id=live.app_id, secret=live.secret, base_url=live.base_url, timeout=30.0)
    yield client
    client.close()


@pytest.fixture(scope="session")
def cleanup(api: LiveAPI, scute: Scute) -> Iterator[Cleanup]:
    """Undo everything the run made. Failures here fail the run (they'd leave data behind)."""
    undo = Cleanup()
    yield undo
    failures = undo.run()
    if failures:
        pytest.fail("cleanup left things behind:\n  " + "\n  ".join(failures), pytrace=False)


@pytest.fixture(scope="session")
def trail() -> Trail:
    """Checks made along the way, for the decision log read-back at the end."""
    return Trail()


@pytest.fixture(scope="session")
def app_settings(api: LiveAPI, cleanup: Cleanup) -> dict[str, Any]:
    """Sign-in-as-user on, and every allow logged (plain allows are sampled otherwise).
    Put back as they were at the end."""
    before = api.ok("GET", api.apps("/authz/settings"))
    wanted = {"impersonation": True, "log_allow_rate": 1}
    cleanup.add("restore authz settings",
                lambda: api.ok("PATCH", api.apps("/authz/settings"), {k: before[k] for k in wanted}), order=90)
    after: dict[str, Any] = api.ok("PATCH", api.apps("/authz/settings"), wanted)
    return after


@pytest.fixture(scope="session")
def policy(api: LiveAPI, names: Names, cleanup: Cleanup, app_settings: dict[str, Any]) -> Policy:
    """This run's resources, permissions and roles, imported as a policy document
    (the SDK has no policy API). Deleted at the end: roles after the grants, then
    the resources with their permissions."""
    p = policy_for(names)
    for role in p.roles:
        cleanup.add(f"delete role {role}", functools.partial(api.gone, "DELETE", api.apps(f"/authz/roles/{role}")), order=60)
    for resource in p.resources:
        cleanup.add(f"delete resource {resource}",
                    functools.partial(api.gone, "DELETE", api.apps(f"/authz/resources/{resource}"), params={"force": "true"}),
                    order=70)
    api.ok("POST", api.apps("/authz/policy/import"), {"document": p.document, "dry_run": False})
    return p


@pytest.fixture(scope="session")
def alice(api: LiveAPI, scute: Scute, names: Names, cleanup: Cleanup, policy: Policy) -> SignedIn:
    """The signed-in user most tests share (one email OTP sign-in per run): a
    clerk and an editor."""
    user = sign_in(api, names.email(1))
    delete_user_later(scute, cleanup, user.user_id)
    assign_role(api, cleanup, user.user_id, policy.clerk)
    assign_role(api, cleanup, user.user_id, policy.editor)
    return user


@pytest.fixture(scope="session")
def nobody(scute: Scute, names: Names, cleanup: Cleanup, policy: Policy) -> str:
    """A user with no roles, made from the backend (no sign-in). Their id."""
    user_id = str(scute.users.create(names.email(9))["user"]["id"])
    delete_user_later(scute, cleanup, user_id)
    return user_id

