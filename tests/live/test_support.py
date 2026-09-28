"""The live suite's own helpers, offline (these run with the unit tests)."""

from __future__ import annotations

import re
import time
from pathlib import Path

import pytest

from .support import (
    Cleanup,
    Names,
    Secret,
    load_env,
    parse_env_file,
    redact,
    safe_path,
    same_secret,
    totp,
    wrong_totp,
)

RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # "12345678901234567890", RFC 6238 appendix B


def test_totp_matches_rfc_6238() -> None:
    assert same_secret(totp(RFC_SECRET, 59, digits=8), "94287082")
    assert same_secret(totp(RFC_SECRET, 1111111109, digits=8), "07081804")
    assert same_secret(totp(RFC_SECRET, 20000000000, digits=8), "65353130")
    now = time.time()
    assert not any(same_secret(wrong_totp(RFC_SECRET), totp(RFC_SECRET, now + d)) for d in (-30, 0, 30))


def test_secrets_never_show_in_a_repr() -> None:
    answer = redact({"access": "eyJ.a.b", "user_id": "u1", "mfa_challenge": {"token": "t0k"}, "backup_codes": ["1", "2"]})
    assert "eyJ" not in repr(answer) and "t0k" not in repr(answer) and "'1'" not in repr(answer)
    assert answer["user_id"] == "u1" and isinstance(answer["access"], Secret)
    assert str(answer["access"]) == "eyJ.a.b" and f"Bearer {answer['access']}" == "Bearer eyJ.a.b"


def test_paths_in_failures_hide_tokens() -> None:
    uuid = "0b5c3f2e-1a2b-4c3d-8e9f-001122334455"
    assert safe_path(f"/v1/auth/app_x/challenges/{'a' * 40}/verify") == "/v1/auth/app_x/challenges/***/verify"
    assert safe_path(f"/v1/app_x/users/{uuid}?challenge=secret") == f"/v1/app_x/users/{uuid}?..."


def test_env_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert parse_env_file('# setup\nexport SCUTE_LIVE_APP_ID="app_1"\nSCUTE_LIVE_SECRET=\'s k\'\n\nnoise\n') == {
        "SCUTE_LIVE_APP_ID": "app_1", "SCUTE_LIVE_SECRET": "s k"}
    for key in ("SCUTE_LIVE_BASE_URL", "SCUTE_LIVE_APP_ID", "SCUTE_LIVE_SECRET"):
        monkeypatch.delenv(key, raising=False)
    env_path = tmp_path / "python.env"
    monkeypatch.setenv("SCUTE_LIVE_ENV_FILE", str(env_path))
    assert load_env() is None
    env_path.write_text("SCUTE_LIVE_BASE_URL=https://api.test/\nSCUTE_LIVE_APP_ID=app_1\nSCUTE_LIVE_SECRET=shh\n")
    env = load_env()
    assert env is not None and (env.base_url, env.app_id, env.source) == ("https://api.test", "app_1", str(env_path))
    assert "shh" not in repr(env)
    monkeypatch.setenv("SCUTE_LIVE_APP_ID", "app_2")
    assert (env := load_env()) is not None and env.app_id == "app_2"


def test_names_stay_in_the_suites_test_ranges() -> None:
    names = Names(run_id="0a1b2c")
    assert re.fullmatch(r"live-python-0a1b2c-3\+scute_test@example\.com", names.email(3))
    assert all(re.fullmatch(r"\+141555501\d\d", names.phone(n)) for n in range(200))
    assert names.slug("clerk") == "live-0a1b2c-clerk"


def test_cleanup_runs_every_step_in_order() -> None:
    done: list[str] = []
    undo = Cleanup()
    undo.add("user", lambda: done.append("user"), order=40)
    undo.add("grant", lambda: done.append("grant"), order=30)
    undo.add("broken", lambda: 1 / 0, order=30)
    undo.add("role", lambda: done.append("role"), order=60)
    failures = undo.run()
    assert done == ["grant", "user", "role"]
    assert failures == ["broken: ZeroDivisionError: division by zero"]
