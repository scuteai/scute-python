"""10. The decision log: rows for the checks made above (SDK checks, the agent's,
the auth MCP's), read back with GET /authz/decisions. The SDK has no decision
log read. Rows are written by a background job, so this waits for them.
"""

from __future__ import annotations

import time
from typing import Any

import pytest

from scute import Scute

from .support import LiveAPI, Policy, SignedIn, Trail, missing_rows

pytestmark = pytest.mark.live

WAIT_SECONDS = 60


def test_reads_back_the_decisions(api: LiveAPI, scute: Scute, alice: SignedIn, policy: Policy, trail: Trail) -> None:
    target = f"{policy.invoice}:404"
    own = scute.authz.check(user_id=alice.user_id, action="refund", resource=target)
    assert own.decision == "deny"
    trail.add(f"{policy.invoice}:refund", "deny", user_id=alice.user_id)

    def rows_for(where: tuple[tuple[str, str], ...]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = api.ok("GET", api.apps("/authz/decisions"), params={**dict(where), "limit": 200})["decisions"]
        return rows

    deadline = time.monotonic() + WAIT_SECONDS
    missing = missing_rows(trail.expected, rows_for)
    while missing and time.monotonic() < deadline:
        time.sleep(3)
        missing = missing_rows(missing, rows_for)
    assert not missing, f"no decision row after {WAIT_SECONDS}s for: " + "; ".join(
        f"{e.permission} {e.decision} {dict(e.where)} via {e.via or '-'}" for e in missing)

    row = next(r for r in rows_for((("user_id", alice.user_id),)) if r.get("resource") == target)
    assert (row["permission"], row["decision"], row["reason"]) == (f"{policy.invoice}:refund", "deny", own.reason)
    assert row["kind"] == "end_user" and isinstance(row["policy_version"], int)
