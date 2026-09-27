from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from scute.local import decide_locally, evaluate_condition

VECTORS = json.loads((Path(__file__).parent / "fixtures" / "authz-conformance.json").read_text())


@pytest.mark.parametrize("case", VECTORS["cases"], ids=[c["name"] for c in VECTORS["cases"]])
def test_matches_the_api_engine(case: dict[str, Any]) -> None:
    got = decide_locally(VECTORS["policy"], roles=case["roles"], user=case["user"], action=case["action"],
                         resource=case["resource"], context=case["context"], now=case["now"], strict=True)
    want = case["expect"]
    assert (got.decision, got.reason, got.permission, list(got.roles) or None) == (
        want["decision"], want["reason"], want.get("permission"), want.get("roles"))
    assert got.allowed == (want["decision"] == "allow")


def test_covers_every_kind_of_answer() -> None:
    reasons = {c["expect"]["reason"] for c in VECTORS["cases"]}
    assert {"role_grant", "no_role_grants_permission", "condition_failed", "verification_required",
            "approval_required", "permission_disabled", "unknown_permission", "impersonating"} <= reasons


def test_booleans_are_not_numbers() -> None:
    attrs = {"user": {"flag": True, "n": 1}}
    assert evaluate_condition({"eq": [{"var": "user.flag"}, 1]}, attrs) is False
    assert evaluate_condition({"eq": [{"var": "user.n"}, True]}, attrs) is False
    assert evaluate_condition({"gt": [{"var": "user.flag"}, 0]}, attrs) is False
    assert evaluate_condition({"eq": [{"var": "user.n"}, 1.0]}, attrs) is True


def test_unknown_when_an_attribute_may_live_on_the_server() -> None:
    policy = {"permissions": {"doc:edit": {"enabled": True}},
              "roles": {"regional": {"permissions": ["doc:edit"],
                                     "conditions": {"doc:edit": {"eq": [{"var": "user.region"}, "eu"]}}}}}
    assert decide_locally(policy, roles=["regional"], action="edit", resource="doc").decision == "unknown"
    assert decide_locally(policy, roles=["regional"], action="edit", resource="doc", strict=True).reason == "condition_failed"


@pytest.mark.parametrize(("value", "blocked"), [(True, True), ("true", True), (1, True), ("t", True), ("yes", True),
                                                (False, False), ("false", False), (0, False), ("0", False), ("off", False),
                                                ("", False), (None, False)])
def test_reads_impersonated_like_the_engine(value: Any, blocked: bool) -> None:
    policy = {"permissions": {"account:close": {"enabled": True, "blocked_while_impersonating": True}},
              "roles": {"member": {"permissions": ["account:close"]}}}
    got = decide_locally(policy, roles=["member"], action="close", resource="account", context={"impersonated": value})
    assert (got.reason == "impersonating") is blocked
