"""7. Authorization.

In the SDK: scute.authz.check, check_batch, permissions, authorized_users, and
scute.local.decide_locally. The SDK has no API for the rest, so it goes
through the HTTP helper: policy import, role assignment, filter, the signed
policy snapshot, and access requests (filing and deciding; the SDK passes the
approval on a check).
"""

from __future__ import annotations

import copy
import json
import time
from typing import Any

import pytest

from scute import Scute
from scute.local import decide_locally

from .support import Cleanup, LiveAPI, Names, Policy, SignedIn, Trail, assign_role, revoke_role_later, verify_jws

pytestmark = pytest.mark.live


def test_policy_import(api: LiveAPI, policy: Policy) -> None:
    """The `policy` fixture imported this run's document; the same again changes
    nothing, and a dry run (the default) plans a change without making it."""
    path = api.apps("/authz/policy/import")
    again = api.ok("POST", path, {"document": policy.document, "dry_run": False})
    assert (again["changes"], again["applied"]) == ([], False)

    changed = copy.deepcopy(policy.document)
    changed["roles"][policy.auditor]["permissions"].append(f"{policy.doc}:read")
    plan = api.ok("POST", path, {"document": changed})
    assert (plan["dry_run"], plan["applied"]) == (True, False)
    assert [(c["op"], c["kind"], c["key"]) for c in plan["changes"]] == [("update", "role", policy.auditor)]
    exported = api.ok("GET", api.apps("/authz/policy/document"))
    assert exported["roles"][policy.auditor]["permissions"] == [f"{policy.invoice}:read"]


def test_assigns_and_removes_a_role(api: LiveAPI, scute: Scute, policy: Policy, nobody: str, cleanup: Cleanup) -> None:
    target = f"{policy.invoice}:1"
    assert not scute.authz.check(user_id=nobody, action="read", resource=target).allowed
    assign_role(api, cleanup, nobody, policy.auditor)
    held = api.ok("GET", api.apps(f"/authz/users/{nobody}/roles"))
    assert [g["role"] for g in held["roles"]] == [policy.auditor]
    assert scute.authz.check(user_id=nobody, action="read", resource=target).allowed

    assert api.call("DELETE", api.apps(f"/authz/users/{nobody}/roles/{policy.auditor}")).status == 204
    assert not scute.authz.check(user_id=nobody, action="read", resource=target).allowed


def test_check(scute: Scute, alice: SignedIn, nobody: str, policy: Policy, trail: Trail) -> None:
    inv, doc = policy.invoice, policy.doc
    read = scute.authz.check(user_id=alice.user_id, action="read", resource=f"{inv}:1")
    assert read.allowed and read.reason == "role_grant" and read.permission == f"{inv}:read"
    assert policy.clerk in read.roles

    small = scute.authz.check(user_id=alice.user_id, action="approve",
                              resource={"type": inv, "attributes": {"amount": 100}})
    big = scute.authz.check(user_id=alice.user_id, action="approve",
                            resource={"type": inv, "attributes": {"amount": 9000}})
    assert small.allowed
    assert (big.decision, big.reason) == ("deny", "condition_failed")

    pay = scute.authz.check(user_id=alice.user_id, action="pay", resource=f"{inv}:7")
    assert pay.needs_approval and not pay.allowed and pay.approval
    delete = scute.authz.check(user_id=alice.user_id, action="delete", resource=f"{doc}:1")
    assert delete.needs_step_up and not delete.allowed
    assert delete.step_up and delete.step_up["authorizes_action"] == f"{doc}:delete"

    refund = scute.authz.check(user_id=alice.user_id, action="refund", resource=f"{inv}:1")
    assert (refund.decision, refund.reason) == ("deny", "no_role_grants_permission")
    assert refund.explanation
    assert not scute.authz.check(user_id=nobody, action="read", resource=f"{inv}:1").allowed

    for permission, decision in ((f"{inv}:read", "allow"), (f"{inv}:approve", "deny"), (f"{inv}:pay", "allow_with_approval"),
                                 (f"{doc}:delete", "allow_with_step_up"), (f"{inv}:refund", "deny")):
        trail.add(permission, decision, user_id=alice.user_id)


def test_check_batch(scute: Scute, alice: SignedIn, nobody: str, policy: Policy) -> None:
    checks: list[dict[str, Any]] = [
        {"user_id": alice.user_id, "action": "read", "resource": f"{policy.invoice}:1"},
        {"user_id": alice.user_id, "action": "refund", "resource": f"{policy.invoice}:1"},
        {"user_id": alice.user_id, "action": "delete", "resource": f"{policy.doc}:1"},
        {"user_id": nobody, "action": "read", "resource": f"{policy.invoice}:1"},
    ]
    batch = scute.authz.check_batch(checks)
    one_by_one = [scute.authz.check(**c) for c in checks]
    assert [(d.decision, d.reason, d.permission) for d in batch] == [(d.decision, d.reason, d.permission) for d in one_by_one]
    assert [d.decision for d in batch] == ["allow", "deny", "allow_with_step_up", "deny"]


def test_permissions(scute: Scute, alice: SignedIn, policy: Policy) -> None:
    mine = scute.authz.permissions(alice.user_id)
    assert mine["user_id"] == alice.user_id
    assert {policy.clerk, policy.editor} <= set(mine["roles"])
    assert {f"{policy.invoice}:read", f"{policy.doc}:edit"} <= set(mine["permissions"])
    assert f"{policy.doc}:delete" in mine["step_up"]
    assert f"{policy.invoice}:pay" in mine["approval"]
    assert f"{policy.invoice}:approve" in [c["permission"] for c in mine["conditional"]]
    on_one = scute.authz.permissions(alice.user_id, resource=f"{policy.invoice}:1")
    assert on_one["resource"] == f"{policy.invoice}:1"


def test_authorized_users(scute: Scute, alice: SignedIn, nobody: str, policy: Policy) -> None:
    who = scute.authz.authorized_users(action="read", resource=policy.invoice)
    assert who["permission"] == f"{policy.invoice}:read"
    assert who["everyone"] is False
    ids = [u["id"] for u in who["users"]]
    assert alice.user_id in ids and nobody not in ids
    page = scute.authz.authorized_users(action="read", resource=policy.invoice, limit=1)
    assert len(page["users"]) == 1 and page["total"] == who["total"]


def test_filter(api: LiveAPI, alice: SignedIn, nobody: str, policy: Policy) -> None:
    """POST /authz/filter: which rows of a type the user may act on. (Not in the SDK.)"""

    def filter_for(user_id: str, action: str) -> Any:
        body = {"user_id": user_id, "action": action, "resource_type": policy.invoice}
        return api.ok("POST", api.auth("/authz/filter"), body)["filter"]

    assert filter_for(alice.user_id, "read") == "all"
    assert filter_for(nobody, "read") == "none"
    conditional = filter_for(alice.user_id, "approve")
    assert isinstance(conditional, dict) and "resource.amount" in json.dumps(conditional)


def test_local_decisions_match_the_server(api: LiveAPI, scute: Scute, alice: SignedIn, nobody: str,
                                          policy: Policy) -> None:
    """The signed snapshot (GET /authz/snapshot, verified with the app's JWKS),
    then decide_locally against scute.authz.check over a small matrix."""
    snapshot = api.ok("GET", api.apps("/authz/snapshot"))
    claims = verify_jws(snapshot["token"], api.ok("GET", api.auth("/.well-known/jwks.json"), secret=False))
    assert claims["typ"] == "scute-authz-snapshot"
    assert claims["version"] == snapshot["version"] and claims["exp"] > time.time()
    local_policy = claims["policy"]

    def held(user_id: str) -> list[str]:
        return [g["role"] for g in api.ok("GET", api.apps(f"/authz/users/{user_id}/roles"))["roles"] if g["active"]]

    roles = {alice.user_id: held(alice.user_id), nobody: held(nobody)}
    inv, doc = policy.invoice, policy.doc
    matrix: list[tuple[str, str, Any, dict[str, Any] | None]] = [
        (alice.user_id, "read", inv, None),
        (alice.user_id, "approve", {"type": inv, "attributes": {"amount": 100}}, None),
        (alice.user_id, "approve", {"type": inv, "attributes": {"amount": 9000}}, None),
        (alice.user_id, "pay", inv, None),
        (alice.user_id, "delete", doc, None),
        (alice.user_id, "edit", doc, None),
        (alice.user_id, "edit", doc, {"impersonated": True, "actor": {"email": "support@example.com"}}),
        (alice.user_id, "refund", inv, None),
        (alice.user_id, "fly", inv, None),
        (nobody, "read", inv, None),
    ]
    for user_id, action, resource, context in matrix:
        local = decide_locally(local_policy, roles=roles[user_id], action=action, resource=resource, context=context)
        server = scute.authz.check(user_id=user_id, action=action, resource=resource, context=context)
        label = f"{action} {json.dumps(resource)} {context or ''}"
        assert (local.decision, local.reason, local.permission, sorted(local.roles)) == (
            server.decision, server.reason, server.permission, sorted(server.roles)), label

    # What the snapshot can't answer comes back "unknown", and then the server decides.
    unknown = decide_locally(local_policy, roles=roles[alice.user_id], action="approve", resource=inv)
    assert unknown.decision == "unknown"
    assert scute.authz.check(user_id=alice.user_id, action="approve", resource=inv).decision == "deny"


def test_access_requests(api: LiveAPI, scute: Scute, alice: SignedIn, nobody: str, policy: Policy, names: Names,
                         cleanup: Cleanup, trail: Trail) -> None:
    """An operation that needs a reviewer: filed, approved, good for one use.
    A role request: filed and denied."""
    target = f"{policy.invoice}:7"
    assert scute.authz.check(user_id=alice.user_id, action="pay", resource=target).needs_approval
    filed = api.ok("POST", api.apps("/authz/requests"),
                   {"user_id": alice.user_id, "action": "pay", "resource": target, "reason": f"{names.prefix} test"})
    assert (filed["status"], filed["permission"], filed["kind"]) == ("pending", f"{policy.invoice}:pay", "operation")
    approved = api.ok("POST", api.apps(f"/authz/requests/{filed['id']}/approve"), {"note": "live suite"})
    assert approved["status"] == "approved"

    used = scute.authz.check(user_id=alice.user_id, action="pay", resource=target, approval=str(filed["id"]))
    assert used.allowed and used.reason == "approved"
    again = scute.authz.check(user_id=alice.user_id, action="pay", resource=target, approval=str(filed["id"]))
    assert again.needs_approval
    trail.add(f"{policy.invoice}:pay", "allow", user_id=alice.user_id)

    revoke_role_later(api, cleanup, nobody, policy.auditor)  # in case it gets granted after all
    asked = api.ok("POST", api.apps("/authz/requests"),
                   {"user_id": nobody, "role": policy.auditor, "reason": f"{names.prefix} test"})
    assert (asked["status"], asked["role"], asked["kind"]) == ("pending", policy.auditor, "role")
    denied = api.ok("POST", api.apps(f"/authz/requests/{asked['id']}/deny"), {"note": "not today"})
    assert (denied["status"], denied["decision_note"]) == ("denied", "not today")
    assert not scute.authz.check(user_id=nobody, action="read", resource=target).allowed
