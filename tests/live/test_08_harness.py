"""8 (harness). scute.harness against the live API: an agent registered with
scute.agents, a run for a test identity (alice), and its tool calls checked by
the permissions guard: proceed, a deny outside the task, a step-up verified
with 424242, a reviewer's approval for the exact call, a property's secret and
signatures checked against the JWKS, a budget of 2 closing the run on the 3rd
action, and a run on a task token your backend minted (no secret).
"""

from __future__ import annotations

import base64
import contextlib
import functools
import secrets
from collections.abc import Iterator
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from scute import APIError, Scute
from scute.harness import Decision, Harness, Run, Verdict, guards

from .support import CODE, Cleanup, LiveAPI, LiveEnv, Names, Policy, Secret, SignedIn, b64url, same_secret, verify_jws

pytestmark = pytest.mark.live


def register(scute: Scute, cleanup: Cleanup, slug: str, roles: list[str], settings: dict[str, Any] | None = None) -> Any:
    def undo() -> None:
        try:
            scute.agents.delete(slug)
        except APIError as e:
            if e.status != 404:
                raise

    cleanup.add(f"delete agent {slug}", undo, order=20)
    return scute.agents.create(slug, name=f"Live {slug}", roles=roles, settings=settings)


def permissions(verdict: Verdict) -> Decision:
    """The permissions guard's own answer (a proceed verdict keeps the plain
    proceed; the engine's reason is on the guard's result)."""
    return next(r.decision for r in verdict.results if r.guard == "permissions")


def tools(policy: Policy) -> dict[str, Any]:
    inv, doc = policy.invoice, policy.doc
    return {"read_invoice": {"permission": f"{inv}:read", "key": "invoice_id"},
            "approve_invoice": {"permission": f"{inv}:approve", "key": "invoice_id"},
            "pay_invoice": {"permission": f"{inv}:pay", "key": "invoice_id", "tier": "high"},
            "delete_doc": {"permission": f"{doc}:delete", "key": "doc_id"}}


@pytest.fixture(scope="module")
def agent(scute: Scute, names: Names, cleanup: Cleanup, policy: Policy) -> Any:
    return register(scute, cleanup, names.slug("harness"), [policy.cashier])


@pytest.fixture(scope="module")
def harness(scute: Scute, agent: Any, policy: Policy) -> Harness:
    return Harness(agent["slug"], scute=scute, tools=tools(policy))


@pytest.fixture(scope="module")
def run(harness: Harness, alice: SignedIn, policy: Policy, names: Names) -> Iterator[Run]:
    """Works for alice; may read and pay invoices and delete docs (not approve)."""
    job = harness.run(acts_for=alice.user_id, ttl=900, ref=f"{names.prefix}-harness",
                      actions=[f"{policy.invoice}:read", f"{policy.invoice}:pay", f"{policy.doc}:delete"])
    yield job
    with contextlib.suppress(APIError):  # already closed by a test
        job.revoke()


def test_proceeds_inside_the_task(run: Run, alice: SignedIn, agent: Any) -> None:
    verdict = run.check("read_invoice", {"invoice_id": "7"})
    assert (verdict.kind, verdict.runs) == ("proceed", True)
    engine = permissions(verdict).engine
    assert engine is not None and engine.allowed and engine.reason
    me = run.whoami()
    assert (me["agent"], me["acts_for"]) == (agent["slug"], alice.user_id)
    assert run.snapshot()["calls"] == 1 and "token" not in run.snapshot()


def test_denies_outside_the_task(run: Run) -> None:
    verdict = run.check("approve_invoice", {"invoice_id": "7", "amount": 10})
    assert (verdict.kind, verdict.decision.reason) == ("deny", "outside_task")
    assert verdict.message and verdict.message.startswith("Not allowed:")
    assert verdict.say


def test_step_up_verified_with_the_test_code(run: Run, policy: Policy) -> None:
    """Deleting a doc needs alice to verify: the run sends her a code (a test
    identity: 424242), and the next check of that permission goes through."""
    asked = run.check("delete_doc", {"doc_id": "9"})
    assert asked.kind == "verify" and (asked.decision.verify or {}).get("permission") == f"{policy.doc}:delete"
    started = run.start_verification(verdict=asked, method="email_otp")
    assert started["status"] == "pending" and started["say"]
    wrong = run.submit_code("000000")
    assert wrong["status"] == "pending" and wrong["say"]
    assert run.submit_code(CODE)["status"] == "completed"
    assert run.verified_at is not None
    passed = run.check("delete_doc", {"doc_id": "9"})
    assert (passed.kind, permissions(passed).reason) == ("proceed", "verified")


def test_approval_by_a_reviewer_for_the_exact_call(run: Run, api: LiveAPI) -> None:
    """Paying needs a reviewer: the harness files the request for this exact
    call; once your reviewer approves it, that call goes through (and only that one)."""
    args = {"invoice_id": "7", "amount": 30}
    pending = run.check("pay_invoice", args)
    assert pending.kind == "approve" and pending.say
    request_id = (pending.decision.approve or {}).get("request_id")
    assert request_id and f"id {request_id}" in (pending.message or "")
    assert run.approval_status(str(request_id))["status"] == "pending"

    other = run.check("pay_invoice", {**args, "amount": 31})  # other arguments: a request of its own
    other_id = (other.decision.approve or {}).get("request_id")
    assert other.kind == "approve" and other_id and other_id != request_id
    api.ok("POST", api.apps(f"/authz/requests/{other_id}/deny"), {"note": "live suite: not this one"})

    api.ok("POST", api.apps(f"/authz/requests/{request_id}/approve"), {"note": "live suite"})
    assert run.approval_status(str(request_id))["status"] == "approved"
    approved = run.check("pay_invoice", args)
    assert (approved.kind, permissions(approved).reason) == ("proceed", "approved")


def test_properties_secret_and_signatures(run: Run, api: LiveAPI, live: LiveEnv, names: Names, cleanup: Cleanup,
                                          agent: Any) -> None:
    secret_name, signer = names.slug("harness-key"), names.slug("harness-signer")
    for name in (secret_name, signer):
        cleanup.add(f"delete property {name}", functools.partial(api.gone, "DELETE", api.apps(f"/properties/{name}")), order=25)
    value = Secret(secrets.token_urlsafe(24))
    api.ok("POST", api.apps("/properties"), {"name": secret_name, "kind": "secret", "value": value, "agents": [agent["slug"]]})
    api.ok("POST", api.apps("/properties"), {"name": signer, "kind": "keypair", "algorithm": "ES256", "agents": [agent["slug"]]})

    assert same_secret(run.property(secret_name), value)

    jwks = api.ok("GET", api.auth(f"/properties/{signer}/jwks.json"), secret=False)
    signed = run.sign(signer, claims={"sub": "live-suite", "run": names.run_id})
    claims = verify_jws(signed["jws"], jwks)
    assert (claims["run"], claims["iss"]) == (names.run_id, f"{live.app_id}/properties/{signer}")

    data = b"pay 30 to INV-7"
    raw = run.sign(signer, data=base64.urlsafe_b64encode(data).rstrip(b"=").decode())
    signature = b64url(raw["signature"])
    key = next(k for k in jwks["keys"] if k["kid"] == raw["kid"])
    public = ec.EllipticCurvePublicNumbers(int.from_bytes(b64url(key["x"]), "big"), int.from_bytes(b64url(key["y"]), "big"),
                                           ec.SECP256R1()).public_key()
    public.verify(encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")), data,
                  ec.ECDSA(hashes.SHA256()))


def test_human_tools_answer_with_say_lines(run: Run, alice: SignedIn) -> None:
    me = run.human_tools()["scute_whoami"]()
    assert me["acts_for"] == alice.user_id and me["may"]


def test_a_budget_of_two_closes_the_run_on_the_third_action(scute: Scute, names: Names, cleanup: Cleanup,
                                                             policy: Policy, alice: SignedIn) -> None:
    budgeted = register(scute, cleanup, names.slug("harness-budget"), [policy.cashier],
                        settings={"budget": {"max_actions": 2, "window_minutes": 60}})
    harness = Harness(budgeted["slug"], scute=scute, tools=tools(policy))
    run = harness.run(acts_for=alice.user_id, actions=[f"{policy.invoice}:read"], ttl=600)
    assert [run.check("read_invoice", {"invoice_id": str(n)}).kind for n in (1, 2)] == ["proceed", "proceed"]
    third = run.check("read_invoice", {"invoice_id": "3"})
    assert (third.kind, third.decision.reason) == ("deny", "budget_exceeded")
    assert run.snapshot()["closed"] is True
    with pytest.raises(APIError) as closed:
        run.token()
    assert closed.value.code == "task_closed"
    after = run.check("read_invoice", {"invoice_id": "4"})
    assert (after.kind, after.decision.reason) == ("deny", "guard_error")
    assert scute.agents.get(budgeted["slug"])["status"] == "suspended"
    assert scute.agents.resume(budgeted["slug"])["status"] == "active"


def test_a_run_on_a_task_token_from_your_backend(scute: Scute, live: LiveEnv, agent: Any, alice: SignedIn,
                                                 policy: Policy) -> None:
    """The backend mints the task (secret key); the agent process runs with the
    token alone, and completing the run ends the task."""
    task = scute.agents.start_task(agent["slug"], acts_for=alice.user_id, actions=[f"{policy.invoice}:read"], ttl=300)
    tokenless = Scute(app_id=live.app_id, secret=None, base_url=live.base_url, timeout=30.0)
    try:
        assert not tokenless.has_secret
        harness = Harness(agent["slug"], scute=tokenless, tools=tools(policy), guards=[guards.permissions()])
        run = harness.run(token=task["token"])
        assert run.check("read_invoice", {"invoice_id": "5"}).kind == "proceed"
        assert run.check("delete_doc", {"doc_id": "5"}).decision.reason == "outside_task"
        assert run.task_id() == task["id"]
        assert not any(t["id"] == task["id"] and t["status"] == "revoked" for t in scute.agents.tasks(agent["slug"]))
    finally:
        tokenless.close()
    scute.agents.revoke_task(agent["slug"], task["id"])
    revoked = [t for t in scute.agents.tasks(agent["slug"]) if t["id"] == task["id"]]
    assert revoked and revoked[0]["status"] == "revoked"
