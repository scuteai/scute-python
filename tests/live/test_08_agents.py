"""8. Agents: register one and mint a task; checks through the task (allow, and
a deny outside the task); a step-up through the human steps with a test
identity; properties (read a secret; sign, then verify with the JWKS); a budget
of 2 that pauses the agent on the 3rd action; suspend and resume.

scute-python has no agent API and no harness yet (the JS SDK has one). So all
of this goes through the HTTP helper: the developer's backend with the secret
key (/v1/apps/:app/authz/agents...), and the agent with its task token as the
bearer (/v1/auth/:app/agent/...), the calls a Python harness would make.
"""

from __future__ import annotations

import functools
import secrets
from typing import Any

import pytest

from .support import (
    CODE,
    Cleanup,
    LiveAPI,
    LiveEnv,
    Names,
    Policy,
    Secret,
    SignedIn,
    Trail,
    same_secret,
    verify_jws,
)

pytestmark = pytest.mark.live


def register(api: LiveAPI, cleanup: Cleanup, slug: str, roles: list[str], settings: dict[str, Any] | None = None) -> Any:
    cleanup.add(f"delete agent {slug}", lambda: api.gone("DELETE", api.apps(f"/authz/agents/{slug}")), order=20)
    body: dict[str, Any] = {"slug": slug, "name": f"Live {slug}", "roles": roles}
    if settings:
        body["settings"] = settings
    return api.ok("POST", api.apps("/authz/agents"), body)


def mint(api: LiveAPI, slug: str, **task: Any) -> Any:
    return api.ok("POST", api.apps(f"/authz/agents/{slug}/tasks"), {"ttl_seconds": 900, **task})


def agent_check(api: LiveAPI, token: str, action: str, resource: Any, **extra: Any) -> Any:
    return api.ok("POST", api.auth("/agent/check"), {"action": action, "resource": resource, **extra}, bearer=token)


@pytest.fixture(scope="module")
def helper(api: LiveAPI, names: Names, cleanup: Cleanup, policy: Policy) -> Any:
    return register(api, cleanup, names.slug("helper"), [policy.assistant])


@pytest.fixture(scope="module")
def task(api: LiveAPI, names: Names, helper: Any, alice: SignedIn, policy: Policy) -> Any:
    """Works for alice; may read invoices and delete docs, nothing else."""
    return mint(api, helper["slug"], acts_for=alice.user_id, ref=f"{names.prefix}-task",
                actions=[f"{policy.invoice}:read", f"{policy.doc}:delete"], resources=[policy.invoice, policy.doc])


def test_registers_an_agent_and_mints_a_task(api: LiveAPI, helper: Any, task: Any, alice: SignedIn,
                                             policy: Policy) -> None:
    assert (helper["status"], helper["roles"]) == ("active", [policy.assistant])
    assert task["acts_for"] == alice.user_id and task["status"] == "open"
    assert task["token"].startswith("sct_")
    me = api.ok("GET", api.auth("/agent/whoami"), bearer=task["token"])
    assert (me["agent"], me["acts_for"]) == (helper["slug"], alice.user_id)
    assert f"{policy.invoice}:read" in me["permissions"]
    assert f"{policy.doc}:delete" in me["step_up"]
    assert f"{policy.invoice}:refund" not in me["ceiling"]  # the agent's role has it; the task doesn't


def test_checks_through_the_task(api: LiveAPI, helper: Any, task: Any, policy: Policy, trail: Trail) -> None:
    allowed = agent_check(api, task["token"], "read", f"{policy.invoice}:3")
    assert (allowed["decision"], allowed["agent"]["agent"]) == ("allow", helper["slug"])
    outside = agent_check(api, task["token"], "approve", {"type": policy.invoice, "key": "3", "attributes": {"amount": 10}})
    assert (outside["decision"], outside["reason"]) == ("deny", "outside_task")
    assert outside["say"]
    trail.add(f"{policy.invoice}:read", "allow", agent_id=helper["id"], via="agent")
    trail.add(f"{policy.invoice}:approve", "deny", agent_id=helper["id"], via="agent")


def test_step_up_through_the_human_steps(api: LiveAPI, task: Any, policy: Policy) -> None:
    """Deleting a doc needs alice to verify: the agent starts it, alice (a test
    identity) reads out 424242, and the check with that verification passes."""
    target = f"{policy.doc}:9"
    assert agent_check(api, task["token"], "delete", target)["decision"] == "allow_with_step_up"
    started = api.ok("POST", api.auth("/agent/verifications"),
                     {"method": "email_otp", "permission": f"{policy.doc}:delete"}, bearer=task["token"])
    assert started["status"] == "pending" and started["say"]
    done = api.ok("POST", api.auth(f"/agent/verifications/{started['token']}/code"), {"code": CODE}, bearer=task["token"])
    assert done["status"] == "completed"
    verified = agent_check(api, task["token"], "delete", target, challenge=started["token"])
    assert (verified["decision"], verified["reason"]) == ("allow", "verified")


def test_properties(api: LiveAPI, live: LiveEnv, names: Names, cleanup: Cleanup, helper: Any, task: Any,
                    alice: SignedIn, policy: Policy) -> None:
    """A secret the agent's tool reads, and a key pair it signs with; the
    signature checks out against the property's public JWKS."""
    secret_name, signer = names.slug("api-key"), names.slug("signer")
    for name in (secret_name, signer):
        cleanup.add(f"delete property {name}", functools.partial(api.gone, "DELETE", api.apps(f"/properties/{name}")), order=25)
    value = Secret(secrets.token_urlsafe(24))
    made = api.ok("POST", api.apps("/properties"),
                  {"name": secret_name, "kind": "secret", "value": value, "agents": [helper["slug"]]})
    assert made["kind"] == "secret" and "value" not in made
    api.ok("POST", api.apps("/properties"), {"name": signer, "kind": "keypair", "algorithm": "ES256", "agents": [helper["slug"]]})

    read = api.ok("GET", api.auth(f"/agent/properties/{secret_name}"), bearer=task["token"])
    assert same_secret(read["value"], value)

    signed = api.ok("POST", api.auth(f"/agent/properties/{signer}/sign"),
                    {"claims": {"sub": "live-suite", "run": names.run_id}}, bearer=task["token"])
    claims = verify_jws(signed["jws"], api.ok("GET", api.auth(f"/properties/{signer}/jwks.json"), secret=False))
    assert (claims["run"], claims["iss"]) == (names.run_id, f"{live.app_id}/properties/{signer}")

    outsider = register(api, cleanup, names.slug("outsider"), [policy.assistant])
    other = mint(api, outsider["slug"], acts_for=alice.user_id)
    refused = api.call("GET", api.auth(f"/agent/properties/{secret_name}"), bearer=other["token"])
    assert (refused.status, refused.error_code) == (403, "agent_not_listed")


def test_budget_pauses_the_agent(api: LiveAPI, names: Names, cleanup: Cleanup, alice: SignedIn, policy: Policy) -> None:
    budgeted = register(api, cleanup, names.slug("budget"), [policy.assistant],
                        settings={"budget": {"max_actions": 2, "window_minutes": 60}})
    token = mint(api, budgeted["slug"], acts_for=alice.user_id, actions=[f"{policy.invoice}:read"])["token"]
    for n in (1, 2):
        assert agent_check(api, token, "read", f"{policy.invoice}:{n}")["decision"] == "allow"
    third = agent_check(api, token, "read", f"{policy.invoice}:3")
    assert (third["decision"], third["reason"]) == ("deny", "budget_exceeded")

    paused = api.ok("GET", api.apps(f"/authz/agents/{budgeted['slug']}"))
    assert paused["status"] == "suspended" and "budget" in str(paused.get("suspended_reason")).lower()
    after = api.call("POST", api.auth("/agent/check"), {"action": "read", "resource": policy.invoice}, bearer=token)
    assert (after.status, after.error_code) == (401, "invalid_task_token")  # its open tasks ended
    assert api.ok("POST", api.apps(f"/authz/agents/{budgeted['slug']}/resume"))["status"] == "active"


def test_suspend_and_resume(api: LiveAPI, helper: Any, task: Any, alice: SignedIn, policy: Policy) -> None:
    """Last in the module: suspending ends the shared task."""
    slug = helper["slug"]
    assert api.ok("POST", api.apps(f"/authz/agents/{slug}/suspend"), {"reason": "live suite"})["status"] == "suspended"
    ended = api.call("POST", api.auth("/agent/check"), {"action": "read", "resource": policy.invoice}, bearer=task["token"])
    assert (ended.status, ended.error_code) == (401, "invalid_task_token")
    refused = api.call("POST", api.apps(f"/authz/agents/{slug}/tasks"), {"acts_for": alice.user_id})
    assert (refused.status, refused.error_code) == (409, "agent_suspended")

    assert api.ok("POST", api.apps(f"/authz/agents/{slug}/resume"))["status"] == "active"
    fresh = mint(api, slug, acts_for=alice.user_id, actions=[f"{policy.invoice}:read"])
    assert agent_check(api, fresh["token"], "read", f"{policy.invoice}:4")["decision"] == "allow"
