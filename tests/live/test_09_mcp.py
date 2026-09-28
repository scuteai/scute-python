"""9. The auth MCP server (JSON-RPC over HTTP with an agent key): initialize,
tools/list, scute_identify (a test email and a conversation id),
scute_submit_code 424242, scute_check; then the developer's backend looks the
conversation up and checks through it.

No SDK surface: an MCP client (the voice or chat platform) talks to it, so this
is JSON-RPC over httpx. The tests run in order, one conversation.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from scute import Scute

from .support import CODE, Cleanup, LiveAPI, Mcp, Names, Policy, Secret, Trail, assign_role, delete_user_later

pytestmark = pytest.mark.live


@pytest.fixture(scope="module")
def voice(api: LiveAPI, names: Names, cleanup: Cleanup, policy: Policy) -> Any:
    """The agent on the platform, with a long-lived key."""
    slug = names.slug("voice")
    cleanup.add(f"delete agent {slug}", lambda: api.gone("DELETE", api.apps(f"/authz/agents/{slug}")), order=20)
    agent = api.ok("POST", api.apps("/authz/agents"), {"slug": slug, "name": "Live voice agent", "roles": [policy.assistant]})
    key = api.ok("POST", api.apps(f"/authz/agents/{slug}/keys"), {"name": f"{names.prefix} platform"})
    assert key["key"].startswith("scak_")
    return {**agent, "key": Secret(key["key"])}


@pytest.fixture(scope="module")
def person(api: LiveAPI, scute: Scute, names: Names, cleanup: Cleanup, policy: Policy) -> dict[str, str]:
    """Who calls in: a user of the app (a clerk) with a test email."""
    email = names.email(5)
    user_id = str(scute.users.create(email)["user"]["id"])
    delete_user_later(scute, cleanup, user_id)
    assign_role(api, cleanup, user_id, policy.clerk)
    return {"id": user_id, "email": email}


@pytest.fixture(scope="module")
def conversation(names: Names) -> str:
    return f"{names.prefix}-conversation"


@pytest.fixture(scope="module")
def mcp(api: LiveAPI, voice: Any) -> Iterator[Mcp]:
    client = Mcp(api, voice["key"])
    yield client
    if client.session_id:
        client.end()


def test_initialize(mcp: Mcp) -> None:
    result = mcp.result("initialize", {"protocolVersion": Mcp.PROTOCOL, "capabilities": {},
                                       "clientInfo": {"name": "scute-python live suite", "version": "1"}})
    assert result["protocolVersion"] == Mcp.PROTOCOL
    assert result["serverInfo"]["name"] == "scute-auth"
    assert mcp.session_id
    assert mcp.send("notifications/initialized", notify=True).status == 202


def test_lists_the_tools(mcp: Mcp) -> None:
    names = {t["name"] for t in mcp.result("tools/list")["tools"]}
    assert {"scute_identify", "scute_submit_code", "scute_check", "scute_whoami", "scute_sign_out"} <= names


def test_identifies_the_person(mcp: Mcp, policy: Policy, person: dict[str, str], conversation: str) -> None:
    before = mcp.tool("scute_check", {"action": "read", "resource": f"{policy.invoice}:3"})
    assert before["error"] == "not_identified"
    sent = mcp.tool("scute_identify", {"email": person["email"], "conversation_id": conversation})
    assert sent["status"] == "code_sent" and not sent["_is_error"]
    verified = mcp.tool("scute_submit_code", {"code": CODE})
    assert verified["status"] == "verified"
    me = mcp.tool("scute_whoami")
    assert me["verified"] is True and me["person"]["email"] == person["email"]


def test_checks_for_the_person(mcp: Mcp, voice: Any, policy: Policy, person: dict[str, str], trail: Trail) -> None:
    yes = mcp.tool("scute_check", {"action": "read", "resource": f"{policy.invoice}:3"})
    assert yes["decision"] == "allow" and not yes["_is_error"]
    no = mcp.tool("scute_check", {"action": "pay", "resource": f"{policy.invoice}:3"})
    assert no["decision"] == "deny" and no["say"]  # the agent's role doesn't pay invoices
    trail.add(f"{policy.invoice}:read", "allow", agent_id=voice["id"], via="auth_mcp")
    trail.add(f"{policy.invoice}:pay", "deny", agent_id=voice["id"], via="auth_mcp")


def test_backend_looks_up_the_conversation(api: LiveAPI, voice: Any, policy: Policy, person: dict[str, str],
                                           conversation: str, trail: Trail) -> None:
    base = api.apps(f"/authz/agents/{voice['slug']}/conversations/{conversation}")
    found = api.ok("GET", base)
    assert (found["verified"], found["person"]["app_user_id"]) == (True, person["id"])
    assert found["ended"] is False
    checked = api.ok("POST", f"{base}/check", {"action": "read", "resource": f"{policy.invoice}:5"})
    assert checked["decision"] == "allow"
    trail.add(f"{policy.invoice}:read", "allow", agent_id=voice["id"], via="conversation")


def test_ending_the_conversation(api: LiveAPI, mcp: Mcp, voice: Any, policy: Policy, conversation: str) -> None:
    assert mcp.end() == 204
    base = api.apps(f"/authz/agents/{voice['slug']}/conversations/{conversation}")
    assert api.ok("GET", base)["ended"] is True
    refused = api.call("POST", f"{base}/check", {"action": "read", "resource": f"{policy.invoice}:5"})
    assert (refused.status, refused.error_code) == (409, "not_verified")
    mcp.session_id = None
