from __future__ import annotations

import functools
import json
import threading
from collections.abc import Iterator
from typing import Any

import httpx
import pytest

from scute import APIError, ConfigurationError, ConnectionError
from scute.harness import Harness, ToolSpec, Verdict, guards, permission_for

from .harness_fake import AUTH, CHECK, MINT, FakeAgentAPI, harness


@pytest.fixture(autouse=True)
def no_env_secret(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv("SCUTE_SECRET", raising=False)
    yield


def in_threads(*calls: Any) -> list[Any]:
    out: list[Any] = [None] * len(calls)

    def work(i: int) -> None:
        out[i] = calls[i]()

    threads = [threading.Thread(target=work, args=(i,)) for i in range(len(calls))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return out


# ── naming convention ──


def test_maps_tool_names_to_permissions() -> None:
    assert permission_for("refund_invoice") == "invoice:refund"
    assert permission_for("resetUserMfa") == "user_mfa:reset"
    assert permission_for("search") == "search"
    assert permission_for("--") == "--"


def test_finds_the_object_in_the_arguments_never_its_attributes() -> None:
    h = harness(tools={"send_money": {"permission": "payment:create", "key": "to", "tier": "high",
                                      "attributes": lambda a: {"currency": a["currency"]}},
                       "get_weather": False})
    assert h.spec("refund_invoice").resource({"invoice_id": 42, "amount": 90, "note": {"x": 1}}) == {"type": "invoice", "key": "42"}
    assert h.spec("reset_user_mfa").resource({"userMfaId": "u1"}) == {"type": "user_mfa", "key": "u1"}
    send = h.spec("send_money")
    assert (send.permission, send.action, send.tier) == ("payment:create", "create", "high")
    assert send.resource({"to": "acct9", "amount": 5, "currency": "EUR"}) == {
        "type": "payment", "key": "acct9", "attributes": {"currency": "EUR"}}
    assert h.spec("get_weather").permission is None
    assert h.spec("read_invoice").resource({"id": True}) == {"type": "invoice"}  # a boolean isn't a key
    assert isinstance(h.spec("x"), ToolSpec)


# ── the permissions guard ──


def test_starts_the_task_once_lazily_and_asks_the_engine() -> None:
    fake = FakeAgentAPI()
    run = harness(fake).run(acts_for="user1", actions=["invoice:refund"], ref="T-9")

    kinds = in_threads(lambda: run.check("refund_invoice", {"invoice_id": 42, "amount": 90}).kind,
                       lambda: run.check("read_invoice", {"id": 1}).kind)
    assert kinds == ["proceed", "proceed"]
    assert len(fake.paths(MINT)) == 1
    assert fake.paths(MINT)[0].body == {"acts_for": "user1", "actions": ["invoice:refund"], "ref": "T-9"}
    refund = next(c for c in fake.paths(CHECK) if c.body["action"] == "refund")
    assert refund.auth == "Bearer sct_token1"
    assert refund.body["resource"] == {"type": "invoice", "key": "42"}
    assert refund.body["context"] == {"args": {"invoice_id": 42, "amount": 90}}


def test_maps_engine_answers_and_tells_the_model_what_to_do_next() -> None:
    answers: dict[str, dict[str, Any]] = {
        "delete": {"decision": "deny", "reason": "agent_role", "say": "I'm not able to do that.",
                   "explanation": "Support bot can't delete invoice 1: none of its roles allow it."},
        "pay": {"decision": "allow_with_step_up", "step_up": {"method": "entra_push", "authorizes_action": "invoice:pay"}},
    }
    run = harness(FakeAgentAPI(decide=lambda body: answers.get(body["action"]))).run(acts_for="user1")

    denied = run.check("delete_invoice", {"id": 1})
    assert (denied.kind, denied.decision.reason, denied.decision.guard) == ("deny", "agent_role", "permissions")
    assert denied.message == ("Not allowed: Support bot can't delete invoice 1: none of its roles allow it. "
                              "Don't retry it; tell the person.")
    assert denied.say == "I'm not able to do that."
    assert not denied.runs

    verify = run.check("pay_invoice", {"id": 1})
    assert verify.kind == "verify"
    assert verify.decision.verify == {"method": "entra_push", "permission": "invoice:pay"}


def test_fails_closed_when_scute_cant_be_reached() -> None:
    fake = FakeAgentAPI(down=True)
    v = harness(fake).run(acts_for="user1").check("refund_invoice", {"id": 1})
    assert (v.kind, v.decision.reason) == ("deny", "guard_error")
    assert isinstance(v.results[0].error, ConnectionError)


def test_verifies_the_person_with_the_task_token_and_carries_the_proof() -> None:
    fake = FakeAgentAPI(decide=lambda body: None if body.get("challenge") == "ch_ok" else {
        "decision": "allow_with_step_up", "say": "Before I do that, I need to verify it's you.",
        "step_up": {"method": "any", "authorizes_action": "invoice:pay"}})
    run = harness(fake, secret=None).run(token="sct_from_backend")

    first = run.check("pay_invoice", {"id": 1})
    assert (first.kind, first.say) == ("verify", "Before I do that, I need to verify it's you.")
    with pytest.raises(ValueError, match="verification method"):
        run.start_verification(verdict=first)

    assert run.start_verification(method="email_otp")["say"] == "I've emailed a code to a***@example.com. What's the code?"
    started = fake.paths(f"{AUTH}/agent/verifications")[0]
    assert (started.auth, started.body) == ("Bearer sct_from_backend",
                                            {"method": "email_otp", "permission": "invoice:pay", "session_id": "sess1"})

    wrong = run.submit_code("000000")
    assert (wrong["status"], wrong["remaining_attempts"], wrong["say"]) == ("pending", 2, "That code didn't work. Want to try again?")
    assert run.verified_at is None
    assert run.submit_code("123456")["status"] == "completed"
    assert run.verified_at and run.verified_at > 0

    assert run.check("pay_invoice", {"id": 1}).kind == "proceed"
    last = fake.paths(CHECK)[-1].body
    assert (last["challenge"], last["session_id"]) == ("ch_ok", "sess1")
    assert fake.paths(MINT) == []


def test_records_a_push_once_its_approved() -> None:
    fake = FakeAgentAPI()
    run = harness(fake).run(acts_for="user1")
    run.start_verification(method="entra_push", permission="invoice:pay")

    with pytest.raises(APIError, match=r"Not verified yet \(pending\)"):
        run.complete_verification()
    fake.verification_status = "completed"
    run.complete_verification()
    assert run.snapshot()["challenges"] == {"invoice:pay": "***"}  # recorded, and never shown


def test_rejects_a_verification_scute_doesnt_accept() -> None:
    run = harness().run(acts_for="user1")
    with pytest.raises(APIError, match="doesn't verify this person"):
        run.complete_verification("ch_forged")
    assert run.verified_at is None


def test_files_the_reviewer_approval_once_and_goes_through_once_approved() -> None:
    fake = FakeAgentAPI()
    fake.decide = lambda body: None if body.get("approval") and fake.request_status == "approved" else {
        "decision": "allow_with_approval", "explanation": "Needs a reviewer."}
    run = harness(fake).run(acts_for="user1")

    pending = run.check("refund_invoice", {"invoice_id": 42, "amount": 900})
    assert pending.kind == "approve"
    assert pending.decision.approve == {"by": "reviewer", "request_id": "req1"}
    assert "The request is filed (id req1)" in (pending.message or "")
    assert pending.say == "I've asked for approval. I'll let you know when there's an answer."
    filed = fake.paths(f"{AUTH}/agent/approvals")[0].body
    assert filed == {"action": "refund", "resource": {"type": "invoice", "key": "42"},
                     "reason": "refund_invoice (invoice_id 42, amount 900)", "details": {"invoice_id": 42, "amount": 900}}
    assert run.approval_status("req1")["say"] == "Still waiting."

    fake.request_status = "approved"
    assert run.check("refund_invoice", {"invoice_id": 42, "amount": 900}).kind == "proceed"
    assert fake.paths(CHECK)[-1].body["approval"] == "req1"
    assert run.snapshot()["approvals"] == {}


def test_files_nothing_while_observing_and_doesnt_claim_a_filing_that_didnt_happen() -> None:
    fake = FakeAgentAPI(decide=lambda body: {"decision": "allow_with_approval", "explanation": "Needs a reviewer."})
    observed = harness(fake, mode="observe").run(acts_for="user1").check("refund_invoice", {"id": 1})
    assert observed.kind == "proceed"
    assert observed.results[0].decision.kind == "approve"

    unfiled = harness(fake, guards=[guards.permissions(file_requests=False)]).run(acts_for="user1").check("refund_invoice", {"id": 1})
    assert unfiled.message == "Needs a reviewer. Tell the person it needs a reviewer's approval."
    assert fake.paths(f"{AUTH}/agent/approvals") == []


# ── runs ──


def test_resumes_from_the_store_by_id_without_a_new_task() -> None:
    fake = FakeAgentAPI()
    h = harness(fake)
    h.run(id="chat-1", acts_for="user1").check("read_invoice", {"id": 1})
    h.run(id="chat-1", acts_for="user1").check("read_invoice", {"id": 2})
    assert len(fake.paths(MINT)) == 1
    assert [c.auth for c in fake.paths(CHECK)] == ["Bearer sct_token1"] * 2


def test_starts_a_new_task_when_the_old_one_expired_but_never_after_it_closed() -> None:
    fake = FakeAgentAPI(ttl=1)
    run = harness(fake).run(acts_for="user1")
    run.check("read_invoice", {"id": 1})
    run.check("read_invoice", {"id": 1})
    assert len(fake.paths(MINT)) == 2

    for reason in ("task_closed", "budget_exceeded"):
        answer: dict[str, Any] = {"decision": "deny", "reason": reason, "explanation": "Closed."}
        closed = FakeAgentAPI(decide=functools.partial(lambda a, body: a, answer))
        run2 = harness(closed).run(acts_for="user1")
        assert run2.check("read_invoice", {"id": 1}).kind == "deny"
        with pytest.raises(APIError, match="task is closed") as e:
            run2.token()
        assert (e.value.status, e.value.code) == (409, "task_closed")
        assert run2.check("read_invoice", {"id": 1}).decision.reason == "guard_error"
        assert len(closed.paths(MINT)) == 1


def test_runs_on_a_task_token_from_your_backend_without_the_secret() -> None:
    fake = FakeAgentAPI()
    h = harness(fake, secret=None)
    assert h.run(token="sct_from_backend").check("read_invoice", {"id": 1}).kind == "proceed"
    assert fake.paths(CHECK)[0].auth == "Bearer sct_from_backend"
    assert fake.paths(MINT) == []

    v = h.run(acts_for="user1").check("read_invoice", {"id": 1})
    assert v.kind == "deny"
    assert isinstance(v.results[0].error, ConfigurationError)
    assert "SCUTE_SECRET" in str(v.results[0].error)


def test_passes_the_parent_task_to_a_sub_agents_task() -> None:
    fake = FakeAgentAPI()
    h = harness(fake)
    parent = h.run(acts_for="user1")
    h.run(acts_for="user1", parent=parent).check("read_invoice", {"id": 1})
    assert [m.body.get("parent_task_id") for m in fake.paths(MINT)] == [None, "task1"]


def test_revokes_its_task_and_ends_the_session() -> None:
    fake = FakeAgentAPI()
    run = harness(fake).run(acts_for="user1")
    run.check("read_invoice", {"id": 1})
    run.session()
    run.revoke()
    assert [s.path for s in fake.seen[-2:]] == [f"{AUTH}/agent/sessions/sess1/end", f"{MINT}/task1/revoke"]
    with pytest.raises(APIError, match="closed"):
        run.token()

    done = harness(fake).run(acts_for="user1")
    done.check("read_invoice", {"id": 1})
    done.complete()
    assert fake.seen[-1].path.endswith("/complete")


def test_a_task_scute_ended_closes_the_run_for_good() -> None:
    fake = FakeAgentAPI()
    run = harness(fake).run(acts_for="user1")
    assert run.check("read_invoice", {"invoice_id": "INV-1"}).kind == "proceed"
    fake.revoked = True
    assert run.check("read_invoice", {"invoice_id": "INV-1"}).decision.reason == "guard_error"
    assert run.snapshot()["closed"] is True
    with pytest.raises(APIError, match="closed"):
        run.token()


def test_lists_the_tools_inside_the_tasks_ceiling() -> None:
    run = harness(FakeAgentAPI(ceiling=["invoice:read"]), tools={"get_weather": False}).run(acts_for="user1")
    assert run.allowed_tools(["read_invoice", "refund_invoice", "get_weather"]) == ["read_invoice", "get_weather"]
    assert run.whoami()["acts_for"] == "user1"


# ── properties ──


def test_reads_a_secret_and_signs_with_the_task_token() -> None:
    fake = FakeAgentAPI()
    run = harness(fake).run(acts_for="user1")
    assert run.property("stripe") == "sk_live_123"
    assert run.sign("mandates", claims={"amount": 4200})["jws"] == "h.b.s"
    assert run.sign("mandates", data="aGVsbG8")["signature"] == "c2ln"
    uses = [s for s in fake.seen if s.path.startswith(f"{AUTH}/agent/properties/")]
    assert all((s.auth or "").startswith("Bearer sct_") for s in uses)
    assert fake.paths(f"{AUTH}/agent/properties/mandates/sign")[0].body == {"claims": {"amount": 4200}}

    with pytest.raises(APIError) as refused:
        run.property("locked")
    assert (refused.value.status, refused.value.code) == (403, "agent_not_listed")
    with pytest.raises(ValueError):
        run.sign("mandates")


# ── combining guards ──


def test_the_strictest_enforced_decision_wins_and_transforms_carry() -> None:
    h = harness(guards=[guards.define("a", lambda c: c.approve("confirm")), guards.define("v", lambda c: c.verify("verify")),
                        guards.define("t", lambda c: c.transform({**c.args, "x": 1}))])
    v = h.run().check("read_invoice", {})
    assert (v.kind, v.decision.guard, v.args) == ("verify", "v", {"x": 1})


def test_later_guards_see_transformed_args_and_the_first_deny_stops() -> None:
    seen: list[Any] = []
    later: list[int] = []
    h = harness(guards=[guards.define("cap", lambda c: c.transform({**c.args, "amount": min(c.args["amount"], 100)})),
                        guards.define("look", lambda c: seen.append(c.args["amount"])),
                        guards.define("no", lambda c: c.deny("no")),
                        guards.define("later", lambda c: later.append(1))])
    assert h.run().check("refund_invoice", {"amount": 900}).kind == "deny"
    assert seen == [100]
    assert later == []


def test_observe_and_monitor_never_block_and_only_enforced_guards_fail_closed() -> None:
    alerts: list[dict[str, Any]] = []

    def boom(call: Any) -> None:
        raise RuntimeError("boom")

    h = harness(on_alert=alerts.append, guards=[guards.define("o", lambda c: c.deny("o"), mode="observe"),
                                                 guards.define("m", lambda c: c.guide("m"), mode="monitor"),
                                                 guards.define("e", boom, mode="observe")])
    v = h.run().check("x", {})
    assert v.kind == "proceed"
    assert [r.decision.kind for r in v.results] == ["deny", "guide", "deny"]
    assert [a["guard"] for a in alerts] == ["m"]

    assert harness(guards=[guards.define("e", boom)]).run().check("x", {}).decision.reason == "guard_error"
    wrong = harness(guards=[guards.define("w", lambda c: True)]).run().check("x", {})  # type: ignore[arg-type, return-value]
    assert isinstance(wrong.results[0].error, TypeError)


def test_reports_every_decision_and_a_raising_hook_changes_nothing() -> None:
    events: list[dict[str, Any]] = []

    def hook(event: dict[str, Any]) -> None:
        events.append(event)
        raise RuntimeError("hook broke")

    h = harness(guards=[guards.define("g", lambda c: c.guide("ask first", "custom"))], on_decision=hook)
    assert h.run(id="r1").check("refund_invoice", {"amount": 5}, id="call1").kind == "guide"
    e = events[0]
    assert (e["run"], e["agent"], e["tool"], e["call_id"], e["phase"], e["kind"], e["guard"], e["reason"]) == (
        "r1", "support-bot", "refund_invoice", "call1", "before", "guide", "g", "custom")


def test_wraps_a_function_and_works_as_a_decorator() -> None:
    h = harness(guards=[guards.define("small", lambda c: c.guide("Keep it under 100.") if c.args["amount"] > 100 else None)])
    run = h.run()
    refund = run.wrap("refund_invoice", lambda amount: f"refunded {amount}")
    assert refund(amount=50) == "refunded 50"
    assert refund(amount=500) == "Keep it under 100."

    @run.wrap("refund_invoice")
    def refund_again(amount: int) -> str:
        """Refund an invoice."""
        return f"again {amount}"

    assert refund_again(amount=20) == "again 20"
    assert refund_again.__doc__ == "Refund an invoice."
    assert run.snapshot()["calls"] == 2
    assert run.tool_names == ["refund_invoice"]


def test_needs_an_agent() -> None:
    with pytest.raises(ConfigurationError, match="agent"):
        Harness("", app_id="a")


def test_never_shows_a_token_or_the_secret() -> None:
    fake = FakeAgentAPI()
    h = harness(fake)
    run = h.run(acts_for="user1")
    run.check("read_invoice", {"id": 1})
    run.start_verification(method="email_otp", permission="invoice:read")
    shown = " ".join([repr(h), repr(run), json.dumps(run.snapshot()), repr(h.client), repr(h.spec("read_invoice"))])
    assert "sct_" not in shown and "sk_test" not in shown and "ch_ok" not in shown

    fake.revoked = True
    with pytest.raises(APIError) as e:
        run.whoami()
    assert "sct_" not in f"{e.value} {e.value!r} {e.value.body}"
    closed = harness(FakeAgentAPI(decide=lambda body: {"decision": "deny", "reason": "task_closed"})).run(acts_for="user1")
    verdict: Verdict = closed.check("read_invoice", {"id": 1})
    assert "sct_" not in f"{verdict!r} {verdict.message}"


# ── the agents API (secret key) ──


def test_registers_agents_and_starts_tasks() -> None:
    fake = FakeAgentAPI()
    scute = harness(fake).client
    made = scute.agents.create("support-bot", roles=["support"], settings={"budget": {"max_actions": 2}})
    assert made["roles"] == ["support"] and fake.seen[-1].body == {"slug": "support-bot", "roles": ["support"],
                                                                   "settings": {"budget": {"max_actions": 2}}}
    assert scute.agents.list() == [{"slug": "support-bot"}]
    task = scute.agents.start_task("support-bot", acts_for="user1", actions=["invoice:read"], ttl=600)
    assert task["token"].startswith("sct_") and fake.seen[-1].body == {"acts_for": "user1", "actions": ["invoice:read"],
                                                                          "ttl_seconds": 600}
    scute.agents.revoke_task("support-bot", task["id"])
    assert fake.seen[-1].path == f"{MINT}/task1/revoke"
    scute.agents.suspend("support-bot", reason="stop")
    assert (fake.seen[-1].path, fake.seen[-1].body) == ("/v1/apps/app1/authz/agents/support-bot/suspend", {"reason": "stop"})


def test_a_budget_answer_from_scute_is_final(monkeypatch: pytest.MonkeyPatch) -> None:
    """The agent went over its budget in Scute: the run is closed, and the next
    call doesn't mint a new task behind its back."""
    fake = FakeAgentAPI()
    count = {"n": 0}

    def decide(body: dict[str, Any]) -> dict[str, Any] | None:
        count["n"] += 1
        return {"decision": "deny", "reason": "budget_exceeded", "say": "I've been paused."} if count["n"] > 2 else None

    fake.decide = decide
    run = harness(fake).run(acts_for="user1")
    kinds = [run.check("read_invoice", {"id": n}).kind for n in range(3)]
    assert kinds == ["proceed", "proceed", "deny"]
    assert run.snapshot()["closed"] is True
    fourth = run.check("read_invoice", {"id": 4})
    assert (fourth.kind, fourth.decision.reason) == ("deny", "guard_error")
    assert len(fake.paths(MINT)) == 1
    assert len(fake.paths(CHECK)) == 3


def test_a_given_token_run_closes_on_a_dead_token_too() -> None:
    fake = FakeAgentAPI(revoked=True)
    run = harness(fake, secret=None).run(token="sct_from_backend")
    with pytest.raises(APIError):
        run.whoami()
    assert run.snapshot()["closed"] is True


def test_httpx_transport_errors_are_connection_errors() -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    run = harness(transport=httpx.MockTransport(fail)).run(acts_for="user1")
    v = run.check("read_invoice", {"id": 1})
    assert isinstance(v.results[0].error, ConnectionError)
