from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any

import httpx

from ..client import Scute
from ..errors import ConfigurationError
from .call import Call
from .convention import ToolSetting, ToolSpec
from .decision import PROCEED, RANK, Decision, GuardResult, Mode, Verdict, for_model
from .guards import Guard, permissions
from .run import Run
from .store import MemoryStore, Store

Hook = Callable[[dict[str, Any]], object]


class Harness:
    """The harness around an agent you build: guards decide on each tool call,
    backed by Scute's engine for who may do what.

        harness = Harness(agent="support-bot", guards=[guards.permissions()])
        run = harness.run(acts_for=user_id, actions=["invoice:read", "invoice:refund"])
        verdict = run.check("refund_invoice", {"invoice_id": "INV-1", "amount": 90})

    Credentials: pass `scute` (a Scute client), or app_id / secret / base_url
    (else SCUTE_APP_ID, SCUTE_SECRET, SCUTE_BASE_URL). The secret mints tasks;
    an agent process without it runs on a task token your backend minted:
    harness.run(token=...).

    tools: {"refund_invoice": {"tier": "high"}, "get_weather": False}
    on_decision(event) sees every decision; on_alert(event) when a guard in
    monitor mode would have blocked. Neither ever gets a token.
    """

    def __init__(self, agent: str, *, guards: Sequence[Guard] | None = None, tools: Mapping[str, ToolSetting] | None = None,
                 mode: Mode = "enforce", default_tier: str = "low", store: Store | None = None, scute: Scute | None = None,
                 app_id: str | None = None, secret: str | None = None, base_url: str | None = None, timeout: float = 10.0,
                 transport: httpx.BaseTransport | None = None, on_decision: Hook | None = None,
                 on_alert: Hook | None = None) -> None:
        if not agent:
            raise ConfigurationError("Harness needs agent: the agent's slug in Scute")
        self.agent = str(agent)
        self.mode: Mode = mode
        self.guards: list[Guard] = list(guards) if guards is not None else [permissions()]
        self._tools = {str(k): v for k, v in (tools or {}).items()}
        self._default_tier = default_tier
        self.store: Store = store if store is not None else MemoryStore()
        self.client = scute or Scute(app_id, secret, base_url, timeout=timeout, transport=transport)
        self._on_decision = on_decision
        self._on_alert = on_alert
        self._specs: dict[str, ToolSpec] = {}
        self._lock = threading.Lock()
        self._log_lock = threading.Lock()
        # Guards that spend single-use proofs go last, in their listed order.
        self._ordered = [g for g in self.guards if not g.runs_last] + [g for g in self.guards if g.runs_last]

    def __repr__(self) -> str:
        return f"Harness(agent={self.agent!r}, guards={[g.name for g in self.guards]!r})"

    def run(self, *, id: str | None = None, acts_for: str | None = None, actions: list[str] | None = None,
            resources: list[str] | None = None, ttl: int | None = None, ref: str | None = None,
            requester: Mapping[str, Any] | None = None, parent: Run | None = None, token: str | None = None,
            session: Mapping[str, Any] | None = None, context: Mapping[str, Any] | None = None) -> Run:
        """Start (or resume, with the same id and acts_for) a job for the agent.

        acts_for: the app user the agent works for (omit for an agent on its own).
        actions / resources / ttl / ref: narrow the task (permission slugs, "invoice"
        or "invoice:42", seconds). requester: who asked ({email, phone, name}).
        parent: the Run that started this one (a sub-agent). token: a task token
        your backend minted (no secret needed here). session: {channel,
        external_ref, caller}. context: sent with every check (context.*).
        The task itself starts on first use."""
        return Run(self, id=id, acts_for=acts_for, actions=actions, resources=resources, ttl=ttl, ref=ref,
                   requester=requester, parent=parent, token=token, session=session, context=context)

    def spec(self, tool: str) -> ToolSpec:
        with self._lock:
            name = str(tool)
            if name not in self._specs:
                self._specs[name] = ToolSpec(name, self._tools.get(name), self._default_tier)
            return self._specs[name]

    # ── evaluation (used by Run) ──

    def evaluate(self, call: Call) -> Verdict:
        """Before-guards: the strictest enforced decision wins."""
        started = time.monotonic()
        results: list[GuardResult] = []
        winner = PROCEED
        for guard in self._ordered:
            if not guard.handles("before"):
                continue
            mode = call.mode = guard.mode or self.mode
            call.clear = winner.rank <= RANK["transform"]
            decision, error = self._ask(guard, "before", call)
            results.append(GuardResult(guard=guard.name, mode=mode, decision=decision, error=error))
            if mode != "enforce":
                if mode == "monitor" and decision.kind != "proceed":
                    self._alert(call, "before", guard.name, decision)
                continue
            if decision.kind == "transform" and decision.args is not None:
                call.args = dict(decision.args)
            if decision.rank > winner.rank:
                winner = decision.named(guard.name)
            if decision.kind == "deny":
                break
        self._emit(call, "before", winner, results, started)
        return self._verdict(call, winner, results)

    def evaluate_after(self, call: Call, result: Any) -> Any:
        """After-guards transform or withhold a result. Returns what the model should see."""
        started = time.monotonic()
        results: list[GuardResult] = []
        current = result
        winner = PROCEED
        for guard in self._ordered:
            if not guard.handles("after"):
                continue
            mode = call.mode = guard.mode or self.mode
            decision, error = self._ask(guard, "after", call, current)
            results.append(GuardResult(guard=guard.name, mode=mode, decision=decision, error=error))
            if mode != "enforce":
                if mode == "monitor" and decision.kind != "proceed":
                    self._alert(call, "after", guard.name, decision)
                continue
            if decision.kind == "proceed":
                continue
            if decision.rank > winner.rank:
                winner = decision.named(guard.name)
            if decision.replaces_result:
                current = decision.result
            elif decision.rank >= RANK["guide"]:
                current = {"error": decision.message or "This result was withheld."}
            if decision.kind == "deny":
                break
        self._emit(call, "after", winner, results, started)
        return current

    def record_execution(self, key: str, tier: str) -> None:
        """Serialized in this process; across processes the store decides (use one
        with atomic writes for hard limits)."""
        with self._log_lock:
            recent = self.executions(key, 3600)
            recent.append({"at": time.time(), "tier": str(tier)})
            self.store.set(key, json.dumps(recent), 3600)

    def executions(self, key: str, window: float) -> list[dict[str, Any]]:
        raw = self.store.get(key)
        since = time.time() - window
        return [e for e in json.loads(raw) if e["at"] > since] if raw else []

    # ── internals ──

    def _verdict(self, call: Call, winner: Decision, results: list[GuardResult]) -> Verdict:
        say = winner.say or (winner.engine.say if winner.engine else None)
        verdict = Verdict(kind=winner.kind, decision=winner, args=call.args, results=results, call_id=call.id,
                          tool=call.tool, say=say)
        if not verdict.runs:
            verdict.message = for_model(verdict.kind, winner, human_tools=bool(call.run.human_tool_names))
        if verdict.kind == "verify":
            call.run.last_verify = winner.verify
        return verdict

    @staticmethod
    def _ask(guard: Guard, phase: str, call: Call, *result: Any) -> tuple[Decision, BaseException | None]:
        try:
            decision = guard.before(call) if phase == "before" else guard.after(call, result[0])
            if decision is None:
                return PROCEED, None
            if not isinstance(decision, Decision):
                raise TypeError(f"{guard.name} answered {type(decision).__name__}, not a Decision")
            return decision, None
        except Exception as e:  # noqa: BLE001 - a guard that raises counts as deny (fail closed)
            message = ("This action couldn't be checked safely right now." if phase == "before"
                       else "This result couldn't be checked safely, so it was withheld.")
            return Decision(kind="deny", reason="guard_error", message=message), e

    def _emit(self, call: Call, phase: str, winner: Decision, results: list[GuardResult], started: float) -> None:
        if not self._on_decision:
            return
        try:
            self._on_decision({"run": call.run.id, "agent": self.agent, "tool": call.tool, "call_id": call.id, "phase": phase,
                               "kind": winner.kind, "guard": winner.guard, "reason": winner.reason, "message": winner.message,
                               "results": results, "ms": round((time.monotonic() - started) * 1000, 2)})
        except Exception:  # noqa: BLE001, S110 - a logging hook never changes a decision
            pass

    def _alert(self, call: Call, phase: str, guard: str, decision: Decision) -> None:
        if not self._on_alert:
            return
        try:
            self._on_alert({"run": call.run.id, "agent": self.agent, "tool": call.tool, "call_id": call.id, "phase": phase,
                            "guard": guard, "decision": decision})
        except Exception:  # noqa: BLE001, S110 - an alert hook never changes a decision
            pass
