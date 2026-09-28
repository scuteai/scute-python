from __future__ import annotations

import builtins
import contextlib
import functools
import hashlib
import json
import threading
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from typing import TYPE_CHECKING, Any, TypeVar, overload

from ..authz import Decision as EngineDecision
from ..errors import APIError, ConfigurationError
from .call import Call
from .convention import resource_ref
from .decision import Verdict, describe_call

if TYPE_CHECKING:
    from .core import Harness
    from .human_tools import HumanTool

F = TypeVar("F", bound=Callable[..., Any])
Messages = Sequence[Any] | Callable[[], Sequence[Any]]

HOUR = 3600
_MASK = "***"


def _epoch(value: Any) -> float | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _canonical(value: Any) -> Any:
    if isinstance(value, Mapping):
        return sorted(([str(k), _canonical(v)] for k, v in value.items()), key=lambda kv: kv[0])
    if isinstance(value, (list, tuple)):
        return [_canonical(v) for v in value]
    return value


def fingerprint(tool: str, args: Mapping[str, Any]) -> str:
    """One exact call (the tool and its arguments, in any key order)."""
    raw = json.dumps([str(tool), _canonical(args)], separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


class Run:
    """One job an agent does: a Scute task (its token never reaches the model),
    its session, and what the guards remember. Reuse `id` (with the same
    `acts_for`) to resume from the harness's store.

    Checks within a run go one at a time, so budgets and single-use proofs
    hold when the model asks for several tools at once. A task Scute ends
    (revoked, completed, the agent suspended or over its budget) closes the run
    for good; it's never quietly replaced.
    """

    HOUR = HOUR

    def __init__(self, harness: Harness, *, id: str | None = None, acts_for: str | None = None,
                 actions: list[str] | None = None, resources: list[str] | None = None, ttl: int | None = None,
                 ref: str | None = None, requester: Mapping[str, Any] | None = None, parent: Run | None = None,
                 token: str | None = None, session: Mapping[str, Any] | None = None,
                 context: Mapping[str, Any] | None = None) -> None:
        self.harness = harness
        self.id = str(id or uuid.uuid4())
        self._acts_for = acts_for
        self._task: dict[str, Any] = {"actions": actions, "resources": resources, "ttl": ttl, "ref": ref}
        self._requester = {k: v for k, v in (requester or {}).items() if v is not None}
        self._parent = parent
        self._given_token = token
        self._session_options = dict(session or {})
        self._context = dict(context or {})
        self._lock = threading.RLock()
        self._serial = threading.Lock()
        self._grounded: set[str] = set()
        self._identified: set[str] = set()
        self._state: dict[str, Any] | None = None
        self._whoami: dict[str, Any] | None = None
        #: Tool names this run guards (allowed_tools narrows these).
        self.tool_names: list[str] = []
        #: The human tools offered to the model (always allowed).
        self.human_tool_names: list[str] = []
        #: The last verification a guard asked for (for scute_verify_person).
        self.last_verify: dict[str, Any] | None = None

    def __repr__(self) -> str:
        return f"Run({self.id!r}, agent={self.harness.agent!r})"

    # ── Task ──

    def token(self) -> str:
        """The task token, starting the task on first use. Never give it to the model."""
        if self._given_token:
            return self._given_token
        with self._lock:
            s = self._load()
            if s.get("closed"):
                raise APIError("This run's task is closed; start a new run", status=409, code="task_closed")
            if s.get("token") and not self._expiring(s):
                return str(s["token"])
            return self._mint()

    def task_id(self) -> str:
        if self._given_token:
            return str(self.whoami()["task"])
        self.token()
        return str(self._load()["task_id"])

    def whoami(self) -> dict[str, Any]:
        """Who the agent works for, what the task allows now, its ceiling and
        how long it has left. Cached per run."""
        with self._lock:
            if self._whoami is None:
                self._whoami = dict(self._agent_call("GET", "/agent/whoami"))
            return self._whoami

    def property(self, name: str) -> str:
        """A secret the app keeps in Scute (a property), read at call time inside
        a tool. Only listed agents can read it, only while the task is live (and
        allowed the property's permission, when it names one). Use it, don't
        return it: it should never reach the model."""
        return str(self._agent_call("GET", f"/agent/properties/{self.harness.client.esc(name)}")["value"])

    def sign(self, name: str, *, claims: Mapping[str, Any] | None = None, data: str | None = None) -> dict[str, Any]:
        """Sign with one of the app's key pairs: claims -> {"jws", "alg", "kid"}, or
        data (base64url bytes) -> {"signature", "alg", "kid"}. The private key never
        leaves Scute; the public keys are at /v1/auth/:app_id/properties/:name/jwks.json."""
        if claims is None and data is None:
            raise ValueError("Pass claims= or data=")
        body = {"claims": dict(claims)} if claims is not None else {"data": data}
        return dict(self._agent_call("POST", f"/agent/properties/{self.harness.client.esc(name)}/sign", body))

    def complete(self) -> None:
        """The job is done: close the task (and its session)."""
        self._close("complete")

    def revoke(self) -> None:
        """Stop now: the task token stops working everywhere."""
        self._close("revoke")

    # ── Session and verification ──

    def session(self) -> str:
        """The run's session (made on first use). A verification lives on it, and
        every check carries it."""
        with self._lock:
            s = self._load()
            if s.get("session_id"):
                return str(s["session_id"])
            body = {"channel": self._session_options.get("channel") or "chat",
                    "external_ref": self._session_options.get("external_ref") or self.id,
                    "caller": self._session_options.get("caller")}
            created = self._agent_call("POST", "/agent/sessions", {k: v for k, v in body.items() if v is not None})
            s["session_id"] = created["id"]
            self._save()
            return str(created["id"])

    @builtins.property
    def verified_at(self) -> float | None:
        """When the person last verified in this run (epoch seconds), if they have."""
        value = self._load().get("verified_at")
        return float(value) if value is not None else None

    def start_verification(self, *, verdict: Verdict | None = None, method: str | None = None,
                           permission: str | None = None) -> dict[str, Any]:
        """Send the person a verification: a code by email or text, their
        authenticator app, or a push. Pass the verdict that asked for it, or a
        method and permission. Works with the task token alone; the answer has a
        "say" line for the person."""
        asked = (verdict.decision.verify if verdict else None) or self.last_verify or {}
        permission = permission or asked.get("permission")
        methods = [str(m) for m in [method, asked.get("method"), *(asked.get("methods") or [])] if m and m != "any"]
        if not methods:
            raise ValueError("Pick a verification method (email_otp, sms_otp, totp, entra_push...)")
        body = {"method": methods[0], "permission": permission, "session_id": self.session()}
        verification = dict(self._agent_call("POST", "/agent/verifications", {k: v for k, v in body.items() if v is not None}))
        with self._lock:
            self._load()["pending"] = {"token": verification["token"], "permission": permission}
            self._save()
        return verification

    def submit_code(self, code: str, challenge_token: str | None = None) -> dict[str, Any]:
        """The person read out the code. A wrong code comes back with status
        "pending" and a "say" line (no exception)."""
        token = challenge_token or self._pending_token()
        try:
            verification = dict(self._agent_call("POST", f"/agent/verifications/{self.harness.client.esc(token)}/code",
                                                 {"code": str(code)}))
        except APIError as e:
            if e.status == 422 and isinstance(e.body, dict) and e.body.get("status"):
                return dict(e.body)
            raise
        if verification.get("status") == "completed":
            self._record_verified(token)
        return verification

    def verification_status(self, challenge_token: str | None = None) -> dict[str, Any]:
        """Where a verification stands (poll this for pushes). Recorded once it's complete."""
        token = challenge_token or self._pending_token()
        verification = dict(self._agent_call("GET", f"/agent/verifications/{self.harness.client.esc(token)}"))
        if verification.get("status") == "completed":
            self._record_verified(token)
        return verification

    def complete_verification(self, challenge_token: str | None = None) -> None:
        """Record a finished verification: one this run started (Scute reports it),
        or a challenge your backend started (Scute checks it's the person's,
        completed and fresh). Raises APIError (409, not_verified) when it isn't done."""
        pending = (self._load().get("pending") or {}).get("token")
        token = challenge_token or pending
        if not token:
            raise ValueError("No verification to complete")
        if token == pending:
            status = self.verification_status(token).get("status")
            if status != "completed":
                raise APIError(f"Not verified yet ({status})", status=409, code="not_verified")
            return
        self._agent_call("POST", f"/agent/sessions/{self.harness.client.esc(self.session())}/verified", {"challenge": token})
        self._record_verified(token)

    def request_approval(self, call: Call) -> dict[str, Any] | None:
        """File (or find: Scute answers with the open one) the reviewer approval
        for this exact call. Its arguments go with it and reviewers see them;
        the approval only counts for the same arguments."""
        if not call.permission or not call.spec.action:
            return None
        body = {"action": call.spec.action, "resource": call.resource, "context": self._context or None,
                "reason": describe_call(call.tool, call.args), "details": call.args}
        approval = dict(self._agent_call("POST", "/agent/approvals", {k: v for k, v in body.items() if v is not None}))
        if not approval.get("id"):
            return None
        with self._lock:
            self._load()["approvals"][self._approval_key(call)] = {"id": approval["id"], "call": fingerprint(call.tool, call.args)}
            self._save()
        return approval

    def approval_status(self, approval_id: str) -> dict[str, Any]:
        """Where an approval this run filed stands, with a "say" line."""
        return dict(self._agent_call("GET", f"/agent/approvals/{self.harness.client.esc(approval_id)}"))

    def confirm(self, tool: str, args: Mapping[str, Any]) -> None:
        """The person confirmed this exact call in your UI: guards.approval() lets it through once."""
        with self._lock:
            self._load()["confirmed"].append(fingerprint(tool, args))
            self._save()

    def consume_confirmation(self, call: Call) -> bool:
        """(For guards) spend a confirmation of this exact call, if there is one."""
        with self._lock:
            confirmed: list[str] = self._load()["confirmed"]
            mark = fingerprint(call.tool, call.args)
            if mark not in confirmed:
                return False
            confirmed.remove(mark)
            self._save()
            return True

    # ── Engine ──

    def engine_check(self, call: Call, context: Mapping[str, Any] | None = None, *, proofs: bool = False) -> EngineDecision:
        """(For guards) Scute's engine on a call: the agent's roles, the person and
        the task. Tool arguments go as context.args, never as the object's
        attributes. proofs: send this run's verification and the approval filed
        for this exact call; they're single-use, so only on the pass nothing
        else stops."""
        s = self._load()
        key = self._approval_key(call)
        filed = s["approvals"].get(key)
        approval = filed["id"] if proofs and filed and filed.get("call") == fingerprint(call.tool, call.args) else None
        body = {"action": call.spec.action, "resource": call.resource,
                "context": {**self._context, **(context or {}), "args": call.args},
                "challenge": s["challenges"].get(call.permission) if proofs else None, "approval": approval,
                "details": call.args if approval else None, "session_id": s.get("session_id")}
        answer = self._agent_call("POST", "/agent/check", {k: v for k, v in body.items() if v is not None}, idempotent=True)
        decision = EngineDecision.from_api(answer)
        with self._lock:
            # budget_exceeded: Scute paused the agent and ended its tasks.
            if decision.reason in ("task_closed", "budget_exceeded"):
                self._load()["closed"] = True
                self._save()
            elif approval and decision.allowed:
                self._load()["approvals"].pop(key, None)  # spent
                self._save()
        return decision

    # ── Checking calls ──

    def check(self, tool: str, args: Mapping[str, Any] | None = None, *, id: str | None = None,
              messages: Sequence[Any] | None = None, approved_by_user: bool = False) -> Verdict:
        """Run the guards on a call before it happens. `messages`: the
        conversation, for guards.grounding(). `approved_by_user`: the person
        already confirmed this call (a framework's approval step)."""
        call = self._new_call(tool, args, id, messages, approved_by_user)
        with self._serial:
            verdict = self.harness.evaluate(call)
            # A call that may run takes its share of the budgets now, before the next check looks.
            if verdict.runs:
                self._reserve(call)
            return verdict

    def after(self, tool: str, args: Mapping[str, Any] | None, result: Any, *, id: str | None = None,
              messages: Sequence[Any] | None = None) -> Any:
        """Run the after-guards on a call's result. Returns what the model should see."""
        return self.harness.evaluate_after(self._new_call(tool, args, id, messages, False), result)

    @overload
    def wrap(self, tool: str, fn: F, *, messages: Messages | None = None) -> Callable[..., Any]: ...

    @overload
    def wrap(self, tool: str, fn: None = None, *, messages: Messages | None = None) -> Callable[[F], Callable[..., Any]]: ...

    def wrap(self, tool: str, fn: F | None = None, *, messages: Messages | None = None) -> Any:
        """Guard a function called with the tool's arguments as keywords. When a
        call doesn't run, the wrapper returns the message for the model instead.
        Works as a decorator too:

            @run.wrap("refund_invoice")
            def refund(invoice_id: str, amount: float) -> str: ...
        """

        def decorate(inner: F) -> Callable[..., Any]:
            if tool not in self.tool_names:
                self.tool_names.append(tool)

            @functools.wraps(inner)
            def guarded(**args: Any) -> Any:
                transcript = messages() if callable(messages) else messages
                verdict = self.check(tool, args, messages=transcript)
                if not verdict.runs:
                    return verdict.message or "Not allowed."
                return self.after(tool, verdict.args, inner(**verdict.args), messages=transcript)

            return guarded

        return decorate(fn) if fn is not None else decorate

    # ── Grounding, identity, usage, budgets ──

    def ground(self, *values: Any) -> None:
        """Values known to be true for this run (an account id you looked up), for guards.grounding()."""
        self._grounded.update(str(v).lower() for v in values if v is not None and str(v) != "")

    def identify(self, *values: Any) -> None:
        """Who is asking, once you know (the verified caller's email or phone). For guards.requester_only()."""
        self._identified.update(str(v).lower() for v in values if v is not None and str(v) != "")

    def identities(self) -> list[str]:
        known = [str(v).lower() for v in self._requester.values() if str(v)]
        return list(dict.fromkeys([*known, *sorted(self._identified)]))

    def grounded_values(self) -> list[str]:
        return list(dict.fromkeys([*sorted(self._grounded), *self.identities()]))

    def record_usage(self, *, usd: float = 0.0) -> None:
        """Model spend, for guards.budget(usd_per_run=...)."""
        with self._lock:
            self._load()["usd"] += float(usd)
            self._save()

    def budget_key(self) -> str:
        """Hourly budgets count per agent and person, across runs."""
        who = self._acts_for or self._load().get("acts_for")
        if not who and self._given_token:
            me = self.whoami()
            who = me.get("acts_for") or f"task-{me.get('task')}"
        return f"scute:hour:{self.harness.agent}:{who or 'none'}"

    def recent_executions(self) -> list[dict[str, Any]]:
        return self.harness.executions(self.budget_key(), HOUR)

    def budget_exhausted(self) -> bool:
        """True when a run budget (calls or spend, from guards.budget()) is used up."""
        return any(g.exhausted(self) for g in self.harness.guards)

    def allowed_tools(self, names: Sequence[str] | None = None) -> list[str]:
        """Tools the task could ever use (its ceiling), plus the human tools.
        Tools without a permission always count."""
        ceiling = list(self.whoami().get("ceiling") or [])
        allowed = [n for n in (self.tool_names if names is None else names)
                   if n in self.human_tool_names or self.harness.spec(n).permission is None
                   or self.harness.spec(n).permission in ceiling]
        return list(dict.fromkeys([*allowed, *self.human_tool_names]))

    def snapshot(self) -> dict[str, Any]:
        """A copy of what this run remembers (counters, task, session,
        verification), with the tokens masked."""
        with self._lock:
            s: dict[str, Any] = json.loads(json.dumps(self._load()))
        s.pop("token", None)
        s["challenges"] = {k: _MASK for k in s.get("challenges", {})}
        if s.get("pending"):
            s["pending"]["token"] = _MASK
        return s

    def human_tools(self, methods: Sequence[str] | None = None) -> dict[str, HumanTool]:
        """Tools the model calls to bring the person in (verify, pass on a code,
        check a push or an approval, whoami), as plain callables with JSON Schema
        parameters. Every answer has a "say" line."""
        from .human_tools import METHODS, build

        return build(self, methods=list(methods or METHODS))

    # ── internals ──

    def _new_call(self, tool: str, args: Mapping[str, Any] | None, id: str | None, messages: Sequence[Any] | None,
                  approved_by_user: bool) -> Call:
        return Call(self, id or str(uuid.uuid4()), tool, args, self.harness.spec(tool), messages, approved_by_user)

    def _key(self) -> str:
        # Keyed by who the run is for too: one id reused for someone else never
        # sees the first person's task, verification or approvals.
        if self._acts_for:
            who = self._acts_for
        elif self._given_token:
            who = f"token-{hashlib.sha256(self._given_token.encode()).hexdigest()[:12]}"
        else:
            who = "self"
        return f"scute:run:{self.harness.agent}:{who}:{self.id}"

    def _load(self) -> dict[str, Any]:
        with self._lock:
            if self._state is None:
                raw = self.harness.store.get(self._key())
                self._state = json.loads(raw) if raw else {}
            s = self._state
            s.setdefault("challenges", {})
            s.setdefault("approvals", {})
            s.setdefault("confirmed", [])
            s.setdefault("calls", 0)
            s.setdefault("usd", 0.0)
            return s

    def _save(self) -> None:
        with self._lock:
            s = self._load()
            until = _epoch(s.get("expires_at"))
            left = max((until - time.time()) if until else 0.0, 0.0)
            # Kept a day past the task, so a conversation resumed later still has its counters.
            self.harness.store.set(self._key(), json.dumps(s), left + 86400)

    def _reserve(self, call: Call) -> None:
        with self._lock:
            self._load()["calls"] += 1
            self._save()
        self.harness.record_execution(self.budget_key(), call.tier)

    @staticmethod
    def _expiring(s: Mapping[str, Any]) -> bool:
        until = _epoch(s.get("expires_at"))
        return until is not None and until <= time.time() + 5

    def _mint(self) -> str:
        client = self.harness.client
        if not client.has_secret:
            raise ConfigurationError("A run needs SCUTE_SECRET to start a task, or a task token (run(token=...)) "
                                     "minted by your backend")
        minted = client.agents.start_task(
            self.harness.agent, acts_for=self._acts_for, actions=self._task["actions"], resources=self._task["resources"],
            ttl=self._task["ttl"], ref=self._task["ref"], requester=self._requester or None,
            parent_task_id=self._parent.task_id() if self._parent else None)
        s = self._load()
        s.update({"token": minted["token"], "task_id": minted["id"], "expires_at": minted.get("expires_at"),
                  "acts_for": minted.get("acts_for"), "minted": True})
        s.pop("session_id", None)
        self._whoami = None
        self._save()
        return str(minted["token"])

    def _close(self, verb: str) -> None:
        with self._lock:
            s = self._load()
            if s.get("session_id") and (s.get("token") or self._given_token):
                # Ending the session is best effort; the task closes regardless.
                with contextlib.suppress(Exception):
                    self._agent_call("POST", f"/agent/sessions/{self.harness.client.esc(s['session_id'])}/end")
            if s.get("task_id"):
                agents = self.harness.client.agents
                (agents.complete_task if verb == "complete" else agents.revoke_task)(self.harness.agent, s["task_id"])
            s["closed"] = True
            self._save()

    def _agent_call(self, method: str, path: str, body: Any = None, *, idempotent: bool | None = None) -> Any:
        """A call with the task token. A token Scute says is dead before its
        expiry (revoked, completed, the agent suspended) closes the run for good."""
        client = self.harness.client
        try:
            return client.http.request(method, client.auth_path(path), bearer=self.token(), body=body, idempotent=idempotent)
        except APIError as e:
            if e.status == 401 and e.code == "invalid_task_token":
                with self._lock:
                    s = self._load()
                    until = _epoch(s.get("expires_at"))
                    if self._given_token or (until is not None and until > time.time()):
                        s["closed"] = True
                        self._save()
            raise

    def _pending_token(self) -> str:
        token = (self._load().get("pending") or {}).get("token")
        if not token:
            raise ValueError("No verification in progress")
        return str(token)

    def _record_verified(self, token: str) -> None:
        with self._lock:
            s = self._load()
            s["verified_at"] = time.time()
            pending = s.get("pending") or {}
            if pending.get("token") == token:
                if pending.get("permission"):
                    s["challenges"][pending["permission"]] = token
                s.pop("pending", None)
            self._save()

    def _approval_key(self, call: Call) -> str:
        return f"{call.permission}|{resource_ref(call.resource)}"
