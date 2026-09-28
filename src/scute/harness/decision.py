from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from ..authz import Decision as EngineDecision

Kind = Literal["proceed", "transform", "approve", "verify", "guide", "redirect", "deny"]
Mode = Literal["enforce", "monitor", "observe"]

# What a guard wants done with a tool call, least to most strict. Verify ranks
# above approve: an approver should see a request from a verified person.
RANK: dict[str, int] = {"proceed": 0, "transform": 1, "approve": 2, "verify": 3, "guide": 4, "redirect": 5, "deny": 6}

_NO_RESULT: Any = object()


@dataclass
class Decision:
    """A guard's answer on one call.

    `result`: from an after-guard, what the model sees instead of the tool's
    result. `say`: a line for the person (voice or chat), when there's
    something to tell them. `engine`: Scute's decision behind it, if any."""

    kind: Kind
    reason: str | None = None
    message: str | None = None
    say: str | None = None
    args: dict[str, Any] | None = None
    verify: dict[str, Any] | None = None
    approve: dict[str, Any] | None = None
    redirect: dict[str, Any] | None = None
    engine: EngineDecision | None = None
    guard: str | None = None
    result: Any = field(default=_NO_RESULT, repr=False)

    def __post_init__(self) -> None:
        if self.kind not in RANK:
            raise ValueError(f"unknown decision {self.kind!r}")

    @property
    def rank(self) -> int:
        return RANK[self.kind]

    @property
    def replaces_result(self) -> bool:
        return self.result is not _NO_RESULT

    def named(self, guard: str) -> Decision:
        return replace(self, guard=guard, verify=dict(self.verify) if self.verify else None,
                       approve=dict(self.approve) if self.approve else None)

    def to_dict(self) -> dict[str, Any]:
        out = {"kind": self.kind, "reason": self.reason, "message": self.message, "args": self.args, "verify": self.verify,
               "approve": self.approve, "redirect": self.redirect, "guard": self.guard}
        return {k: v for k, v in out.items() if v is not None}


PROCEED = Decision(kind="proceed")


@dataclass(frozen=True)
class GuardResult:
    """One guard's opinion on a call (in every mode), and the error if it raised."""

    guard: str
    mode: Mode
    decision: Decision
    error: BaseException | None = None


@dataclass
class Verdict:
    """The harness's answer for one call: the strictest enforced decision, and
    every guard's opinion. `message` is for the model when the call doesn't
    run; `say` is for the person."""

    kind: Kind
    decision: Decision
    args: dict[str, Any]
    results: list[GuardResult]
    call_id: str
    tool: str
    message: str | None = None
    say: str | None = None

    @property
    def runs(self) -> bool:
        """The call may run (proceed, or transform with `args`)."""
        return self.kind in ("proceed", "transform")


def _text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def describe_call(tool: str, args: Mapping[str, Any]) -> str:
    parts = [f"{k} {_text(v)[:60]}" for k, v in args.items() if isinstance(v, (str, int, float, bool))][:4]
    return f"{tool} ({', '.join(parts)})" if parts else tool


def for_model(kind: str, decision: Decision, *, human_tools: bool = False) -> str:
    """What the model reads when a call doesn't run: what to do next, not only that it failed."""
    said = (decision.message or (decision.engine.explanation if decision.engine else None) or "").strip()
    if kind == "deny":
        return f"Not allowed: {said or 'this action is blocked.'} Don't retry it; tell the person."
    if kind == "guide":
        return said or "Don't run this as it is."
    if kind == "redirect":
        to = (decision.redirect or {}).get("to") or "another route"
        return " ".join(p for p in (f"Use {to} instead.", said) if p)
    if kind == "verify":
        base = said or "The person has to verify it's them first."
        return f"{base} Verify them with scute_verify_person, then try again." if human_tools else \
            f"{base} Tell them; try again once they have."
    if kind == "approve":
        approve = decision.approve or {}
        if approve.get("by") != "reviewer":
            return f"{said or 'The person has to confirm this first.'} Ask them to confirm, then try again."
        base = said or "A reviewer has to approve this."
        if not approve.get("request_id"):
            return f"{base} Tell the person it needs a reviewer's approval."
        return f"{base} The request is filed (id {approve['request_id']}); tell the person it's pending and try again once it's approved."
    return said
