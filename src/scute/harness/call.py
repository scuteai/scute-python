from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

from .decision import Decision, Mode

if TYPE_CHECKING:
    from .convention import ToolSpec
    from .run import Run


class Call:
    """A tool call as guards see it, with helpers to answer.

    `args`: after any earlier guard's transform. `mode`: of the guard looking
    at it now. `clear`: no enforced guard so far stops the call (the moment to
    spend single-use proofs)."""

    def __init__(self, run: Run, id: str, tool: str, args: Mapping[str, Any] | None, spec: ToolSpec,
                 messages: Sequence[Any] | None = None, approved_by_user: bool = False) -> None:
        self.run = run
        self.id = id
        self.tool = str(tool)
        self.args: dict[str, Any] = dict(args or {})
        self.spec = spec
        self.messages: Sequence[Any] = messages or []
        self.approved_by_user = approved_by_user
        self.mode: Mode = "enforce"
        self.clear = True

    def __repr__(self) -> str:
        return f"Call({self.tool!r}, id={self.id!r})"

    @property
    def permission(self) -> str | None:
        return self.spec.permission

    @property
    def tier(self) -> str:
        return self.spec.tier

    @property
    def resource(self) -> dict[str, Any] | None:
        return self.spec.resource(self.args)

    def proceed(self) -> Decision:
        return Decision(kind="proceed")

    def deny(self, message: str, reason: str = "denied") -> Decision:
        return Decision(kind="deny", message=message, reason=reason)

    def guide(self, message: str, reason: str = "guided") -> Decision:
        """Don't run; tell the model what to do instead."""
        return Decision(kind="guide", message=message, reason=reason)

    def verify(self, message: str | None = None, **options: Any) -> Decision:
        """The person has to verify first (options: method, methods, permission)."""
        verify = {"permission": self.permission, **options}
        return Decision(kind="verify", reason="verification_required", message=message,
                        verify={k: v for k, v in verify.items() if v is not None})

    def approve(self, message: str | None = None) -> Decision:
        """The person the agent works for confirms this call."""
        return Decision(kind="approve", reason="confirmation_required", message=message, approve={"by": "user"})

    def transform(self, args: Mapping[str, Any], message: str | None = None) -> Decision:
        """Run with these arguments instead (the full set)."""
        return Decision(kind="transform", args=dict(args), message=message)

    def redirect(self, to: str, message: str | None = None) -> Decision:
        return Decision(kind="redirect", redirect={"to": to}, message=message)
