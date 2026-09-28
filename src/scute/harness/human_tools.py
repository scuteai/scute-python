"""Tools the model calls to bring the person in: verify them, pass on the code
they read out, check a push or an approval, and ask what the task allows.
Every answer has a "say" line the agent can speak as is."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..errors import APIError, ScuteError

if TYPE_CHECKING:
    from .run import Run

METHODS = ["email_otp", "sms_otp", "totp", "entra_push"]
NAMES = ["scute_verify_person", "scute_submit_code", "scute_check_verification", "scute_approval_status", "scute_whoami"]

METHOD_HELP = {"email_otp": "a code by email", "sms_otp": "a code by text message", "totp": "the code in their authenticator app",
               "backup_code": "one of their backup codes", "entra_push": "a Microsoft Authenticator request",
               "push": "a request on their phone"}


@dataclass(frozen=True)
class HumanTool:
    """A tool for the model: name, description and JSON Schema parameters (as
    function calling wants them), and the call itself: tool(args) -> dict."""

    name: str
    description: str
    parameters: dict[str, Any]
    fn: Callable[[Mapping[str, Any]], dict[str, Any]] = field(repr=False)

    def __call__(self, args: Mapping[str, Any] | None = None) -> dict[str, Any]:
        return self.fn(args or {})


def _schema(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required or [], "additionalProperties": False}


def build(run: Run, methods: list[str] | None = None) -> dict[str, HumanTool]:
    methods = methods or list(METHODS)
    run.human_tool_names = list(NAMES)
    help_text = "; ".join(f"{m} = {METHOD_HELP.get(m, m)}" for m in methods)
    tools = [
        HumanTool("scute_verify_person",
                  "Verify that the person you're helping is who they say they are. Use it when an action needs "
                  "verification. It sends them a code or a request; tell them the `say` line.",
                  _schema({"method": {"type": "string", "enum": methods, "description": f"How to verify: {help_text}."}}),
                  lambda a: _answer(lambda: _verification(run.start_verification(method=a.get("method"))))),
        HumanTool("scute_submit_code", "Pass on the verification code the person read out to you.",
                  _schema({"code": {"type": "string", "description": "The code, digits only."}}, ["code"]),
                  lambda a: _answer(lambda: _verification(run.submit_code("".join(str(a.get("code") or "").split()))))),
        HumanTool("scute_check_verification",
                  "Check whether the person finished verifying (for a push or a link). Tell them the `say` line.",
                  _schema({}), lambda a: _answer(lambda: _verification(run.verification_status()))),
        HumanTool("scute_approval_status",
                  "Check whether a reviewer answered an approval request. Tell the person the `say` line.",
                  _schema({"id": {"type": "string", "description": "The approval request id."}}, ["id"]),
                  lambda a: _answer(lambda: _pick(run.approval_status(str(a.get("id") or "")), "status", "say"))),
        HumanTool("scute_whoami", "Who you're working for in this task, what you may do, and how long the task has left.",
                  _schema({}), lambda a: _answer(lambda: _whoami(run.whoami()))),
    ]
    return {t.name: t for t in tools}


def _answer(step: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        return step()
    except ValueError as e:
        if str(e).startswith("Pick"):
            return {"error": "method_required",
                    "say": "How would you like to verify: a code by email or text, or your authenticator app?"}
        if str(e).startswith("No verification"):
            return {"error": "no_verification", "say": "Let me send you a verification first."}
        return {"error": str(e)}
    except ScuteError as e:
        say = e.body.get("say") if isinstance(e, APIError) and isinstance(e.body, dict) else None
        return {k: v for k, v in {"error": str(e), "say": say}.items() if v is not None}


def _pick(data: Mapping[str, Any], *keys: str) -> dict[str, Any]:
    return {k: data[k] for k in keys if k in data}


def _verification(answer: Mapping[str, Any]) -> dict[str, Any]:
    out = {"status": answer.get("status"), "say": answer.get("say")}
    if answer.get("status") == "pending" and answer.get("remaining_attempts") is not None:
        out["remaining_attempts"] = answer["remaining_attempts"]
    return out


def _whoami(answer: Mapping[str, Any]) -> dict[str, Any]:
    may = list(answer.get("permissions") or [])
    out = {"acts_for": answer.get("acts_for"), "may": may,
           "could_with_more_access": [p for p in answer.get("ceiling") or [] if p not in may],
           "needs_verification": answer.get("step_up"), "needs_approval": answer.get("approval"),
           "expires_in": answer.get("expires_in"), "warnings": answer.get("warnings")}
    return {k: v for k, v in out.items() if v is not None}
