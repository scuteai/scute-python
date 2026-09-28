"""The harness around the agents you build: guards decide on every tool call,
backed by Scute's engine for who may do what (the agent's roles, the person it
works for, and the task).

    from scute.harness import Harness, guards

    harness = Harness(agent="support-bot", guards=[guards.permissions(), guards.approval(when={"tier": "high"})],
                      tools={"refund_invoice": {"tier": "high"}})
    run = harness.run(acts_for=user_id, actions=["invoice:read", "invoice:refund"])

    verdict = run.check("refund_invoice", {"invoice_id": "INV-1", "amount": 90})
    if verdict.runs: ...                  # proceed (or transform: run with verdict.args)
    else: reply(verdict.message)          # for the model; verdict.say is for the person
"""

from . import guards
from .call import Call
from .convention import ToolConfig, ToolSpec, permission_for, resource_ref
from .core import Harness
from .decision import RANK, Decision, GuardResult, Kind, Mode, Verdict
from .guards import Guard
from .human_tools import HumanTool
from .run import Run
from .store import MemoryStore, Store

__all__ = ["RANK", "Call", "Decision", "Guard", "GuardResult", "Harness", "HumanTool", "Kind", "MemoryStore", "Mode", "Run",
           "Store", "ToolConfig", "ToolSpec", "Verdict", "guards", "permission_for", "resource_ref"]
