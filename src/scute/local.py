"""Local decisions from the app's policy snapshot (a port of the JS SDK's
decideLocally). They must match Scute's engine: the shared conformance vectors
(spec/fixtures/authz/conformance.json in the API) are the test.

Anything the snapshot can't answer (roles on one object, attributes you didn't
pass) comes back as "unknown": ask the API then.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal

Tri = Literal[True, False, "unknown"]

WEEKDAYS = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
# The engine reads context.impersonated as a Rails boolean: blank is unset,
# these are false, anything else is true.
_FALSE_STRINGS = frozenset({"0", "f", "F", "false", "FALSE", "off", "OFF"})


@dataclass(frozen=True)
class LocalDecision:
    decision: Literal["allow", "deny", "allow_with_step_up", "allow_with_approval", "unknown"]
    reason: str
    permission: str | None = None
    roles: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _same(a: Any, b: Any) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_same(a[k], b[k]) for k in a)
    if isinstance(a, (list, dict)) or isinstance(b, (list, dict)):
        return False
    if _is_number(a) and _is_number(b):
        return bool(a == b)
    return type(a) is type(b) and a == b


def _compare(op: str, left: Any, right: Any) -> bool:
    if op == "eq":
        return _same(left, right)
    if op == "ne":
        return not _same(left, right)
    if op in ("lt", "lte", "gt", "gte"):
        if not ((_is_number(left) and _is_number(right)) or (isinstance(left, str) and isinstance(right, str))):
            return False
        return bool({"lt": left < right, "lte": left <= right, "gt": left > right, "gte": left >= right}[op])
    if op == "in":
        return isinstance(right, list) and any(_same(v, left) for v in right)
    if op == "contains":
        return (isinstance(left, list) and any(_same(v, right) for v in left)) or (
            isinstance(left, str) and isinstance(right, str) and right in left)
    if op == "starts_with":
        return isinstance(left, str) and isinstance(right, str) and left.startswith(right)
    return False


_MISSING = object()


def _lookup(row: dict[str, Any], path: str) -> Any:
    current: Any = row
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return _MISSING
        current = current[part]
    return current


def evaluate_condition(condition: dict[str, Any], attrs: dict[str, Any],
                       may_exist_elsewhere: Callable[[str], bool] | None = None) -> Tri:
    """True, False or "unknown" (a missing attribute left it open). None counts as missing."""
    op, arg = next(iter(condition.items()))
    if op == "all":
        parts = [evaluate_condition(c, attrs, may_exist_elsewhere) for c in arg]
        return False if False in parts else ("unknown" if "unknown" in parts else True)
    if op == "any":
        parts = [evaluate_condition(c, attrs, may_exist_elsewhere) for c in arg]
        return True if True in parts else ("unknown" if "unknown" in parts else False)
    if op == "not":
        inner = evaluate_condition(arg, attrs, may_exist_elsewhere)
        return "unknown" if inner == "unknown" else (not inner)
    if op == "unknown":
        return "unknown"
    if op == "exists":
        value = _lookup(attrs, arg["var"])
        if value is not _MISSING and value is not None:
            return True
        return "unknown" if may_exist_elsewhere and may_exist_elsewhere(arg["var"]) else False
    values = [_lookup(attrs, o["var"]) if isinstance(o, dict) and "var" in o else o for o in arg]
    if any(v is _MISSING or v is None for v in values):
        return "unknown"
    return _compare(op, values[0], values[1])


def _impersonating(context: dict[str, Any] | None) -> bool:
    v = (context or {}).get("impersonated")
    if v is None or v == "":
        return False
    if isinstance(v, bool):
        return v
    if _is_number(v):
        return bool(v != 0)
    if isinstance(v, str):
        return v not in _FALSE_STRINGS
    return True


def _parse_resource(resource: Any) -> tuple[str | None, str | None, dict[str, Any]]:
    if not resource:
        return None, None, {}
    if isinstance(resource, str):
        type_, _, key = resource.partition(":")
        return type_, key or None, {}
    return resource.get("type"), resource.get("key"), dict(resource.get("attributes") or {})


def _decision(d: Any, reason: str, permission: str | None = None, roles: list[str] | None = None) -> LocalDecision:
    return LocalDecision(decision=d, reason=reason, permission=permission, roles=tuple(roles or ()))


def decide_locally(policy: dict[str, Any], *, roles: list[str], action: str, resource: Any = None,
                   user: dict[str, Any] | None = None, context: dict[str, Any] | None = None,
                   now: datetime | str | None = None, strict: bool = False) -> LocalDecision:
    type_, key, attributes = _parse_resource(resource)
    type_ = type_.strip().lower() if type_ else None
    action = action.strip().lower()
    slug = f"{type_}:{action}" if type_ else action
    perm = policy["permissions"].get(slug)
    if not perm:
        return _decision("deny", "unknown_permission", slug)
    if not perm.get("enabled"):
        return _decision("deny", "permission_disabled", slug)

    all_roles: dict[str, Any] = policy["roles"]
    defaults = [s for s, r in all_roles.items() if r.get("default")]
    held = sorted({r for r in [*roles, *defaults] if r in all_roles})
    granting = [r for r in held if slug in all_roles[r].get("permissions", [])]

    def condition_of(r: str) -> dict[str, Any] | None:
        return (all_roles[r].get("conditions") or {}).get(slug)

    if isinstance(now, str):
        moment = datetime.fromisoformat(now.replace("Z", "+00:00"))
    else:
        moment = now or datetime.now(timezone.utc)
    moment = moment.astimezone(timezone.utc)
    attrs = {
        "user": {k: v for k, v in (user or {}).items() if v is not None},
        "resource": {k: v for k, v in {**attributes, "type": type_, "key": key}.items() if v is not None},
        "context": {"now": moment.strftime("%Y-%m-%dT%H:%M:%SZ"), "hour_utc": moment.hour,
                    "weekday_utc": WEEKDAYS[moment.weekday()], **(context or {})},
    }

    def may_exist_elsewhere(path: str) -> bool:
        return not strict and (path.startswith("user.") or (bool(key) and path.startswith("resource.")))

    failed = unknown = False
    unconditional = [r for r in granting if not condition_of(r)]
    if unconditional:
        passing = unconditional
    else:
        passing = []
        for r in granting:
            result = evaluate_condition(condition_of(r) or {}, attrs, may_exist_elsewhere)
            if result == "unknown":
                unknown = True
            if result is not True:
                failed = True
            else:
                passing.append(r)

    if passing:
        if perm.get("blocked_while_impersonating") and _impersonating(context):
            return _decision("deny", "impersonating", slug, passing)
        if perm.get("requires_approval"):
            return _decision("allow_with_approval", "approval_required", slug, passing)
        if perm.get("requires_verification"):
            return _decision("allow_with_step_up", "verification_required", slug, passing)
        return _decision("allow", "role_grant", slug, passing)

    object_roles = ((policy.get("resources") or {}).get(type_) or {}).get("roles") or {} if type_ else {}
    if key and any(slug in r.get("permissions", []) for r in object_roles.values()):
        return _decision("unknown", "needs_server", slug)
    if unknown and not strict:
        return _decision("unknown", "needs_server", slug)
    if failed:
        return _decision("deny", "condition_failed", slug)
    return _decision("deny", "no_role_grants_permission", slug)
