from __future__ import annotations

import math
import re
from collections.abc import Callable, Mapping
from typing import Any, Literal, TypedDict, Union


class ToolConfig(TypedDict, total=False):
    """How one tool maps to Scute (all optional; `False` instead of a config:
    no permission check).

    permission: "invoice:refund" (default: from the tool's name), or False.
    tier: "low" / "high" / ... for guards and budgets.
    key: the argument naming the object (default: <type>_id, <type>Id, id).
    attributes: args -> the object's attributes for the engine (Scute's stored ones win).
    resource: args -> the whole resource ({type, key, attributes}), overriding the rest.
    """

    permission: str | Literal[False]
    tier: str
    key: str
    attributes: Callable[[Mapping[str, Any]], Mapping[str, Any] | None]
    resource: Callable[[Mapping[str, Any]], dict[str, Any] | None]


ToolSetting = Union[ToolConfig, Literal[False]]  # noqa: UP007 - evaluated at runtime on 3.10


def permission_for(name: str) -> str:
    """refund_invoice -> "invoice:refund", resetUserMfa -> "user_mfa:reset", search -> "search"."""
    words = [w for w in re.split(r"[^a-z0-9]+", re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(name)).lower()) if w]
    # A name with no letters or digits is still checked (and denied as unknown), never skipped.
    if not words:
        return str(name) or "unnamed_tool"
    if len(words) < 2:
        return words[0]
    return f"{'_'.join(words[1:])}:{words[0]}"


def _is_key(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, str):
        return value != ""
    return isinstance(value, (int, float)) and math.isfinite(value)


def _key_text(value: Any) -> str:
    return str(int(value)) if isinstance(value, float) and value.is_integer() else str(value)


class ToolSpec:
    """How one tool maps to Scute: permission, object, tier. Arguments reach the
    engine as context.args; the object's attributes only come from an explicit
    `attributes` mapping (and Scute's stored ones win)."""

    def __init__(self, name: str, config: ToolSetting | None, default_tier: str) -> None:
        cfg: ToolConfig = {"permission": False} if config is False else (config or {})
        self.name = str(name)
        self._config = cfg
        permission = cfg.get("permission")
        self.permission: str | None = None if permission is False else (permission or permission_for(name))
        self.action: str | None = self.permission
        self.resource_type: str | None = None
        if self.permission and ":" in self.permission:
            self.resource_type, self.action = self.permission.split(":", 1)
        self.tier: str = str(cfg.get("tier") or default_tier)

    def __repr__(self) -> str:
        return f"ToolSpec({self.name!r}, permission={self.permission!r}, tier={self.tier!r})"

    def resource(self, args: Mapping[str, Any]) -> dict[str, Any] | None:
        build = self._config.get("resource")
        if build:
            return build(args)
        if not self.resource_type:
            return None
        key_arg = self._config.get("key") or next((k for k in self._key_candidates() if _is_key(args.get(k))), None)
        resource: dict[str, Any] = {"type": self.resource_type}
        if key_arg and _is_key(args.get(key_arg)):
            resource["key"] = _key_text(args[key_arg])
        attributes = self._config.get("attributes")
        found = attributes(args) if attributes else None
        if found:
            resource["attributes"] = dict(found)
        return resource

    def _key_candidates(self) -> list[str]:
        assert self.resource_type
        camel = re.sub(r"_([a-z0-9])", lambda m: m.group(1).upper(), self.resource_type)
        return [f"{self.resource_type}_id", f"{camel}Id", "id"]


def resource_ref(resource: Mapping[str, Any] | None) -> str:
    """"invoice:42", or "invoice" without a key."""
    if not resource:
        return ""
    return f"{resource['type']}:{resource['key']}" if resource.get("key") else str(resource.get("type") or "")
