"""Restricted bridge for future external/browser/filesystem tools.

The bridge is intentionally inert by default. IDA-hosted analysis can inspect
available external capabilities, but execution requires a host-registered
handler and an explicit allowlist entry.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field


@dataclass
class ExternalToolSpec:
    name: str
    category: str
    description: str
    enabled: bool = False
    metadata: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


class ExternalToolBridge:
    """Allowlisted external tool registry with deny-by-default execution."""

    def __init__(self):
        self._tools = {}
        self._handlers = {}
        self.audit = []

    def register(self, name, category, description, handler=None, enabled=False, metadata=None):
        spec = ExternalToolSpec(
            name=str(name),
            category=str(category or "external"),
            description=str(description or ""),
            enabled=bool(enabled),
            metadata=dict(metadata or {}),
        )
        self._tools[spec.name] = spec
        if handler is not None:
            self._handlers[spec.name] = handler
        return spec

    def set_enabled(self, name, enabled):
        if name in self._tools:
            self._tools[name].enabled = bool(enabled)

    def list_tools(self):
        return [spec.to_dict() for spec in self._tools.values()]

    def execute(self, name, args=None):
        name = str(name or "")
        args = dict(args) if isinstance(args, dict) else {}
        spec = self._tools.get(name)
        if not spec:
            return self._record(name, args, False, "Error: External tool is not registered.")
        if not spec.enabled:
            return self._record(name, args, False, "Error: External tool is disabled by host policy.")
        handler = self._handlers.get(name)
        if handler is None:
            return self._record(name, args, False, "Error: External tool has no host handler.")
        try:
            result = handler(args)
            return self._record(name, args, True, result)
        except Exception as exc:
            return self._record(name, args, False, "Error: External tool failed: %s" % exc)

    def _record(self, name, args, ok, result):
        item = {
            "timestamp": time.time(),
            "tool": str(name or ""),
            "args": dict(args) if isinstance(args, dict) else {},
            "ok": bool(ok),
            "result": str(result or "")[:4000],
        }
        self.audit.append(item)
        del self.audit[:-200]
        return item["result"]

    def audit_log(self):
        return list(self.audit)
