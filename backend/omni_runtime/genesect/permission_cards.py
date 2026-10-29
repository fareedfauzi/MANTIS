# -*- coding: utf-8 -*-
"""Permission-card policy for human-reviewed Genesect actions."""

from __future__ import annotations

import datetime
import json
from dataclasses import asdict, dataclass

from genesect.agent_policy import EXECUTE, NAVIGATE, PATCH, READ, WRITE_IDB

try:
    from genesect.qt_compat import QtWidgets
except Exception:  # pragma: no cover - only used outside IDA/Qt smoke checks
    QtWidgets = None


FILESYSTEM = "filesystem"
NETWORK = "network"
RUNTIME = "runtime"

MODE_OFF = "off"
MODE_ASK = "ask"
MODE_ALLOW = "allow"


@dataclass
class PermissionDecision:
    tool: str
    category: str
    allowed: bool
    mode: str
    reason: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class PermissionAuditRecord:
    timestamp: str
    tool: str
    category: str
    mode: str
    allowed: bool
    args_preview: str
    reason: str = ""

    def to_dict(self):
        return asdict(self)


class PermissionCardManager:
    """Resolve config-driven permission decisions and keep an audit trail."""

    def __init__(self, config=None, parent=None):
        self.config = config
        self.parent = parent
        self.audit = []

    def mode_for_category(self, category):
        category = str(category or "")
        if category in (READ, NAVIGATE):
            return MODE_ALLOW
        option = {
            WRITE_IDB: "permission_write_idb",
            PATCH: "permission_patch_bytes",
            EXECUTE: "permission_execute",
            FILESYSTEM: "permission_filesystem",
            NETWORK: "permission_network",
            RUNTIME: "permission_runtime",
        }.get(category)
        raw = getattr(self.config, option, MODE_ASK) if option and self.config is not None else MODE_ASK
        raw = str(raw or MODE_ASK).strip().lower()
        return raw if raw in (MODE_OFF, MODE_ASK, MODE_ALLOW) else MODE_ASK

    def decide(self, tool, args, category):
        mode = self.mode_for_category(category)
        if mode == MODE_OFF:
            return self._record(tool, category, mode, False, "disabled by Genesect permission settings", args)
        if mode == MODE_ALLOW:
            return self._record(tool, category, mode, True, "allowed by Genesect permission settings", args)
        allowed = self._ask_user(tool, args, category)
        return self._record(tool, category, mode, allowed, "approved by analyst" if allowed else "denied by analyst", args)

    def confirm_callback(self, tool, args, category):
        return self.decide(tool, args, category).allowed

    def export_audit_json(self):
        return json.dumps([record.to_dict() for record in self.audit], indent=2, ensure_ascii=False)

    def _record(self, tool, category, mode, allowed, reason, args):
        record = PermissionAuditRecord(
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            tool=str(tool or ""),
            category=str(category or ""),
            mode=str(mode or ""),
            allowed=bool(allowed),
            args_preview=_args_preview(args),
            reason=str(reason or ""),
        )
        self.audit.append(record)
        return PermissionDecision(record.tool, record.category, record.allowed, record.mode, record.reason)

    def _ask_user(self, tool, args, category):
        if QtWidgets is None:
            return False
        preview = _args_preview(args, limit=3000)
        answer = QtWidgets.QMessageBox.question(
            self.parent,
            "Genesect Permission",
            "Tool: %s\nCategory: %s\n\nArguments:\n%s\n\nAllow this one operation?" % (
                tool, category, preview,
            ),
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
            QtWidgets.QMessageBox.No,
        )
        return answer == QtWidgets.QMessageBox.Yes


def _args_preview(args, limit=1200):
    try:
        text = json.dumps(args or {}, indent=2, ensure_ascii=False, sort_keys=True)
    except Exception:
        text = repr(args)
    if len(text) > limit:
        return text[:limit] + "... <truncated>"
    return text
