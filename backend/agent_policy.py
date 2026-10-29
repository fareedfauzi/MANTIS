import os
from typing import Any, Dict, Iterable


DENIED_ACTIONS = [
    "create_misp_events",
    "modify_misp_events",
    "submit_misp_attributes",
    "upload_samples",
    "trigger_external_scans",
    "publish_events",
    "modify_sightings",
    "modify_tags",
    "modify_galaxies",
    "change_misp_configuration",
    "arbitrary_shell",
    "direct_database_access",
    "filesystem_delete_or_move",
]


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


def bridge_policy(permissions: Iterable[str], tool_names: Iterable[str]) -> Dict[str, Any]:
    perms = sorted({str(p).strip() for p in permissions if str(p).strip()})
    tools = sorted(str(name) for name in tool_names)
    return {
        "mode": "passive_read_only" if perms == ["read_only"] else "permission_scoped",
        "permissions": perms,
        "tool_count": len(tools),
        "tools": tools,
        "rate_limit": {
            "window_seconds": max(1, _int_env("MANTIS_AGENT_RATE_WINDOW_SECONDS", 60)),
            "max_calls_per_tool": max(1, _int_env("MANTIS_AGENT_RATE_MAX_CALLS", 60)),
        },
        "audit": {
            "enabled": True,
            "path": os.environ.get("MANTIS_AGENT_AUDIT_PATH") or "backend/data/agent_audit.jsonl",
        },
        "blocked_actions": DENIED_ACTIONS,
        "approval_required_for_future_write_tools": True,
    }
