import time
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

import agent_audit
from agent_auth import AgentIdentity, require_agent, require_permission
from agent_rate_limit import check_rate_limit
from agent_redaction import redact
from agent_tools.registry import TOOLS, describe_tools, run_tool


router = APIRouter(prefix="/api/agent", tags=["agent-tools"])


class AgentToolRequest(BaseModel):
    arguments: Dict[str, Any] = Field(default_factory=dict)
    workflow_id: str = ""
    reason: str = ""


@router.get("/tools")
def list_agent_tools(identity: AgentIdentity = Depends(require_agent)):
    return describe_tools()


@router.post("/tools/{tool_name}")
def call_agent_tool(tool_name: str, req: AgentToolRequest, identity: AgentIdentity = Depends(require_agent)):
    spec = TOOLS.get((tool_name or "").strip())
    if not spec:
        raise HTTPException(status_code=404, detail=f"Unknown MANTIS agent tool: {tool_name}")
    require_permission(identity, spec.permission)
    check_rate_limit(identity.token_tag, spec.name)
    started = time.time()
    result = run_tool(spec.name, req.arguments)
    duration_ms = int((time.time() - started) * 1000)
    agent_audit.write_audit({
        "agent": identity.name,
        "token_tag": identity.token_tag,
        "tool": spec.name,
        "workflow_id": req.workflow_id,
        "reason": req.reason,
        "duration_ms": duration_ms,
        "ok": bool(result.get("ok")),
        "input": req.arguments,
        "error_count": len(result.get("errors") or []),
    })
    result["duration_ms"] = duration_ms
    return result


@router.get("/audit/recent")
def recent_agent_audit(limit: int = 50, identity: AgentIdentity = Depends(require_agent)):
    require_permission(identity, "read_only")
    return redact(agent_audit.recent(limit=limit))
