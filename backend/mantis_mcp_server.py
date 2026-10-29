"""Minimal stdio MCP server for Hermes -> MANTIS.

The server exposes the same read-only tools as the HTTP agent bridge. It uses
line-delimited JSON-RPC over stdin/stdout and keeps all operational logs away
from stdout so the MCP transport stays clean.
"""

import json
import sys
import time
from typing import Any, Dict, Optional

import agent_audit
from agent_prompts import get_prompt, list_prompts
from agent_resources import list_resources, read_resource
from agent_auth import local_agent_identity, require_permission
from agent_rate_limit import check_rate_limit
from agent_redaction import redact
from agent_tools.registry import TOOLS, describe_tools, run_tool


SERVER_NAME = "mantis-hermes-bridge"
SERVER_VERSION = "0.1.0"
PROTOCOL_VERSION = "2024-11-05"


def _write(message: Dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _result(request_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str, data: Any = None) -> Dict[str, Any]:
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = redact(data)
    return {"jsonrpc": "2.0", "id": request_id, "error": err}


def _mcp_tools() -> list:
    tools = []
    for item in describe_tools().get("tools", []):
        tools.append({
            "name": item["name"],
            "description": item["description"],
            "inputSchema": item.get("input_schema") or {"type": "object", "additionalProperties": True},
        })
    return tools


def _call_tool(params: Dict[str, Any]) -> Dict[str, Any]:
    name = str(params.get("name") or "").strip()
    arguments = params.get("arguments") or {}
    if not isinstance(arguments, dict):
        arguments = {}
    spec = TOOLS.get(name)
    if not spec:
        return {
            "isError": True,
            "content": [{"type": "text", "text": json.dumps({"ok": False, "errors": [{"message": f"Unknown tool: {name}"}]}, ensure_ascii=False)}],
        }

    identity = local_agent_identity()
    require_permission(identity, spec.permission)
    check_rate_limit(identity.token_tag, spec.name)
    started = time.time()
    result = run_tool(spec.name, arguments)
    duration_ms = int((time.time() - started) * 1000)
    result["duration_ms"] = duration_ms
    agent_audit.write_audit({
        "agent": identity.name,
        "token_tag": identity.token_tag,
        "tool": spec.name,
        "workflow_id": str(arguments.get("workflow_id") or ""),
        "reason": "MCP tools/call",
        "duration_ms": duration_ms,
        "ok": bool(result.get("ok")),
        "input": arguments,
        "error_count": len(result.get("errors") or []),
        "transport": "mcp_stdio",
    })
    return {
        "isError": not bool(result.get("ok")),
        "content": [{"type": "text", "text": json.dumps(redact(result), ensure_ascii=False)}],
        "structuredContent": redact(result),
    }


def _handle(request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    method = request.get("method")
    request_id = request.get("id")
    params = request.get("params") or {}
    if not isinstance(params, dict):
        params = {}

    # Notifications do not require a response.
    if request_id is None and str(method or "").startswith("notifications/"):
        return None

    if method == "initialize":
        return _result(request_id, {
            "protocolVersion": params.get("protocolVersion") or PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        })
    if method == "ping":
        return _result(request_id, {})
    if method == "tools/list":
        return _result(request_id, {"tools": _mcp_tools()})
    if method == "tools/call":
        try:
            return _result(request_id, _call_tool(params))
        except Exception as exc:
            return _error(request_id, -32000, str(exc)[:800])
    if method == "prompts/list":
        return _result(request_id, list_prompts())
    if method == "prompts/get":
        try:
            return _result(request_id, get_prompt(str(params.get("name") or ""), params.get("arguments") or {}))
        except KeyError as exc:
            return _error(request_id, -32602, str(exc))
        except Exception as exc:
            return _error(request_id, -32000, str(exc)[:800])
    if method == "resources/list":
        return _result(request_id, list_resources())
    if method == "resources/read":
        try:
            return _result(request_id, read_resource(str(params.get("uri") or "")))
        except KeyError as exc:
            return _error(request_id, -32602, str(exc))
        except Exception as exc:
            return _error(request_id, -32000, str(exc)[:800])
    return _error(request_id, -32601, f"Method not found: {method}")


def main() -> int:
    try:
        local_agent_identity()
    except Exception as exc:
        print(f"MANTIS MCP bridge disabled: {exc}", file=sys.stderr)
        return 2

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            _write(_error(None, -32700, f"Parse error: {exc}"))
            continue
        if not isinstance(request, dict):
            _write(_error(None, -32600, "Invalid request"))
            continue
        response = _handle(request)
        if response is not None:
            _write(response)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
