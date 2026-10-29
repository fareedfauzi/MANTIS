# -*- coding: utf-8 -*-
"""Shared Genesect agent tool catalog and dispatch helpers.

This module is intentionally light on IDA imports. Tool implementations still
live in ``agentic_analyzer`` for now, but the catalog and dispatcher are shared
so external harnesses can expose the same reviewed tool surface.
"""

from __future__ import annotations

from genesect.agent import ToolRegistry
from genesect.agent_policy import EXECUTE, PATCH, TOOL_CATEGORIES, WRITE_IDB


AGENT_TOOL_CATALOG = {
    "function_info": "Function bounds, name, size, flags, and basic graph metrics. Args: ea.",
    "decompile": "Paginated Hex-Rays pseudocode. Args: ea, start_line (optional), max_lines (optional). Follow next_start_line when truncated.",
    "disassemble": "Bounded address-tagged disassembly. Args: ea, max_instructions.",
    "get_xrefs": "Callers and callees for a function. Args: ea.",
    "read_memory": "Bounded mapped bytes and ASCII. Args: ea, size.",
    "get_vtable_ptrs": "Read a bounded pointer table. Args: ea, count.",
    "search_strings": "Search IDB strings for URLs, hosts, IPs, or text. Args: query (optional), max_results.",
    "binary_overview": "Compact binary triage: architecture, segments, entry points, imports/exports, and counts. Args: none.",
    "list_imports": "List bounded imported APIs grouped by module. Args: query (optional), max_results.",
    "list_exports": "List bounded exported symbols. Args: query (optional), max_results.",
    "list_segments": "List memory segments with bounds and permissions. Args: none.",
    "list_entrypoints": "List binary entry points. Args: none.",
    "basic_blocks": "Get CFG blocks and predecessor/successor edges. Args: ea, max_blocks.",
    "stack_layout": "Get decompiler variables, arguments, locations, and types. Args: ea.",
    "function_evidence": "Collect function-local strings, constants, named data, and callees. Args: ea, max_items.",
    "int_convert": "Deterministically convert an integer to hex, decimal, binary, bytes, and ASCII. Args: value, width (optional).",
    "search_findings": "Recall prior evidence-backed findings from this IDB and durable cross-project memory. Args: query.",
    "record_finding": "Record an evidence-backed claim in the current agent session. Args: claim, confidence, evidence, tags.",
    "mark_examined": "Mark an address examined or a dead end in the current agent session. Args: ea, disposition, summary.",
    "record_function_analysis": (
        "Complete one function after evidence and code were collected. Args: ea, suggested_name (empty keeps the "
        "existing name), summary (one sentence), confidence (0-100), evidence (list of concrete citations)."
    ),
    "analyze_subfunction": "Decompile a target callee for focused follow-up. Args: ea.",
    "query_threat_intel": "Query configured threat-intelligence context for an indicator. Args: indicator.",
    "save_finding": "Persist a claim for later sessions and cross-project recall. Args: key, value. Requires IDA changes opt-in.",
    "rename_func": "Rename a function after review. Args: ea, new_name. Requires confirmation.",
    "rename_vars": "Rename local variables after review. Args: ea, renames. Requires confirmation.",
    "add_comment": "Add an analyst comment after review. Args: ea, text. Requires confirmation.",
    "set_func_type": "Apply a validated function prototype after review. Args: ea, signature.",
    "create_apply_struct": "Create and apply a reviewed structure definition. Args: name, fields_json.",
    "jump_to_address": "Navigate the IDA UI. Args: ea.",
    "patch_bytes": "Patch bytes after review. Args: ea, hex_string. Requires confirmation.",
    "execute_idapython": "Execute reviewed IDAPython in IDA. Args: script. Requires confirmation.",
}


AGENT_TOOL_REGISTRY = ToolRegistry.from_catalog(
    AGENT_TOOL_CATALOG,
    categories=TOOL_CATEGORIES,
    confirmation_categories={WRITE_IDB, PATCH, EXECUTE},
)


FUNCTION_SCOPED_AGENT_TOOLS = {
    "function_info", "decompile", "disassemble", "get_xrefs", "basic_blocks",
    "stack_layout", "function_evidence", "rename_func", "rename_vars",
    "add_comment", "set_func_type", "mark_examined", "analyze_subfunction",
    "record_function_analysis",
}


def tool_category(tool_name):
    return TOOL_CATEGORIES.get(str(tool_name), "unknown")


def tool_names(include_session_tools=True):
    if include_session_tools:
        return AGENT_TOOL_REGISTRY.names()
    return tuple(
        name for name in AGENT_TOOL_REGISTRY.names()
        if name not in {"record_finding", "mark_examined", "record_function_analysis"}
    )


def execute_bridge_tool(
    policy,
    tool_name,
    args,
    address=0,
    confirm_callback=None,
    memory_store=None,
    project_id="",
    binary_hash="",
    goal_id="",
):
    """Permission-check, confirm, execute, and audit one shared tool call."""
    args = dict(args or {})
    tool_name = str(tool_name or "")
    confirm_callback = confirm_callback or (lambda _tool, _args, _category: True)

    allowed, reason = policy.can_run(tool_name)
    if not allowed:
        result = "Error: Tool blocked by policy (%s)." % reason
        policy.record(tool_name, args, False, result)
        return result

    category = policy.category(tool_name)
    if category in {WRITE_IDB, PATCH, EXECUTE} and not confirm_callback(tool_name, args, category):
        result = "Error: User denied this IDA-changing tool call."
        policy.record(tool_name, args, False, result)
        return result

    from genesect import agentic_analyzer as aa

    dispatch = {
        "function_info": lambda: aa.tool_function_info(args.get("ea", address)),
        "decompile": lambda: aa.tool_decompile(
            args.get("ea", address), args.get("start_line", 0), args.get("max_lines", 200),
        ),
        "disassemble": lambda: aa.tool_disassemble(args.get("ea", address), args.get("max_instructions", 400)),
        "get_xrefs": lambda: aa.tool_get_xrefs(args.get("ea", address)),
        "search_strings": lambda: aa.tool_search_strings(args.get("query", ""), args.get("max_results", 100)),
        "binary_overview": lambda: aa.tool_binary_overview(),
        "list_imports": lambda: aa.tool_list_imports(args.get("query", ""), args.get("max_results", 250)),
        "list_exports": lambda: aa.tool_list_exports(args.get("query", ""), args.get("max_results", 250)),
        "list_segments": lambda: aa.tool_list_segments(),
        "list_entrypoints": lambda: aa.tool_list_entrypoints(),
        "basic_blocks": lambda: aa.tool_basic_blocks(args.get("ea", address), args.get("max_blocks", 500)),
        "stack_layout": lambda: aa.tool_stack_layout(args.get("ea", address)),
        "function_evidence": lambda: aa.tool_function_evidence(args.get("ea", address), args.get("max_items", 200)),
        "int_convert": lambda: aa.tool_int_convert(args.get("value", 0), args.get("width", 0)),
        "rename_func": lambda: aa.tool_rename_func(aa._agent_ea(args.get("ea", address), address), args.get("new_name", "")),
        "rename_vars": lambda: aa.tool_rename_vars(aa._agent_ea(args.get("ea", address), address), args.get("renames", {})),
        "add_comment": lambda: aa.tool_add_comment(aa._agent_ea(args.get("ea", address), address), args.get("text", "")),
        "analyze_subfunction": lambda: aa.tool_analyze_subfunction(args.get("ea", 0)),
        "create_apply_struct": lambda: aa.tool_create_apply_struct(args.get("name", ""), args.get("fields_json", "")),
        "query_threat_intel": lambda: aa.tool_query_threat_intel(args.get("indicator", "")),
        "get_vtable_ptrs": lambda: aa.tool_get_vtable_ptrs(args.get("ea", 0), args.get("count", 10)),
        "set_func_type": lambda: aa.tool_set_func_type(args.get("ea", address), args.get("signature", "")),
        "read_memory": lambda: aa.tool_read_memory(args.get("ea", 0), args.get("size", 32)),
        "patch_bytes": lambda: aa.tool_patch_bytes(args.get("ea", 0), args.get("hex_string", "")),
        "save_finding": lambda: aa.tool_save_finding(
            args.get("key", ""),
            args.get("value", ""),
            memory_store=memory_store,
            project_id=project_id,
            binary_hash=binary_hash,
            goal_id=goal_id,
        ),
        "search_findings": lambda: aa.tool_search_findings(
            args.get("query", ""),
            memory_store=memory_store,
            project_id=project_id,
        ),
        "execute_idapython": lambda: aa.tool_execute_idapython(args.get("script", "")),
        "jump_to_address": lambda: aa.tool_jump_to_address(args.get("ea", address)),
    }

    if tool_name not in dispatch:
        result = "Error: Tool is not available through the shared bridge."
        policy.record(tool_name, args, False, result)
        return result

    try:
        result = dispatch[tool_name]()
    except Exception as exc:
        result = "Error executing tool: %s" % exc
    policy.record(tool_name, args, True, result)
    return result
