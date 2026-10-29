# -*- coding: utf-8 -*-
"""
Agentic Malware Reverse Engineering module for Genesect.
Allows an AI agent to autonomously investigate a function by running tools.
"""

import re
import json
import time
import html
import ipaddress

import idaapi
import ida_kernwin
import ida_hexrays
import ida_bytes
import ida_nalt
import ida_ua
import ida_name
import hashlib
import heapq
try:
    import ida_ida
except ImportError:  # IDA 8.x exposes this information through idaapi instead.
    ida_ida = None
import idc
import idautils
import sys
import io
import json

from genesect.qt_compat import QtWidgets, QtCore, QtGui
from genesect.config import CONFIG
import genesect.ai_client as _ai_mod
import genesect.idb_storage as _idb_mod
from genesect.idb_storage import save_to_idb, load_from_idb
from genesect.chat import ChatBubble, ChatInput, get_ida_colors, get_chat_font, markdown_to_html
from genesect.chat_export import export_chat_log
from genesect.renamer import count_sub_calls_fast, is_valid_seg, is_sys_func, clean_name
from genesect.agent import (
    AgentPlan,
    AgentReflector,
    AgentStateManager,
    AgentOrchestrator,
    ExternalToolBridge,
    GoalStore,
    MemoryStore,
    project_id_from_context,
)
from genesect.agent_policy import AgentPolicy
from genesect.agent_runtime import (
    AgentSession, build_system_prompt, recovery_guidance, result_status,
)
from genesect.agent_skills import (
    available_skill_routes, detect_skill_route, skill_context_block, skill_profile_title,
)
from genesect.bridge_tools import (
    AGENT_TOOL_CATALOG,
    AGENT_TOOL_REGISTRY,
    FUNCTION_SCOPED_AGENT_TOOLS,
    execute_bridge_tool,
)
from genesect.permission_cards import PermissionCardManager
from genesect.ui.theme import ThemeManager
from genesect.ui.components import PageHeader, Card, StatusBadge, ToggleSwitch, configure_content_tabs
from genesect.ui.typography import ui_font

AGENTIC_HISTORY_TAG = 101


def _agent_ea(value, default=idaapi.BADADDR):
    try:
        return int(str(value), 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return default


def _database_architecture():
    """Return processor name and bitness across IDA 8.x and 9.x APIs."""
    if ida_ida is not None:
        try:
            processor = ida_ida.inf_get_procname()
            if ida_ida.inf_is_64bit():
                bits = 64
            elif getattr(ida_ida, "inf_is_32bit_exactly", lambda: False)():
                bits = 32
            else:
                bits = 16
            return str(processor or "unknown"), bits
        except (AttributeError, RuntimeError):
            pass
    getter = getattr(idaapi, "get_inf_structure", None)
    if callable(getter):
        info = getter()
        processor = getattr(info, "procname", "") or getattr(getattr(idaapi, "ph", None), "id", "unknown")
        return str(processor), 64 if info.is_64bit() else 32 if info.is_32bit() else 16
    processor = getattr(getattr(idaapi, "ph", None), "id", "unknown")
    return str(processor), 32


def _current_binary_identity():
    """Return stable project identity fields without requiring one IDA API version."""
    binary_hash = ""
    input_path = ""
    idb_path = ""
    try:
        sha_func = getattr(ida_nalt, "retrieve_input_file_sha256", None)
        if callable(sha_func):
            value = sha_func()
            if isinstance(value, bytes):
                binary_hash = value.hex()
            else:
                binary_hash = str(value or "")
    except Exception:
        binary_hash = ""
    for getter in (
        getattr(idc, "get_input_file_path", None),
        getattr(idaapi, "get_input_file_path", None),
        getattr(ida_nalt, "get_input_file_path", None),
    ):
        try:
            if callable(getter):
                input_path = str(getter() or "")
                if input_path:
                    break
        except Exception:
            pass
    try:
        idb_path = str(idc.get_idb_path() or "")
    except Exception:
        try:
            idb_path = str(idaapi.get_path(idaapi.PATH_TYPE_IDB) or "")
        except Exception:
            idb_path = ""
    project_id = project_id_from_context(binary_hash, idb_path or input_path)
    return {
        "project_id": project_id,
        "binary_hash": binary_hash,
        "input_path": input_path,
        "idb_path": idb_path,
    }


def _looks_like_focused_request(text):
    """Recognize narrow questions that should not become a full investigation."""
    words = re.findall(r"[A-Za-z0-9_.:/-]+", str(text or "").lower())
    if not words or len(words) > 24:
        return False
    if set(words) & {"investigate", "autonomous", "everything", "entire", "full", "comprehensive"}:
        return False
    if set(words) & {"all", "every", "bulk", "sub-functions", "subfunctions", "callees", "descendants"}:
        return False
    object_terms = {
        "c2", "server", "domain", "url", "uri", "ip", "ioc", "indicator",
        "string", "mutex", "path", "filename", "user-agent", "registry",
        "pseudocode", "decompile", "assembly", "disassembly", "caller", "callee",
        "xref", "variable", "stack", "block", "function", "name", "prototype",
        "comment", "imports", "exports", "segment", "entrypoint", "vtable",
    }
    action_terms = {
        "find", "locate", "identify", "show", "what", "where", "extract", "list",
        "explain", "summarize", "rename", "set", "add", "jump", "read", "display",
    }
    return bool(set(words) & object_terms) and bool(set(words) & action_terms)


def _is_descendant_rename_request(text):
    lowered = str(text or "").lower()
    return "rename" in lowered and any(
        term in lowered for term in ("all sub", "every sub", "sub-function", "subfunction", "all callee", "descendant")
    )


def _requested_rename_prefix(text):
    """Recognize binary-wide requests such as: rename all functions starting with sub_."""
    lowered = str(text or "").lower()
    if "rename" not in lowered or not any(term in lowered for term in ("all", "every")):
        return ""
    match = re.search(
        r"(?:prefix|start(?:ing|s)?\s+with|begin(?:ning|s)?\s+with)\s*[\"'`]?([a-z_$?][\w$?@.-]{0,63})",
        lowered,
    )
    if match:
        return match.group(1)
    if re.search(r"\bsub_(?:\*|functions?|names?)?\b", lowered):
        return "sub_"
    return ""


def _collect_prefixed_functions(prefix, max_functions=500):
    """Enumerate exact IDB function names locally; never ask the model to guess coverage."""
    prefix = str(prefix or "")
    results = []
    for ea in idautils.Functions():
        name = idc.get_func_name(ea) or f"sub_{int(ea):X}"
        if name.lower().startswith(prefix.lower()):
            results.append({"ea": f"0x{int(ea):X}", "name": name})
            if len(results) >= max_functions:
                break
    return results


def _collect_all_functions():
    """Build a callee-first queue; recursive SCCs remain adjacent as cycle groups."""
    addresses = [int(ea) for ea in idautils.Functions()]
    address_set = set(addresses)
    graph = {}
    for ea in addresses:
        func = idaapi.get_func(ea)
        graph[ea] = sorted(
            int(target) for target in (_interfunction_callees(func) if func else {})
            if int(target) in address_set and int(target) != ea
        )

    # Iterative Kosaraju avoids Python's recursion limit on deep call chains.
    finish, visited = [], set()
    for root in addresses:
        if root in visited:
            continue
        visited.add(root)
        stack = [(root, False)]
        while stack:
            node, expanded = stack.pop()
            if expanded:
                finish.append(node)
                continue
            stack.append((node, True))
            for callee in reversed(graph.get(node, ())):
                if callee not in visited:
                    visited.add(callee)
                    stack.append((callee, False))
    reverse_graph = {ea: [] for ea in addresses}
    for caller, callees in graph.items():
        for callee in callees:
            reverse_graph[callee].append(caller)
    components, assigned = [], set()
    for root in reversed(finish):
        if root in assigned:
            continue
        component, stack = [], [root]
        assigned.add(root)
        while stack:
            node = stack.pop()
            component.append(node)
            for caller in reverse_graph.get(node, ()):
                if caller not in assigned:
                    assigned.add(caller)
                    stack.append(caller)
        components.append(sorted(component))

    component_of = {ea: pos for pos, group in enumerate(components) for ea in group}
    dependencies = {
        pos: {component_of[callee] for ea in group for callee in graph.get(ea, ()) if component_of[callee] != pos}
        for pos, group in enumerate(components)
    }
    dependents = {pos: set() for pos in range(len(components))}
    remaining = {pos: len(required) for pos, required in dependencies.items()}
    for caller, required in dependencies.items():
        for callee in required:
            dependents[callee].add(caller)
    ready = [pos for pos, count in remaining.items() if count == 0]
    heapq.heapify(ready)
    ordered_components = []
    while ready:
        component_id = heapq.heappop(ready)
        ordered_components.append(component_id)
        for caller in sorted(dependents[component_id]):
            remaining[caller] -= 1
            if remaining[caller] == 0:
                heapq.heappush(ready, caller)

    results = []
    for order, component_id in enumerate(ordered_components):
        group = components[component_id]
        cycle_id = f"cycle-{order + 1}" if len(group) > 1 else ""
        for ea in group:
            results.append({
                "ea": f"0x{ea:X}",
                "name": idc.get_func_name(ea) or f"sub_{ea:X}",
                "callees": [f"0x{callee:X}" for callee in graph.get(ea, ())],
                "cycle": cycle_id,
            })
    return results


def _collect_descendant_functions(root_ea, max_functions=100, max_depth=6):
    root_func = idaapi.get_func(root_ea)
    if not root_func:
        return []
    queue = [(int(root_func.start_ea), 0)]
    seen = {int(root_func.start_ea)}
    results = []
    while queue and len(results) < max_functions:
        current_ea, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        current = idaapi.get_func(current_ea)
        if not current:
            continue
        for target in sorted(_interfunction_callees(current)):
            target_func = idaapi.get_func(target)
            if not target_func:
                continue
            start = int(target_func.start_ea)
            if start in seen:
                continue
            seen.add(start)
            name = idc.get_func_name(start) or f"sub_{start:X}"
            if is_sys_func(name):
                continue
            results.append({"ea": f"0x{start:X}", "name": name, "depth": depth + 1})
            queue.append((start, depth + 1))
    return results


def _agentic_ui_font():
    """Choose a polished native sans-serif without Qt-version-specific family checks."""
    return ui_font(11.0)


def _resolved_ida_name(ea, fallback_prefix="sub"):
    """Prefer exact symbols/import names, then the containing function name."""
    return idc.get_name(ea) or idc.get_func_name(ea) or f"{fallback_prefix}_{int(ea):X}"


def _decode_ida_string(ea):
    """Read ASCII or UTF-16 IDB strings without collapsing wide strings to one byte."""
    try:
        strtype = idc.get_str_type(ea)
    except Exception:
        strtype = -1
    try:
        raw = idc.get_strlit_contents(ea, -1, strtype)
    except TypeError:
        raw = idc.get_strlit_contents(ea)
    if not raw:
        return ""
    if not isinstance(raw, bytes):
        return str(raw)
    sample = raw[:128]
    odd = sample[1::2]
    wide_hint = bool(odd) and sum(byte == 0 for byte in odd) >= max(1, len(odd) // 2)
    if wide_hint:
        try:
            return raw.decode("utf-16-le", "replace").rstrip("\x00")
        except Exception:
            pass
    return raw.decode("utf-8", "replace").rstrip("\x00")


def _network_iocs(text):
    value = str(text or "")
    urls = re.findall(r"(?i)\b(?:https?|ftp|wss?)://[^\s\"'<>]+", value)
    ip_candidates = re.findall(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])", value)
    valid_ips = []
    for candidate in ip_candidates:
        try:
            valid_ips.append(str(ipaddress.ip_address(candidate)))
        except ValueError:
            continue
    domains = re.findall(
        r"(?i)(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\.)+(?:[a-z]{2,63}|local)(?![\w.-])",
        value,
    )
    file_suffixes = {"exe", "dll", "sys", "dat", "ico", "txt", "json", "xml", "pdb", "obj", "lib"}
    domains = [
        item.lower() for item in domains
        if item.rsplit(".", 1)[-1].lower() not in file_suffixes
        # Decompiler member expressions such as ProcessInformation.hProcess are
        # identifiers, not domains. DNS names are case-insensitive and emitted
        # string literals in IDA preserve their original lowercase spelling.
        and item == item.lower()
    ]
    return list(dict.fromkeys(item.rstrip(".,);]") for item in urls + valid_ips + domains))[:100]


_CALL_XREF_TYPES = {idaapi.fl_CN, idaapi.fl_CF, idaapi.fl_JN, idaapi.fl_JF}


def _edge_kind(xref_type):
    if xref_type in {idaapi.fl_JN, idaapi.fl_JF}:
        return "tail"
    return "far" if xref_type == idaapi.fl_CF else "near"


def _interfunction_callees(func):
    """Return only real call edges leaving func, excluding internal branches."""
    targets = {}
    for head in idautils.Heads(func.start_ea, func.end_ea):
        for xref in idautils.XrefsFrom(head, 0):
            if xref.type not in _CALL_XREF_TYPES:
                continue
            target = int(xref.to)
            target_func = idaapi.get_func(target)
            if target_func and target_func.start_ea == func.start_ea:
                continue
            canonical = target_func.start_ea if target_func else target
            targets[int(canonical)] = _edge_kind(xref.type)
    return targets


def _interfunction_callers(func):
    callers = {}
    for xref in idautils.XrefsTo(func.start_ea, 0):
        if xref.type not in _CALL_XREF_TYPES:
            continue
        caller_func = idaapi.get_func(xref.frm)
        if caller_func and caller_func.start_ea != func.start_ea:
            callers[int(caller_func.start_ea)] = _edge_kind(xref.type)
    return callers


def tool_function_info(ea):
    ea = _agent_ea(ea)
    func = idaapi.get_func(ea)
    if not func:
        return f"Error: No function contains 0x{ea:X}."
    callers = _interfunction_callers(func)
    callees = _interfunction_callees(func)
    unresolved_indirect_calls = []
    for head in idautils.Heads(func.start_ea, func.end_ea):
        mnemonic = str(idc.print_insn_mnem(head) or "").lower()
        if not mnemonic.startswith("call"):
            continue
        if not any(xref.type in _CALL_XREF_TYPES for xref in idautils.XrefsFrom(head, 0)):
            unresolved_indirect_calls.append(f"0x{int(head):X}")
    return json.dumps({
        "ea": f"0x{func.start_ea:X}", "end": f"0x{func.end_ea:X}",
        "name": idc.get_func_name(func.start_ea), "size": func.end_ea - func.start_ea,
        "callers": [f"0x{x:X}" for x in sorted(callers)[:256]],
        "callees": [f"0x{x:X}" for x in sorted(callees)[:256]],
        "caller_details": [
            {"ea": f"0x{x:X}", "name": _resolved_ida_name(x), "call_type": callers[x]} for x in sorted(callers)[:256]
        ],
        "callee_details": [
            {"ea": f"0x{x:X}", "name": _resolved_ida_name(x), "call_type": callees[x]} for x in sorted(callees)[:256]
        ],
        "unresolved_indirect_calls": unresolved_indirect_calls[:256],
    }, ensure_ascii=False)


def tool_disassemble(ea, max_instructions=400):
    ea = _agent_ea(ea)
    func = idaapi.get_func(ea)
    if not func:
        return f"Error: No function contains 0x{ea:X}."
    limit = max(1, min(int(max_instructions or 400), 2000))
    lines = []
    start_ea = max(ea, func.start_ea)
    for head in idautils.Heads(start_ea, func.end_ea):
        if not ida_bytes.is_code(ida_bytes.get_full_flags(head)):
            continue
        line = idc.generate_disasm_line(head, 0)
        if line:
            lines.append(f"0x{head:X}: {idaapi.tag_remove(line)}")
        if len(lines) >= limit:
            lines.append(f"... truncated after {limit} instructions ...")
            break
    return "\n".join(lines) or "Error: No decoded instructions."

# Tool implementations for the Agent
def _full_decompile_text(ea):
    try:
        ea = _agent_ea(ea)
        cfunc = ida_hexrays.decompile(ea)
        if cfunc:
            text = str(cfunc)
            return text[:60000] + ("\n/* truncated */" if len(text) > 60000 else "")
        return "Error: Could not decompile function."
    except Exception as e:
        return f"Error decompiling: {e}"


def tool_decompile(ea, start_line=0, max_lines=200):
    text = _full_decompile_text(ea)
    if text.startswith("Error:"):
        return text
    lines = text.splitlines()
    start = max(0, int(start_line or 0))
    count = max(20, min(int(max_lines or 200), 2000))
    selected = lines[start:start + count]
    end = start + len(selected)
    header = f"/* pseudocode lines {start + 1}-{end} of {len(lines)} */"
    if end < len(lines):
        header += f"\n/* truncated: request start_line={end} to continue */"
    return header + "\n" + "\n".join(selected)

def tool_get_xrefs(ea):
    ea = _agent_ea(ea)
    func = idaapi.get_func(ea)
    target = func.start_ea if func else ea
    callers = []
    caller_edges = _interfunction_callers(func) if func else {}
    for ref in sorted(caller_edges):
        callers.append(f"{_resolved_ida_name(ref)} (0x{ref:X}, {caller_edges[ref]} call)")

    callees = set()
    callee_edges = _interfunction_callees(func) if func else {}
    for ref in sorted(callee_edges):
        callees.add(f"{_resolved_ida_name(ref)} (0x{ref:X}, {callee_edges[ref]} call)")
    
    res = []
    if callers:
        res.append(f"Callers:\n- " + "\n- ".join(set(callers)))
    else:
        res.append("Callers: None")
        
    if callees:
        res.append(f"Callees:\n- " + "\n- ".join(sorted(callees)))
    else:
        res.append("Callees: None")
        
    return "\n\n".join(res)


def tool_search_strings(query="", max_results=100):
    """Return bounded IDB strings matching text or common network-IOC syntax."""
    needle = str(query or "").strip().lower()
    limit = max(1, min(int(max_results or 100), 500))
    network_markers = ("http://", "https://", "ftp://", "ws://", "wss://", ".onion", "user-agent", "host:")
    ipv4 = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
    rows = []
    try:
        strings = idautils.Strings()
        strings.setup(strtypes=[0, 1], minlen=4)
        for item in strings:
            value = str(item)
            lowered = value.lower()
            matches = needle in lowered if needle else (
                any(marker in lowered for marker in network_markers) or bool(ipv4.search(value))
            )
            if matches:
                rows.append(f"0x{int(item.ea):X}: {value[:1000]}")
                if len(rows) >= limit:
                    break
    except Exception as exc:
        return f"Error searching strings: {exc}"
    return "\n".join(rows) if rows else "No matching IDB strings found."


def tool_list_imports(query="", max_results=250):
    needle = str(query or "").strip().lower()
    limit = max(1, min(int(max_results or 250), 2000))
    rows = []
    try:
        for module_index in range(ida_nalt.get_import_module_qty()):
            module = ida_nalt.get_import_module_name(module_index) or f"module_{module_index}"

            def collect(ea, name, ordinal, module=module):
                label = name or f"ordinal_{ordinal}"
                text = f"{module}!{label}"
                if not needle or needle in text.lower():
                    rows.append({"ea": f"0x{int(ea):X}", "module": module, "name": label, "ordinal": int(ordinal)})
                return len(rows) < limit

            ida_nalt.enum_import_names(module_index, collect)
            if len(rows) >= limit:
                break
    except Exception as exc:
        return f"Error listing imports: {exc}"
    return json.dumps(rows, ensure_ascii=False)


def tool_list_exports(query="", max_results=250):
    needle = str(query or "").strip().lower()
    limit = max(1, min(int(max_results or 250), 2000))
    rows = []
    try:
        for index, ordinal, ea, name in idautils.Entries():
            label = name or f"ordinal_{ordinal}"
            if not needle or needle in label.lower():
                rows.append({"ea": f"0x{int(ea):X}", "name": label, "ordinal": int(ordinal), "index": int(index)})
                if len(rows) >= limit:
                    break
    except Exception as exc:
        return f"Error listing exports: {exc}"
    return json.dumps(rows, ensure_ascii=False)


def tool_list_segments():
    rows = []
    for start in idautils.Segments():
        segment = idaapi.getseg(start)
        if not segment:
            continue
        permissions = "".join((
            "R" if segment.perm & idaapi.SEGPERM_READ else "-",
            "W" if segment.perm & idaapi.SEGPERM_WRITE else "-",
            "X" if segment.perm & idaapi.SEGPERM_EXEC else "-",
        ))
        rows.append({
            "name": idc.get_segm_name(start), "start": f"0x{int(segment.start_ea):X}",
            "end": f"0x{int(segment.end_ea):X}", "size": int(segment.end_ea - segment.start_ea),
            "permissions": permissions,
        })
    return json.dumps(rows, ensure_ascii=False)


def tool_list_entrypoints():
    rows = []
    try:
        for index, ordinal, ea, name in idautils.Entries():
            rows.append({"ea": f"0x{int(ea):X}", "name": name or f"entry_{index}", "ordinal": int(ordinal)})
    except Exception as exc:
        return f"Error listing entry points: {exc}"
    return json.dumps(rows[:1000], ensure_ascii=False)


def tool_binary_overview():
    try:
        processor, bits = _database_architecture()
        functions = sum(1 for _ in idautils.Functions())
        strings = sum(1 for _ in idautils.Strings())
        imports = json.loads(tool_list_imports(max_results=2000))
        exports = json.loads(tool_list_exports(max_results=1000))
        segments = json.loads(tool_list_segments())
        entrypoints = json.loads(tool_list_entrypoints())
        capability_terms = (
            "internet", "http", "socket", "connect", "send", "recv", "dns", "url", "wininet", "winhttp",
            "createprocess", "shellexecute", "writeprocess", "virtualalloc", "createremotethread",
            "registry", "regset", "service", "crypt", "bcrypt", "decrypt", "encrypt", "download",
        )
        capability_imports = [
            item for item in imports
            if any(term in str(item.get("name", "")).lower() for term in capability_terms)
        ]
        return json.dumps({
            "file": idc.get_input_file_path(), "processor": str(processor),
            "bits": bits,
            "function_count": functions, "string_count": strings,
            "import_count": len(imports), "export_count": len(exports),
            "segments": segments[:128], "entrypoints": entrypoints[:128],
            "imports_sample": imports[:100], "exports_sample": exports[:100],
            "capability_imports": capability_imports[:500],
            "imports_truncated": len(imports) > 100,
        }, ensure_ascii=False)
    except Exception as exc:
        return f"Error building binary overview: {exc}"


def tool_basic_blocks(ea, max_blocks=500):
    ea = _agent_ea(ea)
    func = idaapi.get_func(ea)
    if not func:
        return f"Error: No function contains 0x{ea:X}."
    limit = max(1, min(int(max_blocks or 500), 2000))
    rows = []
    try:
        # FlowChart may include remote tail/SEH chunks owned by the function.
        # The chat request is about the visible primary body, matching IDA's
        # start_ea..end_ea function range and the ASM conversion behavior.
        blocks = [
            block for block in idaapi.FlowChart(func)
            if int(func.start_ea) <= int(block.start_ea) < int(func.end_ea)
        ][:limit]
        primary_ids = {int(block.id) for block in blocks}
        for block in blocks:
            rows.append({
                "id": int(block.id), "start": f"0x{int(block.start_ea):X}", "end": f"0x{int(block.end_ea):X}",
                "predecessors": sorted({int(item.id) for item in block.preds()} & primary_ids),
                "successors": sorted({int(item.id) for item in block.succs()} & primary_ids),
            })
    except Exception as exc:
        return f"Error reading basic blocks: {exc}"
    return json.dumps(rows, ensure_ascii=False)


def tool_stack_layout(ea):
    ea = _agent_ea(ea)

    def member_value(obj, name, default=None):
        """Read a Hex-Rays member that may be a property or a method."""
        value = getattr(obj, name, default)
        if callable(value):
            try:
                return value()
            except TypeError:
                return default
        return value

    def readable_location(variable, argument=False, result=False):
        """Format Hex-Rays storage without exposing a SWIG proxy repr."""
        if bool(member_value(variable, "is_stk_var", False)):
            offset = member_value(variable, "get_stkoff", None)
            if isinstance(offset, int):
                sign = "+" if offset >= 0 else "-"
                return f"stack {sign}0x{abs(offset):X}"
            return "stack"
        location = member_value(variable, "location", None)
        if location is None:
            location = member_value(variable, "vloc", "")
        for method_name in ("dstr", "to_string"):
            rendered = member_value(location, method_name, None) if location is not None else None
            if rendered and "Swig Object" not in str(rendered) and "vdloc_t" not in str(rendered):
                return str(rendered)
        if result:
            return "return-value storage"
        if argument:
            return "argument storage"
        return "compiler-assigned storage"

    try:
        cfunc = ida_hexrays.decompile(ea)
        if not cfunc:
            return "Error: Could not decompile function."
        rows = []
        for index, variable in enumerate(cfunc.get_lvars()):
            argument = bool(member_value(variable, "is_arg_var", False))
            result = bool(member_value(variable, "is_result_var", False))
            name = str(member_value(variable, "name", "") or "").strip()
            if not name:
                name = "<return value>" if result else f"<unnamed variable {index + 1}>"
            rows.append({
                "name": name,
                "type": str(member_value(variable, "type", "")),
                "location": readable_location(variable, argument, result),
                "argument": argument,
                "result": result,
            })
        return json.dumps(rows, ensure_ascii=False)
    except Exception as exc:
        return f"Error reading stack layout: {exc}"


def tool_function_evidence(ea, max_items=200):
    ea = _agent_ea(ea)
    func = idaapi.get_func(ea)
    if not func:
        return f"Error: No function contains 0x{ea:X}."
    limit = max(1, min(int(max_items or 200), 1000))
    strings, data, callees, constants = {}, {}, {}, set()
    try:
        for head in idautils.Heads(func.start_ea, func.end_ea):
            for ref in idautils.DataRefsFrom(head):
                value = _decode_ida_string(ref)
                if value:
                    if len(strings) < limit:
                        strings[f"0x{int(ref):X}"] = value[:2000]
                else:
                    name = idc.get_name(ref)
                    if name and len(data) < limit:
                        data[f"0x{int(ref):X}"] = name
            # Callees are collected once below using typed call xrefs; ordinary
            # intra-function branches must never become function dependencies.
            insn = idaapi.insn_t()
            if ida_ua.decode_insn(insn, head):
                for operand in insn.ops:
                    if operand.type == idaapi.o_void:
                        break
                    if operand.type == idaapi.o_imm and len(constants) < limit:
                        constants.add(int(operand.value))
        for ref in list(_interfunction_callees(func))[:limit]:
            callees[f"0x{int(ref):X}"] = _resolved_ida_name(ref)
        pseudocode = _full_decompile_text(func.start_ea)
        iocs = _network_iocs(pseudocode if not pseudocode.startswith("Error:") else "")
        for value in strings.values():
            iocs.extend(item for item in _network_iocs(value) if item not in iocs)
        return json.dumps({
            "function": idc.get_func_name(func.start_ea), "ea": f"0x{func.start_ea:X}",
            "strings": strings, "named_data": data, "callees": callees,
            "network_iocs": iocs[:100],
            "constants": [f"0x{value:X}" for value in sorted(constants)[:limit]],
        }, ensure_ascii=False)
    except Exception as exc:
        return f"Error collecting function evidence: {exc}"


def tool_int_convert(value, width=0):
    try:
        number = int(str(value).strip(), 0) if isinstance(value, str) else int(value)
        requested = max(0, min(int(width or 0), 64))
        byte_width = requested or max(1, (number.bit_length() + 7) // 8)
        byte_width = min(byte_width, 64)
        if number < 0:
            number &= (1 << (byte_width * 8)) - 1
        raw_be = number.to_bytes(byte_width, "big", signed=False)
        raw_le = raw_be[::-1]
        printable = lambda raw: "".join(chr(item) if 32 <= item <= 126 else "." for item in raw)
        return json.dumps({
            "decimal": number, "hex": f"0x{number:X}", "binary": f"0b{number:b}",
            "big_endian_hex": raw_be.hex(" "), "little_endian_hex": raw_le.hex(" "),
            "big_endian_ascii": printable(raw_be), "little_endian_ascii": printable(raw_le),
        })
    except Exception as exc:
        return f"Error converting integer: {exc}"

def tool_rename_func(ea, new_name):
    from genesect.renamer import clean_name
    old_name = idc.get_func_name(ea)
    safe_name = clean_name(new_name, ea=ea)
    if idc.set_name(ea, safe_name, idc.SN_AUTO):
        save_to_idb(ea, "renamed_by_agent", tag=83)
        idaapi.request_refresh(idaapi.IWID_DISASM)
        return f"Success: Renamed '{old_name}' to '{safe_name}'"
    return f"Error: Failed to rename to '{safe_name}'"

def tool_rename_vars(ea, renames_dict):
    try:
        from genesect.var_renamer import apply_var_renames
        applied, failed, _ = apply_var_renames(ea, renames_dict, log_fn=None)
        if applied > 0:
            save_to_idb(ea, "variables_renamed_agent", tag=86)
            idaapi.request_refresh(idaapi.IWID_DISASM)
        return f"Success: {applied} variables renamed, {failed} failed."
    except Exception as e:
        return f"Error applying variable renames: {e}"

def tool_add_comment(ea, comment_text):
    try:
        current = idc.get_func_cmt(ea, 0)
        new_comment = comment_text if not current else current + "\n" + comment_text
        idc.set_func_cmt(ea, new_comment, 0)
        idaapi.request_refresh(idaapi.IWID_DISASM)
        return "Success: Comment added to function."
    except Exception as e:
        return f"Error adding comment: {e}"


_MANAGED_COMMENT_PREFIX = "[Genesect] "
_FUNCTION_ANALYSIS_VERSION = 1


def _short_function_summary(value):
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    text = re.sub(r"(?i)^this function\s+", "", text)
    if not text:
        return ""
    text = text[:280].rstrip(" ,;:")
    return text if text.endswith((".", "!", "?")) else text + "."


def _function_code_fingerprint(ea):
    func = idaapi.get_func(ea)
    if not func:
        return ""
    material = bytearray(f"{int(func.start_ea):X}:{int(func.end_ea):X}".encode("ascii"))
    for start, end in idautils.Chunks(func.start_ea):
        size = max(0, end - start)
        material.extend(ida_bytes.get_bytes(start, min(size, 4096)) or b"")
        if size > 4096:
            material.extend(ida_bytes.get_bytes(max(start, end - 4096), min(size, 4096)) or b"")
    return hashlib.sha256(bytes(material)).hexdigest()[:24]


def _replace_managed_comment(existing, summary):
    preserved = [
        line for line in str(existing or "").splitlines()
        if not line.strip().startswith(_MANAGED_COMMENT_PREFIX)
    ]
    managed = _MANAGED_COMMENT_PREFIX + summary if summary else ""
    return "\n".join([line for line in preserved + [managed] if line]).strip()


def _apply_function_name_and_comment(ea, proposed_name, summary):
    """Apply one reviewed rename/comment transaction on IDA's main thread."""
    result = {"ok": False, "renamed": False, "commented": False, "error": ""}
    ea = _agent_ea(ea)

    def apply():
        original_name = idc.get_func_name(ea) or f"sub_{ea:X}"
        original_comment = idc.get_func_cmt(ea, 0) or ""
        final_name = original_name
        try:
            if proposed_name and proposed_name != original_name:
                if not load_from_idb(ea, tag=82):
                    save_to_idb(ea, original_name, tag=82)
                if not ida_name.set_name(ea, proposed_name, ida_name.SN_NOWARN | ida_name.SN_FORCE):
                    raise RuntimeError("IDA rejected the validated function name")
                if (idc.get_func_name(ea) or "") != proposed_name:
                    raise RuntimeError("IDA did not retain the validated function name")
                final_name = proposed_name
                result["renamed"] = True
                save_to_idb(ea, "renamed_by_genesect", tag=83)
            updated_comment = _replace_managed_comment(original_comment, summary)
            if updated_comment != original_comment:
                if not idc.set_func_cmt(ea, updated_comment, 0):
                    raise RuntimeError("IDA rejected the managed function comment")
                if (idc.get_func_cmt(ea, 0) or "") != updated_comment:
                    raise RuntimeError("IDA did not retain the managed function comment")
                result["commented"] = True
            try:
                ida_hexrays.mark_cfunc_dirty(ea, False)
            except Exception:
                try:
                    ida_hexrays.clear_cached_cfuncs()
                except Exception:
                    pass
            result.update({"ok": True, "final_name": final_name, "original_name": original_name,
                           "original_comment": original_comment})
        except Exception as exc:
            if result["renamed"]:
                ida_name.set_name(ea, original_name, ida_name.SN_NOWARN | ida_name.SN_FORCE)
                save_to_idb(ea, "", tag=83)
                result["renamed"] = False
            idc.set_func_cmt(ea, original_comment, 0)
            result["error"] = str(exc)

    idaapi.execute_sync(apply, idaapi.MFF_WRITE)
    return result

def tool_analyze_subfunction(ea):
    try:
        if type(ea) == str:
            if ea.startswith("0x"): ea = int(ea, 16)
            else: ea = int(ea)
            
        cfunc = ida_hexrays.decompile(ea)
        if cfunc:
            return f"Pseudocode for subfunction at 0x{ea:X}:\n```c\n{str(cfunc)}\n```"
        return f"Error: Could not decompile subfunction at 0x{ea:X}."
    except Exception as e:
        return f"Error decompiling subfunction: {e}"

def tool_create_apply_struct(name, fields_json):
    try:
        # Fallback for IDA 9+ where ida_struct is removed and replaced by ida_typeinf
        try:
            import ida_struct
            tid = ida_struct.add_struc(idaapi.BADADDR, name)
        except ImportError:
            # IDA 9.0+ 
            import ida_typeinf
            # Creating structs in IDA 9 is complex and requires UDTs
            return f"Error: Struct creation not fully supported in IDA 9 via this tool. Please define via Local Types."

        if tid == idaapi.BADADDR:
            return f"Error: Could not create struct '{name}' (may already exist)."
        
        sptr = ida_struct.get_struc(tid)
        if not sptr: return "Error: Could not get struct pointer."
        
        # Basic parsing, expect list of dicts: [{"name": "field1", "type": "DWORD", "size": 4}]
        # Simplified creation for demonstration
        idaapi.request_refresh(idaapi.IWID_DISASM)
        return f"Success: Created struct '{name}'. (Note: full field population requires complex IDAPython typing APIs, stubbed for safety)."
    except Exception as e:
        return f"Error creating struct: {e}"

def tool_query_threat_intel(indicator):
    return "Unavailable: Genesect does not fabricate threat-intelligence results. Use External Pivot Search with analyst approval."

def tool_read_memory(ea, size=32):
    try:
        if type(ea) == str:
            if ea.startswith("0x"): ea = int(ea, 16)
            else: ea = int(ea)
            
        size = max(1, min(int(size or 32), 4096))
        data = ida_bytes.get_bytes(ea, size)
        if not data: return f"Error: Could not read {size} bytes at 0x{ea:X}."
        
        # Format as standard hex dump
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{ea+i:08X}: {hex_part:<48} | {ascii_part}")
            
        return "Memory Dump:\n```\n" + "\n".join(lines) + "\n```"
    except Exception as e:
        return f"Error reading memory: {e}"

def tool_patch_bytes(ea, hex_string):
    try:
        if type(ea) == str:
            if ea.startswith("0x"): ea = int(ea, 16)
            else: ea = int(ea)
            
        # Clean hex string
        hex_string = hex_string.replace(" ", "").replace("\\x", "")
        patch_data = bytes.fromhex(hex_string)
        
        # User Safety Check
        res = [False]
        def _ask_patch():
            orig_data = ida_bytes.get_bytes(ea, len(patch_data))
            if not orig_data: orig_data = b""
            orig_hex = " ".join(f"{b:02X}" for b in orig_data)
            new_hex = " ".join(f"{b:02X}" for b in patch_data)
            
            prompt = (
                f"Agent wants to patch binary at 0x{ea:X}:\n\n"
                f"Original: {orig_hex}\n"
                f"New:      {new_hex}\n\n"
                f"Allow patch?"
            )
            # 1 = Yes, 0 = No, -1 = Cancel
            res[0] = ida_kernwin.ask_yn(1, prompt) == 1
            
        ida_kernwin.execute_sync(_ask_patch, ida_kernwin.MFF_READ)
        if not res[0]:
            return "Error: User denied the patch request."
        
        ida_bytes.patch_bytes(ea, patch_data)
        idaapi.request_refresh(idaapi.IWID_DISASM)
        return f"Success: Patched {len(patch_data)} bytes at 0x{ea:X}."
    except Exception as e:
        return f"Error patching bytes: {e}"

def tool_save_finding(key, value, memory_store=None, project_id="", binary_hash="", goal_id=""):
    try:
        _idb_mod.agent_save_finding(key, value)
        if memory_store:
            memory_store.upsert_record(
                record_id="saved:%s:%s" % (str(project_id or "default"), hashlib.sha256(str(key).encode("utf-8")).hexdigest()[:16]),
                project_id=project_id or "default",
                binary_hash=binary_hash,
                scope="global",
                kind="saved_finding",
                title=str(key or "")[:500],
                text=str(value or ""),
                tags=["manual-save"],
                source_goal_id=goal_id,
            )
        return f"Success: Saved finding for '{key}'."
    except Exception as e:
        return f"Error saving finding: {e}"

def tool_search_findings(query, memory_store=None, project_id=""):
    parts = []
    try:
        parts.append("IDB memory:\n" + _idb_mod.agent_search_findings(query))
    except Exception as e:
        parts.append(f"IDB memory error: {e}")
    if memory_store:
        try:
            matches = memory_store.search(
                query,
                project_id=project_id or None,
                limit=10,
                include_cross_project=True,
            )
            parts.append(memory_store.format_results(matches))
        except Exception as e:
            parts.append(f"Durable memory error: {e}")
    return "\n\n".join(parts)

def tool_get_vtable_ptrs(ea, count=10):
    try:
        if type(ea) == str:
            if ea.startswith("0x"): ea = int(ea, 16)
            else: ea = int(ea)
        
        count = max(1, min(int(count or 10), 256))
        _processor, bits = _database_architecture()
        ptr_size = 8 if bits == 64 else 4
        
        results = []
        for i in range(count):
            curr_ea = ea + (i * ptr_size)
            if ptr_size == 8:
                ptr_val = idc.get_qword(curr_ea)
            else:
                ptr_val = idc.get_dword(curr_ea)
                
            name = idc.get_func_name(ptr_val)
            if name:
                results.append(f"+0x{i*ptr_size:X} -> 0x{ptr_val:X} ({name})")
            else:
                results.append(f"+0x{i*ptr_size:X} -> 0x{ptr_val:X}")
                
        return "VTable/Pointer Array:\n" + "\n".join(results)
    except Exception as e:
        return f"Error reading pointers: {e}"

def tool_set_func_type(ea, signature):
    try:
        if type(ea) == str:
            if ea.startswith("0x"): ea = int(ea, 16)
            else: ea = int(ea)
            
        res = idc.SetType(ea, signature)
        if res:
            idaapi.request_refresh(idaapi.IWID_DISASM)
            return f"Success: Set function signature to '{signature}' at 0x{ea:X}."
        else:
            return f"Error: Failed to apply signature '{signature}'. Ensure it is valid C syntax."
    except Exception as e:
        return f"Error setting function type: {e}"

def tool_execute_idapython(script):
    old_stdout = sys.stdout
    try:
        # User Safety Check
        res = [False]
        def _ask_exec():
            prompt = (
                f"Agent wants to execute the following IDAPython script:\n\n"
                f"{script}\n\n"
                f"Allow execution?"
            )
            res[0] = ida_kernwin.ask_yn(0, prompt) == 1
            
        ida_kernwin.execute_sync(_ask_exec, ida_kernwin.MFF_READ)
        if not res[0]:
            return "Error: User denied script execution."
            
        sys.stdout = mystdout = io.StringIO()
        
        # We execute in a new dictionary to avoid polluting globals
        exec_globals = {"idaapi": idaapi, "idc": idc, "idautils": idautils, "ida_hexrays": ida_hexrays}
        exec(script, exec_globals)
        
        sys.stdout = old_stdout
        output = mystdout.getvalue()
        if not output: return "Success: Script executed with no output."
        return f"Script Output:\n{output}"
    except Exception as e:
        sys.stdout = old_stdout
        return f"Error executing script:\n{e}"

def tool_jump_to_address(ea):
    try:
        if type(ea) == str:
            if ea.startswith("0x"): ea = int(ea, 16)
            else: ea = int(ea)
        
        def _do_jump():
            ida_kernwin.jumpto(ea)
        
        # safely execute UI request
        def wrapper():
            try:
                _do_jump()
            except: pass
            return False
        
        try:
            ida_kernwin.execute_ui_requests((wrapper,))
            return f"Success: Jumped IDA View to 0x{ea:X}"
        except:
            ida_kernwin.execute_sync(_do_jump, ida_kernwin.MFF_WRITE)
            return f"Success: Jumped IDA View to 0x{ea:X}"
    except Exception as e:
        return f"Error jumping to address: {e}"


def execute_agent_tool(
    policy,
    tool_name,
    args,
    address,
    confirm_callback,
    memory_store=None,
    project_id="",
    binary_hash="",
    goal_id="",
):
    """Permission-check, confirm, execute, and audit one tool call."""
    return execute_bridge_tool(
        policy,
        tool_name,
        args,
        address=address,
        confirm_callback=confirm_callback,
        memory_store=memory_store,
        project_id=project_id,
        binary_hash=binary_hash,
        goal_id=goal_id,
    )

# UI and Agentic Loop
class AgenticForm(ida_kernwin.PluginForm):
    def __init__(self, address, function_name):
        super(AgenticForm, self).__init__()
        self.address = address
        self.function_name = function_name
        self.system_prompt = {
            "role": "system",
            "content": (
                f"You are an autonomous Malware Reverse Engineering Agent analyzing `{function_name}` at `0x{address:X}`.\n"
                "You have access to the following tools:\n"
                "1. `decompile`: Returns C pseudocode for the current function.\n"
                "2. `get_xrefs`: Returns cross-references (callers/callees) for the current function.\n"
                "3. `rename_func`: Renames the current function. Arg: `new_name` (string).\n"
                "4. `rename_vars`: Renames variables. Arg: `renames` (dict mapping old name to new name).\n"
                "5. `add_comment`: Adds a comment to the function. Arg: `text` (string).\n"
                "6. `analyze_subfunction`: Decompiles a target callee function. Arg: `ea` (integer or hex string).\n"
                "8. `create_apply_struct`: Creates a struct type. Args: `name` (string), `fields_json` (string).\n"
                "9. `query_threat_intel`: Queries VT for an IOC. Arg: `indicator` (string).\n"
                "10. `get_vtable_ptrs`: Reads pointers from an address (e.g., vtable). Args: `ea` (int/hex str), `count` (int, default 10).\n"
                "12. `read_memory`: Reads memory and returns a hex dump. Args: `ea` (int/hex str), `size` (int, default 32).\n"
                "13. `patch_bytes`: Patches memory. Args: `ea` (int/hex str), `hex_string` (str, e.g. \"90 90\"). USER WILL BE PROMPTED.\n"
                "14. `save_finding`: Save data to global IDB memory for later use. Args: `key` (str), `value` (str).\n"
                "15. `search_findings`: Search global IDB memory. Arg: `query` (str).\n"
                "16. `execute_idapython`: Executes raw IDAPython code and returns stdout. Arg: `script` (string). USER WILL BE PROMPTED.\n"
                "17. `jump_to_address`: Moves the IDA UI to a specific address. Arg: `ea` (int/hex str).\n\n"
                "To use a tool, respond with ONLY a JSON block containing `tool` and `args`.\n"
                "IMPORTANT: JSON requires numbers to be base-10. For addresses/hex values, pass them as STRINGS (e.g. `\"0x10010798\"`).\n"
                "Example:\n"
                "```json\n"
                "{\"tool\": \"decompile\", \"args\": {}}\n"
                "```\n\n"
                "CRITICAL INSTRUCTION: If you spot a subfunction that appears to contain the core malicious logic, payload, or decryption routines, you MUST use `analyze_subfunction` to dive deeply into it. When you provide your final analysis, you MUST include a detailed, step-by-step breakdown of what those subfunctions do, including specific variables and decompiled logic. Do not just give a high-level summary!\n\n"
                "If you have fully exhausted the analysis of the main logic and subfunctions, respond with your normal text (no JSON tool call) to provide a final analysis. "
                "Always start by decompiling the function."
            )
        }
        # The legacy prompt above is retained only for migration readability;
        # the runtime uses the strict mission/tool envelope below.
        self.system_prompt = {
            "role": "system",
            "content": build_system_prompt(
                address, function_name, AGENT_TOOL_CATALOG, skill_context_block("triage-router"),
            ),
        }
        self.session = AgentSession(address, function_name, skill_route="triage-router")
        try:
            checkpoint = load_from_idb(address, tag=AGENTIC_HISTORY_TAG)
            if checkpoint:
                restored = AgentSession.from_json(checkpoint)
                if restored.root_ea == address:
                    self.session = restored
        except Exception:
            pass
        self.history = [self.system_prompt]
        self.export_transcript = []
        self.protocol_audit = []
        self.is_running = False
        self.is_paused = False
        self.error_count = 0
        self.policy = AgentPolicy()
        try:
            self.goal_store = GoalStore()
        except Exception:
            self.goal_store = None
        try:
            self.memory_store = MemoryStore()
        except Exception:
            self.memory_store = None
        self.goal_id = ""
        self.project_id = ""
        self.binary_hash = ""
        self.agent_plan = AgentPlan()
        self.reflector = AgentReflector()
        self.external_bridge = ExternalToolBridge()
        self.external_bridge.register(
            "filesystem",
            "filesystem",
            "Host-approved file operations outside IDA. Disabled until a handler is registered.",
            enabled=False,
        )
        self.external_bridge.register(
            "browser",
            "browser",
            "Host-approved browser/web operations. Disabled until a handler is registered.",
            enabled=False,
        )
        self._reflection_context = ""
        self.orchestrator = AgentOrchestrator(
            address, self.session, self.policy, AGENT_TOOL_REGISTRY, plan=self.agent_plan,
        )
        self._active_request_id = None
        self._request_generation = 0
        self._focused_request = False
        self._focused_tool_rounds = 0
        self._tool_rounds = 0
        self._max_tool_rounds = 12
        self._must_finalize = False
        self._finalize_reminders = 0
        self._report_revisions = 0
        self._task_profile = ""
        self._task_targets = []
        self._skill_route = str(getattr(self.session, "skill_route", "") or "triage-router")
        self._apply_skill_route(self._skill_route)
        self.history = [self.system_prompt]

    def _skill_title(self, route):
        if route == "off":
            return "Off"
        if route == "auto":
            return "Auto"
        return skill_profile_title(route or "triage-router")

    def _selected_skill_route(self, text="", default_auto="triage-router"):
        mode = "auto"
        try:
            mode = str(self.skill_mode_combo.currentData() or "auto")
        except Exception:
            mode = "auto"
        if mode == "off":
            return "off"
        if mode and mode != "auto":
            return mode
        if text:
            return detect_skill_route(text, self.function_name, self._task_profile)
        return default_auto

    def _apply_skill_route(self, route):
        self._skill_route = route or "triage-router"
        try:
            self.session.skill_route = self._skill_route
        except Exception:
            pass
        self.system_prompt = {
            "role": "system",
            "content": build_system_prompt(
                self.address,
                self.function_name,
                AGENT_TOOL_CATALOG,
                "" if self._skill_route == "off" else skill_context_block(self._skill_route),
            ),
        }
        return self._skill_route

    def _reset_agent_core(self, mode="interactive"):
        identity = _current_binary_identity()
        self.project_id = identity["project_id"]
        self.binary_hash = identity["binary_hash"]
        self.goal_id = ""
        if getattr(self, "goal_store", None):
            try:
                objective = getattr(self.session, "mission", "") or "Investigate %s at 0x%X" % (
                    self.function_name, self.address,
                )
                self.goal_id = self.goal_store.create_goal(
                    objective=objective,
                    project_id=identity["project_id"],
                    binary_hash=identity["binary_hash"],
                    root_ea="0x%X" % self.address,
                    function_name=self.function_name,
                    mode=str(mode or ""),
                    metadata={
                        "input_path": identity["input_path"],
                        "idb_path": identity["idb_path"],
                        "task_profile": str(getattr(self, "_task_profile", "") or ""),
                        "skill_route": str(getattr(self, "_skill_route", "") or ""),
                        "target_count": len(getattr(self, "_task_targets", []) or []),
                    },
                )
            except Exception:
                self.goal_id = ""
        self.orchestrator = AgentOrchestrator(
            self.address,
            self.session,
            self.policy,
            AGENT_TOOL_REGISTRY,
            goal_store=getattr(self, "goal_store", None),
            goal_id=self.goal_id,
            plan=self.agent_plan,
        )
        self.orchestrator.reset(self.session, self.policy)
        self.reflector.reset()
        self._reflection_context = ""
        self.orchestrator.reset_plan(
            objective=getattr(self.session, "mission", "") or "Investigate %s at 0x%X" % (
                self.function_name, self.address,
            ),
            mode=str(mode or "interactive"),
            target_count=len(getattr(self, "_task_targets", []) or []),
        )
        self.orchestrator.event_log.append(
            "run_mode",
            goal_id=self.goal_id,
            mode=str(mode or ""),
            task_profile=str(getattr(self, "_task_profile", "") or ""),
            skill_route=str(getattr(self, "_skill_route", "") or ""),
            skill_title=self._skill_title(getattr(self, "_skill_route", "") or "triage-router"),
            max_steps=getattr(self.policy, "max_steps", 0),
            max_seconds=getattr(self.policy, "max_seconds", 0),
            allow_mutations=bool(getattr(self.policy, "allow_mutations", False)),
            tool_count=len(AGENT_TOOL_REGISTRY.names()),
            project_id=identity["project_id"],
        )

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.setup_ui()
        # self.start_agent() no longer auto-starts

    def setup_ui(self):
        self._setup_professional_ui()
        return

    def _setup_professional_ui(self):
        """Build the investigation-console layout used by the autonomous agent."""
        self.theme_manager = ThemeManager(self.parent, "system")
        tokens = self.theme_manager.tokens
        self.parent.setObjectName("agenticRoot")
        self.parent.setFont(_agentic_ui_font())
        self._apply_agentic_visual_style(tokens)
        root = QtWidgets.QVBoxLayout(self.parent)
        root.setContentsMargins(20, 18, 20, 18)
        root.setSpacing(14)

        header = PageHeader(
            "Autonomous Investigation",
            f"{self.function_name}  •  0x{self.address:X}",
        )
        header.setObjectName("agenticHeader")
        header.subtitle_label.setText(f"{self.function_name}  •  0x{self.address:X}")
        self.agent_status_badge = StatusBadge("Ready", "neutral")
        header.add_action(self.agent_status_badge)
        root.addWidget(header)

        control_row = QtWidgets.QHBoxLayout()
        control_row.setSpacing(8)

        self.btn_start = QtWidgets.QPushButton("Start Investigation")
        self.btn_start.setProperty("pnVariant", "primary")
        self.btn_start.clicked.connect(self.on_start_autopilot)
        control_row.addWidget(self.btn_start)

        self.btn_pause = QtWidgets.QPushButton("Pause")
        self.btn_pause.clicked.connect(self.on_pause)
        self.btn_pause.setEnabled(False)
        self.btn_pause.setVisible(False)
        control_row.addWidget(self.btn_pause)

        self.btn_continue = QtWidgets.QPushButton("Resume")
        self.btn_continue.clicked.connect(self.on_continue)
        self.btn_continue.setEnabled(False)
        self.btn_continue.setVisible(False)
        control_row.addWidget(self.btn_continue)

        self.btn_stop = QtWidgets.QPushButton("Stop")
        self.btn_stop.setProperty("pnVariant", "danger")
        self.btn_stop.setToolTip("Cancel the active request and stop this investigation")
        self.btn_stop.clicked.connect(self.on_stop)
        self.btn_stop.setEnabled(False)
        self.btn_stop.setVisible(False)
        control_row.addWidget(self.btn_stop)

        self.skill_mode_combo = QtWidgets.QComboBox()
        self.skill_mode_combo.setToolTip("Select compact autonomous analysis guidance. Auto routes from the analyst request.")
        self.skill_mode_combo.addItem("Skill: Auto", "auto")
        for route in available_skill_routes():
            self.skill_mode_combo.addItem(skill_profile_title(route), route)
        self.skill_mode_combo.addItem("Skills Off", "off")
        self.skill_mode_combo.setMinimumWidth(210)
        control_row.addWidget(self.skill_mode_combo)
        self.btn_audit = QtWidgets.QPushButton("Audit Log")
        self.btn_audit.setObjectName("auditButton")
        self.btn_audit.setToolTip("Inspect and export every tool decision")
        self.btn_audit.clicked.connect(self.on_view_audit)
        control_row.addWidget(self.btn_audit)
        self.btn_agent_state = QtWidgets.QPushButton("Agent State")
        self.btn_agent_state.setObjectName("agentStateButton")
        self.btn_agent_state.setToolTip("Inspect durable goals and cross-project memory")
        self.btn_agent_state.clicked.connect(self.on_view_agent_state)
        control_row.addWidget(self.btn_agent_state)
        self.btn_export_log = QtWidgets.QPushButton("Export Log")
        self.btn_export_log.setToolTip("Export the visible chat conversation and final summary")
        self.btn_export_log.clicked.connect(self.export_investigation_log)
        control_row.addWidget(self.btn_export_log)

        self.allow_changes_cb = ToggleSwitch("Enable IDA changes")
        self.allow_changes_cb.setObjectName("idaChangesToggle")
        self.allow_changes_cb.setChecked(False)
        self.allow_changes_cb.setToolTip(
            "Apply validated bottom-up function names and short Genesect comments automatically during analysis."
        )
        self.allow_changes_cb.toggled.connect(lambda checked: setattr(self.policy, "allow_mutations", bool(checked)))
        control_row.addStretch()
        control_row.addWidget(self.allow_changes_cb)
        root.addLayout(control_row)

        workspace_splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        workspace_splitter.setChildrenCollapsible(False)

        investigation_card = Card("Investigation")
        investigation_card.setObjectName("investigationCard")

        target_label = QtWidgets.QLabel(f"{self.function_name}\n0x{self.address:X}")
        target_label.setObjectName("agentTargetLabel")
        target_label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        investigation_card.add_widget(target_label)

        self.chat_input = ChatInput()
        self.chat_input.input_box.setPlaceholderText(
            "Ask the agent or focus on an address..."
        )
        self.chat_input.submitted.connect(self.on_user_chat)
        self.chat_input.input_box.setMaximumHeight(82)
        self.chat_input.setMaximumHeight(102)
        self.chat_input.send_btn.setText("Send")
        self.chat_input.send_btn.setToolTip("Send")
        investigation_card.add_widget(self.chat_input)

        self.analysis_progress = QtWidgets.QProgressBar()
        self.analysis_progress.setRange(0, 1)
        self.analysis_progress.setValue(0)
        self.analysis_progress.setTextVisible(False)
        self.analysis_progress.setMinimumHeight(8)
        self.analysis_progress.setMaximumHeight(8)
        self.analysis_progress.setToolTip("Host-verified autonomous coverage")
        investigation_card.add_widget(self.analysis_progress)

        stats_grid = QtWidgets.QGridLayout()
        stats_grid.setHorizontalSpacing(8)
        stats_grid.setVerticalSpacing(8)
        self.steps_value = self._make_agent_metric(stats_grid, 0, 0, "Steps", "0")
        self.examined_value = self._make_agent_metric(stats_grid, 0, 1, "Examined", "0")
        self.findings_value = self._make_agent_metric(stats_grid, 1, 0, "Findings", "0")
        self.processed_value = self._make_agent_metric(stats_grid, 1, 1, "Processed", "0 / 0")
        investigation_card.add_layout(stats_grid)

        self.session_summary_label = QtWidgets.QLabel("Ready to investigate")
        self.session_summary_label.setProperty("pnMuted", True)
        self.session_summary_label.setWordWrap(True)
        investigation_card.add_widget(self.session_summary_label)

        self.typing_indicator = QtWidgets.QLabel("Agent is reasoning...")
        self.typing_indicator.setProperty("pnMuted", True)
        self.typing_indicator.setVisible(False)
        investigation_card.add_widget(self.typing_indicator)
        investigation_card.body.addStretch()
        investigation_card.setMinimumWidth(330)
        workspace_splitter.addWidget(investigation_card)

        output_card = Card()
        output_card.setObjectName("activityCard")
        output_card.body.setContentsMargins(0, 0, 0, 0)
        output_card.body.setSpacing(0)
        self.activity_tabs = QtWidgets.QTabWidget()
        self.activity_tabs.setObjectName("agentActivityTabs")
        configure_content_tabs(self.activity_tabs)
        self.scroll = QtWidgets.QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.scroll_content = QtWidgets.QWidget()
        self.scroll_layout = QtWidgets.QVBoxLayout(self.scroll_content)
        self.scroll_layout.setContentsMargins(8, 8, 8, 8)
        self.scroll_layout.setSpacing(8)
        self.scroll_layout.addStretch()
        self.scroll.setWidget(self.scroll_content)
        self.activity_tabs.addTab(self.scroll, "Activity")

        self.findings_view = QtWidgets.QPlainTextEdit()
        self.findings_view.setReadOnly(True)
        self.findings_view.setPlaceholderText("Evidence-backed findings will appear here.")
        self.activity_tabs.addTab(self.findings_view, "Findings")

        self.agent_state_view = QtWidgets.QPlainTextEdit()
        self.agent_state_view.setReadOnly(True)
        self.agent_state_view.setPlaceholderText("Current phase, open questions, and recent memory will appear here.")
        self.activity_tabs.addTab(self.agent_state_view, "Agent State")

        output_card.add_widget(self.activity_tabs, 1)
        workspace_splitter.addWidget(output_card)
        workspace_splitter.setStretchFactor(0, 0)
        workspace_splitter.setStretchFactor(1, 1)
        workspace_splitter.setSizes([360, 980])
        root.addWidget(workspace_splitter, 1)
        self.show_agent_empty_state()
        self._refresh_agent_dashboard()

    def _make_agent_metric(self, layout, row, column, label, value):
        frame = QtWidgets.QFrame()
        frame.setObjectName("agentMetricCard")
        box = QtWidgets.QVBoxLayout(frame)
        box.setContentsMargins(10, 8, 10, 8)
        box.setSpacing(2)
        value_label = QtWidgets.QLabel(value)
        value_label.setObjectName("agentMetricValue")
        label_widget = QtWidgets.QLabel(label)
        label_widget.setProperty("pnMuted", True)
        box.addWidget(value_label)
        box.addWidget(label_widget)
        layout.addWidget(frame, row, column)
        return value_label

    def show_agent_empty_state(self):
        if getattr(self, "_agent_empty_state", None):
            return
        tokens = self.theme_manager.tokens
        frame = QtWidgets.QFrame()
        frame.setObjectName("agentEmptyState")
        box = QtWidgets.QVBoxLayout(frame)
        box.setContentsMargins(28, 72, 28, 72)
        box.setSpacing(8)
        box.setAlignment(QtCore.Qt.AlignCenter)
        title = QtWidgets.QLabel("Ready to investigate")
        title.setAlignment(QtCore.Qt.AlignCenter)
        title.setStyleSheet(f"font-size:18px; font-weight:700; color:{tokens.text};")
        message = QtWidgets.QLabel(
            "Start the investigation to let the agent inspect functions, record evidence, "
            "and produce findings. IDA changes stay off until you enable them."
        )
        message.setAlignment(QtCore.Qt.AlignCenter)
        message.setWordWrap(True)
        message.setStyleSheet(f"color:{tokens.text_muted};")
        box.addWidget(title)
        box.addWidget(message)
        self._agent_empty_state = frame
        self.scroll_layout.insertWidget(0, frame)

    def clear_agent_empty_state(self):
        frame = getattr(self, "_agent_empty_state", None)
        if frame:
            self.scroll_layout.removeWidget(frame)
            frame.deleteLater()
            self._agent_empty_state = None

    def _apply_agentic_visual_style(self, tokens):
        """Apply a restrained macOS-inspired finish only to this workspace."""
        base = self.parent.styleSheet()
        self.parent.setStyleSheet(base + f"""
#agenticRoot {{ background: {tokens.window}; }}
#agenticHeader QLabel[pnTitle="true"] {{ font-size: 20pt; font-weight: 650; letter-spacing: -0.3px; }}
#agenticHeader QLabel[pnMuted="true"] {{ font-size: 10pt; }}
#activityCard, #investigationCard {{
    background: {tokens.surface}; border: 1px solid {tokens.border}; border-radius: 12px;
}}
#activityCard > QLabel {{ font-size: 10.5pt; font-weight: 650; }}
QTabWidget#agentActivityTabs::pane {{ border: 0; }}
#agentTargetLabel {{ font-family: Consolas, monospace; font-size: 10pt; color: {tokens.text}; }}
#agentMetricCard {{
    background: {tokens.surface_alt}; border: 1px solid {tokens.border}; border-radius: 8px;
}}
#agentMetricValue {{ font-size: 16pt; font-weight: 750; color: {tokens.text}; }}
#agentEmptyState {{ background: transparent; border: 0; }}
#auditButton {{ background: transparent; }}
#idaChangesToggle {{ font-size: 10pt; }}
QSplitter::handle {{ background: transparent; width: 8px; }}
QScrollArea {{ background: transparent; border: 0; }}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: {tokens.border_strong}; border-radius: 4px; min-height: 28px; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
""")

    def _refresh_agent_dashboard(self):
        processed = 0
        total = 0
        if getattr(self, "_task_profile", "") == "autonomous_full":
            total = len(getattr(self, "_task_targets", []))
            target_eas = {item["ea"] for item in getattr(self, "_task_targets", [])}
            covered = sum(
                1 for ea, item in self.session.function_memory.items()
                if ea in target_eas and item.get("state") in ("analyzed", "applied")
            )
            scoped_memory = [item for ea, item in self.session.function_memory.items() if ea in target_eas]
            renamed = sum(1 for item in scoped_memory if item.get("rename_applied"))
            commented = sum(1 for item in scoped_memory if item.get("comment_applied"))
            failed = sum(1 for item in scoped_memory if item.get("state") in ("failed", "apply_failed"))
            processed = covered + sum(1 for item in scoped_memory if item.get("state") == "failed")
            coverage_text = f"{covered:,}/{total:,} analyzed  •  {renamed:,} renamed  •  {commented:,} commented"
            if failed:
                coverage_text += f"  •  {failed:,} need attention"
        else:
            coverage_text = f"{len(self.session.examined):,} examined"
        if hasattr(self, "analysis_progress"):
            self.analysis_progress.setRange(0, max(1, total))
            self.analysis_progress.setValue(min(processed, total))
        if hasattr(self, "processed_value"):
            self.processed_value.setText(f"{processed:,} / {total:,}")
        if hasattr(self, "steps_value"):
            self.steps_value.setText(f"{self.policy.steps:,}")
        if hasattr(self, "examined_value"):
            self.examined_value.setText(f"{len(self.session.examined):,}")
        if hasattr(self, "findings_value"):
            self.findings_value.setText(f"{len(self.session.findings):,}")
        if hasattr(self, "findings_view"):
            finding_lines = []
            for finding in self.session.findings[-40:]:
                finding_lines.append(f"[{finding.confidence.upper()}] {finding.claim}")
                for evidence in finding.evidence[:4]:
                    finding_lines.append(f"  - {evidence}")
                finding_lines.append("")
            self.findings_view.setPlainText("\n".join(finding_lines).strip())
        if hasattr(self, "agent_state_view"):
            state_lines = [
                f"Phase: {str(self.session.phase or 'triage').replace('_', ' ').title()}",
                f"Coverage: {coverage_text}",
                f"Budget: {self.policy.steps:,} / {self.policy.max_steps:,} tool steps",
                "",
                "Open Questions:",
            ]
            questions = list(self.session.open_questions[-12:])
            state_lines.extend([f"- {question}" for question in questions] or ["- None"])
            self.agent_state_view.setPlainText("\n".join(state_lines))
        if hasattr(self, "session_summary_label"):
            self.session_summary_label.setText(
                f"{self.policy.steps:,} steps  •  {coverage_text}  •  {len(self.session.findings):,} findings"
            )
            return
        if not hasattr(self, "coverage_value"):
            return
        self.phase_value.setText(str(self.session.phase or "triage").replace("_", " ").title())
        self.coverage_value.setText(f"{coverage_text}  •  {len(self.session.findings):,} findings")
        self.budget_value.setText(f"{self.policy.steps:,} / {self.policy.max_steps:,} tool steps")
        lines = []
        for finding in self.session.findings[-20:]:
            lines.append(f"[{finding.confidence.upper()}] {finding.claim}")
            for evidence in finding.evidence[:3]:
                lines.append(f"  • {evidence}")
        if self.session.open_questions:
            lines.append("\nOPEN QUESTIONS")
            lines.extend(f"• {question}" for question in self.session.open_questions[-10:])
        self.evidence_view.setPlainText("\n".join(lines))
        return

        colors = get_ida_colors()
        colors = get_ida_colors()
        self.parent.setStyleSheet(f"background-color: {colors['window']};")
        
        btn_style = f"""
        QPushButton {{ 
            background-color: {colors['button']}; 
            color: {colors['button_text']}; 
            border: 1px solid {colors['mid']}; 
            padding: 4px 10px; 
            border-radius: 3px; 
            font-weight: bold; 
            font-family: {get_chat_font().family()}; 
            font-size: 11px; 
        }}
        QPushButton:disabled {{
            color: gray;
        }}
        """
        
        layout = QtWidgets.QVBoxLayout(self.parent)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header
        header = QtWidgets.QFrame()
        header.setStyleSheet(f"background-color: {colors['alt_base']};")
        header_vbox = QtWidgets.QVBoxLayout(header)
        header_vbox.setContentsMargins(20, 10, 20, 10)
        
        header_hbox = QtWidgets.QHBoxLayout()
        self.title_label = QtWidgets.QLabel(f'<span style="font-size: 13px; color: {colors["window_text"]};">Agentic Analysis: </span><b style="font-size: 14px; color: {colors["highlight"]}; font-family: monospace;">{self.function_name}</b>')
        header_hbox.addWidget(self.title_label)
        header_hbox.addStretch()
        
        self.btn_kb = QtWidgets.QPushButton("🧠 View Knowledge Base")
        self.btn_kb.setStyleSheet(btn_style)
        self.btn_kb.clicked.connect(self.on_view_kb)
        header_hbox.addWidget(self.btn_kb)

        self.btn_audit = QtWidgets.QPushButton("Audit Timeline")
        self.btn_audit.setStyleSheet(btn_style)
        self.btn_audit.clicked.connect(self.on_view_audit)
        header_hbox.addWidget(self.btn_audit)
        self.btn_agent_state = QtWidgets.QPushButton("Agent State")
        self.btn_agent_state.setStyleSheet(btn_style)
        self.btn_agent_state.clicked.connect(self.on_view_agent_state)
        header_hbox.addWidget(self.btn_agent_state)

        self.allow_changes_cb = QtWidgets.QCheckBox("Allow IDA changes")
        self.allow_changes_cb.setChecked(False)
        self.allow_changes_cb.setToolTip("Off by default. Every changing tool still requires confirmation when enabled.")
        self.allow_changes_cb.toggled.connect(lambda checked: setattr(self.policy, 'allow_mutations', bool(checked)))
        header_hbox.addWidget(self.allow_changes_cb)
        
        header_vbox.addLayout(header_hbox)
        layout.addWidget(header)

        # Chat History
        self.scroll = QtWidgets.QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.scroll.setStyleSheet("background: transparent;")
        
        self.scroll_content = QtWidgets.QWidget()
        self.scroll_layout = QtWidgets.QVBoxLayout(self.scroll_content)
        self.scroll_layout.setContentsMargins(5, 5, 5, 5)
        self.scroll_layout.addStretch()
        
        self.scroll.setWidget(self.scroll_content)
        layout.addWidget(self.scroll, stretch=1)

        # Chat Input
        self.chat_input = ChatInput()
        self.chat_input.input_box.setPlaceholderText("Steer the agent... (e.g. 'Focus on the loop at 0x401000')")
        self.chat_input.submitted.connect(self.on_user_chat)
        layout.addWidget(self.chat_input)

        # Controls and Typing Indicator
        self.controls_container = QtWidgets.QFrame()
        self.controls_container.setMinimumHeight(40)
        self.controls_container.setStyleSheet(f"background-color: {colors['alt_base']}; border-top: 1px solid {colors['mid']};")
        controls_layout = QtWidgets.QHBoxLayout(self.controls_container)
        controls_layout.setContentsMargins(10, 5, 10, 5)
        
        self.btn_start = QtWidgets.QPushButton("▶ Auto-Pilot Bulk Analyze")
        self.btn_start.setStyleSheet(btn_style)
        self.btn_start.clicked.connect(self.on_start_autopilot)
        controls_layout.addWidget(self.btn_start)
        
        self.btn_pause = QtWidgets.QPushButton("⏸ Pause")
        self.btn_pause.setStyleSheet(btn_style)
        self.btn_pause.clicked.connect(self.on_pause)
        self.btn_pause.setEnabled(False)
        controls_layout.addWidget(self.btn_pause)
        
        self.btn_continue = QtWidgets.QPushButton("⏭ Continue")
        self.btn_continue.setStyleSheet(btn_style)
        self.btn_continue.clicked.connect(self.on_continue)
        self.btn_continue.setEnabled(False)
        controls_layout.addWidget(self.btn_continue)
        
        controls_layout.addStretch()
        
        self.typing_indicator = QtWidgets.QLabel("Agent is thinking...")
        self.typing_indicator.setStyleSheet(f"color: {colors['highlight']}; font-style: italic; font-weight: bold; font-size: 11px;")
        self.typing_indicator.setVisible(False)
        controls_layout.addWidget(self.typing_indicator)
        
        layout.addWidget(self.controls_container)

    def on_view_kb(self):
        durable = ""
        if getattr(self, "memory_store", None):
            try:
                matches = self.memory_store.search(
                    "",
                    project_id=getattr(self, "project_id", "") or None,
                    limit=20,
                    include_cross_project=True,
                )
                durable = "\n\nDURABLE CROSS-PROJECT MEMORY\n" + self.memory_store.format_results(matches)
            except Exception as exc:
                durable = f"\n\nDURABLE CROSS-PROJECT MEMORY\nError reading memory: {exc}"
        res = (
            "CURRENT INVESTIGATION\n"
            + self.session.snapshot()
            + "\n\nPERSISTENT FINDINGS\n"
            + _idb_mod.agent_search_findings("")
            + durable
        )
        QtWidgets.QMessageBox.information(self.parent, "Agent Knowledge Base", res)

    def on_view_audit(self):
        dialog = QtWidgets.QDialog(self.parent)
        dialog.setWindowTitle("Agent Tool Audit Timeline")
        dialog.resize(760, 520)
        layout = QtWidgets.QVBoxLayout(dialog)
        viewer = QtWidgets.QPlainTextEdit()
        viewer.setReadOnly(True)
        def audit_text():
            try:
                tool_audit = json.loads(self.policy.export_json())
            except Exception:
                tool_audit = self.policy.export_json()
            goal = None
            goal_events = []
            memory_matches = []
            if getattr(self, "goal_store", None) and getattr(self, "goal_id", ""):
                try:
                    goal = self.goal_store.get_goal(self.goal_id)
                    goal_events = self.goal_store.goal_events(self.goal_id, limit=500)
                except Exception:
                    goal = {"id": self.goal_id, "error": "could not read durable goal state"}
            if getattr(self, "memory_store", None):
                try:
                    memory_matches = self.memory_store.search(
                        self.function_name,
                        project_id=getattr(self, "project_id", "") or None,
                        limit=20,
                        include_cross_project=True,
                    )
                except Exception:
                    memory_matches = []
            return json.dumps({
                "tool_audit": tool_audit,
                "model_protocol": self.protocol_audit,
                "agent_events": json.loads(self.orchestrator.export_events_json()),
                "agent_plan": self.agent_plan.to_dict(),
                "reflections": self.reflector.to_list(),
                "external_tools": self.external_bridge.list_tools(),
                "external_tool_audit": self.external_bridge.audit_log(),
                "durable_goal": goal,
                "durable_goal_events": goal_events,
                "durable_memory_matches": memory_matches,
            }, ensure_ascii=False, indent=2)
        viewer.setPlainText(audit_text())
        layout.addWidget(viewer)
        save_btn = QtWidgets.QPushButton("Export JSON")
        def save_audit():
            path, _ = QtWidgets.QFileDialog.getSaveFileName(dialog, "Export Agent Audit", "agent_audit.json", "JSON (*.json)")
            if path:
                with open(path, "w", encoding="utf-8") as stream:
                    stream.write(audit_text())
        save_btn.clicked.connect(save_audit)
        layout.addWidget(save_btn)
        dialog.exec_()

    def on_view_agent_state(self):
        dialog = QtWidgets.QDialog(self.parent)
        dialog.setWindowTitle("Durable Agent State")
        dialog.resize(820, 560)
        layout = QtWidgets.QVBoxLayout(dialog)
        search_row = QtWidgets.QHBoxLayout()
        query_box = QtWidgets.QLineEdit()
        query_box.setPlaceholderText("Search durable memory")
        search_row.addWidget(query_box, 1)
        refresh_btn = QtWidgets.QPushButton("Refresh")
        search_row.addWidget(refresh_btn)
        layout.addLayout(search_row)
        viewer = QtWidgets.QPlainTextEdit()
        viewer.setReadOnly(True)
        layout.addWidget(viewer, 1)

        def state_text():
            try:
                manager = AgentStateManager(
                    goal_store=getattr(self, "goal_store", None),
                    memory_store=getattr(self, "memory_store", None),
                )
                return manager.export_json(
                    project_id=getattr(self, "project_id", "") or None,
                    query=query_box.text(),
                )
            except Exception as exc:
                return json.dumps({"error": str(exc)}, ensure_ascii=False, indent=2)

        def refresh():
            viewer.setPlainText(state_text())

        refresh_btn.clicked.connect(refresh)
        query_box.returnPressed.connect(refresh)
        save_btn = QtWidgets.QPushButton("Export JSON")

        def save_state():
            path, _ = QtWidgets.QFileDialog.getSaveFileName(dialog, "Export Agent State", "agent_state.json", "JSON (*.json)")
            if path:
                with open(path, "w", encoding="utf-8") as stream:
                    stream.write(state_text())

        save_btn.clicked.connect(save_state)
        layout.addWidget(save_btn)
        refresh()
        dialog.exec_()

    def confirm_tool(self, tool_name, args, category):
        if not hasattr(self, "permission_cards"):
            self.permission_cards = PermissionCardManager(CONFIG, self.parent)
        return self.permission_cards.confirm_callback(tool_name, args, category)

    def _execute_agent_tool(self, tool_name, args):
        return execute_agent_tool(
            self.policy,
            tool_name,
            args,
            self.address,
            self.confirm_tool,
            memory_store=getattr(self, "memory_store", None),
            project_id=getattr(self, "project_id", ""),
            binary_hash=getattr(self, "binary_hash", ""),
            goal_id=getattr(self, "goal_id", ""),
        )

    def _memory_context(self, query="", limit=5):
        if not getattr(self, "memory_store", None):
            return ""
        try:
            matches = self.memory_store.search(
                query or self.function_name,
                project_id=getattr(self, "project_id", "") or None,
                limit=limit,
                include_cross_project=True,
            )
            if not matches:
                return ""
            return "\n\nDURABLE MEMORY HINTS\n" + self.memory_store.format_results(matches)
        except Exception:
            return ""

    def _plan_context(self):
        try:
            text = self.orchestrator.plan_prompt()
            return ("\n\n" + text) if text else ""
        except Exception:
            return ""

    def _reflect_after_round(self, all_calls_repeated=False):
        try:
            pending_count = len(self._pending_coverage_targets()) if self._task_profile == "autonomous_full" else 0
        except Exception:
            pending_count = 0
        try:
            reflections = self.reflector.after_round(
                self.session,
                self.agent_plan,
                all_calls_repeated=all_calls_repeated,
                task_profile=self._task_profile,
                pending_count=pending_count,
            )
            for reflection in reflections:
                self.orchestrator.event_log.append("reflection", **reflection.to_dict())
            self._reflection_context = self.reflector.guidance_text(reflections)
        except Exception:
            self._reflection_context = ""

    def _reflection_prompt_context(self):
        return ("\n\n" + self._reflection_context) if self._reflection_context else ""

    def export_investigation_log(self):
        path = export_chat_log(
            self.parent, "Export Autonomous Conversation", f"autonomous_conversation_{self.address:X}.md",
            {
                "title": "Autonomous Investigation", "mode": "autonomous_investigation",
                "function": self.function_name, "address": f"0x{self.address:X}",
                "phase": getattr(self.session, "phase", ""), "mission": getattr(self.session, "mission", ""),
                "goal_id": getattr(self, "goal_id", ""),
                "plan_progress": self.agent_plan.progress(),
                "tool_steps": self.policy.steps,
            },
            self.export_transcript,
        )
        if path:
            self.agent_status_badge.setToolTip("Investigation log exported to %s" % path)
            ida_kernwin.msg("[Genesect] Autonomous conversation exported to %s\n" % path)

    def on_user_chat(self, text):
        text = text.strip()
        if not text: return

        self.add_message(text, is_user=True)
        if not self.is_running:
            self.stop_active_request()
            self._focused_request = _looks_like_focused_request(text)
            self._focused_tool_rounds = 0
            self._tool_rounds = 0
            self._max_tool_rounds = 1 if self._focused_request else 8
            self._must_finalize = False
            self._finalize_reminders = 0
            self._report_revisions = 0
            rename_prefix = _requested_rename_prefix(text)
            if rename_prefix:
                self._task_profile = "rename_prefix"
                self._task_targets = _collect_prefixed_functions(rename_prefix)
            elif _is_descendant_rename_request(text):
                self._task_profile = "rename_descendants"
                self._task_targets = _collect_descendant_functions(self.address)
            else:
                self._task_profile, self._task_targets = "", []
            route = self._selected_skill_route(text, default_auto="triage-router")
            self.session = AgentSession(self.address, self.function_name, mission=text, skill_route=route)
            self._apply_skill_route(route)
            if self._focused_request:
                self.policy = AgentPolicy(
                    allow_mutations=self.allow_changes_cb.isChecked(),
                    max_steps=12, max_seconds=180, max_result_chars=8000,
                )
                guidance = (
                    "This is a focused analyst question. Use one compact tool round, then return a concise final "
                    "answer with concrete addresses and uncertainty. For C2/IOC questions, prefer search_strings "
                    "plus decompile or targeted disassembly; do not perform general function triage."
                )
            else:
                target_budget = len(self._task_targets) if self._task_profile.startswith("rename_") else 0
                self.policy = AgentPolicy(
                    allow_mutations=self.allow_changes_cb.isChecked(),
                    max_steps=max(40, target_budget * 3 + 12), max_seconds=max(900, target_budget * 45),
                )
                guidance = "Answer the analyst request with the smallest sufficient evidence-driven investigation."
                if self._task_profile in ("rename_descendants", "rename_prefix"):
                    scope = "host-enumerated binary-wide prefix matches" if self._task_profile == "rename_prefix" else "host-enumerated descendants"
                    guidance = (
                        f"This is a multi-function renaming workflow over {scope}. The target list is authoritative and "
                        "was read directly from the IDB; never claim it is empty or replace it with imports. Analyze every target, "
                        "prefer decompile plus function_evidence, and propose a descriptive name with its address and evidence. "
                        "Do not re-read the root after its evidence is available. If IDA changes are disabled, still produce "
                        "the complete rename proposal table and explain that applying it requires Enable IDA changes; never "
                        "claim read tools require permission. If IDA changes are enabled, apply evidence-backed proposals "
                        "with rename_func and report every success or failure. Candidate targets:\n"
                        + json.dumps(self._task_targets, ensure_ascii=False)
                    )
                    self._max_tool_rounds = max(8, (target_budget * 3 + 3) // 4 + 2)
            self._reset_agent_core("focused" if self._focused_request else "interactive")
            self.orchestrator.event_log.append(
                "analyst_request",
                text=text,
                focused=bool(self._focused_request),
                target_count=len(self._task_targets),
                skill_route=self._skill_route,
            )
            self.history = [self.system_prompt, {
                "role": "user",
                "content": (
                    f"{guidance}\n\nSKILL ROUTE\n{self._skill_route}: {self._skill_title(self._skill_route)}"
                    f"\n\nANALYST REQUEST\n{text}\n\nCURRENT STATE\n{self.session.snapshot()}"
                    + self._plan_context()
                    + self._memory_context(text)
                ),
            }]
            self.is_running = True
            self.is_paused = False
            self.btn_start.setEnabled(False)
            self.btn_pause.setEnabled(True)
            self.btn_pause.setVisible(True)
            self.btn_continue.setEnabled(False)
            self.btn_continue.setVisible(False)
            self.btn_stop.setEnabled(True)
            self.btn_stop.setVisible(True)
            self.agent_status_badge.setText("Running")
            self.agent_status_badge.set_tone("info")
            self._refresh_agent_dashboard()
            self.run_loop()
            return

        self.history.append({"role": "user", "content": text})
        if getattr(self, 'is_paused', False):
            self.is_paused = False
            self.btn_pause.setEnabled(True)
            self.btn_continue.setEnabled(False)
            self.run_loop()

    def add_message(self, text, is_user=False):
        self.clear_agent_empty_state()
        self.export_transcript.append({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "role": "user" if is_user else "assistant", "content": str(text),
        })
        bubble = ChatBubble(text, is_user)
        tokens = self.theme_manager.tokens
        bubble.label.setFont(_agentic_ui_font())
        bubble.bubble.layout().setContentsMargins(15, 11, 15, 11)
        if not is_user:
            bubble.bubble.setMinimumWidth(300)
        background = tokens.accent if is_user else tokens.surface_alt
        foreground = tokens.accent_text if is_user else tokens.text
        border = "0" if is_user else f"1px solid {tokens.border}"
        bubble.bubble.setStyleSheet(
            f"QFrame#chatBubble {{ background:{background}; border:{border}; border-radius:14px; }} "
            f"QLabel {{ color:{foreground}; background:transparent; border:none; }}"
        )
        self.scroll_layout.insertWidget(self.scroll_layout.count() - 1, bubble)
        QtCore.QTimer.singleShot(100, self.scroll_to_bottom)

    def scroll_to_bottom(self):
        self.scroll.verticalScrollBar().setValue(self.scroll.verticalScrollBar().maximum())

    def _pending_coverage_targets(self):
        if self._task_profile != "autonomous_full":
            return []
        pending = []
        for target in self._task_targets:
            ea = target["ea"]
            memory = self.session.function_memory.get(ea, {})
            terminal = memory.get("state") in ("analyzed", "applied", "failed")
            writes_complete = (
                memory.get("state") == "failed"
                or not self.policy.allow_mutations
                or memory.get("state") == "applied"
            )
            if not (terminal and memory.get("state") != "stale" and writes_complete):
                pending.append(target)
        return pending

    def _ready_coverage_targets(self, limit=1):
        """Return only pending functions whose external SCC dependencies are terminal."""
        pending = self._pending_coverage_targets()
        ready = []
        for target in pending:
            cycle = target.get("cycle", "")
            dependencies_ready = True
            for callee in target.get("callees", []):
                callee_target = getattr(self, "_target_by_ea", {}).get(callee)
                if cycle and callee_target and callee_target.get("cycle") == cycle:
                    continue
                state = self.session.function_memory.get(callee, {}).get("state")
                terminal = state in ("analyzed", "applied", "failed")
                writes_complete = (
                    state == "failed" or not self.policy.allow_mutations or state == "applied"
                )
                if not (terminal and writes_complete):
                    dependencies_ready = False
                    break
            if dependencies_ready:
                ready.append(target)
                if len(ready) >= limit:
                    break
        # Defensive cycle-breaker: malformed IDA graphs must not deadlock the queue.
        return ready or pending[:1]

    def _invalidate_stale_function_memory(self):
        """Fingerprint completed records once per start, never on every UI refresh."""
        conflicts = 0
        stale = set()
        for target in self._task_targets:
            ea = target["ea"]
            memory = self.session.function_memory.get(ea)
            if not memory or memory.get("state") not in ("analyzed", "applied", "failed"):
                continue
            current_name = idc.get_func_name(_agent_ea(ea)) or ea
            if memory.get("current_name") and current_name != memory.get("current_name"):
                memory["state"] = "failed"
                memory["last_error"] = "Manual function rename conflicts with the saved autonomous decision."
                conflicts += 1
                continue
            if memory.get("comment_applied"):
                current_comment = idc.get_func_cmt(_agent_ea(ea), 0) or ""
                expected = _MANAGED_COMMENT_PREFIX + str(memory.get("summary", ""))
                if expected and expected not in current_comment.splitlines():
                    memory["state"] = "failed"
                    memory["last_error"] = "The managed function comment was edited or removed manually."
                    conflicts += 1
                    continue
            current = _function_code_fingerprint(_agent_ea(ea))
            if (
                not current
                or current != memory.get("code_fingerprint")
                or memory.get("analysis_version") != _FUNCTION_ANALYSIS_VERSION
            ):
                memory["state"] = "stale"
                memory["last_error"] = "Function code or autonomous analysis version changed."
                self.session.invalidate_function_cache(ea)
                stale.add(ea)
        # A changed callee invalidates every already-analyzed caller that used
        # its old semantic name/summary, including transitive callers.
        changed = True
        while changed:
            changed = False
            for target in self._task_targets:
                ea = target["ea"]
                memory = self.session.function_memory.get(ea)
                if ea in stale or not memory or memory.get("state") not in ("analyzed", "applied"):
                    continue
                if any(callee in stale for callee in target.get("callees", [])):
                    memory["state"] = "stale"
                    memory["last_error"] = "A callee changed and caller context must be refreshed."
                    self.session.invalidate_function_cache(ea)
                    stale.add(ea)
                    changed = True
        if conflicts:
            self.add_message(
                f"{conflicts:,} prior function change(s) conflict with manual IDA edits and need review; they were not overwritten.",
                is_user=False,
            )

    def _coverage_batch_text(self, batch_size=1):
        pending = self._pending_coverage_targets()
        total = len(self._task_targets) if self._task_profile == "autonomous_full" else 0
        covered = total - len(pending)
        if pending:
            self.session.phase = "analyzing_cycles" if pending[0].get("cycle") else (
                "analyzing_leaves" if covered == 0 else "analyzing_callers"
            )
        else:
            self.session.phase = "final_validation"
        batch = []
        for target in self._ready_coverage_targets(batch_size):
            item = dict(target)
            known_callees = []
            for callee in target.get("callees", [])[:12]:
                memory = self.session.function_memory.get(callee, {})
                if memory.get("summary"):
                    known_callees.append({
                        "ea": callee,
                        "name": memory.get("current_name") or memory.get("suggested_name") or callee,
                        "summary": memory.get("summary"),
                        "confidence": memory.get("confidence", 0),
                    })
            if known_callees:
                item["known_callees"] = known_callees
            batch.append(item)
        return (
            f"BINARY-WIDE COVERAGE: {covered:,}/{total:,} functions; {len(pending):,} pending.\n"
            "CURRENT FUNCTION TRANSACTION (callee-first; complete this function before advancing):\n"
            + json.dumps(batch, ensure_ascii=False)
            + "\nFor this one function: collect function_evidence, decompile (or disassemble fallback), then call "
              "record_function_analysis with a meaningful name decision, one-sentence summary, confidence, and evidence. "
              "Do not inspect another function until record_function_analysis succeeds for this address."
        )

    def on_start_autopilot(self):
        """Start an evidence-driven A-to-Z investigation of the entire IDB."""
        self.stop_active_request()
        self.export_transcript = []
        self.protocol_audit = []
        if not isinstance(getattr(self.session, "function_memory", None), dict):
            self.session = AgentSession(self.address, self.function_name)
        self.session.phase = "building_call_graph"
        self.session.final_report = ""
        self._task_profile = "autonomous_full"
        self._apply_skill_route(self._selected_skill_route("", default_auto="malware-re"))
        self._task_targets = _collect_all_functions()
        self._target_by_ea = {target["ea"]: target for target in self._task_targets}
        self._visible_analyzing = set()
        self._invalidate_stale_function_memory()
        target_count = len(self._task_targets)
        self.policy = AgentPolicy(
            allow_mutations=self.allow_changes_cb.isChecked(),
            max_steps=max(128, target_count * 10 + 64),
            max_seconds=max(1800, target_count * 30),
        )
        self._reset_agent_core("autonomous_full")
        self.orchestrator.event_log.append(
            "coverage_targets_built",
            target_count=target_count,
        )
        self.history = [self.system_prompt, {
            "role": "user",
            "content": (
                "Begin a complete A-to-Z autonomous investigation. First obtain binary_overview, then analyze every "
                "host-enumerated function with function_evidence plus decompile (or disassemble when decompilation "
                "fails). Use deeper tools for suspicious or structurally important functions. Never return a final "
                "report while the host reports pending coverage.\n\n"
                f"SKILL ROUTE\n{self._skill_route}: {self._skill_title(self._skill_route)}\n\n"
                + self._coverage_batch_text()
                + "\n\nCurrent session state:\n" + self.session.snapshot()
                + self._plan_context()
                + self._memory_context(self.function_name)
            ),
        }]
        self.error_count = 0
        self._focused_request = False
        self._focused_tool_rounds = 0
        self._tool_rounds = 0
        self._max_tool_rounds = max(24, (target_count * 9 + 3) // 4 + 32)
        self._must_finalize = False
        self._finalize_reminders = 0
        self._report_revisions = 0
        self.is_running = True
        self.is_paused = False
        self.btn_start.setEnabled(False)
        self.btn_pause.setEnabled(True)
        self.btn_start.setVisible(False)
        self.btn_pause.setVisible(True)
        self.btn_continue.setEnabled(False)
        self.btn_continue.setVisible(False)
        self.btn_stop.setEnabled(True)
        self.btn_stop.setVisible(True)
        self.chat_input.setEnabled(True)
        self.add_message("Autonomous investigation started in read-only mode." if not self.policy.allow_mutations else "Autonomous investigation started with reviewed IDA changes enabled.", is_user=False)
        self.agent_status_badge.setText("Running")
        self.agent_status_badge.set_tone("info")
        self._refresh_agent_dashboard()
        self.run_loop()

    def _legacy_bulk_autopilot(self):
        # Clear chat history visually
        self.history = [self.system_prompt]
        self.policy = AgentPolicy(allow_mutations=self.allow_changes_cb.isChecked())
        self._reset_agent_core("legacy_bulk")
        self.error_count = 0
        self.btn_start.setEnabled(False)
        self.btn_pause.setEnabled(True)
        self.btn_continue.setEnabled(False)
        self.chat_input.setEnabled(False)
        self.is_running = True
        self.is_paused = False
        self.add_message("▶ Auto-Pilot Bulk Analysis started. Scanning binary...", is_user=False)
        self.typing_indicator.setText("Scanning functions...")
        self.typing_indicator.setVisible(True)
        
        # Build the queue
        self.active_queue = []
        self.blocked_queue = []
        self.processed_eas = set()
        self.markdown_report = "# Full Binary Analysis Report\n\n"
        
        def _scan():
            for ea in idautils.Functions():
                if not is_valid_seg(ea) or is_sys_func(idc.get_func_name(ea)): continue
                sub_count = count_sub_calls_fast(ea)
                if sub_count == 0:
                    self.active_queue.append(ea)
                else:
                    self.blocked_queue.append(ea)
        
        ida_kernwin.execute_sync(_scan, ida_kernwin.MFF_READ)
        
        self.add_message(f"Found {len(self.active_queue)} leaf functions and {len(self.blocked_queue)} blocked functions.", is_user=False)
        
        # Start processing
        QtCore.QTimer.singleShot(100, self.run_autopilot_loop)

    def on_pause(self):
        self.is_paused = True
        self.stop_active_request()
        self._remove_live_bubble()
        self.typing_indicator.setVisible(False)
        self.agent_status_badge.setText("Paused")
        self.agent_status_badge.set_tone("warning")
        self.btn_pause.setEnabled(False)
        self.btn_pause.setVisible(False)
        self.btn_continue.setEnabled(True)
        self.btn_continue.setVisible(True)
        self._sync_goal_status("paused")
        self.add_message("⏸ Agent paused. It will stop after the current thought completes.", is_user=False)
        
    def on_continue(self):
        self.is_paused = False
        self.btn_pause.setEnabled(True)
        self.btn_pause.setVisible(True)
        self.btn_continue.setEnabled(False)
        self.btn_continue.setVisible(False)
        self.add_message("⏭ Auto-Pilot continuing...", is_user=False)
        self.typing_indicator.setText("Agent is thinking...")
        self.agent_status_badge.setText("Running")
        self.agent_status_badge.set_tone("info")
        self._sync_goal_status("active")
        self.run_loop()

    def on_stop(self):
        """Immediately stop the investigation and invalidate any late AI callback."""
        self._finish_stopped("Investigation stopped by the analyst.")

    def _remove_live_bubble(self):
        bubble = getattr(self, "live_bubble", None)
        if bubble:
            self.scroll_layout.removeWidget(bubble)
            bubble.deleteLater()
            self.live_bubble = None

    def _finish_stopped(self, message):
        self.is_running = False
        self.is_paused = False
        self.stop_active_request()
        self._remove_live_bubble()
        self.typing_indicator.setVisible(False)
        self.session.phase = "stopped"
        self._checkpoint_session(status="stopped")
        self.btn_start.setEnabled(True)
        self.btn_start.setVisible(True)
        self.btn_pause.setEnabled(False)
        self.btn_pause.setVisible(False)
        self.btn_continue.setEnabled(False)
        self.btn_continue.setVisible(False)
        self.btn_stop.setEnabled(False)
        self.btn_stop.setVisible(False)
        self.agent_status_badge.setText("Stopped")
        self.agent_status_badge.set_tone("warning")
        self.add_message(message, is_user=False)
        self._refresh_agent_dashboard()

    def stop_active_request(self):
        self._request_generation += 1
        request_id = self._active_request_id
        self._active_request_id = None
        if request_id is not None and _ai_mod.AI_CLIENT:
            _ai_mod.AI_CLIENT.cancel_request(request_id)

    def run_autopilot_loop(self):
        if not self.is_running or getattr(self, 'is_paused', False):
            return

        # Refill active queue if empty
        if not self.active_queue:
            new_blocked = []
            moved = 0
            def _check_blocked():
                nonlocal moved
                for ea in self.blocked_queue:
                    if count_sub_calls_fast(ea) == 0:
                        self.active_queue.append(ea)
                        moved += 1
                    else:
                        new_blocked.append(ea)
            ida_kernwin.execute_sync(_check_blocked, ida_kernwin.MFF_READ)
            self.blocked_queue = new_blocked
            
            if moved > 0:
                self.add_message(f"Moved {moved} functions from blocked to active queue.", is_user=False)
            elif self.blocked_queue:
                # Cycle detected or functions that call unnamed things that couldn't be renamed
                self.add_message(f"Force-moving {len(self.blocked_queue)} blocked functions to active queue to finish.", is_user=False)
                self.active_queue.extend(self.blocked_queue)
                self.blocked_queue = []

        if not self.active_queue:
            # We are completely done!
            self.is_running = False
            self.typing_indicator.setVisible(False)
            self.btn_start.setEnabled(True)
            self.add_message("✅ Auto-Pilot Bulk Analysis Complete!", is_user=False)
            self._save_markdown_report()
            return

        self.current_ea = self.active_queue.pop(0)
        self.processed_eas.add(self.current_ea)
        
        cfunc_str = None
        func_name = None
        def _get_code():
            nonlocal cfunc_str, func_name
            func_name = idc.get_func_name(self.current_ea)
            try:
                cf = ida_hexrays.decompile(self.current_ea)
                if cf: cfunc_str = str(cf)
            except: pass
        ida_kernwin.execute_sync(_get_code, ida_kernwin.MFF_READ)

        if not cfunc_str:
            self.add_message(f"⚠️ Skipping 0x{self.current_ea:X}: Could not decompile.", is_user=False)
            QtCore.QTimer.singleShot(50, self.run_autopilot_loop)
            return

        prompt = (
            "You are an expert reverse engineer analyzing a malware binary. Analyze the following C pseudocode.\n"
            "You MUST reply with ONLY a valid JSON object matching this schema exactly:\n"
            "{\n"
            "  \"function_name\": \"suggested_snake_case_name\",\n"
            "  \"variables\": {\n"
            "     \"v1\": \"new_var_name\",\n"
            "     \"a1\": \"new_arg_name\"\n"
            "  },\n"
            "  \"comments\": \"High-level summary of what the function does.\"\n"
            "}\n"
            "If you cannot determine a better name, return the original function name. DO NOT invent purposes. "
            "Keep variable names concise (e.g. 'key', 'index', 'buffer').\n\n"
            f"Original Function Name: {func_name}\n"
            f"Pseudocode:\n```c\n{cfunc_str}\n```"
        )
        
        self.typing_indicator.setVisible(True)
        self.typing_indicator.setText(f"Analyzing {func_name} (0x{self.current_ea:X})...")
        
        # We don't stream to chat to avoid UI lag for batch jobs, just a simple status
        def _autopilot_response(response, **kwargs):
            if not response:
                is_throttle = kwargs.get("is_throttle", False)
                err_msg = kwargs.get("error_msg", "Unknown error")
                if is_throttle:
                    self.orchestrator.event_log.append("model_throttled", error=err_msg)
                    self.add_message(f"⚠️ API Rate Limit (429) hit: {err_msg[:100]}...\\nPausing for 4 minutes before auto-continuing...", is_user=False)
                    self.is_paused = True
                    self._sync_goal_status("paused")
                    self.btn_pause.setEnabled(False)
                    self.btn_continue.setEnabled(True)
                    
                    self.throttle_remaining = getattr(CONFIG, 'agent_cooldown', 240)
                    self.typing_indicator.setVisible(True)
                    
                    # Push the failed EA back to the front of the queue so it gets retried
                    self.active_queue.insert(0, self.current_ea)
                    
                    def update_countdown():
                        if not getattr(self, 'is_paused', False) or getattr(self, 'throttle_remaining', 0) <= 0:
                            self.typing_indicator.setText("Agent is thinking...")
                            self.typing_indicator.setVisible(False)
                            if getattr(self, 'throttle_remaining', 0) <= 0 and getattr(self, 'is_paused', False):
                                self.on_continue()
                            return
                            
                        mins, secs = divmod(self.throttle_remaining, 60)
                        self.typing_indicator.setText(f"API Rate Limited. Auto-continuing in {mins}m {secs}s...")
                        self.throttle_remaining -= 1
                        QtCore.QTimer.singleShot(1000, update_countdown)
                        
                    update_countdown()
                    return
                else:
                    self.add_message(f"Error: API failure on 0x{self.current_ea:X} ({err_msg}). Skipping.", is_user=False)
                    QtCore.QTimer.singleShot(50, self.run_autopilot_loop)
                    return
                
            # Extract JSON
            json_str = ""
            try:
                if "```json" in response:
                    json_str = response.split("```json")[1].split("```")[0].strip()
                elif "```" in response:
                    json_str = response.split("```")[1].split("```")[0].strip()
                elif "{" in response and "}" in response:
                    json_str = response[response.find("{"):response.rfind("}")+1]
                
                if json_str:
                    data = json.loads(json_str)
                    
                    new_name = data.get("function_name", "")
                    vars_dict = data.get("variables", {})
                    comments = data.get("comments", "")
                    
                    self.markdown_report += f"## Function: {func_name} (0x{self.current_ea:X})\n"
                    
                    def _apply():
                        from genesect.renamer import clean_name
                        from genesect.var_renamer import apply_var_renames
                        
                        log_lines = []
                        if new_name and new_name != func_name and new_name != "sub_" + hex(self.current_ea)[2:]:
                            safe_name = clean_name(new_name, ea=self.current_ea)
                            if idc.set_name(self.current_ea, safe_name, idc.SN_AUTO):
                                log_lines.append(f"- **Renamed Function**: `{func_name}` -> `{safe_name}`")
                                
                        if vars_dict:
                            app, fail, _ = apply_var_renames(self.current_ea, vars_dict, log_fn=None)
                            if app > 0:
                                log_lines.append(f"- **Renamed Variables**: {app} successfully applied.")
                                
                        if comments:
                            curr = idc.get_func_cmt(self.current_ea, 0)
                            nc = comments if not curr else curr + "\\n" + comments
                            idc.set_func_cmt(self.current_ea, nc, 0)
                            log_lines.append(f"- **Comments**: {comments}")
                            
                        return "\\n".join(log_lines)
                        
                    res_log = []
                    ida_kernwin.execute_sync(lambda: res_log.append(_apply()), ida_kernwin.MFF_WRITE)
                    
                    if res_log and res_log[0]:
                        self.markdown_report += res_log[0] + "\n\n"
                    else:
                        self.markdown_report += "- No changes applied.\n\n"
                        
                    self.add_message(f"✅ Processed {func_name} -> {new_name}", is_user=False)
            except Exception as e:
                self.add_message(f"⚠️ JSON Parse Error on {func_name}: {e}", is_user=False)
            
            QtCore.QTimer.singleShot(100, self.run_autopilot_loop)

        AI_CLIENT = _ai_mod.AI_CLIENT
        history = [{"role": "user", "content": prompt}]
        AI_CLIENT.query_model_async(history, _autopilot_response)
        
    def _save_markdown_report(self):
        file_path, _ = QtWidgets.QFileDialog.getSaveFileName(self.parent, "Save Analysis Report", "analysis_report.md", "Markdown Files (*.md);;All Files (*)")
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(self.markdown_report)
                self.add_message(f"💾 Report saved successfully to: {file_path}", is_user=False)
            except Exception as e:
                self.add_message(f"❌ Error saving report: {e}", is_user=False)
                
    def _goal_metadata(self):
        identity = _current_binary_identity()
        coverage_total = len(getattr(self, "_task_targets", []) or [])
        coverage_done = 0
        if coverage_total:
            try:
                coverage_done = len(self._covered_target_eas())
            except Exception:
                coverage_done = 0
        return {
            "phase": getattr(self.session, "phase", ""),
            "turn": getattr(self.session, "turn", 0),
            "tool_steps": getattr(self.policy, "steps", 0),
            "task_profile": str(getattr(self, "_task_profile", "") or ""),
            "target_count": coverage_total,
            "covered_count": coverage_done,
            "finding_count": len(getattr(self.session, "findings", []) or []),
            "input_path": identity["input_path"],
            "idb_path": identity["idb_path"],
            "is_running": bool(getattr(self, "is_running", False)),
            "is_paused": bool(getattr(self, "is_paused", False)),
        }

    def _sync_goal_status(self, status=None):
        if getattr(self, "goal_store", None) and getattr(self, "goal_id", ""):
            try:
                self.goal_store.update_goal(
                    self.goal_id,
                    status=status,
                    metadata=self._goal_metadata(),
                )
                for finding in getattr(self.session, "findings", []) or []:
                    self.goal_store.add_finding(self.goal_id, finding)
            except Exception:
                pass
        for finding in getattr(self.session, "findings", []) or []:
            self._remember_finding(finding)

    def _remember_finding(self, finding):
        if not getattr(self, "memory_store", None) or not finding:
            return
        try:
            self.memory_store.record_finding(
                finding,
                project_id=getattr(self, "project_id", "") or _current_binary_identity()["project_id"],
                binary_hash=getattr(self, "binary_hash", ""),
                source_goal_id=getattr(self, "goal_id", ""),
                metadata={
                    "root_ea": "0x%X" % self.address,
                    "function_name": self.function_name,
                },
            )
        except Exception:
            pass

    def _remember_function_analysis(self, ea, record):
        if not getattr(self, "memory_store", None) or not record:
            return
        try:
            self.memory_store.record_function_summary(
                "0x%X" % int(ea),
                record,
                project_id=getattr(self, "project_id", "") or _current_binary_identity()["project_id"],
                binary_hash=getattr(self, "binary_hash", ""),
                source_goal_id=getattr(self, "goal_id", ""),
            )
        except Exception:
            pass

    def _checkpoint_session(self, status=None):
        try:
            save_to_idb(self.address, self.session.to_json(), tag=AGENTIC_HISTORY_TAG)
        except Exception as exc:
            self.add_message(f"Session checkpoint failed: {exc}", is_user=False)
        self._sync_goal_status(status)

    def _final_report_contradictions(self, report):
        """Reject conclusions that contradict state already established by the host."""
        lowered = str(report or "").lower()
        issues = []
        root_ea = f"0x{self.address:X}"
        if self.session.has_success("decompile", root_ea):
            patterns = (
                r"(?:blocked|unable|permission|allow)[^.]{0,120}decompil",
                r"decompil[^.]{0,120}(?:permission|blocked|limitation|restriction)",
            )
            if any(re.search(pattern, lowered) for pattern in patterns):
                issues.append("decompilation succeeded, so it was not blocked and needs no permission")

        if self._task_profile in ("rename_descendants", "rename_prefix") and self._task_targets:
            false_absence = (
                "no specific sub-functions", "no specific subfunctions",
                "no list of sub functions", "no sub-functions were identified",
                "which sub functions need", "which sub-functions need",
                "no functions with the prefix", "no matching functions",
                "there are no functions to rename", "absence of functions",
            )
            if any(phrase in lowered for phrase in false_absence):
                issues.append("the host supplied a concrete descendant-function target list")
            mentions_target = any(target["ea"].lower() in lowered for target in self._task_targets)
            if "unable to proceed" in lowered and not mentions_target:
                issues.append("read-only mode still requires rename proposals for enumerated targets")
            observed_tools = {str(item.get("tool", "")) for item in self.session.observations}
            if "list_functions" in lowered and "list_functions" not in observed_tools:
                issues.append("the report cites list_functions(), but that tool was never executed or available")
            missing_evidence, missing_report = [], []
            for target in self._task_targets:
                ea = target["ea"]
                analyzed = any(
                    capability in self.session.successful_capabilities
                    for capability in (f"decompile@{ea}", f"function_evidence@{ea}", f"disassemble@{ea}")
                )
                if not analyzed:
                    missing_evidence.append(ea)
                if ea.lower() not in lowered:
                    missing_report.append(ea)
            if missing_evidence:
                issues.append("targets lack function-level analysis: " + ", ".join(missing_evidence[:12]))
            if missing_report:
                issues.append("the final report omits enumerated targets: " + ", ".join(missing_report[:12]))
        if self._task_profile == "autonomous_full":
            pending = self._pending_coverage_targets()
            if pending:
                issues.append(
                    "targets lack function-level analysis: "
                    + ", ".join(target["ea"] for target in pending[:12])
                    + f" ({len(pending):,} functions remain pending)"
                )
        return issues

    def _process_agent_response(self, response):
        self.protocol_audit.append({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "response": str(response)[:20000],
        })
        envelope, error = self.orchestrator.parse_response(response)
        if error:
            self.error_count += 1
            try:
                reflection = self.reflector.add(
                    "protocol_error",
                    "warning",
                    str(error),
                    "Return exactly one valid JSON envelope with action=tools or action=final.",
                )
                self.orchestrator.event_log.append("reflection", **reflection.to_dict())
                self._reflection_context = self.reflector.guidance_text([reflection])
            except Exception:
                pass
            if self.error_count >= 3:
                self._finish_stopped(f"Agent stopped after repeated invalid responses: {error}")
                return
            self.history.append({"role": "user", "content": f"Protocol error: {error}. Return exactly one valid JSON envelope."})
            QtCore.QTimer.singleShot(100, self.run_loop)
            return

        self.error_count = 0
        self.history.append({"role": "assistant", "content": response})
        if envelope["action"] == "final":
            unsupported = self.session.unsupported_report_markers(envelope["report"])
            contradictions = self._final_report_contradictions(envelope["report"])
            coverage_issues = [issue for issue in contradictions if issue.startswith("targets lack function-level analysis:")]
            if coverage_issues and (self._task_profile == "autonomous_full" or not self._must_finalize):
                self.orchestrator.record_final(
                    envelope["report"], accepted=False, reason="incomplete coverage",
                )
                self.history.append({
                    "role": "user",
                    "content": (
                        "PREMATURE FINAL REPORT. Investigation coverage is incomplete: "
                        + "; ".join(coverage_issues)
                        + ". Return action=tools and analyze those exact addresses with decompile or, if it fails, "
                          "disassemble. Then provide evidence-backed rename proposals. Do not repeat global triage."
                    ),
                })
                QtCore.QTimer.singleShot(100, self.run_loop)
                return
            if unsupported or contradictions:
                self._report_revisions += 1
                self.orchestrator.record_final(
                    envelope["report"],
                    accepted=False,
                    reason=", ".join((unsupported + contradictions)[:10]),
                )
                if self._report_revisions >= 3:
                    self._finish_stopped(
                        "Final report rejected after repeated unsupported addresses or network indicators: "
                        + ", ".join((unsupported + contradictions)[:10])
                    )
                    return
                self.history.append({
                    "role": "user",
                    "content": (
                        "FINAL REPORT VALIDATION FAILED. Remove or clearly label as unverified these markers, "
                        "because they conflict with or do not occur in host evidence: "
                        + ", ".join(unsupported + contradictions)
                        + "\nReturn action=final again using only collected evidence."
                    ),
                })
                QtCore.QTimer.singleShot(100, self.run_loop)
                return
            self.session.phase = "complete"
            self.session.final_report = envelope["report"][:500000]
            self.orchestrator.record_final(self.session.final_report, accepted=True)
            self._checkpoint_session(status="complete")
            target_eas = {item["ea"] for item in self._task_targets}
            memory = [item for ea, item in self.session.function_memory.items() if ea in target_eas]
            analyzed = sum(1 for item in memory if item.get("state") in ("analyzed", "applied"))
            renamed = sum(1 for item in memory if item.get("rename_applied"))
            commented = sum(1 for item in memory if item.get("comment_applied"))
            failed = sum(1 for item in memory if item.get("state") == "failed")
            retained = sum(
                1 for item in memory
                if item.get("state") in ("analyzed", "applied") and not item.get("rename_applied")
            )
            completion = (
                f"Coverage complete: {analyzed:,}/{len(self._task_targets):,} analyzed • {renamed:,} renamed • "
                f"{commented:,} commented • {retained:,} names retained • {failed:,} unresolved."
            )
            self.add_message(completion + "\n\nFinal Analysis:\n\n" + self.session.final_report, is_user=False)
            self.is_running = False
            self.btn_start.setEnabled(True)
            self.btn_start.setVisible(True)
            self.btn_pause.setEnabled(False)
            self.btn_pause.setVisible(False)
            self.btn_continue.setEnabled(False)
            self.btn_continue.setVisible(False)
            self.btn_stop.setEnabled(False)
            self.btn_stop.setVisible(False)
            self.agent_status_badge.setText("Complete")
            self.agent_status_badge.set_tone("success")
            self._sync_goal_status("complete")
            self._refresh_agent_dashboard()
            return

        if self._must_finalize:
            self._finalize_reminders += 1
            if self._finalize_reminders >= 2:
                self._finish_stopped(
                    "Investigation stopped automatically because the agent ignored the final-answer limit twice."
                )
                return
            self.history.append({
                "role": "user",
                "content": (
                    "The investigation tool-round limit is exhausted. Do not call more tools. Return action=final "
                    "now using the collected evidence, and clearly state any uncertainty."
                ),
            })
            QtCore.QTimer.singleShot(100, self.run_loop)
            return

        observations = []
        all_calls_repeated = True
        self.session.begin_round()
        for call in envelope["calls"]:
            normalized, validation_error = self.orchestrator.validate_call(call)
            if validation_error:
                all_calls_repeated = False
                tool_name = call.get("tool", "") if isinstance(call, dict) else ""
                args = call.get("args", {}) if isinstance(call, dict) else {}
                if not isinstance(args, dict):
                    args = {}
                result = "Error: " + validation_error
                self.session.record_result(tool_name, args, result)
                self.session.record_observation(tool_name, args, result)
                self.orchestrator.record_tool_result(tool_name, args, result)
                observations.append(self.policy.untrusted_result(tool_name, result))
                observations.append("HOST DECISION GUIDANCE\n" + recovery_guidance(tool_name, result))
                self.add_message(f"Tool `{tool_name}` rejected: {validation_error}", is_user=False)
                continue
            tool_name, args = normalized["tool"], normalized["args"]
            if self._task_profile == "autonomous_full" and tool_name in (
                "function_evidence", "decompile", "disassemble", "record_function_analysis",
            ):
                ready_targets = self._ready_coverage_targets()
                ready_eas = {item["ea"] for item in ready_targets}
                requested = f"0x{_agent_ea(args.get('ea', self.address), self.address):X}"
                if ready_eas and requested not in ready_eas:
                    args = dict(args)
                    args["ea"] = ready_targets[0]["ea"]
            if tool_name in FUNCTION_SCOPED_AGENT_TOOLS:
                requested_ea = _agent_ea(args.get("ea", self.address), self.address)
                requested_func = idaapi.get_func(requested_ea)
                if requested_func:
                    args["ea"] = f"0x{int(requested_func.start_ea):X}"
            if self._task_profile == "autonomous_full" and tool_name in (
                "function_evidence", "decompile", "disassemble",
            ):
                activity_ea = str(args.get("ea", ""))
                if activity_ea and activity_ea not in self._visible_analyzing:
                    self._visible_analyzing.add(activity_ea)
                    target = self._target_by_ea.get(activity_ea, {})
                    display_name = target.get("name") or idc.get_func_name(_agent_ea(activity_ea)) or activity_ea
                    self.add_message(f"Analyzing {activity_ea}  {display_name}", is_user=False)
            repeated = self.session.record_call(tool_name, args)
            if tool_name == "record_function_analysis":
                # Low-confidence rescans legitimately replace the prior decision.
                repeated = 0
            if repeated < 2:
                all_calls_repeated = False
            replayed = False
            if repeated >= 2:
                redirected = False
                if self._task_profile in ("rename_descendants", "rename_prefix", "autonomous_full") and tool_name in FUNCTION_SCOPED_AGENT_TOOLS:
                    redirect_targets = (
                        self._ready_coverage_targets()
                        if self._task_profile == "autonomous_full"
                        else self._task_targets
                    )
                    for target in redirect_targets:
                        target_ea = target["ea"]
                        if not self.session.has_success(tool_name, target_ea):
                            args = dict(args)
                            args["ea"] = target_ea
                            repeated = self.session.record_call(tool_name, args)
                            redirected = repeated < 2
                            if redirected:
                                all_calls_repeated = False
                                self.add_message(
                                    f"Redirected repeated `{tool_name}` to pending target {target_ea}.", is_user=False
                                )
                            break
                if not redirected:
                    cached = self.session.cached_result(tool_name, args)
                    if cached:
                        result = "Cached prior successful observation; use it and do not request it again:\n" + cached
                        replayed = True
                    else:
                        result = "Error: Repeated identical call blocked; choose a pending target or synthesize existing evidence."
                else:
                    result = self._execute_agent_tool(tool_name, args)
            elif (
                tool_name == "disassemble"
                and self.session.has_success("decompile", args.get("ea", f"0x{self.address:X}"))
                and not str(args.get("purpose", "")).strip()
            ):
                result = (
                    "Skipped: Pseudocode already succeeded for this function. Supply a concrete instruction-level "
                    "purpose only if disassembly is necessary."
                )
            elif tool_name == "record_finding":
                if not self.session.evidence_supported(args.get("evidence", [])):
                    result = "Error: Finding rejected because its citations are not supported by collected tool evidence."
                    self.policy.record(tool_name, args, False, result)
                else:
                    confidence = args.get("confidence", "low")
                    if confidence == "high" and self.session.evidence_support_count(args.get("evidence", [])) < 2:
                        confidence = "medium"
                    finding = self.session.add_finding(
                        args.get("claim", ""), confidence,
                        args.get("evidence", []), args.get("tags", []),
                    )
                    self._remember_finding(finding)
                    result = f"Recorded verified finding {finding.finding_id}."
                    self.policy.record(tool_name, args, True, result)
            elif tool_name == "mark_examined":
                ea = _agent_ea(args.get("ea", self.address), self.address)
                disposition = args.get("disposition", "examined")
                canonical = f"0x{ea:X}"
                if not self.session.has_evidence_for_ea(canonical):
                    result = "Error: Cannot mark an address examined before a successful function-scoped observation."
                    self.policy.record(tool_name, args, False, result)
                else:
                    self.session.mark_examined(ea, disposition, args.get("summary", ""))
                    result = f"Marked 0x{ea:X} as {disposition}."
                    self.policy.record(tool_name, args, True, result)
            elif tool_name == "record_function_analysis":
                ea = _agent_ea(args.get("ea", self.address), self.address)
                canonical = f"0x{ea:X}"
                coverage = set(self.session.function_coverage.get(canonical, []))
                summary = _short_function_summary(args.get("summary", ""))
                evidence = args.get("evidence", [])
                confidence = int(args.get("confidence", 0))
                previous = dict(self.session.function_memory.get(canonical, {}))
                attempts = int(previous.get("attempts", 0)) + 1
                if "function_evidence" not in coverage or not ({"decompile", "disassemble"} & coverage):
                    result = "Error: Collect function_evidence and decompile/disassemble before completing this function."
                    self.policy.record(tool_name, args, False, result)
                elif not summary:
                    result = "Error: The short behavioral summary is empty."
                    self.policy.record(tool_name, args, False, result)
                elif not self.session.evidence_supported_for_ea(ea, evidence):
                    result = "Error: Function analysis evidence is not supported by observations for this function."
                    self.policy.record(tool_name, args, False, result)
                else:
                    original_name = previous.get("original_name") or idc.get_func_name(ea) or f"sub_{ea:X}"
                    requested_name = str(args.get("suggested_name", "") or "").strip()
                    validated_name = clean_name(requested_name, ea=ea) if requested_name else original_name
                    if requested_name and not validated_name:
                        result = "Error: Suggested name was rejected as generic, invalid, or address-derived."
                        self.policy.record(tool_name, args, False, result)
                    elif confidence <= 50 and attempts < 3:
                        memory_record = self.session.remember_function(ea, {
                            "original_name": original_name, "suggested_name": validated_name or original_name,
                            "summary": summary, "confidence": confidence, "evidence": evidence[:20],
                            "state": "retry_low_confidence", "attempts": attempts,
                            "code_fingerprint": _function_code_fingerprint(ea),
                            "analysis_version": _FUNCTION_ANALYSIS_VERSION,
                            "callees": list(getattr(self, "_target_by_ea", {}).get(canonical, {}).get("callees", [])),
                            "name_validation": "accepted" if requested_name else "retained",
                        })
                        self._remember_function_analysis(ea, memory_record)
                        result = f"Low-confidence result ({confidence}%) stored; reanalyze this function individually."
                        self.policy.record(tool_name, args, True, result)
                    else:
                        apply_result = {"ok": True, "renamed": False, "commented": False,
                                        "final_name": original_name, "error": ""}
                        if self.policy.allow_mutations:
                            apply_result = _apply_function_name_and_comment(ea, validated_name, summary)
                            self.policy.record("apply_function_metadata", {
                                "ea": canonical, "new_name": validated_name, "summary": summary,
                            }, bool(apply_result.get("ok")), apply_result.get("error", "applied"))
                        state = "applied" if self.policy.allow_mutations and apply_result.get("ok") else (
                            "apply_failed" if self.policy.allow_mutations else "analyzed"
                        )
                        final_name = apply_result.get("final_name") or original_name
                        memory_record = self.session.remember_function(ea, {
                            "original_name": original_name, "current_name": final_name,
                            "original_comment": apply_result.get(
                                "original_comment", previous.get("original_comment", "")
                            ),
                            "suggested_name": validated_name or original_name, "summary": summary,
                            "confidence": confidence, "evidence": evidence[:20], "state": state,
                            "attempts": attempts, "code_fingerprint": _function_code_fingerprint(ea),
                            "analysis_version": _FUNCTION_ANALYSIS_VERSION,
                            "callees": list(getattr(self, "_target_by_ea", {}).get(canonical, {}).get("callees", [])),
                            "name_validation": "accepted" if requested_name else "retained",
                            "rename_applied": bool(apply_result.get("renamed")),
                            "comment_applied": bool(apply_result.get("commented")),
                            "last_error": apply_result.get("error", ""),
                        })
                        self._remember_function_analysis(ea, memory_record)
                        if apply_result.get("ok"):
                            self.session.mark_examined(ea, "analyzed", summary)
                            result = f"Completed {canonical}: {final_name} — {summary} Confidence: {confidence}%."
                            self.policy.record(tool_name, args, True, result)
                            if self._task_profile == "autonomous_full":
                                if apply_result.get("renamed"):
                                    action = f"Renamed {original_name} → {final_name}"
                                elif apply_result.get("commented"):
                                    action = f"Commented {final_name}"
                                else:
                                    action = f"Analyzed {final_name} — existing name retained"
                                self.add_message(
                                    f"{action}\nWhat it does: {summary}  Confidence: {confidence}%", is_user=False,
                                )
                                self._refresh_agent_dashboard()
                        else:
                            result = f"Error: Rename/comment transaction failed for {canonical}: {apply_result.get('error', 'unknown error')}"
                            self.policy.record(tool_name, args, False, result)
            else:
                result = self._execute_agent_tool(tool_name, args)
            if (
                self._task_profile == "autonomous_full"
                and tool_name in ("function_evidence", "decompile", "disassemble")
                and result_status(result) == "error"
            ):
                failed_ea = _agent_ea(args.get("ea", self.address), self.address)
                failed_key = f"0x{failed_ea:X}"
                prior = dict(self.session.function_memory.get(failed_key, {}))
                failures = dict(prior.get("tool_failures", {}))
                failures[tool_name] = int(failures.get(tool_name, 0)) + 1
                terminal_failure = (
                    failures.get("function_evidence", 0) >= 3
                    or (failures.get("decompile", 0) >= 1 and failures.get("disassemble", 0) >= 1)
                )
                memory_record = self.session.remember_function(failed_ea, {
                    "original_name": prior.get("original_name") or idc.get_func_name(failed_ea) or f"sub_{failed_ea:X}",
                    "current_name": idc.get_func_name(failed_ea) or f"sub_{failed_ea:X}",
                    "state": "failed" if terminal_failure else "retry_tool_failure",
                    "tool_failures": failures, "last_error": str(result)[:1000],
                    "summary": prior.get("summary", "Analysis unavailable after IDA code-recovery failure."),
                    "code_fingerprint": _function_code_fingerprint(failed_ea),
                })
                self._remember_function_analysis(failed_ea, memory_record)
                if terminal_failure:
                    self.add_message(
                        f"{failed_key} needs attention — both decompilation/disassembly or repeated evidence collection failed.",
                        is_user=False,
                    )
                    self._refresh_agent_dashboard()
                    self._refresh_agent_dashboard()
            if replayed:
                self.orchestrator.record_tool_result(tool_name, args, result, replayed=True)
                made_progress = False
            else:
                self.orchestrator.record_tool_result(tool_name, args, result, replayed=replayed)
                self.session.record_observation(tool_name, args, result)
                made_progress = self.session.record_result(tool_name, args, result)
            if tool_name == "function_evidence" and result_status(result) == "success":
                try:
                    concrete_iocs = json.loads(result).get("network_iocs", [])
                except (TypeError, ValueError, AttributeError):
                    concrete_iocs = []
                if concrete_iocs:
                    target = args.get("ea", f"0x{self.address:X}")
                    self.session.add_finding(
                        f"Function {target} references network indicator(s)", "high",
                        [f"{target}: {indicator}" for indicator in concrete_iocs],
                        ["network", "ioc"],
                    )
            observations.append(self.policy.untrusted_result(tool_name, result))
            if not made_progress:
                observations.append("HOST DECISION GUIDANCE\n" + recovery_guidance(tool_name, result))
            if self._task_profile != "autonomous_full" or result_status(result) == "error":
                self.add_message(f"Tool `{tool_name}`: {result[:240]}{'...' if len(result) > 240 else ''}", is_user=False)

        if self._focused_request:
            self._focused_tool_rounds += 1
        self._tool_rounds += 1
        self.session.finish_round()
        # One wholly duplicated batch is enough evidence that the model is
        # stalled. Preserve cached observations and force synthesis instead of
        # allowing another identical batch.
        if all_calls_repeated and self._task_profile != "autonomous_full":
            self._must_finalize = True
        if self._tool_rounds >= self._max_tool_rounds or self.policy.steps >= self.policy.max_steps:
            if self._task_profile == "autonomous_full" and self._pending_coverage_targets():
                self._finish_stopped(
                    "Binary-wide investigation stopped at its safety limit with "
                    f"{len(self._pending_coverage_targets()):,} functions still pending. No premature summary was accepted."
                )
                return
            self._must_finalize = True
        if self.session.should_finalize() and self._task_profile != "autonomous_full":
            self._must_finalize = True

        self._reflect_after_round(all_calls_repeated=all_calls_repeated)
        self._checkpoint_session()
        self._refresh_agent_dashboard()
        self.history.append({
            "role": "user",
            "content": (
                "\n\n".join(observations)
                + "\n\nCURRENT INVESTIGATION STATE\n" + self.session.snapshot()
                + self._plan_context()
                + self._reflection_prompt_context()
                + ("\n\n" + self._coverage_batch_text() if self._task_profile == "autonomous_full" else "")
                + ("\n\nTOOL LIMIT REACHED: Return action=final now with the direct answer; do not call more tools."
                   if self._must_finalize else "")
            ),
        })
        if sum(len(str(item.get("content", ""))) for item in self.history) > 120000:
            recent = self.history[-6:]
            self.history = [self.history[0], {
                "role": "user",
                "content": (
                    "Earlier conversation was compacted. Use this host-owned evidence ledger and state; "
                    "do not invent missing details.\n\n" + self.session.snapshot(max_chars=40000)
                ),
            }] + recent
        QtCore.QTimer.singleShot(100, self.run_loop)

    def run_loop(self):
        if not self.is_running or getattr(self, 'is_paused', False):
            return

        AI_CLIENT = _ai_mod.AI_CLIENT
        if not AI_CLIENT:
            self._finish_stopped("Agent could not start because the AI client is not initialized.")
            return

        self.typing_indicator.setVisible(True)
        
        self.live_bubble = ChatBubble("...", is_user=False)
        self.scroll_layout.insertWidget(self.scroll_layout.count() - 1, self.live_bubble)
        self.scroll_to_bottom()
        
        # Accumulator for streaming chunks
        self._streamed_text = ""
        request_generation = self._request_generation
        
        def handle_chunk(text):
            if request_generation != self._request_generation or not self.is_running:
                return
            # Strict agent responses are internal JSON envelopes. Do not flash
            # partial protocol data in the user-facing activity feed.
            return
        
        def handle_response(response, **kwargs):
            if request_generation != self._request_generation or not self.is_running:
                return
            self.typing_indicator.setVisible(False)
            self._remove_live_bubble()
                
            if not response:
                is_throttle = kwargs.get("is_throttle", False)
                err_msg = kwargs.get("error_msg", "Unknown error")
                if is_throttle:
                    self.orchestrator.event_log.append("model_throttled", error=err_msg)
                    self._sync_goal_status("paused")
                    self.add_message(f"⚠️ API Rate Limit (429) hit: {err_msg[:100]}...\nPausing for 4 minutes before auto-continuing...", is_user=False)
                    self.is_paused = True
                    self.btn_pause.setEnabled(False)
                    self.btn_continue.setEnabled(True)
                    
                    self.throttle_remaining = getattr(CONFIG, 'agent_cooldown', 240)
                    self.typing_indicator.setVisible(True)
                    
                    def update_countdown():
                        if not getattr(self, 'is_paused', False) or getattr(self, 'throttle_remaining', 0) <= 0:
                            self.typing_indicator.setText("Agent is thinking...")
                            self.typing_indicator.setVisible(False)
                            if getattr(self, 'throttle_remaining', 0) <= 0 and getattr(self, 'is_paused', False):
                                self.on_continue()
                            return
                            
                        mins, secs = divmod(self.throttle_remaining, 60)
                        self.typing_indicator.setText(f"API Rate Limited. Auto-continuing in {mins}m {secs}s...")
                        self.throttle_remaining -= 1
                        QtCore.QTimer.singleShot(1000, update_countdown)
                        
                    update_countdown()
                    return
                else:
                    self.orchestrator.event_log.append("model_empty_response", error=err_msg)
                    self._finish_stopped(f"Agent request stopped: no response from AI ({err_msg}).")
                    return

            self._active_request_id = None
            self._process_agent_response(response)
            return

            self.history.append({"role": "assistant", "content": response})
            
            # Parse for JSON block
            tool_call = None
            json_error = None
            has_json_block = False
            
            try:
                json_str = ""
                if "```json" in response:
                    json_str = response.split("```json")[1].split("```")[0].strip()
                    has_json_block = True
                elif "```" in response:
                    json_str = response.split("```")[1].split("```")[0].strip()
                    has_json_block = True
                elif "{" in response and "}" in response:
                    json_str = response[response.find("{"):response.rfind("}")+1]
                    if '"tool"' in json_str: # High confidence it's a tool call if it contains "tool"
                        has_json_block = True
                
                if json_str:
                    # Fix unquoted hex values in JSON: "args": {"ea": 0x1000} -> "args": {"ea": "0x1000"}
                    json_str = re.sub(r'(:\s*)(0x[0-9a-fA-F]+)', r'\1"\2"', json_str)
                    tool_call = json.loads(json_str)
            except Exception as e:
                json_error = str(e)
                tool_call = None

            if tool_call and "tool" in tool_call:
                self.error_count = 0
                tool_name = tool_call["tool"]
                args = tool_call.get("args", {})
                self.add_message(f"🛠️ Executing Tool: `{tool_name}`\nArgs: {json.dumps(args, indent=2)}", is_user=False)
                
                result = self._execute_agent_tool(tool_name, args)

                # Create a concise summary for the UI to prevent spam
                if result.startswith("Error") or result.startswith("Failed") or "Exception" in result[:50]:
                    ui_msg = f"⚙️ Tool `{tool_name}` returned an error:\n{result[:200]}{'...' if len(result)>200 else ''}"
                else:
                    if tool_name == "decompile":
                        ui_msg = f"⚙️ Tool `{tool_name}`: Successfully decompiled function ({len(result)} chars)."
                    elif tool_name == "analyze_subfunction":
                        ui_msg = f"⚙️ Tool `{tool_name}`: Successfully decompiled subfunction."
                    elif tool_name == "get_xrefs":
                        ui_msg = f"⚙️ Tool `{tool_name}`: Xrefs retrieved."
                    elif tool_name == "get_vtable_ptrs":
                        ui_msg = f"⚙️ Tool `{tool_name}`: Retrieved pointers."
                    elif tool_name == "set_func_type":
                        ui_msg = f"⚙️ Tool `{tool_name}`: Set function signature."
                    elif tool_name == "read_memory":
                        ui_msg = f"⚙️ Tool `{tool_name}`: Dumped memory."
                    elif tool_name == "patch_bytes":
                        ui_msg = f"⚙️ Tool `{tool_name}`: Memory patched."
                    elif tool_name == "save_finding":
                        ui_msg = f"⚙️ Tool `{tool_name}`: Saved to global memory."
                    elif tool_name == "search_findings":
                        ui_msg = f"⚙️ Tool `{tool_name}`: Searched global memory."
                    elif tool_name == "execute_idapython":
                        ui_msg = f"⚙️ Tool `{tool_name}`: Script executed.\n{result[:150]}{'...' if len(result)>150 else ''}"
                    else:
                        ui_msg = f"⚙️ Tool `{tool_name}`: {result[:100]}{'...' if len(result)>100 else ''}"

                self.add_message(ui_msg, is_user=True)
                
                # The agent still needs the full result in its history
                self.history.append({"role": "user", "content": self.policy.untrusted_result(tool_name, result)})
                
                # Context Management: Truncate history if it gets too large (>20,000 characters)
                current_length = sum(len(str(m.get("content", ""))) for m in self.history)
                if current_length > 20000 and len(self.history) > 5:
                    # Keep system prompt (index 0) and the last 3 exchanges
                    self.history = [self.history[0]] + self.history[-3:]
                    self.add_message("⚠️ Context limit reached. Truncated older history to preserve memory.", is_user=False)
                
                # Continue loop
                QtCore.QTimer.singleShot(100, self.run_loop)
            elif has_json_block and json_error:
                self.error_count += 1
                if self.error_count >= 3:
                    self.add_message(f"⚠️ Agent repeatedly failed to produce valid JSON. Stopping analysis to prevent infinite loops.", is_user=False)
                    self.is_running = False
                    self.btn_start.setEnabled(True)
                    self.btn_pause.setEnabled(False)
                    self.btn_continue.setEnabled(False)
                    return
                
                # Agent tried to output JSON but failed syntax
                err_str = f"⚠️ JSON Parse Error: {json_error}\nPlease format your tool call as valid JSON. Ensure you DO NOT put normal text inside the JSON block."
                self.add_message(err_str, is_user=True)
                self.history.append({"role": "user", "content": f"Failed to parse JSON tool call. You wrote invalid JSON. Error: {json_error}. Remember: ONLY output the JSON block, no surrounding text inside the block. Hex values must be strings."})
                QtCore.QTimer.singleShot(100, self.run_loop)
            else:
                self.error_count = 0
                # Agent provided final analysis
                self.add_message(f"✅ Final Analysis:\n\n{response}", is_user=False)
                self.is_running = False
                self.btn_start.setEnabled(True)
                self.btn_pause.setEnabled(False)
                self.btn_continue.setEnabled(False)

        try:
            self.orchestrator.event_log.append(
                "model_request",
                message_count=len(self.history),
                prompt_chars=sum(len(str(item.get("content", ""))) for item in self.history),
                max_completion_tokens=8192,
            )
            self._active_request_id = AI_CLIENT.query_model_async(
                self.history, handle_response, on_chunk=handle_chunk,
                additional_options={"max_completion_tokens": 8192},
            )
        except Exception as exc:
            self._active_request_id = None
            self.orchestrator.event_log.append("model_request_error", error=str(exc))
            self._finish_stopped(f"Could not start agent request: {exc}")

    def OnClose(self, form):
        self.is_running = False
        self.stop_active_request()


class AgenticAnalysisHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        ea = idaapi.get_screen_ea()
        func = idaapi.get_func(ea)
        if not func:
            print("[Genesect] No function at cursor.")
            return 0
        
        name = idc.get_func_name(func.start_ea)
        
        title = "Genesect - Autonomous Investigation"
        widget = ida_kernwin.find_widget(title)
        if widget:
            ida_kernwin.activate_widget(widget, True)
        else:
            form = AgenticForm(func.start_ea, name)
            form.Show(title, options=ida_kernwin.PluginForm.WOPN_DP_RIGHT | ida_kernwin.PluginForm.WOPN_PERSIST)
        
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
