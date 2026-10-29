# -*- coding: utf-8 -*-
"""Reusable semantic evidence collection for API-centric explorers."""
from __future__ import annotations

from collections import defaultdict

import idaapi
import ida_funcs
import idautils
import idc

from genesect.api_knowledge import describe_api, normalize_api_name


CALL_XREF_TYPES = (getattr(idaapi, "fl_CF", 16), getattr(idaapi, "fl_CN", 17))


def function_start(ea):
    func = ida_funcs.get_func(int(ea))
    return int(func.start_ea) if func else idaapi.BADADDR


def function_name(ea):
    start = function_start(ea)
    return idc.get_func_name(start) or ("sub_%X" % start if start != idaapi.BADADDR else "")


def collect_api_calls():
    """Return normalized imported API calls grouped by owning function."""
    by_function = defaultdict(list)
    for api_ea, raw_name in idautils.Names():
        knowledge = describe_api(raw_name)
        if not knowledge["known"]:
            continue
        normalized = knowledge["normalized"]
        for xref in idautils.XrefsTo(api_ea, 0):
            if xref.type not in CALL_XREF_TYPES:
                continue
            owner = function_start(xref.frm)
            if owner == idaapi.BADADDR:
                continue
            by_function[owner].append({
                "site": int(xref.frm), "api_ea": int(api_ea), "api": normalized,
                "owner": owner, "function": function_name(owner), "knowledge": knowledge,
            })
    for calls in by_function.values():
        calls.sort(key=lambda item: item["site"])
    return dict(by_function)


def direct_internal_callees(func_ea):
    result = set()
    func = ida_funcs.get_func(int(func_ea))
    if not func:
        return result
    for ea in idautils.FuncItems(func.start_ea):
        for target in idautils.CodeRefsFrom(ea, False):
            start = function_start(target)
            if start not in (idaapi.BADADDR, func.start_ea):
                result.add(start)
    return result


def nearby_argument_setup(call_ea, limit=24):
    """Collect bounded pre-call operand evidence without claiming exact ABI flow."""
    owner = function_start(call_ea)
    rows, cursor = [], int(call_ea)
    for _index in range(limit):
        cursor = idc.prev_head(cursor)
        if cursor == idaapi.BADADDR or function_start(cursor) != owner:
            break
        mnemonic = (idc.print_insn_mnem(cursor) or "").lower()
        if mnemonic in ("call", "jmp", "ret", "retn", "br", "blr"):
            break
        rows.append({
            "ea": int(cursor), "mnemonic": mnemonic,
            "destination": idc.print_operand(cursor, 0) or "",
            "source": idc.print_operand(cursor, 1) or "",
            "source_type": idc.get_operand_type(cursor, 1),
            "source_value": int(idc.get_operand_value(cursor, 1)),
            "line": idaapi.tag_remove(idc.generate_disasm_line(cursor, 0) or ""),
        })
    rows.reverse()
    return rows


def recover_call_arguments(call_ea, signature=None):
    """Recover conservative x64-register/x86-push argument evidence."""
    setup = nearby_argument_setup(call_ea)
    params = list((signature or {}).get("params") or [])
    registers = ("rcx", "rdx", "r8", "r9")
    recovered = []
    by_register = {}
    for item in reversed(setup):
        destination = item["destination"].strip().casefold()
        if destination in registers and destination not in by_register:
            by_register[destination] = item
    pushes = [item for item in reversed(setup) if item["mnemonic"] == "push"]
    count = max(len(params), len(by_register), len(pushes))
    for index in range(count):
        param = params[index] if index < len(params) else {}
        evidence = by_register.get(registers[index]) if index < len(registers) else None
        location = registers[index].upper() if evidence else ""
        if evidence is None and index < len(pushes):
            evidence, location = pushes[index], "stack +%d" % (index * 4)
        recovered.append({
            "index": index, "name": param.get("name") or "arg%d" % (index + 1),
            "type": param.get("type") or "", "location": location,
            "value": (evidence["destination"] if evidence and evidence["mnemonic"] == "push" else evidence["source"]) if evidence else "not recovered",
            "setup_ea": evidence["ea"] if evidence else None,
            "setup": evidence["line"] if evidence else "No bounded setup evidence",
        })
    return recovered


def call_target_name(call_ea):
    """Resolve a direct call target name from the current instruction."""
    for target in idautils.CodeRefsFrom(int(call_ea), False):
        name = idc.get_name(target) or idc.get_func_name(target)
        if name:
            return normalize_api_name(name), int(target)
    operand = idc.print_operand(int(call_ea), 0) or ""
    return normalize_api_name(operand), int(idc.get_operand_value(int(call_ea), 0))


def format_call(call):
    taxonomy = call["knowledge"].get("taxonomy") or {}
    suffix = " [%s/%s]" % (taxonomy.get("category"), taxonomy.get("severity")) if taxonomy else ""
    return "0x%X: %s%s" % (call["site"], call["api"], suffix)
