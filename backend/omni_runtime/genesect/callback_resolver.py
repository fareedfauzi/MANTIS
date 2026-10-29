# -*- coding: utf-8 -*-
"""Resolve callbacks, dispatch tables, jump tables, and indirect calls in IDA."""
import csv
import io
import os
import re

try:
    import idaapi
    import ida_bytes
    import ida_funcs
    import ida_ida
    import ida_kernwin
    import ida_nalt
    import ida_segment
    import ida_ua
    import idautils
    import idc
except ImportError:
    idaapi = None
    ida_bytes = None
    ida_funcs = None
    ida_ida = None
    ida_kernwin = None
    ida_nalt = None
    ida_segment = None
    ida_ua = None
    idautils = None
    idc = None

from genesect.qt_compat import QtCore, QtWidgets
from genesect.ui.components import PageHeader, Card
from genesect.ui.mac_workspace import apply_mac_workspace
from genesect.api_knowledge import callback_parameters, normalize_api_name


_resolver = None
_MAX_DATA_SCAN = 512 * 1024 * 1024
_MAX_POINTER_ROWS = 100000
_MAX_INDIRECT_ROWS = 100000
_CALLBACK_API = re.compile(
    r"(?:setwindowshookex|registerclass|createdialog|dialogbox|enum(?:windows|childwindows|threadwindows|fonts|processes)|"
    r"settimer|queueuserapc|createthread|beginthread|atexit|qsort|bsearch|register.*callback|set.*handler|"
    r"addvectoredexceptionhandler|setconsolectrlhandler|(?:^|_)(?:signal|notify|subscribe)(?:_|$))", re.I,
)
_HANDLER_NAME = re.compile(r"(?:wndproc|dialogproc|dlgproc|hookproc|threadproc|on_[a-z]|(?:^|_)(?:callback|handler|dispatch|signal|visitor|listener)(?:_|$))", re.I)

_REG_FAMILIES = {
    "rax": {"rax", "eax", "ax", "al", "ah"},
    "rbx": {"rbx", "ebx", "bx", "bl", "bh"},
    "rcx": {"rcx", "ecx", "cx", "cl", "ch"},
    "rdx": {"rdx", "edx", "dx", "dl", "dh"},
    "rsi": {"rsi", "esi", "si", "sil"},
    "rdi": {"rdi", "edi", "di", "dil"},
    "rbp": {"rbp", "ebp", "bp", "bpl"},
    "rsp": {"rsp", "esp", "sp", "spl"},
    "r8": {"r8", "r8d", "r8w", "r8b"},
    "r9": {"r9", "r9d", "r9w", "r9b"},
    "r10": {"r10", "r10d", "r10w", "r10b"},
    "r11": {"r11", "r11d", "r11w", "r11b"},
    "r12": {"r12", "r12d", "r12w", "r12b"},
    "r13": {"r13", "r13d", "r13w", "r13b"},
    "r14": {"r14", "r14d", "r14w", "r14b"},
    "r15": {"r15", "r15d", "r15w", "r15b"},
}


def _hex(ea):
    return "0x%X" % int(ea)


def _pointer_size():
    return 8 if (ida_ida and hasattr(ida_ida, "inf_is_64bit") and ida_ida.inf_is_64bit()) else 4


def _read_pointer(ea):
    if not ida_bytes or not hasattr(ida_bytes, "is_loaded") or not ida_bytes.is_loaded(ea):
        return getattr(idaapi, "BADADDR", 0xffffffffffffffff) if idaapi else 0xffffffffffffffff
    return ida_bytes.get_qword(ea) if _pointer_size() == 8 else ida_bytes.get_dword(ea)


def _function_start(ea):
    if not ida_funcs or not hasattr(ida_funcs, "get_func"):
        return getattr(idaapi, "BADADDR", 0xffffffffffffffff) if idaapi else 0xffffffffffffffff
    func = ida_funcs.get_func(ea)
    return int(func.start_ea) if func else (getattr(idaapi, "BADADDR", 0xffffffffffffffff) if idaapi else 0xffffffffffffffff)


def _function_name(ea):
    start = _function_start(ea)
    badaddr = getattr(idaapi, "BADADDR", 0xffffffffffffffff) if idaapi else 0xffffffffffffffff
    if start == badaddr:
        return ""
    name = idc.get_func_name(start) if idc else ""
    return name or ("sub_%X" % start)


def _owner(ea):
    name = _function_name(ea)
    start = _function_start(ea)
    return "%s (%s)" % (name, _hex(start)) if name else "<outside function>"


def _is_executable_function(ea):
    start = _function_start(ea)
    badaddr = getattr(idaapi, "BADADDR", 0xffffffffffffffff) if idaapi else 0xffffffffffffffff
    if start == badaddr:
        return False
    if not ida_segment or not hasattr(ida_segment, "getseg"):
        return True
    segment = ida_segment.getseg(start)
    perm_exec = getattr(ida_segment, "SEGPERM_EXEC", 1)
    return bool(segment and (segment.perm & perm_exec))


def _canonical_reg(reg_name):
    if not reg_name:
        return ""
    r = reg_name.lower().strip().lstrip("%")
    for canon, members in _REG_FAMILIES.items():
        if r in members:
            return canon
    return r


def _reg_matches(op_text, target_reg):
    canon_target = _canonical_reg(target_reg)
    canon_op = _canonical_reg(op_text)
    if canon_target and canon_op:
        return canon_target == canon_op
    return canon_target in op_text.lower()


def _check_argument_register(reg_name, func=None):
    canon = _canonical_reg(reg_name)
    is_64 = ida_ida.inf_is_64bit() if (ida_ida and hasattr(ida_ida, "inf_is_64bit")) else True
    if is_64:
        win_args = ["rcx", "rdx", "r8", "r9"]
        if canon in win_args:
            return {"arg_index": win_args.index(canon), "abi": "win64", "reg": canon}
        sysv_args = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        if canon in sysv_args:
            return {"arg_index": sysv_args.index(canon), "abi": "sysv", "reg": canon}
    else:
        if canon == "rcx":
            return {"arg_index": 0, "abi": "fastcall/thiscall", "reg": "ecx"}
        if canon == "rdx":
            return {"arg_index": 1, "abi": "fastcall", "reg": "edx"}
    return None


def _hunt_callers_for_argument(func_start, arg_index, max_callers=25):
    badaddr = getattr(idaapi, "BADADDR", 0xffffffffffffffff) if idaapi else 0xffffffffffffffff
    if func_start == badaddr or not func_start or not idautils:
        return []
    is_64 = ida_ida.inf_is_64bit() if (ida_ida and hasattr(ida_ida, "inf_is_64bit")) else True
    target_reg_names = []
    if is_64:
        win_map = [["rcx", "ecx"], ["rdx", "edx"], ["r8", "r8d"], ["r9", "r9d"]]
        if arg_index < len(win_map):
            target_reg_names.extend(win_map[arg_index])
    else:
        if arg_index == 0:
            target_reg_names.extend(["ecx", "cx"])
        elif arg_index == 1:
            target_reg_names.extend(["edx", "dx"])

    candidates = []
    caller_count = 0
    for xref in idautils.CodeRefsTo(func_start, 0):
        caller_ea = xref
        caller_count += 1
        if caller_count > max_callers:
            break
        cur = caller_ea
        for _ in range(15):
            cur = idc.prev_head(cur)
            if cur == badaddr or cur < _function_start(caller_ea):
                break
            mnem = idc.print_insn_mnem(cur).lower()
            op0 = idc.print_operand(cur, 0).lower().strip()
            matched = any(_reg_matches(op0, r) for r in target_reg_names) if target_reg_names else False
            if not is_64 and mnem == "push":
                matched = True

            if matched:
                val = idc.get_operand_value(cur, 1 if mnem != "push" else 0)
                if _is_executable_function(val):
                    candidates.append({
                        "caller_site": caller_ea,
                        "setup_ea": cur,
                        "target": _function_start(val),
                        "evidence": "Caller %s passes %s" % (_function_name(caller_ea), _function_name(val)),
                    })
                    break
                for dref in idautils.DataRefsFrom(cur):
                    if _is_executable_function(dref):
                        candidates.append({
                            "caller_site": caller_ea,
                            "setup_ea": cur,
                            "target": _function_start(dref),
                            "evidence": "Caller %s passes %s" % (_function_name(caller_ea), _function_name(dref)),
                        })
                        break
    return candidates


def hunt_indirect_call_target(ea, deep=False):
    """Trace register and memory sources to resolve the target of an indirect call."""
    if not ida_ua or not hasattr(ida_ua, "decode_insn"):
        return None
    insn = ida_ua.insn_t()
    dec = ida_ua.decode_insn(insn, ea)
    if isinstance(dec, (int, float)) and dec <= 0:
        return None

    badaddr = getattr(idaapi, "BADADDR", 0xffffffffffffffff) if idaapi else 0xffffffffffffffff

    # Step 1: Check existing IDA CodeRefs and DataRefs
    if idautils:
        for cref in idautils.CodeRefsFrom(ea, 0):
            if _is_executable_function(cref):
                target = _function_start(cref)
                return {
                    "target": target,
                    "confidence": "high",
                    "evidence": "IDA code reference points to %s" % _function_name(target),
                }
        for dref in idautils.DataRefsFrom(ea):
            if _is_executable_function(dref):
                target = _function_start(dref)
                return {
                    "target": target,
                    "confidence": "high",
                    "evidence": "Data reference points to %s" % _function_name(target),
                }
            elif ida_bytes and hasattr(ida_bytes, "is_loaded") and ida_bytes.is_loaded(dref):
                ptr = _read_pointer(dref)
                if _is_executable_function(ptr):
                    target = _function_start(ptr)
                    return {
                        "target": target,
                        "confidence": "high",
                        "evidence": "Pointer at %s points to %s" % (_hex(dref), _function_name(target)),
                    }

    op = insn.ops[0]
    op_type = op.type

    # Step 2: Memory operand call [mem] or call [rip + disp]
    if op_type in (getattr(ida_ua, "o_mem", 2), getattr(ida_ua, "o_displ", 4), getattr(ida_ua, "o_phrase", 3)):
        target_mem = op.addr if op.addr != 0 else (idc.get_operand_value(ea, 0) if idc else 0)
        if target_mem and ida_bytes and hasattr(ida_bytes, "is_loaded") and ida_bytes.is_loaded(target_mem):
            ptr = _read_pointer(target_mem)
            if _is_executable_function(ptr):
                target = _function_start(ptr)
                return {
                    "target": target,
                    "confidence": "high",
                    "evidence": "Memory pointer [%s] -> %s" % (_hex(target_mem), _function_name(target)),
                }
            name = (idc.get_name(target_mem) if idc else "") or (idc.get_name(ptr) if idc else "")
            if name and not name.startswith("unk_"):
                return {
                    "target": ptr if _is_executable_function(ptr) else badaddr,
                    "confidence": "high",
                    "evidence": "Import / Global pointer [%s] -> %s" % (_hex(target_mem), name),
                }

    # Step 3: Register operand call reg (e.g. call r12, call rax)
    if op_type == getattr(ida_ua, "o_reg", 1):
        reg_name = idc.print_operand(ea, 0).strip() if idc else ""
        func = ida_funcs.get_func(ea) if ida_funcs else None
        if not func:
            return None
        start_ea = int(func.start_ea)
        cur_ea = int(ea)
        current_reg = reg_name
        slice_steps = []
        max_depth = 50 if deep else 30

        for _ in range(max_depth):
            cur_ea = idc.prev_head(cur_ea)
            if cur_ea == badaddr or cur_ea < start_ea:
                break
            cur_insn = ida_ua.insn_t()
            dec = ida_ua.decode_insn(cur_insn, cur_ea)
            if isinstance(dec, (int, float)) and dec <= 0:
                continue
            mnem = idc.print_insn_mnem(cur_ea).lower() if idc else ""
            op0_text = idc.print_operand(cur_ea, 0).lower().strip() if idc else ""
            op1_text = idc.print_operand(cur_ea, 1).lower().strip() if idc else ""

            if _reg_matches(op0_text, current_reg):
                disasm_line = idc.generate_disasm_line(cur_ea, 0) or idc.GetDisasm(cur_ea) if idc else ""
                slice_steps.append((cur_ea, disasm_line))

                # Case A: LEA reg, [target]
                if mnem == "lea":
                    op1 = cur_insn.ops[1]
                    val = op1.addr if op1.addr != 0 else (idc.get_operand_value(cur_ea, 1) if idc else 0)
                    if _is_executable_function(val):
                        return {
                            "target": _function_start(val),
                            "confidence": "high",
                            "evidence": "Static LEA address load at %s: %s" % (_hex(cur_ea), disasm_line),
                            "slice": slice_steps,
                        }
                    if idautils:
                        for dref in idautils.DataRefsFrom(cur_ea):
                            if _is_executable_function(dref):
                                return {
                                    "target": _function_start(dref),
                                    "confidence": "high",
                                    "evidence": "LEA target data reference to %s" % _function_name(dref),
                                    "slice": slice_steps,
                                }

                # Case B: MOV reg, imm / [mem] / other_reg
                elif mnem in ("mov", "movabs", "movsxd", "movzx"):
                    op1_type = idc.get_operand_type(cur_ea, 1) if idc else 0
                    val = idc.get_operand_value(cur_ea, 1) if idc else 0
                    if _is_executable_function(val):
                        return {
                            "target": _function_start(val),
                            "confidence": "high",
                            "evidence": "Constant function pointer loaded at %s: %s" % (_hex(cur_ea), disasm_line),
                            "slice": slice_steps,
                        }
                    if op1_type in (getattr(ida_ua, "o_mem", 2), getattr(ida_ua, "o_displ", 4)):
                        target_addr = cur_insn.ops[1].addr if cur_insn.ops[1].addr != 0 else val
                        if ida_bytes and hasattr(ida_bytes, "is_loaded") and ida_bytes.is_loaded(target_addr):
                            ptr = _read_pointer(target_addr)
                            if _is_executable_function(ptr):
                                return {
                                    "target": _function_start(ptr),
                                    "confidence": "high",
                                    "evidence": "Pointer loaded from %s -> %s" % (_hex(target_addr), _function_name(ptr)),
                                    "slice": slice_steps,
                                }
                    if op1_type == getattr(ida_ua, "o_reg", 1):
                        current_reg = op1_text
                        continue

                elif mnem in ("xor", "sub") and op0_text == op1_text:
                    break
                elif mnem == "call":
                    return {
                        "target": badaddr,
                        "confidence": "medium",
                        "evidence": "Return value from call at %s: %s" % (_hex(cur_ea), disasm_line),
                        "slice": slice_steps,
                    }
                else:
                    break

        # Check if current_reg is an incoming function argument
        arg_info = _check_argument_register(current_reg, func)
        if arg_info:
            caller_targets = _hunt_callers_for_argument(func.start_ea, arg_info["arg_index"])
            if caller_targets:
                first_target = caller_targets[0]["target"]
                evidence = "Passed as argument #%d (%s) across %d caller(s): %s" % (
                    arg_info["arg_index"] + 1,
                    current_reg,
                    len(caller_targets),
                    ", ".join(_function_name(t["target"]) for t in caller_targets[:3]),
                )
                return {
                    "target": first_target,
                    "confidence": "high" if len(caller_targets) == 1 else "medium",
                    "evidence": evidence,
                    "slice": slice_steps,
                    "candidates": caller_targets,
                }
            else:
                return {
                    "target": badaddr,
                    "confidence": "unresolved",
                    "evidence": "Passed as argument #%d (%s) from callers; no constant candidate found" % (arg_info["arg_index"] + 1, current_reg),
                    "slice": slice_steps,
                }

        if slice_steps:
            return {
                "target": badaddr,
                "confidence": "unresolved",
                "evidence": "Dynamic register assignment tracked (%d steps)" % len(slice_steps),
                "slice": slice_steps,
            }

    return None


def _row(kind, site, target=None, evidence="", confidence="high", detail="", slice=None, candidates=None):
    badaddr = getattr(idaapi, "BADADDR", 0xffffffffffffffff) if idaapi else 0xffffffffffffffff
    t_val = int(target) if target is not None else badaddr
    row_dict = {
        "kind": kind, "site": int(site), "target": t_val,
        "target_name": _function_name(t_val) if t_val != badaddr else "Unresolved",
        "owner": _owner(site), "evidence": evidence, "confidence": confidence, "detail": detail,
    }
    if slice:
        row_dict["slice"] = slice
    if candidates:
        row_dict["candidates"] = candidates
    return row_dict


def scan_address_taken_functions():
    rows = []
    if not idautils:
        return rows
    for func_ea in idautils.Functions():
        for xref in idautils.DataRefsTo(func_ea):
            if _is_executable_function(xref):
                detail = idc.generate_disasm_line(xref, 0) or idc.GetDisasm(xref) if idc else ""
                if detail:
                    if detail.strip().startswith("push "):
                        evidence = "Pushed function pointer"
                    else:
                        evidence = "Address-taken in code"
                    rows.append(_row("Address-taken", xref, func_ea, evidence, "high", detail))
            if len(rows) >= _MAX_POINTER_ROWS:
                return rows
        if ida_kernwin and hasattr(ida_kernwin, "user_cancelled") and ida_kernwin.user_cancelled():
            break
    return rows


def scan_dispatch_tables():
    rows = []
    if not idautils:
        return rows
    ptr_size = _pointer_size()
    for seg_ea in idautils.Segments():
        segment = ida_segment.getseg(seg_ea) if ida_segment else None
        perm_exec = getattr(ida_segment, "SEGPERM_EXEC", 1) if ida_segment else 1
        if not segment or (segment.perm & perm_exec):
            continue
        ea = (int(segment.start_ea) + ptr_size - 1) & ~(ptr_size - 1)
        current_table = []
        
        while ea + ptr_size <= segment.end_ea:
            if ida_kernwin and hasattr(ida_kernwin, "user_cancelled") and ida_kernwin.user_cancelled():
                return rows
                
            target = _read_pointer(ea)
            if _is_executable_function(target):
                current_table.append((ea, target))
            else:
                if len(current_table) >= 3:
                    table_start = current_table[0][0]
                    for entry_ea, entry_target in current_table:
                        rows.append(_row("Dispatch Table", entry_ea, entry_target, "Sequential dispatch table at %s" % _hex(table_start), "high", "Entry %d of %d" % (current_table.index((entry_ea, entry_target)) + 1, len(current_table))))
                current_table = []
                
            ea += ptr_size
            
        if len(current_table) >= 3:
            table_start = current_table[0][0]
            for entry_ea, entry_target in current_table:
                rows.append(_row("Dispatch Table", entry_ea, entry_target, "Sequential dispatch table at %s" % _hex(table_start), "high", "Entry %d of %d" % (current_table.index((entry_ea, entry_target)) + 1, len(current_table))))
                
    return rows


def scan_tls_callbacks():
    rows = []
    if not idautils:
        return rows
    for func_ea in idautils.Functions():
        name = idc.get_func_name(func_ea) if idc else ""
        if name and name.lower().startswith("tlscallback_"):
            rows.append(_row("TLS Callback", func_ea, func_ea, "IDA identified TLS Callback", "high", name))
    return rows


def _nearby_function_constants(call_ea, max_instructions=12):
    candidates = {}
    ea = int(call_ea)
    call_func = ida_funcs.get_func(call_ea) if ida_funcs else None
    badaddr = getattr(idaapi, "BADADDR", 0xffffffffffffffff) if idaapi else 0xffffffffffffffff
    call_start = int(call_func.start_ea) if call_func else badaddr
    for _index in range(max_instructions):
        ea = idc.prev_head(ea) if idc else badaddr
        current_func = ida_funcs.get_func(ea) if ida_funcs else None
        if ea in (badaddr, getattr(idc, "BADADDR", badaddr)) or not current_func or int(current_func.start_ea) != call_start:
            break
        for operand in range(3):
            operand_type = idc.get_operand_type(ea, operand) if idc else 0
            if operand_type in (getattr(ida_ua, "o_imm", 5), getattr(ida_ua, "o_mem", 2), getattr(ida_ua, "o_near", 7), getattr(ida_ua, "o_far", 6)):
                value = idc.get_operand_value(ea, operand) if idc else 0
                if _is_executable_function(value):
                    candidates[_function_start(value)] = ea
    return candidates


def scan_callback_registrations():
    rows = []
    if not idautils:
        return rows
    for api_ea, api_name in idautils.Names():
        normalized = normalize_api_name(api_name)
        if not _CALLBACK_API.search(normalized):
            continue
        callback_params = callback_parameters(normalized)
        generic_name_match = bool(re.search(r"(?:register.*callback|set.*handler|notify|subscribe)", normalized, re.I))
        if generic_name_match and not callback_params:
            continue
        semantic_detail = ""
        if callback_params:
            semantic_detail = "callback parameter(s): " + ", ".join(
                "%d:%s (%s)" % (param["index"], param["name"] or "unnamed", param["type"] or "unknown")
                for param in callback_params
            )
        for xref in idautils.XrefsTo(api_ea, 0):
            if xref.type not in (getattr(idaapi, "fl_CF", 16), getattr(idaapi, "fl_CN", 17)):
                continue
            candidates = _nearby_function_constants(xref.frm)
            if candidates:
                for target, setup_ea in candidates.items():
                    confidence = "high" if callback_params else "medium"
                    detail = "; ".join(value for value in ("setup at %s" % _hex(setup_ea), semantic_detail) if value)
                    rows.append(_row("Callback registration", xref.frm, target, "function address prepared before %s" % normalized, confidence, detail))
            else:
                rows.append(_row("Callback registration", xref.frm, evidence="call to %s; callback argument unresolved" % normalized, confidence="low", detail=semantic_detail))
    return rows


def scan_named_handlers():
    rows = []
    if not idautils:
        return rows
    for ea in idautils.Functions():
        name = idc.get_func_name(ea) if idc else ""
        if _HANDLER_NAME.search(name):
            rows.append(_row("Named handler", ea, ea, "handler/callback naming pattern", "high", name))
    return rows


def scan_switches():
    rows = []
    if not idautils:
        return rows
    ptr_size = _pointer_size()
    badaddr = getattr(idaapi, "BADADDR", 0xffffffffffffffff) if idaapi else 0xffffffffffffffff
    for func_ea in idautils.Functions():
        for ea in idautils.FuncItems(func_ea):
            switch = ida_nalt.get_switch_info(ea) if ida_nalt else None
            if not switch:
                continue
            jumps = int(getattr(switch, "jumps", badaddr))
            count = min(max(0, int(getattr(switch, "ncases", 0))), 65536)
            added = 0
            calculator = getattr(ida_nalt, "calc_switch_cases", None) or getattr(idaapi, "calc_switch_cases", None)
            if calculator:
                try:
                    case_info = calculator(ea, switch)
                    targets = list(getattr(case_info, "targets", []) or [])
                    cases = list(getattr(case_info, "cases", []) or [])
                    for index, target in enumerate(targets[:65536]):
                        case_values = list(cases[index]) if index < len(cases) else []
                        label = ", ".join(str(value) for value in case_values[:32]) or str(index)
                        rows.append(_row("Jump-table target", ea, _function_start(target) if _is_executable_function(target) else int(target), "IDA switch cases %s, table %s" % (label, _hex(jumps)), "high"))
                        added += 1
                except Exception:
                    added = 0
            if jumps != badaddr and count:
                for index in range(count if not added else 0):
                    entry = jumps + index * ptr_size
                    target = _read_pointer(entry)
                    if ida_bytes and hasattr(ida_bytes, "is_loaded") and ida_bytes.is_loaded(target):
                        rows.append(_row("Jump-table target", ea, _function_start(target) if _is_executable_function(target) else target, "IDA switch metadata; case %d, table %s" % (index, _hex(jumps)), "high", "entry %s" % _hex(entry)))
                        added += 1
            if not added:
                rows.append(_row("Jump table", ea, evidence="IDA switch metadata; %d cases at %s" % (count, _hex(jumps)), confidence="high"))
        if ida_kernwin and hasattr(ida_kernwin, "user_cancelled") and ida_kernwin.user_cancelled():
            break
    return rows


def scan_indirect_calls():
    rows = []
    if not idautils:
        return rows
    badaddr = getattr(idaapi, "BADADDR", 0xffffffffffffffff) if idaapi else 0xffffffffffffffff
    cf_call = getattr(idaapi, "CF_CALL", 0x10) if idaapi else 0x10

    for func_ea in idautils.Functions():
        for ea in idautils.FuncItems(func_ea):
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, ea) <= 0 or not (insn.get_canon_feature() & cf_call):
                continue
            op = insn.ops[0]
            if op.type not in (getattr(ida_ua, "o_reg", 1), getattr(ida_ua, "o_phrase", 3), getattr(ida_ua, "o_displ", 4)):
                continue

            detail = (idc.generate_disasm_line(ea, 0) if idc else "") or (idc.GetDisasm(ea) if idc else "")
            resolved = hunt_indirect_call_target(ea, deep=False)
            target = resolved.get("target", badaddr) if resolved else badaddr
            confidence = resolved.get("confidence", "unresolved") if resolved else "unresolved"
            evidence = resolved.get("evidence", "decoded call through register/memory operand") if resolved else "decoded call through register/memory operand"
            slice_steps = resolved.get("slice") if resolved else None
            candidates = resolved.get("candidates") if resolved else None

            rows.append(_row(
                "Indirect call", ea, target, evidence, confidence, detail,
                slice=slice_steps, candidates=candidates
            ))
            if len(rows) >= _MAX_INDIRECT_ROWS:
                return rows
        if ida_kernwin and hasattr(ida_kernwin, "user_cancelled") and ida_kernwin.user_cancelled():
            break
    return rows


def resolve_callbacks_and_dispatch():
    rows = []
    for scanner in (scan_indirect_calls, scan_address_taken_functions, scan_dispatch_tables, scan_tls_callbacks):
        rows.extend(scanner())
        if ida_kernwin and hasattr(ida_kernwin, "user_cancelled") and ida_kernwin.user_cancelled():
            break
    unique = {}
    for item in rows:
        key = (item["kind"], item["site"], item["target"], item["evidence"])
        unique[key] = item
    return sorted(unique.values(), key=lambda item: (item["kind"], item["site"], item["target"]))


class CallbackDispatchResolver(getattr(ida_kernwin, "PluginForm", object) if ida_kernwin else object):
    def __init__(self):
        super().__init__()
        self.rows = []

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        apply_mac_workspace(self.parent)
        root = QtWidgets.QVBoxLayout(self.parent)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)
        header = PageHeader("Indirect Call Explorer", "Dynamic indirect calls, function pointers, TLS callbacks, and dispatch tables")
        
        hunt = QtWidgets.QPushButton("Hunt Target")
        hunt.setProperty("pnVariant", "primary")
        hunt.setToolTip("Perform deep backward slicing and caller argument analysis on selected call")
        hunt.clicked.connect(self.hunt_selected)
        header.add_action(hunt)

        refresh = QtWidgets.QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        header.add_action(refresh)
        copy = QtWidgets.QPushButton("Copy Selected")
        copy.clicked.connect(self.copy_selected)
        header.add_action(copy)
        export = QtWidgets.QPushButton("Export CSV")
        export.clicked.connect(self.export_csv)
        header.add_action(export)
        root.addWidget(header)
        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("Filter by kind, address, target, function, evidence, or instruction…")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.apply_filter)
        root.addWidget(self.filter_edit)
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        table_card = Card()
        self.table = QtWidgets.QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["Kind", "Site", "Target", "Target name", "Containing function", "Confidence", "Evidence"])
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.itemSelectionChanged.connect(self.show_details)
        self.table.itemDoubleClicked.connect(self.navigate_selected)
        table_card.add_widget(self.table)
        splitter.addWidget(table_card)
        details_card = Card("Resolution evidence")
        self.details = QtWidgets.QTextBrowser()
        details_card.add_widget(self.details)
        splitter.addWidget(details_card)
        splitter.setSizes([1000, 400])
        root.addWidget(splitter, 1)
        self.status = QtWidgets.QLabel("Ready")
        self.status.setProperty("pnMuted", True)
        root.addWidget(self.status)
        QtCore.QTimer.singleShot(0, self.refresh)

    def refresh(self):
        if ida_kernwin and hasattr(ida_kernwin, "show_wait_box"):
            ida_kernwin.show_wait_box("Resolving callbacks and indirect dispatch…\nPress Cancel to stop safely.")
        try:
            self.rows = resolve_callbacks_and_dispatch()
        except Exception as exc:
            self.rows = []
            if ida_kernwin and hasattr(ida_kernwin, "warning"):
                ida_kernwin.warning("Callback Explorer failed:\n%s" % exc)
        finally:
            if ida_kernwin and hasattr(ida_kernwin, "hide_wait_box"):
                ida_kernwin.hide_wait_box()
        self.populate()

    def populate(self):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(max(1, len(self.rows)))
        if not self.rows:
            item = QtWidgets.QTableWidgetItem("No results found.")
            item.setFlags(QtCore.Qt.ItemIsEnabled)
            item.setTextAlignment(QtCore.Qt.AlignCenter)
            self.table.setItem(0, 0, item)
            self.table.setSpan(0, 0, 1, 7)
        else:
            self.table.clearSpans()
            badaddr = getattr(idaapi, "BADADDR", 0xffffffffffffffff) if idaapi else 0xffffffffffffffff
            for row_idx, row in enumerate(self.rows):
                values = [
                    row["kind"],
                    _hex(row["site"]),
                    _hex(row["target"]) if row["target"] != badaddr else "Unresolved",
                    row["target_name"],
                    row["owner"],
                    row["confidence"],
                    row["evidence"],
                ]
                for col_idx, value in enumerate(values):
                    item = QtWidgets.QTableWidgetItem(str(value))
                    item.setData(QtCore.Qt.UserRole, row_idx)
                    self.table.setItem(row_idx, col_idx, item)
        self.table.setSortingEnabled(True)
        self.status.setText("Total results: %d" % len(self.rows))

    def selected_row(self):
        selected = self.table.selectedItems()
        if not selected:
            return None
        item = self.table.item(selected[0].row(), 0)
        index = item.data(QtCore.Qt.UserRole) if item else None
        return self.rows[int(index)] if index is not None and 0 <= int(index) < len(self.rows) else None

    def apply_filter(self, text):
        if not getattr(self, "rows", None):
            return
        needle = str(text or "").strip().lower()
        for row in range(self.table.rowCount()):
            haystack = " ".join(self.table.item(row, col).text() for col in range(self.table.columnCount()) if self.table.item(row, col)).lower()
            source = self.rows[int(self.table.item(row, 0).data(QtCore.Qt.UserRole))]
            haystack += " " + source.get("detail", "").lower()
            self.table.setRowHidden(row, bool(needle and needle not in haystack))

    def show_details(self):
        row = self.selected_row()
        if not row:
            self.details.setPlainText("Select a result to inspect its resolution evidence.")
            return
        badaddr = getattr(idaapi, "BADADDR", 0xffffffffffffffff) if idaapi else 0xffffffffffffffff
        lines = [
            "Kind: %s" % row["kind"],
            "Site: %s" % _hex(row["site"]),
            "Containing function: %s" % row["owner"],
            "Target: %s %s" % (_hex(row["target"]) if row["target"] != badaddr else "Unresolved", row["target_name"]),
            "Confidence: %s" % row["confidence"],
            "\nEvidence: %s" % row["evidence"],
            "\nInstruction / detail:\n%s" % row.get("detail", ""),
        ]
        if row.get("slice"):
            lines.append("\nBackward Data-Flow Slice:")
            for s_ea, s_dis in row["slice"]:
                lines.append("  • %s: %s" % (_hex(s_ea), s_dis))
        if row.get("candidates"):
            lines.append("\nCaller Argument Candidates:")
            for c in row["candidates"]:
                lines.append("  • %s -> %s (at %s)" % (
                    _function_name(c["caller_site"]),
                    _function_name(c["target"]),
                    _hex(c.get("setup_ea", c["caller_site"])),
                ))
        self.details.setPlainText("\n".join(lines))

    def hunt_selected(self):
        row = self.selected_row()
        if not row:
            return
        site = row["site"]
        badaddr = getattr(idaapi, "BADADDR", 0xffffffffffffffff) if idaapi else 0xffffffffffffffff
        resolved = hunt_indirect_call_target(site, deep=True)
        if resolved and resolved.get("target") != badaddr:
            row["target"] = resolved["target"]
            row["target_name"] = _function_name(resolved["target"])
            row["confidence"] = resolved["confidence"]
            row["evidence"] = resolved["evidence"]
            if "slice" in resolved:
                row["slice"] = resolved["slice"]
            if "candidates" in resolved:
                row["candidates"] = resolved["candidates"]
            self.populate()
            self.show_details()
            self.status.setText("Resolved target: %s" % row["target_name"])

            if ida_kernwin and hasattr(ida_kernwin, "ask_yn") and hasattr(ida_kernwin, "jumpto"):
                msg = "Target resolved to %s (%s)!\n\nJump to this function now?" % (row["target_name"], _hex(row["target"]))
                if ida_kernwin.ask_yn(1, msg) == 1:
                    ida_kernwin.jumpto(row["target"])
        else:
            self.status.setText("Could not resolve target statically")
            if ida_kernwin and hasattr(ida_kernwin, "info"):
                ida_kernwin.info("Could not resolve static target for %s.\nThe value may be dynamic, vtable-computed, or passed at runtime." % _hex(site))

    def navigate_selected(self, *_args):
        row = self.selected_row()
        if row and ida_kernwin and hasattr(ida_kernwin, "jumpto"):
            badaddr = getattr(idaapi, "BADADDR", 0xffffffffffffffff) if idaapi else 0xffffffffffffffff
            target = row.get("target", badaddr)
            site = row.get("site", badaddr)
            dest = target if (target not in (badaddr, 0, None)) else site
            if dest != badaddr:
                ida_kernwin.jumpto(dest)

    def _csv_text(self, rows):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Kind", "Site", "Target", "Target name", "Containing function", "Confidence", "Evidence", "Detail"])
        badaddr = getattr(idaapi, "BADADDR", 0xffffffffffffffff) if idaapi else 0xffffffffffffffff
        for row in rows:
            writer.writerow([
                row["kind"], _hex(row["site"]),
                _hex(row["target"]) if row["target"] != badaddr else "",
                row["target_name"], row["owner"], row["confidence"], row["evidence"], row.get("detail", ""),
            ])
        return output.getvalue()

    def copy_selected(self):
        row = self.selected_row()
        if row:
            QtWidgets.QApplication.clipboard().setText(self._csv_text([row]))
            self.status.setText("Copied selected resolution")

    def export_csv(self):
        path, _selected = QtWidgets.QFileDialog.getSaveFileName(self.parent, "Export Callback Results", "callbacks.csv", "CSV files (*.csv)")
        if path:
            with open(path, "w", encoding="utf-8-sig", newline="") as handle:
                handle.write(self._csv_text(self.rows))
            self.status.setText("Exported %d results to %s" % (len(self.rows), os.path.basename(path)))

    def OnClose(self, form):
        global _resolver
        if _resolver is self:
            _resolver = None


def show_callback_dispatch_resolver():
    global _resolver
    if _resolver is None:
        _resolver = CallbackDispatchResolver()
    _resolver.Show("Genesect - Callback Explorer", options=ida_kernwin.PluginForm.WOPN_PERSIST)


if idaapi:
    class CallbackDispatchResolverHandler(idaapi.action_handler_t):
        def activate(self, ctx):
            show_callback_dispatch_resolver()
            return 1

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS
else:
    class CallbackDispatchResolverHandler(object):
        def activate(self, ctx):
            show_callback_dispatch_resolver()
            return 1

        def update(self, ctx):
            return 1
