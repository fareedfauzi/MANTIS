# -*- coding: utf-8 -*-
"""Best-effort structured IDB catalogs used by the AI workspace exporter.

All IDA modules are imported lazily so this module remains importable in the
ordinary unit-test runner.  Collectors deliberately tolerate missing APIs:
IDA has changed a number of type, fixup, and source-map interfaces between
releases, and one unavailable catalog must not make the workspace unusable.
"""

from __future__ import annotations

import os
import re


MAX_DATA_OBJECT_BYTES = 16 * 1024
MAX_SOURCE_ROWS = 200_000
MAX_UNDEFINED_RANGES = 50_000
MAX_POINTER_TABLES = 20_000


def _hex(value):
    return "0x%X" % int(value)


def _member(obj, name, default=None):
    value = getattr(obj, name, default)
    if callable(value):
        try:
            return value()
        except Exception:
            return default
    return value


def _int_address(value):
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return 0
    try:
        return int(value)
    except Exception:
        return 0


def _name(ea):
    try:
        import idc
        return str(idc.get_name(int(ea)) or "")
    except Exception:
        return ""


def _func_info(ea):
    try:
        import ida_funcs
        func = ida_funcs.get_func(int(ea))
        if func:
            start = int(func.start_ea)
            return _hex(start), str(ida_funcs.get_func_name(start) or "")
    except Exception:
        pass
    return "", ""


def collect_local_types():
    """Return ``(C header text, structured Local Types records)``."""
    import ida_typeinf

    til = ida_typeinf.get_idati()
    flags = (
        getattr(ida_typeinf, "PRTYPE_DEF", 0)
        | getattr(ida_typeinf, "PRTYPE_MULTI", 0)
        | getattr(ida_typeinf, "PRTYPE_TYPE", 0)
        | getattr(ida_typeinf, "PRTYPE_SEMI", 0)
    )
    try:
        limit = int(ida_typeinf.get_ordinal_limit(til))
    except Exception:
        limit = 0
    forward, declarations, records = [], [], []
    for ordinal in range(1, limit):
        try:
            name = ida_typeinf.get_numbered_type_name(til, ordinal)
            if not name:
                continue
            tif = ida_typeinf.tinfo_t()
            if not tif.get_numbered_type(til, ordinal):
                continue
            declaration = str(tif._print(name, flags) or "").strip()
            if not declaration:
                continue
            kind = "type"
            for predicate, label in (
                ("is_struct", "struct"), ("is_union", "union"),
                ("is_enum", "enum"), ("is_func", "function"),
                ("is_typeref", "typedef"),
            ):
                if bool(_member(tif, predicate, False)):
                    kind = label
                    break
            try:
                size = int(tif.get_size())
                if size < 0 or size > (1 << 60):
                    size = None
            except Exception:
                size = None
            if kind in ("struct", "union"):
                forward.append("%s %s;" % (kind, name))
            declarations.append(declaration.rstrip(";") + ";")
            records.append({
                "ordinal": ordinal, "name": str(name), "kind": kind,
                "size": size, "declaration": declaration,
            })
        except Exception:
            continue
    lines = [
        "/* Local Types recovered from the IDA database.",
        " * Declarations are printed by IDA and may contain compiler-specific annotations. */",
        "",
    ]
    if forward:
        lines.extend(["/* forward declarations */", *forward, ""])
    lines.extend(declarations or ["/* No Local Types were available in this database. */"])
    return "\n".join(lines) + "\n", records


def collect_applied_types(functions, global_records):
    """Collect address-level type applications for functions, globals, and names."""
    import idautils
    import idc

    records, seen = [], set()

    def add(ea, name, kind, declaration):
        declaration = str(declaration or "").strip()
        key = (int(ea), kind)
        if not declaration or key in seen:
            return
        seen.add(key)
        records.append({
            "address": _hex(ea), "name": str(name or ""),
            "kind": kind, "type": declaration,
        })

    for row in functions:
        ea = _int_address(row.get("ea", row.get("address", 0)))
        declared = row.get("prototype", "")
        if not declared:
            try:
                declared = idc.get_type(ea) or ""
            except Exception:
                declared = ""
        add(ea, row.get("name", ""), "function", declared)
    for row in global_records:
        add(_int_address(row.get("address", row.get("ea", 0))), row.get("name", ""), "global", row.get("type", ""))
    for ea, name in idautils.Names():
        try:
            declared = idc.get_type(int(ea)) or ""
        except Exception:
            declared = ""
        add(ea, name, "named_address", declared)
    return sorted(records, key=lambda item: (_int_address(item["address"]), item["kind"]))


def collect_xrefs():
    """Collect typed code and data references from every defined IDB item."""
    import ida_funcs
    import ida_xref
    import idaapi
    import idautils

    type_names = {}
    for name in ("fl_CF", "fl_CN", "fl_JF", "fl_JN", "fl_F", "dr_O", "dr_W", "dr_R", "dr_T", "dr_I"):
        value = getattr(ida_xref, name, getattr(idaapi, name, None))
        if value is not None:
            type_names[int(value)] = name
    rows, seen = [], set()
    for seg_ea in idautils.Segments():
        try:
            import ida_segment
            seg = ida_segment.getseg(seg_ea)
            if not seg:
                continue
            heads = idautils.Heads(int(seg.start_ea), int(seg.end_ea))
        except Exception:
            continue
        for source in heads:
            for xref in idautils.XrefsFrom(int(source), 0):
                target = int(xref.to)
                xtype = int(getattr(xref, "type", -1))
                key = (int(source), target, xtype)
                if key in seen:
                    continue
                seen.add(key)
                source_func, source_func_name = _func_info(source)
                target_func, target_func_name = _func_info(target)
                raw_kind = type_names.get(xtype, "type_%d" % xtype)
                category = "code" if raw_kind.startswith("fl_") else "data"
                access = {
                    "fl_CF": "call", "fl_CN": "call", "fl_JF": "jump", "fl_JN": "jump",
                    "fl_F": "flow", "dr_R": "read", "dr_W": "write", "dr_O": "offset",
                    "dr_T": "text", "dr_I": "informational",
                }.get(raw_kind, "reference")
                rows.append({
                    "source": _hex(source), "target": _hex(target),
                    "source_name": _name(source), "target_name": _name(target),
                    "source_function": source_func, "source_function_name": source_func_name,
                    "target_function": target_func, "target_function_name": target_func_name,
                    "category": category, "access": access, "ida_type": raw_kind,
                    "direct": raw_kind in ("fl_CF", "fl_CN", "fl_JF", "fl_JN", "fl_F"),
                    "user": bool(getattr(xref, "user", False)),
                })
    return rows


def collect_cfg(functions):
    """Return per-function basic blocks and directed CFG edges."""
    import ida_funcs
    import idaapi

    result = []
    for row in functions:
        ea = _int_address(row.get("ea", row.get("address", 0)))
        func = ida_funcs.get_func(ea)
        if not func:
            continue
        try:
            blocks = list(idaapi.FlowChart(func))
        except Exception:
            continue
        known_ids = {int(block.id) for block in blocks}
        block_rows, edges = [], []
        for block in blocks:
            block_id = int(block.id)
            predecessors = sorted({int(item.id) for item in block.preds()} & known_ids)
            successors = sorted({int(item.id) for item in block.succs()} & known_ids)
            block_rows.append({
                "id": block_id, "start": _hex(block.start_ea), "end": _hex(block.end_ea),
                "predecessors": predecessors, "successors": successors,
            })
            edges.extend({"source": block_id, "target": target} for target in successors)
        result.append({
            "function": _hex(ea), "name": str(row.get("name", "")),
            "blocks": block_rows, "edges": edges,
        })
    return result


_INIT_SEGMENT = re.compile(r"(?:\.init_array|\.preinit_array|\.fini_array|\.ctors|\.dtors|__mod_init_func|__mod_term_func|\.crt|xc[auz]|xl[auz])", re.I)
_TLS_NAME = re.compile(r"(?:tls.*callback|callback.*tls|__xl_[a-z]|_xl_[a-z]|\.crt\$xl)", re.I)
_START_NAME = re.compile(r"^(?:_?main|wmain|winmain|wwinmain|dllmain|driverentry|start|_start|moduleentry|service_main)$", re.I)


def collect_entrypoints():
    """Collect loader entries plus common TLS/constructor array targets."""
    import ida_bytes
    import ida_funcs
    import ida_ida
    import ida_segment
    import idaapi
    import idautils

    pointer_size = 8 if ida_ida.inf_is_64bit() else 4

    def read_pointer(ea):
        if not ida_bytes.is_loaded(ea):
            return idaapi.BADADDR
        return int(ida_bytes.get_qword(ea) if pointer_size == 8 else ida_bytes.get_dword(ea))

    def add(rows, category, ea, origin, ordinal="", evidence="", confidence="high"):
        func = ida_funcs.get_func(int(ea))
        target = int(func.start_ea) if func else int(ea)
        rows.append({
            "category": category, "address": _hex(target),
            "name": (ida_funcs.get_func_name(target) if func else _name(target)) or "entry_%X" % target,
            "origin": origin, "ordinal": str(ordinal) if ordinal not in (None, "") else "",
            "evidence": evidence, "confidence": confidence,
        })

    rows = []
    start_getter = getattr(ida_ida, "inf_get_start_ea", None)
    if start_getter:
        try:
            start_ea = int(start_getter())
            if start_ea != int(getattr(idaapi, "BADADDR", -1)):
                add(rows, "Executable entry", start_ea, "IDA start address", evidence="database executable start address")
        except Exception:
            pass
    for index, ordinal, ea, name in idautils.Entries():
        add(rows, "IDA entry/export", ea, "IDA entry table", ordinal, "entry index %s" % index)
    for ea, name in idautils.Names():
        text = str(name or "")
        if _TLS_NAME.search(text):
            target = read_pointer(int(ea))
            if ida_funcs.get_func(target):
                add(rows, "TLS callback", target, text, evidence="pointer at %s" % _hex(ea))
            elif ida_funcs.get_func(int(ea)):
                add(rows, "TLS callback", ea, "function symbol", evidence="TLS callback naming pattern", confidence="symbol-backed")
    for func_ea in idautils.Functions():
        name = ida_funcs.get_func_name(func_ea) or ""
        if _START_NAME.search(name):
            add(rows, "Named startup routine", func_ea, "function symbol", evidence="well-known entry name", confidence="symbol-backed")
    scanned = 0
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        seg_name = ida_segment.get_segm_name(seg) if seg else ""
        if not seg or not _INIT_SEGMENT.search(seg_name or ""):
            continue
        ea = (int(seg.start_ea) + pointer_size - 1) & ~(pointer_size - 1)
        while ea + pointer_size <= int(seg.end_ea) and scanned < 128 * 1024 * 1024:
            scanned += pointer_size
            target = read_pointer(ea)
            if ida_funcs.get_func(target):
                category = "Finalization array" if re.search(r"fini|dtor|term", seg_name, re.I) else "Initialization array"
                add(rows, category, target, seg_name, evidence="function pointer at %s" % _hex(ea), confidence="metadata-backed")
            ea += pointer_size
    unique = {(r["category"], r["address"], r["origin"]): r for r in rows}
    return sorted(unique.values(), key=lambda r: (r["category"], _int_address(r["address"]), r["name"].lower()))


def _location_text(variable, argument=False, result=False):
    if bool(_member(variable, "is_stk_var", False)):
        offset = _member(variable, "get_stkoff", None)
        if isinstance(offset, int):
            return "stack %s0x%X" % ("+" if offset >= 0 else "-", abs(offset))
        return "stack"
    location = _member(variable, "location", None) or _member(variable, "vloc", None)
    if location is not None:
        for method in ("dstr", "to_string"):
            rendered = _member(location, method, None)
            if rendered and "Swig Object" not in str(rendered) and "vdloc_t" not in str(rendered):
                return str(rendered)
    if result:
        return "return-value storage"
    if argument:
        return "argument storage"
    return "compiler-assigned storage"


def collect_function_variables(functions):
    """Collect Hex-Rays lvars and basic stack-frame sizes per function."""
    import ida_hexrays
    import idc

    records = []
    for row in functions:
        ea = _int_address(row.get("ea", row.get("address", 0)))
        frame_size = None
        try:
            frame_size = int(idc.get_frame_size(ea))
        except Exception:
            pass
        item = {
            "function": _hex(ea), "name": str(row.get("name", "")),
            "frame_size": frame_size, "variables": [], "decompilation_error": None,
        }
        try:
            cfunc = ida_hexrays.decompile(ea)
            if not cfunc:
                raise RuntimeError("Hex-Rays returned no cfunc")
            for index, variable in enumerate(cfunc.get_lvars()):
                argument = bool(_member(variable, "is_arg_var", False))
                result = bool(_member(variable, "is_result_var", False))
                name = str(_member(variable, "name", "") or "")
                type_value = _member(variable, "type", "")
                width = _member(variable, "width", None)
                item["variables"].append({
                    "index": index, "name": name or ("<return value>" if result else "<unnamed %d>" % (index + 1)),
                    "type": str(type_value or ""), "width": int(width) if isinstance(width, int) else None,
                    "location": _location_text(variable, argument, result),
                    "argument": argument, "result": result,
                    "user_name": bool(_member(variable, "has_user_name", False) or _member(variable, "is_user_name", False)),
                    "user_type": bool(_member(variable, "has_user_type", False) or _member(variable, "is_user_type", False)),
                })
        except Exception as exc:
            item["decompilation_error"] = str(exc)
        records.append(item)
    return records


def collect_data_objects(global_records):
    """Return selective global-data payloads as ``(metadata, bytes)`` pairs."""
    import ida_bytes
    import idc

    results = []
    for item in global_records:
        ea = _int_address(item.get("address", item.get("ea", 0)))
        size = max(0, int(item.get("size", 0) or 0))
        exported = min(size, MAX_DATA_OBJECT_BYTES)
        raw = ida_bytes.get_bytes(ea, exported) if exported else b""
        raw = bytes(raw or b"")
        decoded = None
        try:
            value = idc.get_strlit_contents(ea, max(1, min(size, MAX_DATA_OBJECT_BYTES)), idc.get_str_type(ea))
            if isinstance(value, bytes):
                decoded = value.decode("utf-8", "replace")
            elif value is not None:
                decoded = str(value)
        except Exception:
            pass
        metadata = {
            "address": _hex(ea), "name": str(item.get("name", "")), "type": str(item.get("type", "")),
            "size": size, "exported_size": len(raw), "truncated": size > len(raw),
            "loaded": len(raw) == exported, "decoded_string": decoded,
            "file": "data/%016X.bin" % ea if raw else None,
        }
        results.append((metadata, raw))
    return results


def collect_fixups():
    import ida_fixup
    import idaapi

    bad = int(getattr(idaapi, "BADADDR", (1 << 64) - 1))
    first = getattr(ida_fixup, "get_first_fixup_ea", None)
    next_fixup = getattr(ida_fixup, "get_next_fixup_ea", None)
    if not first or not next_fixup:
        return []
    rows, ea = [], int(first())
    while ea != bad:
        data = None
        try:
            data = ida_fixup.fixup_data_t()
            if not ida_fixup.get_fixup(data, ea):
                data = None
        except Exception:
            try:
                data = ida_fixup.get_fixup(ea)
            except Exception:
                data = None
        rows.append({
            "address": _hex(ea), "name": _name(ea),
            "type": int(getattr(data, "type", -1)) if data is not None else None,
            "selector": int(getattr(data, "sel", 0)) if data is not None else None,
            "offset": _hex(getattr(data, "off", 0)) if data is not None else None,
            "displacement": int(getattr(data, "displacement", 0)) if data is not None else None,
        })
        nxt = int(next_fixup(ea))
        if nxt == ea:
            break
        ea = nxt
    return rows


def collect_switches():
    import ida_nalt
    import ida_xref
    import idaapi
    import idautils

    getter = getattr(ida_nalt, "get_switch_info", None) or getattr(idaapi, "get_switch_info", None)
    calculator = getattr(ida_xref, "calc_switch_cases", None) or getattr(idaapi, "calc_switch_cases", None)
    if not getter:
        return []
    rows = []
    for func_ea in idautils.Functions():
        for ea in idautils.FuncItems(func_ea):
            try:
                switch = getter(ea)
            except TypeError:
                switch = None
            if not switch:
                continue
            record = {
                "address": _hex(ea), "function": _hex(func_ea), "function_name": _name(func_ea),
                "case_count": int(_member(switch, "get_ncases", 0) or getattr(switch, "ncases", 0) or 0),
                "jump_table": _hex(getattr(switch, "jumps", 0)) if getattr(switch, "jumps", 0) else None,
                "value_table": _hex(getattr(switch, "values", 0)) if getattr(switch, "values", 0) else None,
                "default": _hex(getattr(switch, "defjump", 0)) if getattr(switch, "defjump", 0) else None,
                "cases": [],
            }
            if calculator:
                try:
                    cases = calculator(ea, switch)
                    targets = list(getattr(cases, "targets", []))
                    values = list(getattr(cases, "cases", []))
                    for index, target in enumerate(targets):
                        raw_values = values[index] if index < len(values) else []
                        try:
                            rendered = [int(v) for v in raw_values]
                        except TypeError:
                            rendered = [int(raw_values)]
                        record["cases"].append({"values": rendered, "target": _hex(target)})
                except Exception:
                    pass
            rows.append(record)
    return rows


def collect_pointer_tables():
    """Find runs of at least three loaded pointers in non-code segments."""
    import ida_bytes
    import ida_ida
    import ida_segment
    import idautils

    pointer_size = 8 if ida_ida.inf_is_64bit() else 4

    def pointer_at(ea):
        if not ida_bytes.is_loaded(ea):
            return None
        value = int(ida_bytes.get_qword(ea) if pointer_size == 8 else ida_bytes.get_dword(ea))
        return value if ida_segment.getseg(value) else None

    tables = []
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg or int(getattr(seg, "type", -1)) == int(getattr(ida_segment, "SEG_CODE", 2)):
            continue
        slots = set()
        for head in idautils.Heads(int(seg.start_ea), int(seg.end_ea)):
            head = int(head)
            try:
                item_size = max(1, int(ida_bytes.get_item_size(head) or 1))
            except Exception:
                item_size = 1
            slot_count = max(1, min(item_size // pointer_size, 65_536))
            for index in range(slot_count):
                slots.add(head + (index * pointer_size))
        heads = sorted(slots)
        run = []
        for ea in heads:
            target = pointer_at(ea) if ea % pointer_size == 0 else None
            if target is not None and (not run or ea == run[-1][0] + pointer_size):
                run.append((ea, target))
                continue
            if len(run) >= 3:
                tables.append(run)
            run = [(ea, target)] if target is not None else []
            if len(tables) >= MAX_POINTER_TABLES:
                break
        if len(run) >= 3 and len(tables) < MAX_POINTER_TABLES:
            tables.append(run)
        if len(tables) >= MAX_POINTER_TABLES:
            break
    return [{
        "address": _hex(run[0][0]), "name": _name(run[0][0]), "count": len(run),
        "pointer_size": pointer_size,
        "entries": [{"slot": _hex(ea), "target": _hex(target), "target_name": _name(target)} for ea, target in run],
    } for run in tables]


def collect_analysis_gaps(functions, decompilation_failures=None):
    import ida_auto
    import ida_bytes
    import ida_segment
    import idautils

    undefined, truncated = [], False
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg:
            continue
        cursor = int(seg.start_ea)
        for head in idautils.Heads(int(seg.start_ea), int(seg.end_ea)):
            head = int(head)
            if head > cursor:
                undefined.append({"start": _hex(cursor), "end": _hex(head), "size": head - cursor,
                                  "segment": ida_segment.get_segm_name(seg) or ""})
                if len(undefined) >= MAX_UNDEFINED_RANGES:
                    truncated = True
                    break
            cursor = max(cursor, head + max(1, int(ida_bytes.get_item_size(head) or 1)))
        if truncated:
            break
        if cursor < int(seg.end_ea):
            undefined.append({"start": _hex(cursor), "end": _hex(seg.end_ea), "size": int(seg.end_ea) - cursor,
                              "segment": ida_segment.get_segm_name(seg) or ""})

    chunk_owners = {}
    for row in functions:
        ea = _int_address(row.get("ea", row.get("address", 0)))
        try:
            chunks = list(idautils.Chunks(ea))
        except Exception:
            chunks = []
        for start, end in chunks:
            chunk_owners.setdefault((int(start), int(end)), []).append(ea)
    shared = [{
        "start": _hex(start), "end": _hex(end),
        "owners": [_hex(owner) for owner in owners],
    } for (start, end), owners in chunk_owners.items() if len(owners) > 1]
    try:
        auto_ok = bool(ida_auto.auto_is_ok())
        auto_state = int(ida_auto.get_auto_state())
    except Exception:
        auto_ok, auto_state = None, None
    problems = []
    try:
        import ida_ida
        import ida_problems
        import idaapi
        minimum = int(ida_ida.inf_get_min_ea())
        bad = int(idaapi.BADADDR)
        for problem_type in range(int(getattr(ida_problems, "PR_END", 0))):
            cursor = minimum
            while True:
                ea = int(ida_problems.get_problem(problem_type, cursor))
                if ea == bad or ea < cursor:
                    break
                problems.append({
                    "address": _hex(ea), "type": problem_type,
                    "name": str(ida_problems.get_problem_name(problem_type, True) or ""),
                    "description": str(ida_problems.get_problem_desc(problem_type, ea) or ""),
                })
                cursor = ea + 1
    except Exception:
        pass
    failures = decompilation_failures or []
    return {
        "autoanalysis_complete": auto_ok, "autoanalysis_state": auto_state,
        "decompilation_failures": failures,
        "undefined_ranges": undefined, "undefined_ranges_truncated": truncated,
        "shared_function_chunks": shared,
        "ida_problems": problems,
    }


def collect_source_map():
    """Collect source line mappings and symbol-name provenance where IDA exposes it."""
    import ida_bytes
    import ida_lines
    import ida_name
    import ida_nalt
    import ida_segment
    import idautils

    lines, symbols, truncated = [], [], False
    get_source = getattr(ida_lines, "get_sourcefile", None) or getattr(ida_nalt, "get_sourcefile", None)
    get_line = getattr(ida_nalt, "get_source_linnum", None)
    if get_source:
        seen = set()
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if not seg:
                continue
            for ea in idautils.Heads(int(seg.start_ea), int(seg.end_ea)):
                try:
                    source = get_source(ea) or ""
                    line = int(get_line(ea)) if get_line else 0
                except Exception:
                    continue
                if not source:
                    continue
                key = (int(ea), str(source), line)
                if key in seen:
                    continue
                seen.add(key)
                lines.append({"address": _hex(ea), "file": str(source), "line": line or None})
                if len(lines) >= MAX_SOURCE_ROWS:
                    truncated = True
                    break
            if truncated:
                break
    for ea, name in idautils.Names():
        try:
            flags = int(ida_bytes.get_full_flags(int(ea)))
        except Exception:
            flags = 0
        provenance = []
        for predicate, label in (
            ("has_user_name", "user"), ("has_auto_name", "auto"),
            ("has_dummy_name", "dummy"),
        ):
            method = getattr(ida_bytes, predicate, None)
            try:
                if method and method(flags):
                    provenance.append(label)
            except Exception:
                pass
        for predicate, label in (("is_public_name", "public"), ("is_weak_name", "weak")):
            method = getattr(ida_name, predicate, None)
            try:
                if method and method(int(ea)):
                    provenance.append(label)
            except Exception:
                pass
        symbols.append({"address": _hex(ea), "name": str(name), "provenance": provenance or ["unknown"]})
    try:
        debug_names = ida_name.get_debug_names()
        iterator = debug_names.items() if hasattr(debug_names, "items") else debug_names
        known = {(item["address"], item["name"]) for item in symbols}
        for ea, name in iterator:
            item = {"address": _hex(ea), "name": str(name), "provenance": ["debug"]}
            if (item["address"], item["name"]) not in known:
                symbols.append(item)
    except Exception:
        pass
    return {"source_lines": lines, "source_lines_truncated": truncated, "symbols": symbols}
