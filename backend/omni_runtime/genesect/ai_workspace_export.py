# -*- coding: utf-8 -*-
"""Export an AI-readable workspace from the current IDB."""

from __future__ import annotations

import csv
import html
import json
import os
import re
import subprocess
import sys
import time

try:
    import ida_auto
    import ida_funcs
    import ida_hexrays
    import ida_kernwin
    import ida_lines
    import ida_nalt
    import ida_segment
    import idaapi
    import idautils
    import idc
except ImportError:
    ida_auto = None
    ida_funcs = None
    ida_hexrays = None
    ida_kernwin = None
    ida_lines = None
    ida_nalt = None
    ida_segment = None
    idaapi = None
    idautils = None
    idc = None

from genesect.qt_compat import QtCore, QtWidgets
from genesect.ai_skill_pack import write_skill_pack


_WORKSPACE_COMPANION_FILES = ("run_analysis.md", "render_report.py", "dump_ai_workspace.py", "find_ida.py", "find_ilspycmd.py")


def _plain(value):
    try:
        if ida_lines and hasattr(ida_lines, "tag_remove"):
            return ida_lines.tag_remove(str(value or ""))
    except Exception:
        pass
    return str(value or "")


def _hex(ea):
    return "0x%X" % int(ea)


def _win_path(path):
    """Normalize path and apply Windows extended-length prefix (\\?\\) to bypass MAX_PATH (260)."""
    if not path or not isinstance(path, str):
        return path
    if os.name != "nt":
        return path
    norm = os.path.normpath(os.path.abspath(path))
    if norm.startswith("\\\\?\\"):
        return norm
    if norm.startswith("\\\\"):
        return "\\\\?\\UNC\\" + norm[2:]
    return "\\\\?\\" + norm


def _safe_filename(value, fallback="item", limit=60):
    text = _plain(value).strip() or fallback
    text = re.sub(r"[<>:\"/\\|?*\x00-\x1f]+", "_", text)
    text = re.sub(r"\s+", "_", text)
    text = re.sub(r"_+", "_", text)
    text = text.strip("._ ")
    if not text:
        text = fallback
    text = text[:limit].rstrip("._ ")
    return text or fallback


def _short_label(value, limit=90):
    text = _plain(value).strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _ensure_dir(path):
    wpath = _win_path(path)
    if not os.path.isdir(wpath):
        os.makedirs(wpath, exist_ok=True)


def _write_text(path, text):
    parent = os.path.dirname(path)
    if parent:
        _ensure_dir(parent)
    with open(_win_path(path), "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def _write_csv(path, headers, rows):
    parent = os.path.dirname(path)
    if parent:
        _ensure_dir(parent)
    with open(_win_path(path), "w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t" if path.lower().endswith(".tsv") else ",")
        writer.writerow(headers)
        writer.writerows(rows)


def _write_json(path, data):
    parent = os.path.dirname(path)
    if parent:
        _ensure_dir(parent)
    with open(_win_path(path), "w", encoding="utf-8", newline="\n") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False, sort_keys=True)


def _write_bytes(path, data):
    parent = os.path.dirname(path)
    if parent:
        _ensure_dir(parent)
    with open(_win_path(path), "wb") as handle:
        handle.write(bytes(data))


def _write_workspace_companion_files(output_root):
    """Copy the self-contained analysis prompt and report renderer into an export."""
    template_root = os.path.join(os.path.dirname(__file__), "workspace_templates")
    written = []
    for name in _WORKSPACE_COMPANION_FILES:
        source = os.path.join(template_root, name)
        with open(_win_path(source), "r", encoding="utf-8") as handle:
            content = handle.read()
        if name == "dump_ai_workspace.py":
            content = content.replace('"__ENGINE_ROOT__"', json.dumps(os.path.dirname(os.path.dirname(__file__))))
        _write_text(os.path.join(output_root, name), content)
        written.append(name)
    return written


def _input_basename():
    name = ""
    try:
        if idc and hasattr(idc, "get_root_filename"):
            name = idc.get_root_filename() or ""
    except Exception:
        pass
    if not name:
        try:
            if idc and hasattr(idc, "get_input_file_path"):
                name = os.path.basename(idc.get_input_file_path() or "")
        except Exception:
            pass
    return _safe_filename(name, "idb", limit=60)


def _default_parent_dir():
    for getter in (
        lambda: os.path.dirname(idc.get_idb_path()) if idc else "",
        lambda: os.path.dirname(idc.get_input_file_path()) if idc else "",
        lambda: os.getcwd(),
    ):
        try:
            path = getter()
            if path and os.path.isdir(path):
                return path
        except Exception:
            continue
    return os.getcwd()


def _default_output_root():
    return os.path.normpath(os.path.join(_default_parent_dir(), "%s_genesect_ai_workspace" % _input_basename()))


def _normalize_workspace_folder(path):
    if not path:
        return ""
    norm = os.path.normpath(path)
    base = os.path.basename(norm).lower()
    if base.endswith("_genesect_ai_workspace") or base == "genesect_ai_workspace":
        return norm
    return os.path.normpath(os.path.join(norm, "%s_genesect_ai_workspace" % _input_basename()))


def _selected_output_root(parent=None):
    selected = QtWidgets.QFileDialog.getExistingDirectory(
        parent,
        "Choose AI Workspace Export Location",
        _default_parent_dir(),
    )
    if not selected:
        return ""
    return _normalize_workspace_folder(selected)


def _function_rows():
    rows = []
    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        if not func:
            continue
        flags = int(getattr(func, "flags", 0))
        rows.append({
            "ea": int(func.start_ea),
            "end_ea": int(func.end_ea),
            "size": max(0, int(func.end_ea) - int(func.start_ea)),
            "name": ida_funcs.get_func_name(func.start_ea) or idc.get_func_name(func.start_ea) or "",
            "is_library": bool(flags & getattr(ida_funcs, "FUNC_LIB", 0)),
            "is_thunk": bool(flags & getattr(ida_funcs, "FUNC_THUNK", 0)),
            "comment": ida_funcs.get_func_cmt(func, True) or ida_funcs.get_func_cmt(func, False) or "",
        })
    return sorted(rows, key=lambda row: row["ea"])


def _xref_function(frm):
    func = ida_funcs.get_func(int(frm))
    return int(func.start_ea) if func else idaapi.BADADDR


def _callgraph_for_functions(functions, progress=None):
    function_eas = {row["ea"] for row in functions}
    names = {row["ea"]: row["name"] for row in functions}
    edges = set()
    callers = {row["ea"]: set() for row in functions}
    callees = {row["ea"]: set() for row in functions}
    total = len(functions)
    for index, row in enumerate(functions, 1):
        src = row["ea"]
        if progress is not None:
            progress.step("Collecting callgraph %d/%d: %s" % (index, total, _short_label(row["name"])))
        for item_ea in idautils.FuncItems(src):
            for xref in idautils.XrefsFrom(item_ea, 0):
                dst = _xref_function(xref.to)
                if dst == idaapi.BADADDR or dst not in function_eas or dst == src:
                    continue
                edge = (src, dst)
                if edge in edges:
                    continue
                edges.add(edge)
                callees[src].add(dst)
                callers[dst].add(src)
    edge_rows = [
        [_hex(src), names.get(src, ""), _hex(dst), names.get(dst, "")]
        for src, dst in sorted(edges)
    ]
    return callers, callees, edge_rows


def _disassembly_for_function(ea):
    lines = []
    for item_ea in idautils.FuncItems(ea):
        try:
            line = _plain(idc.generate_disasm_line(item_ea, 0))
        except Exception:
            line = ""
        if line:
            lines.append("%s  %s" % (_hex(item_ea), line))
    return "\n".join(lines) + ("\n" if lines else "")


def _decompile_function(ea):
    try:
        cfunc = ida_hexrays.decompile(ea)
        if cfunc:
            return _plain(str(cfunc))
    except Exception as exc:
        return "/* Hex-Rays decompilation failed for %s: %s */\n" % (_hex(ea), exc)
    return "/* Hex-Rays decompilation unavailable for %s */\n" % _hex(ea)


def _collect_strings():
    rows = []
    try:
        strings = idautils.Strings()
        strings.setup(strtypes=getattr(idautils.Strings, "STR_C", 0))
    except Exception:
        strings = idautils.Strings()
    for item in strings:
        try:
            rows.append([_hex(int(item.ea)), str(item)])
        except Exception:
            continue
    return rows


def _collect_imports():
    rows = []
    try:
        qty = int(idaapi.get_import_module_qty())
    except Exception:
        qty = 0
    for index in range(qty):
        module = str(idaapi.get_import_module_name(index) or "")

        def collect(ea, name, ordinal, module_name=module):
            rows.append([module_name, _hex(int(ea)), str(name or ""), str(ordinal or "")])
            return True

        try:
            idaapi.enum_import_names(index, collect)
        except Exception:
            continue
    return rows


def _collect_exports():
    rows = []
    try:
        for index, ordinal, ea, name in idautils.Entries():
            rows.append([str(index), str(ordinal), _hex(int(ea)), str(name or "")])
    except Exception:
        pass
    return rows


def _collect_segments():
    rows = []
    for start_ea in idautils.Segments():
        seg = ida_segment.getseg(start_ea)
        if not seg:
            continue
        rows.append([
            ida_segment.get_segm_name(seg) or "",
            _hex(int(seg.start_ea)),
            _hex(int(seg.end_ea)),
            str(int(seg.perm)),
            str(int(seg.type)),
        ])
    return rows


def _collect_named_addresses():
    rows = []
    try:
        names = idautils.Names()
    except Exception:
        names = []
    for ea, name in names:
        rows.append([_hex(int(ea)), _plain(name)])

    return rows


def _global_records(rows, imported_eas=None):
    """Normalize Global Variable Explorer rows for portable JSON/TSV export."""
    imported_eas = set(imported_eas or ())
    records = []
    for row in rows or []:
        try:
            ea = int(row.get("ea", 0))
        except Exception:
            continue
        if ea in imported_eas:
            continue

        def xrefs(items):
            result = []
            for item in items or []:
                try:
                    address = _hex(int(item.get("ea", 0)))
                except Exception:
                    continue
                result.append({
                    "address": address,
                    "function": str(item.get("function") or ""),
                })
            return result

        reads = xrefs(row.get("reads"))
        writes = xrefs(row.get("writes"))
        references = xrefs(row.get("references"))
        records.append({
            "address": _hex(ea),
            "name": str(row.get("name") or "global_%X" % ea),
            "segment": str(row.get("segment") or ""),
            "type": str(row.get("type") or ""),
            "size": max(1, int(row.get("size") or 1)),
            "initial_value": str(row.get("initial") or ""),
            "aliases": [str(value) for value in row.get("aliases", []) if value],
            "reads": reads,
            "writes": writes,
            "references": references,
            "referencing_functions": [str(value) for value in row.get("functions", []) if value],
        })
    return records


def _collect_globals(import_rows=None):
    from genesect.global_explorer import scan_globals

    imported_eas = set()
    for row in import_rows or []:
        try:
            imported_eas.add(int(row[1], 16))
        except Exception:
            continue
    return _global_records(scan_globals(), imported_eas)


def _write_globals(output_root, records):
    def refs_text(items):
        return "; ".join(
            "%s%s" % (item["address"], " @ " + item["function"] if item.get("function") else "")
            for item in items
        )

    _write_csv(
        os.path.join(output_root, "globals.tsv"),
        [
            "address", "name", "segment", "type", "size", "initial_value", "aliases",
            "reads", "writes", "references", "referencing_functions",
        ],
        [[
            record["address"], record["name"], record["segment"], record["type"], record["size"],
            record["initial_value"], "; ".join(record["aliases"]), refs_text(record["reads"]),
            refs_text(record["writes"]), refs_text(record["references"]),
            "; ".join(record["referencing_functions"]),
        ] for record in records],
    )
    _write_json(os.path.join(output_root, "catalog", "globals.json"), {
        "total": len(records),
        "globals": records,
    })


def _export_advanced_catalogs(output_root, functions, global_records, decomp_by_ea, counts, progress):
    """Write advanced IDB catalogs without allowing one collector to abort export."""
    from genesect import advanced_workspace_export as advanced

    def attempt(key, label, collector, writer):
        progress.step(label)
        try:
            value = collector()
            writer(value)
            return value
        except Exception as exc:
            counts[key + "_error"] = str(exc)
            _write_text(os.path.join(output_root, "%s.error.txt" % key), str(exc) + "\n")
            return None

    def write_types(value):
        header, records, applications = value
        _write_text(os.path.join(output_root, "headers", "local_types.h"), header)
        _write_json(os.path.join(output_root, "catalog", "types.json"), {
            "total": len(records), "application_count": len(applications),
            "types": records, "applications": applications,
        })
        counts["types"] = len(records)
        counts["type_applications"] = len(applications)

    attempt(
        "types", "Writing Local Types catalog...",
        lambda: (*advanced.collect_local_types(), advanced.collect_applied_types(functions, global_records)),
        write_types,
    )

    def write_xrefs(records):
        headers = [
            "source", "target", "source_name", "target_name", "source_function",
            "source_function_name", "target_function", "target_function_name",
            "category", "access", "ida_type", "direct", "user",
        ]
        _write_csv(os.path.join(output_root, "xrefs.tsv"), headers, [
            [record.get(header, "") for header in headers] for record in records
        ])
        by_access = {}
        for record in records:
            access = record.get("access", "reference")
            by_access[access] = by_access.get(access, 0) + 1
        _write_json(os.path.join(output_root, "catalog", "xrefs.json"), {
            "total": len(records), "by_access": by_access,
            "records_file": "../xrefs.tsv",
        })
        counts["xrefs"] = len(records)

    attempt("xrefs", "Writing complete xref catalog...", advanced.collect_xrefs, write_xrefs)

    def write_cfg(records):
        index = []
        for record in records:
            ea = int(record["function"], 0)
            rel = "functions/cfg/%016X.json" % ea
            _write_json(os.path.join(output_root, rel.replace("/", os.sep)), record)
            index.append({
                "function": record["function"], "name": record.get("name", ""),
                "blocks": len(record.get("blocks", [])), "file": rel,
            })
        _write_json(os.path.join(output_root, "catalog", "cfg.json"), {
            "functions": len(index), "index": index,
        })
        counts["cfg_functions"] = len(index)
        counts["basic_blocks"] = sum(item["blocks"] for item in index)

    attempt("cfg", "Writing control-flow graphs...", lambda: advanced.collect_cfg(functions), write_cfg)

    def write_entrypoints(records):
        _write_json(os.path.join(output_root, "catalog", "entrypoints.json"), {
            "total": len(records), "entrypoints": records,
        })
        counts["entrypoints"] = len(records)

    attempt("entrypoints", "Writing entrypoint and initializer catalog...", advanced.collect_entrypoints, write_entrypoints)

    def write_variables(records):
        index = []
        variable_count = 0
        for record in records:
            ea = int(record["function"], 0)
            rel = "functions/variables/%016X.json" % ea
            _write_json(os.path.join(output_root, rel.replace("/", os.sep)), record)
            variable_count += len(record.get("variables", []))
            index.append({
                "function": record["function"], "name": record.get("name", ""),
                "variables": len(record.get("variables", [])),
                "decompilation_error": record.get("decompilation_error"), "file": rel,
            })
        _write_json(os.path.join(output_root, "catalog", "function_variables.json"), {
            "functions": len(index), "variables": variable_count, "index": index,
        })
        counts["function_variables"] = variable_count

    attempt("function_variables", "Writing function variables and stack frames...", lambda: advanced.collect_function_variables(functions), write_variables)

    def write_data_objects(pairs):
        records = []
        total_bytes = 0
        for record, raw in pairs:
            if raw and record.get("file"):
                _write_bytes(os.path.join(output_root, record["file"].replace("/", os.sep)), raw)
                total_bytes += len(raw)
            records.append(record)
        _write_json(os.path.join(output_root, "catalog", "data_objects.json"), {
            "total": len(records), "byte_cap_per_object": advanced.MAX_DATA_OBJECT_BYTES,
            "objects": records,
        })
        counts["data_objects"] = len(records)
        counts["data_object_bytes"] = total_bytes

    attempt("data_objects", "Writing selective global-data payloads...", lambda: advanced.collect_data_objects(global_records), write_data_objects)

    attempt(
        "fixups", "Writing relocations and fixups...", advanced.collect_fixups,
        lambda records: (
            _write_json(os.path.join(output_root, "catalog", "fixups.json"), {"total": len(records), "fixups": records}),
            counts.__setitem__("fixups", len(records)),
        ),
    )
    attempt(
        "switches", "Writing switch tables...", advanced.collect_switches,
        lambda records: (
            _write_json(os.path.join(output_root, "catalog", "switches.json"), {"total": len(records), "switches": records}),
            counts.__setitem__("switches", len(records)),
        ),
    )
    attempt(
        "pointer_tables", "Writing pointer tables...", advanced.collect_pointer_tables,
        lambda records: (
            _write_json(os.path.join(output_root, "catalog", "pointer_tables.json"), {"total": len(records), "tables": records}),
            counts.__setitem__("pointer_tables", len(records)),
        ),
    )

    failures = []
    for ea, text in decomp_by_ea.items():
        if "decompilation failed" in text.lower() or "decompilation unavailable" in text.lower():
            failures.append({"function": _hex(ea), "name": ida_funcs.get_func_name(ea) or "", "reason": text.strip("/* \n")[:1000]})
    def write_analysis_gaps(value):
        _write_json(os.path.join(output_root, "catalog", "analysis_gaps.json"), value)
        counts["decompilation_failures"] = len(value.get("decompilation_failures", []))
        counts["undefined_ranges"] = len(value.get("undefined_ranges", []))
        counts["ida_problems"] = len(value.get("ida_problems", []))

    attempt(
        "analysis_gaps", "Writing analysis-quality and gap catalog...",
        lambda: advanced.collect_analysis_gaps(functions, failures),
        write_analysis_gaps,
    )

    def write_source_map(value):
        _write_json(os.path.join(output_root, "catalog", "source_map.json"), value)
        counts["source_lines"] = len(value.get("source_lines", []))
        counts["symbols"] = len(value.get("symbols", []))

    attempt(
        "source_map", "Writing source mappings and symbol provenance...",
        advanced.collect_source_map,
        write_source_map,
    )


def _analyze_function_classify(row, decomp_text, strings_by_ea, import_by_ea, import_names, callers_map, callees_map):
    import genesect.classify as cl

    ea = row["ea"]
    string_eas = []
    seen_strings = set()
    imports_called = []
    seen_imports = set()

    def note_import(name: str) -> None:
        if name and name not in seen_imports:
            seen_imports.add(name)
            imports_called.append(name)

    if idautils:
        try:
            for item in idautils.FuncItems(ea):
                for dst in idautils.CodeRefsFrom(item, False):
                    dst_int = int(dst)
                    if dst_int in import_by_ea:
                        note_import(cl.normalize_import(import_by_ea[dst_int]))
                    elif ida_funcs:
                        target = ida_funcs.get_func(dst_int)
                        if target and (int(getattr(target, "flags", 0)) & (getattr(ida_funcs, "FUNC_THUNK", 0) | getattr(ida_funcs, "FUNC_LIB", 0))):
                            tname = cl.normalize_import(ida_funcs.get_func_name(dst_int) or "")
                            if tname.lower() in import_names:
                                note_import(tname)
                for dst in idautils.DataRefsFrom(item):
                    dst_int = int(dst)
                    if dst_int in strings_by_ea:
                        if dst_int not in seen_strings:
                            seen_strings.add(dst_int)
                            string_eas.append(dst_int)
                    elif dst_int in import_by_ea:
                        note_import(cl.normalize_import(import_by_ea[dst_int]))
        except Exception:
            pass

    strings = [strings_by_ea[s] for s in string_eas if s in strings_by_ea]
    signals = cl.scan_function_text(decomp_text)
    capabilities = []
    for name in imports_called:
        for cap in cl.capabilities_of_import(name):
            if cap not in capabilities:
                capabilities.append(cap)
    capabilities.sort(key=cl.CAPABILITY_ORDER.index)
    scores, reasons = cl.score_modules(imports_called, strings, signals)
    string_categories = sorted({c for s in strings for c in cl.classify_string(s)})
    triage_score, triage = cl.triage_signals(capabilities, signals, string_categories)

    header = []
    for line in (decomp_text or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("{"):
            break
        header.append(stripped)
        if len(header) > 6:
            break
    prototype = " ".join(header).rstrip(";") if header else ""

    return {
        **row,
        "callees": sorted(callees_map.get(ea, set())),
        "callers": sorted(callers_map.get(ea, set())),
        "string_eas": string_eas,
        "strings": strings,
        "string_categories": string_categories,
        "imports_called": imports_called,
        "capabilities": capabilities,
        "signals": signals,
        "scores": scores,
        "reasons": reasons,
        "prototype": prototype,
        "triage_score": triage_score,
        "triage": triage,
    }


def _export_behavioral_modules_and_catalog(
    output_root,
    functions,
    decomp_by_ea,
    disasm_by_ea,
    string_rows,
    import_rows,
    export_rows,
    segment_rows,
    callers,
    callees,
    edge_rows,
    counts,
    progress=None,
):
    from collections import Counter, defaultdict
    import genesect.classify as cl

    strings_by_ea = {}
    for r in string_rows:
        try:
            strings_by_ea[int(r[0], 16)] = str(r[1])
        except Exception:
            continue

    import_by_ea = {}
    import_names = set()
    for r in import_rows:
        try:
            ea_int = int(r[1], 16)
            name_str = str(r[2])
            import_by_ea[ea_int] = name_str
            import_names.add(cl.normalize_import(name_str).lower())
        except Exception:
            continue

    export_eas = set()
    for r in export_rows:
        try:
            export_eas.add(int(r[2], 16))
        except Exception:
            continue

    entry_ea = -1
    if idaapi and hasattr(idaapi, "get_entry"):
        try:
            entry_ea = int(idaapi.get_entry(idaapi.get_entry_ordinal(0)))
        except Exception:
            entry_ea = -1

    analyzed = []
    for index, row in enumerate(functions, 1):
        decomp_text = decomp_by_ea.get(row["ea"], "")
        analyzed.append(
            _analyze_function_classify(
                row, decomp_text, strings_by_ea, import_by_ea, import_names, callers, callees
            )
        )

    # Module assignment
    modules = {}
    reasons = {}
    fixed = set()
    for fn in analyzed:
        ea = fn["ea"]
        is_entry = ea == entry_ea or bool(cl.ENTRY_NAME_RE.match(fn["name"]))
        if is_entry:
            modules[ea] = cl.MODULE_ENTRY
            reasons[ea] = ["entry point or C runtime start-up"]
            fixed.add(ea)
        elif fn["is_library"] or fn["is_thunk"]:
            modules[ea] = cl.MODULE_LIBRARY
            reasons[ea] = ["library code" if fn["is_library"] else "thunk"]
            fixed.add(ea)
        else:
            module = cl.choose_module(fn["scores"])
            modules[ea] = module
            if module:
                reasons[ea] = fn["reasons"].get(module, [])

    callers_map = {fn["ea"]: set(fn["callers"]) for fn in analyzed}
    callees_map = {fn["ea"]: set(fn["callees"]) for fn in analyzed}
    propagated = cl.propagate_modules(modules, callers_map, callees_map, fixed=fixed)

    for fn in analyzed:
        ea = fn["ea"]
        module = propagated.get(ea)
        if module is None:
            module = cl.MODULE_UTILITY
        elif modules.get(ea) is None:
            reasons[ea] = ["call-graph neighbours are %s" % module.split("_", 1)[1].replace("_", " ")]
        fn["module"] = module
        fn["module_reasons"] = reasons.get(ea, [])
        fn["flags"] = [
            label for label, on in (
                ("entry point", ea == entry_ea), ("exported", ea in export_eas),
                ("library", fn["is_library"]), ("thunk", fn["is_thunk"]),
            ) if on
        ]

    cl.assign_layout(analyzed)
    names = {fn["ea"]: fn["name"] for fn in analyzed}

    # Headers
    signatures = ["/* Function prototypes recovered by IDA / Hex-Rays. */", ""]
    for fn in analyzed:
        if fn.get("prototype"):
            signatures.append("/* 0x%X - modules/%s */" % (fn["ea"], fn["dir"]))
            signatures.append(fn["prototype"] + ";")
    _write_text(os.path.join(output_root, "headers", "signatures.h"), "\n".join(signatures) + "\n")

    # Per-function modules files
    for fn in analyzed:
        base = os.path.join(output_root, "modules", fn["dir"].replace("/", os.sep), fn["stem"])
        try:
            head = "/* %s @ 0x%X | module %s | Genesect */\n\n" % (fn["name"], fn["ea"], fn["module"])
            decomp_content = head + decomp_by_ea.get(fn["ea"], "")
            _write_text(base + ".c", decomp_content)
            _write_text(base + ".asm", disasm_by_ea.get(fn["ea"], ""))
            _write_text(base + ".brief.md", cl.render_brief(fn, names))
            fn["files"] = {
                ext: "modules/%s/%s.%s" % (fn["dir"], fn["stem"], ext) for ext in ("c", "asm", "brief.md")
            }
        except OSError:
            counts["write_errors"] = counts.get("write_errors", 0) + 1
            fn["files"] = {}

    # Catalog
    catalog = os.path.join(output_root, "catalog")
    _ensure_dir(catalog)

    module_counts = Counter(fn["module"].split("/")[0] for fn in analyzed)
    counts["modules"] = dict(module_counts)

    function_records = [{
        "address": _hex(fn["ea"]), "end": _hex(fn["end_ea"]), "size": fn["size"],
        "name": fn["name"], "original_name": fn.get("original_name") or None,
        "module": fn["module"], "module_reasons": fn.get("module_reasons", []),
        "prototype": fn.get("prototype") or None, "flags": fn.get("flags", []),
        "capabilities": fn.get("capabilities", []), "imports_called": fn.get("imports_called", []),
        "string_count": len(fn.get("strings", [])),
        "callers": [_hex(e) for e in fn.get("callers", [])], "callees": [_hex(e) for e in fn.get("callees", [])],
        "triage_score": fn.get("triage_score", 0), "files": fn.get("files", {}),
    } for fn in analyzed]
    _write_json(os.path.join(catalog, "functions.json"), function_records)

    ranked = sorted((fn for fn in analyzed if fn.get("triage_score", 0) > 0), key=lambda f: (-f.get("triage_score", 0), f["ea"]))
    triage = {
        "note": "Heuristic leads, not verdicts. Score weights: injection APIs 4, dynamic resolution 3, "
                "crypto constants 3, command strings 3, large stack buffers 1-3, network/crypto APIs 2.",
        "summary": {
            "functions_flagged": len(ranked),
            "large_stack_buffers": sum(1 for f in analyzed if f.get("signals", {}).get("stack_buffers")),
            "dynamic_api_resolution": sum(1 for f in analyzed if f.get("signals", {}).get("dynamic_resolution")),
            "crypto_indicators": sum(1 for f in analyzed if f.get("signals", {}).get("crypto_constants") or f.get("signals", {}).get("xor_loop") or f.get("signals", {}).get("rc4_like")),
            "command_strings": sum(1 for f in analyzed if "command" in f.get("string_categories", [])),
        },
        "ranked_functions": [{
            "address": _hex(f["ea"]), "name": f["name"], "module": f["module"],
            "score": f["triage_score"], "signals": f["triage"],
        } for f in ranked[:50]],
        "large_stack_buffers": [
            {"function": f["name"], "address": _hex(f["ea"]), **buf}
            for f in analyzed for buf in f.get("signals", {}).get("stack_buffers", [])
        ],
        "dynamic_api_resolution": [
            {"function": f["name"], "address": _hex(f["ea"]), "resolved_apis": f.get("signals", {}).get("resolved_apis", [])}
            for f in analyzed if f.get("signals", {}).get("dynamic_resolution")
        ],
        "crypto": [
            {"function": f["name"], "address": _hex(f["ea"]), "constants": f.get("signals", {}).get("crypto_constants", []),
             "xor_loop": f.get("signals", {}).get("xor_loop"), "rc4_like": f.get("signals", {}).get("rc4_like")}
            for f in analyzed if f.get("signals", {}).get("crypto_constants") or f.get("signals", {}).get("xor_loop") or f.get("signals", {}).get("rc4_like")
        ],
        "command_strings": [
            {"function": f["name"], "address": _hex(f["ea"]), "string": s[:300]}
            for f in analyzed for s in f.get("strings", []) if "command" in cl.classify_string(s)
        ],
        "network_indicators": [
            {"function": f["name"], "address": _hex(f["ea"]), "string": s[:300]}
            for f in analyzed for s in f.get("strings", []) if set(cl.classify_string(s)) & {"url", "ip", "domain"}
        ],
    }
    _write_json(os.path.join(catalog, "triage_indicators.json"), triage)

    refs_by_string = defaultdict(list)
    for fn in analyzed:
        for sea in fn.get("string_eas", []):
            refs_by_string[sea].append(_hex(fn["ea"]))
    string_records = []
    for item in string_rows:
        try:
            ea_int = int(item[0], 16)
            text_str = item[1]
            cats = cl.classify_string(text_str)
            string_records.append({
                "address": item[0], "text": text_str[:400], "categories": cats,
                "referenced_by": refs_by_string.get(ea_int, [])[:20],
            })
        except Exception:
            continue
    string_records.sort(key=lambda r: (not r["categories"], not r["referenced_by"], r["address"]))
    _write_json(os.path.join(catalog, "strings.json"), {
        "total": len(string_records), "exported": min(len(string_records), 2000),
        "strings": string_records[:2000],
    })

    callers_of_import = defaultdict(list)
    for fn in analyzed:
        for name in fn.get("imports_called", []):
            callers_of_import[name].append(_hex(fn["ea"]))
    import_records = []
    for item in import_rows:
        try:
            imp_name = item[2]
            import_records.append({
                "module": item[0], "name": imp_name, "address": item[1],
                "capabilities": cl.capabilities_of_import(imp_name),
                "called_by": callers_of_import.get(cl.normalize_import(imp_name), [])[:25],
            })
        except Exception:
            continue
    grouped = defaultdict(list)
    for record in import_records:
        for cap in record["capabilities"] or ["other"]:
            grouped[cap].append(record)
    _write_json(os.path.join(catalog, "imports.json"), {
        "total": len(import_records),
        "by_capability": {cap: grouped[cap] for cap in [*cl.CAPABILITY_ORDER, "other"] if cap in grouped},
    })

    export_records = []
    for item in export_rows:
        export_records.append({"index": item[0], "ordinal": item[1], "address": item[2], "name": item[3]})
    _write_json(os.path.join(catalog, "exports.json"), export_records)

    section_records = []
    for item in segment_rows:
        section_records.append({"name": item[0], "start": item[1], "end": item[2], "perm": item[3], "type": item[4]})
    _write_json(os.path.join(catalog, "sections.json"), section_records)

    callgraph_edges = [[_hex(src), _hex(dst)] for src, callees_set in callees.items() for dst in sorted(callees_set)]
    _write_json(os.path.join(catalog, "callgraph.json"), {
        "nodes": [{"address": _hex(fn["ea"]), "name": fn["name"], "module": fn.get("module", cl.MODULE_UTILITY)} for fn in analyzed],
        "edges": callgraph_edges,
    })
    _write_csv(
        os.path.join(catalog, "callgraph.tsv"),
        ["caller_address", "caller", "callee_address", "callee"],
        edge_rows,
    )


def _database_metadata():
    input_path = ""
    idb_path = ""
    md5 = ""
    sha256 = ""
    try:
        input_path = idc.get_input_file_path() or ""
    except Exception:
        pass
    try:
        idb_path = idc.get_idb_path() or ""
    except Exception:
        pass
    try:
        md5 = ida_nalt.retrieve_input_file_md5().hex()
    except Exception:
        try:
            md5 = idc.retrieve_input_file_md5().hex()
        except Exception:
            md5 = ""
    try:
        sha256 = ida_nalt.retrieve_input_file_sha256().hex()
    except Exception:
        sha256 = ""
    info = {}
    try:
        inf = idaapi.get_inf_structure()
        info = {
            "processor": str(getattr(inf, "procname", "") or ""),
            "is_64bit": bool(inf.is_64bit()),
            "is_32bit": bool(inf.is_32bit()),
        }
    except Exception:
        pass
    try:
        imagebase = idaapi.get_imagebase()
    except Exception:
        try:
            imagebase = ida_nalt.get_imagebase()
        except Exception:
            imagebase = 0
    return {
        "tool": "Genesect",
        "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "input_file": input_path,
        "idb_file": idb_path,
        "root_filename": _input_basename(),
        "imagebase": _hex(imagebase),
        "md5": md5,
        "sha256": sha256,
        "ida": {
            "version": idaapi.get_kernel_version(),
        },
        "database": info,
    }


class _Progress:
    def __init__(self, parent, maximum):
        self.dialog = QtWidgets.QProgressDialog(
            "Preparing AI workspace export...",
            "Cancel",
            0,
            max(1, int(maximum)),
            parent,
        )
        self.dialog.setWindowTitle("Export AI Workspace")
        self.dialog.setWindowModality(QtCore.Qt.ApplicationModal)
        self.dialog.setMinimumDuration(0)
        self.value = 0
        self.maximum = max(1, int(maximum))

    def step(self, label, amount=1):
        self.value = min(self.maximum, self.value + int(amount))
        self.dialog.setLabelText(label)
        self.dialog.setValue(self.value)
        QtWidgets.QApplication.processEvents()
        if self.dialog.wasCanceled() or ida_kernwin.user_cancelled():
            raise RuntimeError("Export cancelled")

    def close(self):
        self.dialog.setValue(self.maximum)
        self.dialog.close()


class _HeadlessProgress:
    """Progress sink used by unattended IDA sessions.

    The interactive export keeps its cancellable dialog.  Batch callers cannot
    create that dialog reliably (especially when IDA is launched with ``-A``),
    so they use this lightweight callback-backed implementation instead.
    """

    def __init__(self, maximum, callback=None):
        self.maximum = max(1, int(maximum))
        self.value = 0
        self.callback = callback

    def step(self, label, amount=1):
        self.value = min(self.maximum, self.value + int(amount))
        if self.callback:
            self.callback(str(label), self.value, self.maximum)

    def close(self):
        return None


def export_ai_workspace(output_root, parent=None, show_progress=True, progress_callback=None):
    output_root = os.path.normpath(os.path.abspath(output_root))
    if ida_auto is None:
        raise RuntimeError("IDA autoanalysis API is unavailable; run this exporter inside IDA.")
    if not ida_auto.auto_wait():
        raise RuntimeError("IDA autoanalysis did not complete; refusing to export an incomplete workspace.")
    metadata = _database_metadata()
    functions = _function_rows()
    total_steps = 25 + (len(functions) * 3)
    progress = (
        _Progress(parent, total_steps)
        if show_progress
        else _HeadlessProgress(total_steps, progress_callback)
    )
    counts = {"functions": len(functions)}
    try:
        progress.step("Creating folders...")
        _ensure_dir(output_root)
        _ensure_dir(os.path.join(output_root, "functions"))
        _ensure_dir(os.path.join(output_root, "functions", "decompiled"))
        _ensure_dir(os.path.join(output_root, "functions", "disassembly"))

        callers, callees, edge_rows = _callgraph_for_functions(functions, progress)
        progress.step("Writing callgraph...")
        _write_csv(
            os.path.join(output_root, "functions", "callgraph.tsv"),
            ["caller_ea", "caller_name", "callee_ea", "callee_name"],
            edge_rows,
        )
        counts["call_edges"] = len(edge_rows)

        decompiled_paths = {}
        disassembly_paths = {}
        decomp_by_ea = {}
        disasm_by_ea = {}
        hexrays_ready = False
        try:
            hexrays_ready = bool(ida_hexrays.init_hexrays_plugin())
        except Exception:
            hexrays_ready = False

        target_max_path = 240
        disasm_dir = os.path.join(output_root, "functions", "disassembly")
        dir_len = len(os.path.normpath(os.path.abspath(disasm_dir)))

        for index, row in enumerate(functions, 1):
            ea_hex = "%08X" % int(row["ea"])
            overhead = dir_len + 1 + len(ea_hex) + 1 + 4
            name_budget = target_max_path - overhead
            safe_name_limit = max(20, min(60, name_budget))
            prefix = "%s_%s" % (ea_hex, _safe_filename(row["name"], "sub", limit=safe_name_limit))

            rel_disasm = os.path.join("functions", "disassembly", prefix + ".asm")
            progress.step("Writing disassembly %d/%d: %s" % (index, len(functions), _short_label(row["name"])))
            disasm_text = _disassembly_for_function(row["ea"])
            disasm_by_ea[row["ea"]] = disasm_text
            try:
                _write_text(os.path.join(output_root, rel_disasm), disasm_text)
            except Exception:
                fallback_rel = os.path.join("functions", "disassembly", "%s.asm" % ea_hex)
                try:
                    _write_text(os.path.join(output_root, fallback_rel), disasm_text)
                    rel_disasm = fallback_rel
                except Exception:
                    counts["write_errors"] = counts.get("write_errors", 0) + 1
                    rel_disasm = ""
            if rel_disasm:
                disassembly_paths[row["ea"]] = rel_disasm.replace("\\", "/")

            rel_decomp = os.path.join("functions", "decompiled", prefix + ".c")
            progress.step("Writing decompilation %d/%d: %s" % (index, len(functions), _short_label(row["name"])))
            if hexrays_ready:
                decomp_text = _decompile_function(row["ea"])
            else:
                decomp_text = "/* Hex-Rays decompiler is not available in this IDA session. */\n"
            decomp_by_ea[row["ea"]] = decomp_text
            try:
                _write_text(os.path.join(output_root, rel_decomp), decomp_text)
            except Exception:
                fallback_rel = os.path.join("functions", "decompiled", "%s.c" % ea_hex)
                try:
                    _write_text(os.path.join(output_root, fallback_rel), decomp_text)
                    rel_decomp = fallback_rel
                except Exception:
                    counts["write_errors"] = counts.get("write_errors", 0) + 1
                    rel_decomp = ""
            if rel_decomp:
                decompiled_paths[row["ea"]] = rel_decomp.replace("\\", "/")

        index_rows = []
        for row in functions:
            src = row["ea"]
            index_rows.append([
                _hex(src),
                _hex(row["end_ea"]),
                str(row["size"]),
                row["name"],
                "1" if row["is_library"] else "0",
                "1" if row["is_thunk"] else "0",
                ";".join(_hex(ea) for ea in sorted(callers.get(src, set()))),
                ";".join(_hex(ea) for ea in sorted(callees.get(src, set()))),
                decompiled_paths.get(src, ""),
                disassembly_paths.get(src, ""),
                _plain(row["comment"]).replace("\n", " "),
            ])
        progress.step("Writing function index...")
        _write_csv(
            os.path.join(output_root, "functions", "index.tsv"),
            [
                "ea", "end_ea", "size", "name", "is_library", "is_thunk",
                "callers", "callees", "decompiled_path", "disassembly_path", "comment",
            ],
            index_rows,
        )

        progress.step("Writing strings...")
        string_rows = _collect_strings()
        counts["strings"] = len(string_rows)
        _write_csv(os.path.join(output_root, "strings.tsv"), ["ea", "text"], string_rows)

        progress.step("Writing imports...")
        import_rows = _collect_imports()
        counts["imports"] = len(import_rows)
        _write_csv(os.path.join(output_root, "imports.tsv"), ["module", "ea", "name", "ordinal"], import_rows)

        progress.step("Writing exports...")
        export_rows = _collect_exports()
        counts["exports"] = len(export_rows)
        _write_csv(os.path.join(output_root, "exports.tsv"), ["index", "ordinal", "ea", "name"], export_rows)

        progress.step("Writing segments and names...")
        segment_rows = _collect_segments()
        name_rows = _collect_named_addresses()
        counts["segments"] = len(segment_rows)
        counts["names"] = len(name_rows)
        _write_csv(os.path.join(output_root, "segments.tsv"), ["name", "start_ea", "end_ea", "perm", "type"], segment_rows)
        _write_csv(os.path.join(output_root, "names.tsv"), ["ea", "name"], name_rows)

        progress.step("Writing global-variable catalog...")
        global_records = []
        try:
            global_records = _collect_globals(import_rows)
            counts["globals"] = len(global_records)
            _write_globals(output_root, global_records)
        except Exception as exc:
            counts["globals_error"] = str(exc)
            _write_text(os.path.join(output_root, "globals.error.txt"), str(exc) + "\n")

        _export_advanced_catalogs(
            output_root, functions, global_records, decomp_by_ea, counts, progress,
        )

        progress.step("Classifying behavioral modules and writing catalog...")
        try:
            _export_behavioral_modules_and_catalog(
                output_root,
                functions,
                decomp_by_ea,
                disasm_by_ea,
                string_rows,
                import_rows,
                export_rows,
                segment_rows,
                callers,
                callees,
                edge_rows,
                counts,
                progress,
            )
        except Exception as exc:
            counts["behavioral_export_error"] = str(exc)
            _write_text(os.path.join(output_root, "behavioral_export.error.txt"), str(exc) + "\n")

        progress.step("Writing Go/Rust map...")
        try:
            from genesect.go_rust_user_code_map import collect_language_map
            from genesect.go_rust_user_code_map import _hex as gr_hex
            rows, groups = collect_language_map()
            counts["go_rust_functions"] = len(rows)
            counts["go_rust_groups"] = len(groups)
            _write_csv(
                os.path.join(output_root, "go_rust_user_code_map.csv"),
                ["Address", "Language", "Category", "Group", "Function", "Original Name", "Strings", "Imports", "Size"],
                [
                    [
                        gr_hex(row["ea"]), row["language"], row["category"], row["group"],
                        row["display_name"], row["name"], len(row["strings"]),
                        len(row["imports"]), row["size"],
                    ]
                    for row in rows
                ],
            )
        except Exception as exc:
            counts["go_rust_error"] = str(exc)
            _write_text(os.path.join(output_root, "go_rust_user_code_map.error.txt"), str(exc) + "\n")

        progress.step("Writing virtual-class report...")
        try:
            from genesect.virtual_class_explorer import VirtualClassExplorer, recover_virtual_classes
            classes = recover_virtual_classes()
            helper = VirtualClassExplorer()
            helper.classes = classes
            counts["virtual_classes"] = len(classes)
            counts["virtual_vtables"] = sum(len(record["tables"]) for record in classes)
            _write_text(os.path.join(output_root, "virtual_classes.txt"), helper._all_report_text())
        except Exception as exc:
            counts["virtual_class_error"] = str(exc)
            _write_text(os.path.join(output_root, "virtual_classes.error.txt"), str(exc) + "\n")

        progress.step("Writing runtime artifact...")
        try:
            from genesect.runtime_artifacts import artifact_summary, load_artifact_from_idb
            artifact = load_artifact_from_idb()
            if artifact:
                _ensure_dir(os.path.join(output_root, "runtime"))
                _write_text(
                    os.path.join(output_root, "runtime", "artifact.json"),
                    json.dumps(artifact, indent=2, ensure_ascii=False, sort_keys=True),
                )
                summary = artifact_summary(artifact)
                counts["runtime_events"] = summary.get("events", 0)
                counts["runtime_coverage"] = summary.get("coverage", 0)
                counts["runtime_memory_regions"] = summary.get("memory_regions", 0)
                metadata["runtime_artifact"] = {
                    "path": "runtime/artifact.json",
                    "summary": summary,
                }
        except Exception as exc:
            counts["runtime_artifact_error"] = str(exc)
            _write_text(os.path.join(output_root, "runtime_artifact.error.txt"), str(exc) + "\n")

        progress.step("Writing analysis prompt and report renderer...")
        companion_files = _write_workspace_companion_files(output_root)
        counts["workspace_companion_files"] = len(companion_files)
        metadata["workspace_companion_files"] = companion_files

        progress.step("Writing manifest...")
        metadata["counts"] = counts
        _write_text(os.path.join(output_root, "manifest.json"), json.dumps(metadata, indent=2, sort_keys=True))
        write_skill_pack(output_root, metadata)
        return {"path": output_root, "counts": counts}
    finally:
        progress.close()


def _open_path(path):
    if not path or not os.path.exists(path):
        return False
    try:
        if os.name == "nt":
            os.startfile(path)
            return True
        elif sys.platform == "darwin":
            subprocess.run(["open", path], check=False)
            return True
        else:
            subprocess.run(["xdg-open", path], check=False)
            return True
    except Exception:
        return False


def export_and_analyze_workspace(
    output_root,
    profile=None,
    parent=None,
    show_progress=True,
    progress_callback=None,
    cancel_checker=None,
):
    """Programmatic entry point to export an AI workspace and immediately run AI threat analysis."""
    export_result = export_ai_workspace(
        output_root,
        parent=parent,
        show_progress=show_progress,
        progress_callback=progress_callback,
    )

    from genesect.workspace_analysis import analyze_workspace, get_active_profile_dict

    prof = dict(profile or get_active_profile_dict())
    log_cb = (lambda m: progress_callback(m, 0, 100)) if progress_callback else None

    analysis_result = analyze_workspace(
        output_root,
        primary=prof,
        log_fn=log_cb,
        cancel_checker=cancel_checker,
    )
    return {
        "export": export_result,
        "analysis": analysis_result,
        "path": output_root,
    }


class ExportAIWorkspaceDialog(QtWidgets.QDialog if QtWidgets else object):
    """Dialog prompting the user whether to Export Only or Export and Analyze."""

    def __init__(self, default_path, provider_name, model_name, parent=None):
        if not QtWidgets:
            return
        super().__init__(parent)
        self.setWindowTitle("Export AI Workspace")
        self.resize(600, 440)
        self.selected_path = default_path
        self.selected_mode = "export_only"

        try:
            from genesect.ui.mac_workspace import apply_mac_workspace
            apply_mac_workspace(self)
        except Exception:
            pass

        self._init_ui(default_path, provider_name, model_name)

    def _init_ui(self, default_path, provider_name, model_name):
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)

        # Header
        try:
            from genesect.ui.components import PageHeader
            header = PageHeader(
                "Export AI Workspace",
                "Export decompiled functions, disassembly, callgraphs, and triage artifacts for AI analysis.",
            )
            layout.addWidget(header)
        except Exception:
            title_lbl = QtWidgets.QLabel("<b>Export AI Workspace</b>")
            layout.addWidget(title_lbl)

        # Path Selection Card
        try:
            from genesect.ui.components import Card
            loc_card = Card("Export Location", "Target directory where the workspace folder will be created.")
        except Exception:
            loc_card = QtWidgets.QGroupBox("Export Location")
            loc_card.body = QtWidgets.QVBoxLayout(loc_card)

        path_row = QtWidgets.QHBoxLayout()
        self.path_edit = QtWidgets.QLineEdit(default_path)
        browse_btn = QtWidgets.QPushButton("Browse...")
        browse_btn.clicked.connect(self._on_browse)
        path_row.addWidget(self.path_edit, 1)
        path_row.addWidget(browse_btn)

        if hasattr(loc_card, "add_layout"):
            loc_card.add_layout(path_row)
        else:
            loc_card.body.addLayout(path_row)
        layout.addWidget(loc_card)

        # Workflow Options Card
        try:
            from genesect.ui.components import Card
            mode_card = Card("Workflow Mode", "Choose whether to dump files only or proceed with autonomous AI threat analysis.")
        except Exception:
            mode_card = QtWidgets.QGroupBox("Workflow Mode")
            mode_card.body = QtWidgets.QVBoxLayout(mode_card)

        self.radio_analyze = QtWidgets.QRadioButton("Export & Analyze")
        analyze_desc = QtWidgets.QLabel(
            "Dump workspace and immediately execute autonomous AI malware analysis to produce "
            "Markdown, interactive HTML, and vector PDF reports with IDA IDB navigation tables."
        )
        analyze_desc.setWordWrap(True)
        analyze_desc.setStyleSheet("color: #718096; margin-left: 22px; font-size: 11px;")

        self.radio_export = QtWidgets.QRadioButton("Export Only")
        self.radio_export.setChecked(True)
        export_desc = QtWidgets.QLabel(
            "Only dump decompiled code, disassembly, callgraphs, and metadata catalogs into "
            "the workspace directory without running AI analysis."
        )
        export_desc.setWordWrap(True)
        export_desc.setStyleSheet("color: #718096; margin-left: 22px; font-size: 11px;")

        self.radio_analyze.toggled.connect(self._on_mode_toggled)

        mode_layout = QtWidgets.QVBoxLayout()
        mode_layout.setSpacing(4)
        mode_layout.addWidget(self.radio_analyze)
        mode_layout.addWidget(analyze_desc)
        mode_layout.addSpacing(6)
        mode_layout.addWidget(self.radio_export)
        mode_layout.addWidget(export_desc)

        if hasattr(mode_card, "add_layout"):
            mode_card.add_layout(mode_layout)
        else:
            mode_card.body.addLayout(mode_layout)
        layout.addWidget(mode_card)

        # Provider Info Box
        provider_info = QtWidgets.QFrame()
        provider_info.setObjectName("pnProviderInfo")
        provider_info.setStyleSheet(
            "QFrame#pnProviderInfo { background: rgba(128, 128, 128, 0.08); border-radius: 6px; padding: 6px; }"
        )
        pi_layout = QtWidgets.QHBoxLayout(provider_info)
        pi_layout.setContentsMargins(10, 6, 10, 6)
        self.provider_lbl = QtWidgets.QLabel(
            f"<b>Active AI Provider:</b> {provider_name} &nbsp;&bull;&nbsp; <b>Model:</b> {model_name or 'default'}"
        )
        pi_layout.addWidget(self.provider_lbl, 1)
        layout.addWidget(provider_info)

        # Action Buttons
        btn_row = QtWidgets.QHBoxLayout()
        btn_row.addStretch(1)
        self.cancel_btn = QtWidgets.QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        self.start_btn = QtWidgets.QPushButton("Export & Analyze")
        self.start_btn.setDefault(True)
        self.start_btn.clicked.connect(self._on_start)

        btn_row.addWidget(self.cancel_btn)
        btn_row.addWidget(self.start_btn)
        layout.addLayout(btn_row)
        self._on_mode_toggled()

    def _on_browse(self):
        curr = self.path_edit.text().strip() or _default_parent_dir()
        selected = QtWidgets.QFileDialog.getExistingDirectory(
            self,
            "Choose AI Workspace Export Location",
            curr,
        )
        if selected:
            self.path_edit.setText(_normalize_workspace_folder(selected))

    def _on_mode_toggled(self):
        is_analyze = self.radio_analyze.isChecked()
        self.start_btn.setText("Export & Analyze" if is_analyze else "Export Only")
        self.provider_lbl.setEnabled(is_analyze)

    def _on_start(self):
        path = self.path_edit.text().strip()
        if not path:
            QtWidgets.QMessageBox.warning(self, "Invalid Path", "Please enter a valid export path.")
            return
        self.selected_path = os.path.normpath(path)
        self.selected_mode = "export_and_analyze" if self.radio_analyze.isChecked() else "export_only"
        self.accept()


class AnalysisCompleteDialog(QtWidgets.QDialog if QtWidgets else object):
    """Dialog displayed after export or export-and-analysis completes."""

    def __init__(self, workspace_path, deliverables=None, counts=None, is_analysis=True, parent=None):
        if not QtWidgets:
            return
        super().__init__(parent)
        self.workspace_path = workspace_path
        self.deliverables = deliverables or {}
        self.counts = counts or {}
        self.is_analysis = is_analysis

        self.setWindowTitle("AI Workspace Complete" if is_analysis else "AI Workspace Exported")
        self.resize(580, 360)

        try:
            from genesect.ui.mac_workspace import apply_mac_workspace
            apply_mac_workspace(self)
        except Exception:
            pass

        self._init_ui()

    def _init_ui(self):
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)

        title = "AI Workspace Export & Analysis Complete" if self.is_analysis else "AI Workspace Export Complete"
        sub = (
            "Threat intelligence deliverables and workspace files are ready."
            if self.is_analysis
            else "Workspace files have been exported successfully."
        )

        try:
            from genesect.ui.components import PageHeader
            header = PageHeader(title, sub)
            layout.addWidget(header)
        except Exception:
            layout.addWidget(QtWidgets.QLabel(f"<b>{title}</b>"))

        # Details Card
        try:
            from genesect.ui.components import Card
            card = Card("Export Details")
        except Exception:
            card = QtWidgets.QGroupBox("Export Details")
            card.body = QtWidgets.QVBoxLayout(card)

        info_lines = [
            f"<b>Location:</b> <code>{html.escape(self.workspace_path)}</code>",
        ]
        if self.counts:
            info_lines.append(
                f"<b>Exported Artifacts:</b> {self.counts.get('functions', 0):,} functions &bull; "
                f"{self.counts.get('call_edges', 0):,} call edges &bull; "
                f"{self.counts.get('strings', 0):,} strings"
            )
        if self.is_analysis:
            info_lines.append("<br><b>Deliverable Reports Generated:</b>")
            info_lines.append("&bull; <b>Markdown:</b> <code>malware_analysis_report.md</code>")
            info_lines.append("&bull; <b>Interactive HTML:</b> <code>malware_analysis_report.html</code> (Mermaid execution flow & IDB navigation)")
            info_lines.append("&bull; <b>Vector PDF:</b> <code>malware_analysis_report.pdf</code>")

        info_lbl = QtWidgets.QLabel("<br>".join(info_lines))
        info_lbl.setWordWrap(True)
        info_lbl.setTextFormat(QtCore.Qt.RichText if QtCore else 1)

        if hasattr(card, "add_widget"):
            card.add_widget(info_lbl)
        else:
            card.body.addWidget(info_lbl)
        layout.addWidget(card)

        # Buttons
        btn_row = QtWidgets.QHBoxLayout()
        btn_row.setSpacing(8)

        if self.is_analysis:
            html_path = self.deliverables.get("html") or os.path.join(self.workspace_path, "malware_analysis_report.html")
            pdf_path = self.deliverables.get("pdf") or os.path.join(self.workspace_path, "malware_analysis_report.pdf")

            if os.path.exists(html_path):
                btn_html = QtWidgets.QPushButton("🌐 Open HTML Report")
                btn_html.clicked.connect(lambda: _open_path(html_path))
                btn_row.addWidget(btn_html)

            if os.path.exists(pdf_path):
                btn_pdf = QtWidgets.QPushButton("📕 Open PDF Report")
                btn_pdf.clicked.connect(lambda: _open_path(pdf_path))
                btn_row.addWidget(btn_pdf)

        btn_folder = QtWidgets.QPushButton("📁 Open Folder")
        btn_folder.clicked.connect(lambda: _open_path(self.workspace_path))
        btn_row.addWidget(btn_folder)

        btn_row.addStretch(1)
        btn_close = QtWidgets.QPushButton("Close")
        btn_close.clicked.connect(self.accept)
        btn_row.addWidget(btn_close)

        layout.addLayout(btn_row)


_action_base = idaapi.action_handler_t if (idaapi and hasattr(idaapi, "action_handler_t")) else object


class ExportAIWorkspaceHandler(_action_base):
    def activate(self, ctx):
        if not QtWidgets:
            if ida_kernwin:
                ida_kernwin.warning("Qt is not available; cannot open the export location picker.")
            return 0
        try:
            parent = QtWidgets.QApplication.activeWindow()
        except Exception:
            parent = None

        from genesect.config import CONFIG
        from genesect.workspace_analysis import get_active_profile_dict

        active_profile = get_active_profile_dict(CONFIG)
        provider_name = active_profile.get("provider", "OpenAI")
        model_name = active_profile.get("model", "default")
        default_root = _default_output_root()

        # Ask user whether to Export Only or Export and Analyze
        dlg = ExportAIWorkspaceDialog(default_root, provider_name, model_name, parent=parent)
        if hasattr(dlg, "exec_"):
            accepted = dlg.exec_()
        else:
            accepted = dlg.exec()

        if not accepted:
            return 0

        output_root = dlg.selected_path
        mode = dlg.selected_mode

        # Step 1: Export AI workspace files
        try:
            export_result = export_ai_workspace(output_root, parent)
        except RuntimeError as exc:
            if ida_kernwin:
                ida_kernwin.warning(str(exc))
            return 0
        except Exception as exc:
            if ida_kernwin:
                ida_kernwin.warning("Export AI Workspace failed:\n%s" % exc)
            return 0

        counts = export_result.get("counts", {})

        # Step 2: Handle chosen mode
        if mode == "export_only":
            try:
                complete_dlg = AnalysisCompleteDialog(
                    output_root,
                    counts=counts,
                    is_analysis=False,
                    parent=parent,
                )
                if hasattr(complete_dlg, "exec_"):
                    complete_dlg.exec_()
                else:
                    complete_dlg.exec()
            except Exception:
                msg = (
                    "AI workspace exported.\n\n"
                    "Location: %s\n"
                    "Functions: %d\n"
                    "Call edges: %d\n"
                    "Strings: %d"
                    % (
                        output_root,
                        counts.get("functions", 0),
                        counts.get("call_edges", 0),
                        counts.get("strings", 0),
                    )
                )
                if ida_kernwin:
                    ida_kernwin.info(msg)
            return 1

        # Mode is "export_and_analyze": run analysis with progress dialog
        progress_dlg = QtWidgets.QProgressDialog(
            f"Analyzing exported workspace with {provider_name} ({model_name})...\n\n"
            "Inspecting decompiled source, triage catalogs, and generating deliverables...",
            "Cancel",
            0,
            0,
            parent,
        )
        progress_dlg.setWindowTitle("AI Workspace Analysis")
        progress_dlg.setWindowModality(QtCore.Qt.ApplicationModal)
        progress_dlg.setMinimumDuration(0)
        progress_dlg.show()
        QtWidgets.QApplication.processEvents()

        analysis_res = None
        try:
            from genesect.workspace_analysis import analyze_workspace

            def log_step(msg):
                progress_dlg.setLabelText(f"Analyzing workspace with {provider_name}...\n{msg}")
                QtWidgets.QApplication.processEvents()

            analysis_res = analyze_workspace(
                output_root,
                primary=active_profile,
                log_fn=log_step,
                cancel_checker=lambda: progress_dlg.wasCanceled(),
            )
        except Exception as exc:
            progress_dlg.close()
            if ida_kernwin:
                ida_kernwin.warning("AI Workspace Analysis failed:\n%s\n\n(Workspace files were successfully exported to: %s)" % (exc, output_root))
            return 1
        finally:
            progress_dlg.close()

        # Step 3: Show completed analysis dialog with HTML/PDF open buttons
        try:
            deliverables = analysis_res.get("deliverables") if analysis_res else {}
            complete_dlg = AnalysisCompleteDialog(
                output_root,
                deliverables=deliverables,
                counts=counts,
                is_analysis=True,
                parent=parent,
            )
            if hasattr(complete_dlg, "exec_"):
                complete_dlg.exec_()
            else:
                complete_dlg.exec()
        except Exception:
            if ida_kernwin:
                ida_kernwin.info("AI Workspace exported and analyzed.\n\nLocation: %s" % output_root)

        return 1

    def update(self, ctx):
        if idaapi and hasattr(idaapi, "AST_ENABLE_ALWAYS"):
            return idaapi.AST_ENABLE_ALWAYS
        return 0
