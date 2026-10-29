# Ghidra Headless Python Script for MANTIS Binary Lab
#
# Automatically decompiles functions, extracts symbols, imports, exports,
# strings, and metadata, and exports an AI workspace compatible with
# MANTIS Binary Analysis Lab.
#
# @category MANTIS

from __future__ import annotations

import json
import os
import re

try:
    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.util import DefinedDataIterator
except ImportError:
    pass


def sanitize_name(name):
    if not name:
        return "func"
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", name)


def main():
    args = getScriptArgs()
    if not args:
        printerr("export_ghidra_workspace error: Missing output workspace directory argument.")
        return

    ws_dir = os.path.abspath(args[0])
    catalog_dir = os.path.join(ws_dir, "catalog")
    src_dir = os.path.join(ws_dir, "src")
    asm_dir = os.path.join(ws_dir, "asm")

    for d in (catalog_dir, src_dir, asm_dir):
        if not os.path.exists(d):
            os.makedirs(d)

    prog = currentProgram
    if not prog:
        printerr("export_ghidra_workspace error: No currentProgram loaded.")
        return

    # Extraction limits (configurable via CLI args or environment variables; <= 0 means unlimited)
    max_decompile = 0
    max_strings = 0
    if len(args) > 1:
        try:
            max_decompile = int(args[1])
        except (ValueError, TypeError):
            pass
    if max_decompile <= 0:
        try:
            max_decompile = int(os.environ.get("GHIDRA_MAX_DECOMPILE", "0"))
        except (ValueError, TypeError):
            pass

    if len(args) > 2:
        try:
            max_strings = int(args[2])
        except (ValueError, TypeError):
            pass
    if max_strings <= 0:
        try:
            max_strings = int(os.environ.get("GHIDRA_MAX_STRINGS", "0"))
        except (ValueError, TypeError):
            pass

    limit_decompile = max_decompile if max_decompile > 0 else float("inf")
    limit_strings = max_strings if max_strings > 0 else float("inf")

    println('OMNI_EVENT {"kind":"sample_stage","stage":"Ghidra Auto-Analysis Completed"}')
    println(
        f"Exporting Ghidra AI Workspace to: {ws_dir} "
        f"(limits: max_decompile={max_decompile if max_decompile > 0 else 'unlimited'}, "
        f"max_strings={max_strings if max_strings > 0 else 'unlimited'})"
    )

    # 1. Metadata
    prog_name = prog.getName()
    fmt = prog.getExecutableFormat()
    lang = prog.getLanguage().getLanguageID().getIdAsString()
    compiler = prog.getCompilerSpec().getCompilerSpecID().getIdAsString()
    img_base = str(prog.getImageBase())
    min_addr = str(prog.getMinAddress()) if prog.getMinAddress() else ""
    max_addr = str(prog.getMaxAddress()) if prog.getMaxAddress() else ""
    func_total = prog.getFunctionManager().getFunctionCount()

    meta = {
        "program_name": prog_name,
        "executable_format": fmt,
        "language_id": lang,
        "compiler_spec": compiler,
        "image_base": img_base,
        "min_address": min_addr,
        "max_address": max_addr,
        "total_functions": func_total,
        "max_decompile_limit": max_decompile,
        "max_strings_limit": max_strings,
        "disassembler": "Ghidra (Headless)",
    }
    with open(os.path.join(catalog_dir, "assembly.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    with open(os.path.join(catalog_dir, "metadata.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    # 2. Imports
    suspicious_tags = []
    suspicious_api_patterns = [
        "virtualalloc", "writeprocessmemory", "createremotethread", "ntcreatethreadex",
        "setwindowshook", "queueuserapc", "loadlibrary", "getprocaddress", "internetopen",
        "internetconnect", "httpopenrequest", "httpsendrequest", "urldownloadtofile",
        "wsastartup", "connect", "send", "recv", "regsetvalue", "regcreatekey",
        "createprocess", "winexec", "shellexecute", "isdebuggerpresent", "checkremotedebuggerpresent",
        "cryptacquirecontext", "cryptencrypt", "cryptdecrypt"
    ]

    imports_list = []
    sym_table = prog.getSymbolTable()
    ext_symbols = sym_table.getExternalSymbols()
    while ext_symbols.hasNext():
        sym = ext_symbols.next()
        name = sym.getName()
        parent = sym.getParentNamespace().getName() if sym.getParentNamespace() else "EXTERNAL"
        addr = str(sym.getAddress()) if sym.getAddress() else ""

        lower = name.lower()
        for pat in suspicious_api_patterns:
            if pat in lower:
                suspicious_tags.append(f"API: {name} ({parent})")
                break

        imports_list.append({"library": parent, "name": name, "address": addr})

    with open(os.path.join(catalog_dir, "imports.json"), "w", encoding="utf-8") as f:
        json.dump(imports_list, f, indent=2)

    # 3. Exports
    exports_list = []
    entry_iter = sym_table.getExternalEntryPointIterator()
    while entry_iter.hasNext():
        ep = entry_iter.next()
        sym = sym_table.getPrimarySymbol(ep)
        name = sym.getName() if sym else str(ep)
        exports_list.append({"name": name, "address": str(ep)})

    with open(os.path.join(catalog_dir, "exports.json"), "w", encoding="utf-8") as f:
        json.dump(exports_list, f, indent=2)

    # 4. Strings
    strings_list = []
    data_it = prog.getListing().getDefinedData(True)
    str_count = 0
    strings_truncated = False
    while data_it.hasNext():
        if str_count >= limit_strings:
            strings_truncated = True
            break
        d = data_it.next()
        if not d:
            continue
        dt_name = d.getDataType().getName().lower() if d.getDataType() else ""
        if not ("string" in dt_name or "unicode" in dt_name or "char" in dt_name):
            continue
        val = str(d.getValue() or d.getDefaultValueRepresentation() or "").strip()
        if val.startswith('"') and val.endswith('"') and len(val) >= 2:
            val = val[1:-1]
        if len(val) >= 4:
            lower = val.lower()
            if lower.startswith(("http://", "https://")) or ".onion" in lower:
                suspicious_tags.append(f"Network Indicator: {val}")
            elif any(cmd in lower for cmd in ("powershell", "cmd.exe", "/bin/sh")):
                suspicious_tags.append(f"Command Execution Indicator: {val}")

            strings_list.append({
                "address": str(d.getAddress()),
                "length": len(val),
                "value": val,
            })
            str_count += 1

    with open(os.path.join(catalog_dir, "strings.json"), "w", encoding="utf-8") as f:
        json.dump(strings_list, f, indent=2)

    # 5. Triage indicators
    with open(os.path.join(catalog_dir, "triage_indicators.json"), "w", encoding="utf-8") as f:
        json.dump({"indicators": suspicious_tags}, f, indent=2)

    # 6. Decompilation
    println('OMNI_EVENT {"kind":"sample_stage","stage":"Decompiling in Ghidra"}')
    decomp = DecompInterface()
    decomp.openProgram(prog)

    funcs_list = []
    f_it = prog.getFunctionManager().getFunctions(True)
    decomp_count = 0
    decomp_truncated = False

    while f_it.hasNext():
        fn = f_it.next()
        name = fn.getName()
        entry = fn.getEntryPoint()
        size = fn.getBody().getNumAddresses()
        proto = fn.getPrototypeString(True, False)
        is_thunk = fn.isThunk()

        funcs_list.append({
            "name": name,
            "entry_point": str(entry),
            "size": size,
            "signature": proto,
            "is_thunk": is_thunk,
        })

        if not is_thunk:
            if decomp_count < limit_decompile:
                try:
                    res = decomp.decompileFunction(fn, 30, monitor)
                    if res and res.decompileCompleted():
                        df = res.getDecompiledFunction()
                        if df and df.getC():
                            c_code = df.getC()
                            safe = sanitize_name(name)
                            safe_entry = str(entry).replace(":", "_")
                            c_path = os.path.join(src_dir, f"{safe}_{safe_entry}.c")
                            with open(c_path, "w", encoding="utf-8") as f:
                                f.write(c_code)
                            decomp_count += 1
                except Exception:
                    pass
            else:
                decomp_truncated = True

    with open(os.path.join(catalog_dir, "functions.json"), "w", encoding="utf-8") as f:
        json.dump(funcs_list, f, indent=2)
    decomp.dispose()

    # 7. AGENTS.md, CLAUDE.md, README.md
    decomp_limit_text = f" (limit: {max_decompile}{' — limit reached' if decomp_truncated else ''})" if max_decompile > 0 else " (unlimited)"
    str_limit_text = f" (limit: {max_strings}{' — limit reached' if strings_truncated else ''})" if max_strings > 0 else " (unlimited)"

    agents_lines = [
        f"# Binary Lab AI Workspace — Ghidra Binary Analysis: {prog_name}",
        "",
        "## Overview",
        f"- **Sample**: `{prog_name}`",
        "- **Disassembler**: Ghidra (Headless Auto-Analysis + DecompInterface)",
        f"- **Format**: {fmt}",
        f"- **Architecture / Language**: {lang}",
        f"- **Total Functions**: {func_total}",
        f"- **Decompiled Functions**: {decomp_count}{decomp_limit_text}",
        f"- **Imports**: {len(imports_list)}",
        f"- **Extracted Strings**: {len(strings_list)}{str_limit_text}",
        "",
        "## Structure",
        "- `catalog/assembly.json`: Program format, architecture, and memory layout.",
        "- `catalog/functions.json`: Complete function catalog and prototypes.",
        "- `catalog/imports.json`: External dynamic library and Win32/POSIX imports.",
        "- `catalog/exports.json`: Exported symbol entry points.",
        "- `catalog/strings.json`: Defined string literals extracted from data sections.",
        "- `catalog/triage_indicators.json`: High-priority suspicious behavioral indicators.",
        "- `src/*.c`: High-level decompiled C source code for functions.",
        "",
        "## Triage Findings",
    ]
    if suspicious_tags:
        agents_lines.extend([f"- ⚠ {t}" for t in suspicious_tags])
    else:
        agents_lines.append("- No obvious high-risk triage flags triggered.")

    if decomp_truncated:
        agents_lines.append(f"- ℹ Decompilation capped at configured limit ({max_decompile} functions).")
    if strings_truncated:
        agents_lines.append(f"- ℹ Strings capped at configured limit ({max_strings} strings).")

    agents_lines.extend([
        "",
        "## Autonomous Analysis Pipeline",
        "- `run_analysis.md` — Investigation runbook and instructions.",
        "- `render_report.py` — Report compiler for report.md -> report.html / report.pdf.",
        "- `dump_ai_workspace.py` — Static artifact extractor for unpacker workflows.",
    ])

    doc = "\n".join(agents_lines)
    for doc_name in ("AGENTS.md", "CLAUDE.md", "README.md"):
        with open(os.path.join(ws_dir, doc_name), "w", encoding="utf-8") as f:
            f.write(doc)

    println(
        f'OMNI_EVENT {{"kind":"ghidra_limits","max_decompile":{max_decompile},"max_strings":{max_strings},'
        f'"decompiled":{decomp_count},"strings":{len(strings_list)},"decomp_truncated":{str(decomp_truncated).lower()},'
        f'"strings_truncated":{str(strings_truncated).lower()}}}'
    )
    println('OMNI_EVENT {"kind":"sample_stage","stage":"AI Workspace Exported"}')
    println(f"Ghidra export complete: {func_total} functions, {len(imports_list)} imports, {len(strings_list)} strings, {decomp_count} C files")


if __name__ == "__main__" or "currentProgram" in globals():
    main()
