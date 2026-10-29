# -*- coding: utf-8 -*-
"""Rust binary triage and symbol cleanup helpers."""

from __future__ import annotations

from collections import Counter
import os
import re
import shutil
import subprocess

import ida_funcs
import ida_kernwin
import ida_name
import idaapi
import idautils

from genesect.qt_compat import QtWidgets


# Indicators are based on JPCERT/CC's Rust binary analysis research.
PLAIN_RUST_STRINGS = (
    "run with `RUST_BACKTRACE=1` environment variable to display a backtrace",
    "called `Result::unwrap()` on an `Err` value",
    "called `Option::unwrap()` on a `None` value",
)

MINSIZE_RUST_STRINGS = (
    "<unknown>",
    "<redacted>",
    "failed to write whole buffer",
    "failed to write the buffered data",
)

RUST_LEGACY_ESCAPES = {
    "$SP$": "@",
    "$BP$": "*",
    "$RF$": "&",
    "$LT$": "<",
    "$GT$": ">",
    "$LP$": "(",
    "$RP$": ")",
    "$C$": ",",
}

RUST_NAME_MARKERS = (
    "core::",
    "std::",
    "alloc::",
    "rust_begin_unwind",
    "lang_start_internal",
    "panic_fmt",
    "drop_in_place",
    "rust_eh_personality",
)

PANIC_MARKERS = (
    "core::panicking::panic_fmt",
    "panic_fmt",
    "rust_begin_unwind",
    "RtlFailFast",
    "_CxxThrowException",
)

LOCATION_PATH_MARKERS = (
    ".cargo\\registry",
    ".cargo/registry",
    "\\rustc\\",
    "/rustc/",
    "\\library\\core\\src\\",
    "/library/core/src/",
    "\\library\\std\\src\\",
    "/library/std/src/",
)

IDA_PREFIXES = ("sub_", "loc_", "j_", "nullsub_", "byte_", "word_", "dword_", "qword_", "off_", "unk_")
MAX_EVIDENCE_ITEMS = 40
MAX_INLINE_RUST_STRING = 4096
STRING_FIXUPS_ACTION_ID = "genesect:rust_string_fixups"

_string_fixup_hooks = None
_string_fixups_enabled = False
_rust_detection_cache = None


def _config():
    from genesect.config import CONFIG
    return CONFIG


def _display_ea(ea):
    if ea is None or ea == idaapi.BADADDR:
        return ""
    return "0x%X" % int(ea)


def _truncate(value, limit=140):
    value = " ".join(str(value or "").split())
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def _set_string_fixups_checked(enabled):
    setter = getattr(ida_kernwin, "set_action_checked", None)
    if callable(setter):
        try:
            setter(STRING_FIXUPS_ACTION_ID, bool(enabled))
        except Exception:
            pass


def _iter_strings():
    try:
        strings = idautils.Strings()
        strings.setup(strtypes=getattr(idautils.Strings, "STR_C", 0))
    except Exception:
        strings = idautils.Strings()
    for item in strings:
        try:
            yield int(getattr(item, "ea", idaapi.BADADDR)), str(item)
        except Exception:
            continue


def _iter_names():
    for ea, name in idautils.Names():
        if name:
            yield int(ea), str(name)


def _iter_function_names():
    for func_ea in idautils.Functions():
        try:
            name = ida_funcs.get_func_name(func_ea) or ""
        except Exception:
            name = ""
        if name:
            yield int(func_ea), name


def _looks_like_legacy_rust_symbol(name):
    value = _symbol_candidate(name)
    return bool(re.search(r"_?ZN\d+", value) and re.search(r"17h[0-9A-Fa-f]{16}E?$", value))


def _looks_like_v0_rust_symbol(name):
    value = _symbol_candidate(name)
    return bool(value.startswith("_R") or re.match(r"^R[INvMC][A-Za-z0-9_]", value))


def looks_like_rust_mangled(name):
    return _looks_like_legacy_rust_symbol(name) or _looks_like_v0_rust_symbol(name)


def _symbol_candidate(name):
    value = str(name or "")
    value = value.replace("j_", "", 1) if value.startswith("j_") else value
    value = value.replace("__imp_", "", 1) if value.startswith("__imp_") else value
    value = value.replace("__imp__", "", 1) if value.startswith("__imp__") else value
    idx = value.find("_ZN")
    if idx > 0:
        return value[idx:]
    idx = value.find("__ZN")
    if idx >= 0:
        return value[idx + 1 :]
    idx = value.find("_R")
    if idx > 0:
        return value[idx:]
    return value


def _legacy_demangle(symbol):
    value = _symbol_candidate(symbol)
    if value.startswith("__ZN"):
        value = value[1:]
    if value.startswith("_ZN"):
        cursor = 3
    elif value.startswith("ZN"):
        cursor = 2
    else:
        return ""

    parts = []
    while cursor < len(value):
        if value[cursor] == "E":
            break
        match = re.match(r"\d+", value[cursor:])
        if not match:
            break
        size_text = match.group(0)
        cursor += len(size_text)
        size = int(size_text)
        part = value[cursor : cursor + size]
        if len(part) != size:
            break
        cursor += size
        if re.fullmatch(r"h[0-9A-Fa-f]{16}", part):
            break
        parts.append(_unescape_legacy_part(part))
    return "::".join(parts)


def _unescape_legacy_part(part):
    value = str(part or "")
    for escaped, literal in RUST_LEGACY_ESCAPES.items():
        value = value.replace(escaped, literal)

    def _decode_unicode(match):
        try:
            return chr(int(match.group(1), 16))
        except Exception:
            return match.group(0)

    value = re.sub(r"\$u([0-9A-Fa-f]{2,6})\$", _decode_unicode, value)
    return value


def _resolve_rustfilt():
    for name in ("rustfilt", "rustfilt.exe"):
        path = shutil.which(name)
        if path:
            return path
    return ""


def _rustfilt_demangle(symbol):
    rustfilt = _resolve_rustfilt()
    if not rustfilt:
        return ""
    try:
        completed = subprocess.run(
            [rustfilt, _symbol_candidate(symbol)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0,
        )
    except Exception:
        return ""
    if completed.returncode != 0:
        return ""
    demangled = (completed.stdout or b"").decode("utf-8", "replace").strip()
    if not demangled or demangled == symbol:
        return ""
    return demangled


def demangle_rust_symbol(symbol):
    return _legacy_demangle(symbol) or _rustfilt_demangle(symbol)


def _ida_safe_name(demangled, ea):
    value = re.sub(r"\{\{closure\}\}", "closure", demangled)
    value = value.replace("::", "__")
    value = re.sub(r"[^A-Za-z0-9_$@?]+", "_", value)
    value = value.strip("_")
    if not value:
        value = "rust_symbol"
    if not re.match(r"^[A-Za-z_?$@]", value):
        value = "rust_" + value
    if len(value) > 220:
        value = value[:220].rstrip("_") + "_%X" % int(ea)
    return value


def _name_flags():
    return (
        getattr(idaapi, "SN_NOWARN", getattr(ida_name, "SN_NOWARN", 0))
        | getattr(idaapi, "SN_NOCHECK", getattr(ida_name, "SN_NOCHECK", 0))
        | getattr(ida_name, "SN_FORCE", 0)
    )


def _set_name(ea, name):
    if ea is None or ea == idaapi.BADADDR or not name:
        return False
    if idaapi.set_name(ea, name, _name_flags()):
        return True
    return idaapi.set_name(ea, "%s_%X" % (name, int(ea)), _name_flags())


def collect_rust_evidence():
    string_hits = []
    plain_hits = []
    minsize_hits = []
    panic_hits = []
    path_hits = []
    crate_hits = Counter()

    crate_re = re.compile(r"[\\/]\.cargo[\\/]registry[\\/]src[\\/][^\\/]+[\\/]([A-Za-z0-9_.-]+-\d+\.\d+(?:\.\d+)?)")
    for ea, value in _iter_strings():
        lower = value.lower()
        if value in PLAIN_RUST_STRINGS:
            plain_hits.append((ea, value))
        if value in MINSIZE_RUST_STRINGS:
            minsize_hits.append((ea, value))
        if any(marker.lower() in lower for marker in PANIC_MARKERS):
            panic_hits.append((ea, value))
        if any(marker.lower() in lower for marker in LOCATION_PATH_MARKERS):
            path_hits.append((ea, value))
            match = crate_re.search(value)
            if match:
                crate_hits[match.group(1)] += 1
        if len(string_hits) < MAX_EVIDENCE_ITEMS and (
            value in PLAIN_RUST_STRINGS
            or value in MINSIZE_RUST_STRINGS
            or any(marker.lower() in lower for marker in LOCATION_PATH_MARKERS)
        ):
            string_hits.append((ea, value))

    mangled_names = []
    rust_names = []
    main_candidates = []
    for ea, name in _iter_names():
        clean = name.replace("__", "::")
        if looks_like_rust_mangled(name) and len(mangled_names) < MAX_EVIDENCE_ITEMS:
            mangled_names.append((ea, name))
        if any(marker in clean for marker in RUST_NAME_MARKERS) and len(rust_names) < MAX_EVIDENCE_ITEMS:
            rust_names.append((ea, name))
        if _is_main_candidate(clean) and len(main_candidates) < MAX_EVIDENCE_ITEMS:
            main_candidates.append((ea, name))

    score = 0
    score += 45 if len(plain_hits) >= 3 else 18 * len(plain_hits)
    score += 40 if len(minsize_hits) >= 3 else 10 * len(minsize_hits)
    score += min(len(mangled_names), 10) * 4
    score += min(len(rust_names), 8) * 3
    score += min(len(panic_hits), 6) * 3
    score += min(len(path_hits), 8) * 2
    score = min(score, 100)

    if score >= 70:
        confidence = "High"
    elif score >= 40:
        confidence = "Medium"
    elif score:
        confidence = "Low"
    else:
        confidence = "None"

    return {
        "score": score,
        "confidence": confidence,
        "plain_hits": plain_hits,
        "minsize_hits": minsize_hits,
        "string_hits": string_hits,
        "panic_hits": panic_hits,
        "path_hits": path_hits[:MAX_EVIDENCE_ITEMS],
        "crate_hits": crate_hits,
        "mangled_names": mangled_names,
        "rust_names": rust_names,
        "main_candidates": main_candidates,
    }


def is_probable_rust_binary():
    global _rust_detection_cache
    if _rust_detection_cache is not None:
        return bool(_rust_detection_cache)
    try:
        evidence = collect_rust_evidence()
        _rust_detection_cache = evidence["score"] >= 25 or bool(evidence["mangled_names"] or evidence["rust_names"])
    except Exception:
        _rust_detection_cache = False
    return bool(_rust_detection_cache)


def _is_main_candidate(name):
    if not name:
        return False
    value = name.replace("\\", "/")
    return (
        "lang_start_internal" in value
        or value.endswith("::main")
        or "::main::h" in value
        or value.endswith("__main")
        or "__main__h" in value
    )


def _format_evidence_rows(title, rows, limit=12):
    if not rows:
        return []
    lines = [title]
    for ea, value in rows[:limit]:
        loc = _display_ea(ea)
        lines.append("  - %s%s" % ((loc + ": ") if loc else "", _truncate(value)))
    if len(rows) > limit:
        lines.append("  - ... %d more" % (len(rows) - limit))
    return lines


def build_rust_report(evidence):
    lines = [
        "Rust Binary Triage",
        "Confidence: %(confidence)s (%(score)d/100)" % evidence,
        "",
        "Signal counts:",
        "  - Plain Rust panic/backtrace strings: %d" % len(evidence["plain_hits"]),
        "  - Min-size Rust strings: %d" % len(evidence["minsize_hits"]),
        "  - Rust mangled names: %d" % len(evidence["mangled_names"]),
        "  - Rust runtime/library names: %d" % len(evidence["rust_names"]),
        "  - Panic-related strings/names: %d" % len(evidence["panic_hits"]),
        "  - Rust source/crate path strings: %d" % len(evidence["path_hits"]),
    ]

    if evidence["crate_hits"]:
        lines.append("")
        lines.append("Likely crate/version strings:")
        for crate, count in evidence["crate_hits"].most_common(12):
            lines.append("  - %s (%d refs)" % (crate, count))

    lines.append("")
    if evidence["main_candidates"]:
        lines.append("Main-function hints:")
        lines.append("  - lang_start_internal or demangled main-like names were found.")
        lines.append("  - In Rust release builds, the user main is typically passed toward lang_start_internal.")
        lines.append("  - In size-minimized builds, main startup can be inlined and the user main may be called directly.")
    else:
        lines.append("Main-function hints:")
        lines.append("  - No named lang_start_internal/main candidate was found.")
        lines.append("  - Check startup code manually if the binary is stripped or size-minimized.")

    sections = []
    sections.extend(_format_evidence_rows("Plain Rust indicators:", evidence["plain_hits"]))
    sections.extend(_format_evidence_rows("Min-size indicators:", evidence["minsize_hits"]))
    sections.extend(_format_evidence_rows("Mangled Rust symbols:", evidence["mangled_names"]))
    sections.extend(_format_evidence_rows("Rust runtime/library names:", evidence["rust_names"]))
    sections.extend(_format_evidence_rows("Main candidates:", evidence["main_candidates"]))
    sections.extend(_format_evidence_rows("Rust path strings:", evidence["path_hits"]))
    if sections:
        lines.append("")
        lines.extend([line for line in sections if line])

    lines.append("")
    lines.append("Analyst next steps:")
    lines.append("  - Run Demangle Rust Symbols to normalize legacy Rust symbols in the IDB.")
    lines.append("  - Prioritize non-std/non-core functions and crate paths over runtime glue.")
    lines.append("  - Review panic Location strings for source paths, crate names, and line/column clues.")
    lines.append("  - For library pruning, build FLIRT/RIFT signatures with matching Rust and Cargo profile options.")
    return "\n".join(lines)


def show_rust_triage_report(parent=None):
    evidence = collect_rust_evidence()
    report = build_rust_report(evidence)
    ida_kernwin.msg(report + "\n")
    box = QtWidgets.QMessageBox(parent or QtWidgets.QApplication.activeWindow())
    box.setWindowTitle("Rust Binary Triage")
    box.setIcon(QtWidgets.QMessageBox.Information)
    box.setText("Rust confidence: %(confidence)s (%(score)d/100)" % evidence)
    box.setInformativeText(
        "Found %d JPCERT-style strings, %d mangled symbols, and %d Rust runtime/library names."
        % (
            len(evidence["plain_hits"]) + len(evidence["minsize_hits"]),
            len(evidence["mangled_names"]),
            len(evidence["rust_names"]),
        )
    )
    box.setDetailedText(report)
    box.exec_()
    return evidence


def _line_text(line):
    value = getattr(line, "line", line)
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _rust_string_text(data):
    if not data:
        return ""
    if len(data) > MAX_INLINE_RUST_STRING:
        return ""
    text = data.decode("utf-8", "replace")
    text = text.rstrip("\x00")
    if not text:
        return ""
    # Keep the replacement single-line and readable inside Hex-Rays output.
    text = (
        text.replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
        .replace("\t", "\\t")
    )
    return "\"%s\"" % text


def _read_string_literal(ea):
    try:
        import ida_bytes
        import idc
    except Exception:
        return ""
    try:
        if ea is None or ea == idaapi.BADADDR:
            return ""
        if not idc.is_strlit(ida_bytes.get_full_flags(ea)):
            return ""
        size = int(ida_bytes.get_item_size(ea))
        if size <= 0 or size > MAX_INLINE_RUST_STRING:
            return ""
        data = ida_bytes.get_bytes(ea, size)
        return _rust_string_text(data or b"")
    except Exception:
        return ""


def _colored_string_literal(text):
    try:
        import ida_lines
        color = getattr(ida_lines, "SCOLOR_STRING", getattr(ida_lines, "SCOLOR_CREF", 0))
        return ida_lines.COLSTR(text, color)
    except Exception:
        return text


def _refresh_open_pseudocode_views():
    try:
        import ida_hexrays
    except Exception:
        idaapi.request_refresh(getattr(idaapi, "IWID_PSEUDOCODE", getattr(idaapi, "IWID_DISASM", 0)))
        return
    get_count = getattr(ida_kernwin, "get_widget_qty", None)
    get_widget = getattr(ida_kernwin, "getn_widget", None)
    if not callable(get_count) or not callable(get_widget):
        idaapi.request_refresh(getattr(idaapi, "IWID_PSEUDOCODE", getattr(idaapi, "IWID_DISASM", 0)))
        return
    try:
        for index in range(int(get_count())):
            widget = get_widget(index)
            if widget and idaapi.get_widget_type(widget) == idaapi.BWN_PSEUDOCODE:
                vu = ida_hexrays.get_widget_vdui(widget)
                if vu:
                    vu.refresh_view(True)
    except Exception as exc:
        ida_kernwin.msg("[Genesect] Could not refresh Rust string fixups: %s\n" % exc)


def _apply_rust_string_fixups(cfunc):
    try:
        import ida_hexrays
    except Exception:
        return 0
    pseudocode = cfunc.get_pseudocode()
    replacements = {}
    for item in cfunc.treeitems:
        try:
            if hasattr(item, "is_expr") and not item.is_expr():
                continue
            if getattr(item, "op", None) != ida_hexrays.cot_obj:
                continue
            expr = item.cexpr
            literal = _read_string_literal(int(expr.obj_ea))
            if not literal:
                continue
            rendered = str(expr.dstr() or "")
            if rendered.startswith(("\"", "L\"")):
                continue
            original = str(expr.print1(None) or rendered)
            if not original or original.startswith(("\"", "L\"")):
                continue
            _x, line_index = cfunc.find_item_coords(item)
            if line_index is None or line_index < getattr(cfunc, "hdrlines", 0):
                continue
            replacements.setdefault(int(line_index), {})[original] = _colored_string_literal(literal)
        except Exception:
            continue

    for line_index, row in replacements.items():
        try:
            simple_line = pseudocode[line_index]
            text = _line_text(simple_line)
            for original, replacement in row.items():
                text = text.replace(original, replacement)
            simple_line.line = text
            pseudocode[line_index] = simple_line
        except Exception:
            continue
    return len(replacements)


def _make_rust_string_fixup_hooks_class():
    import ida_hexrays

    class RustStringFixupHooks(ida_hexrays.Hexrays_Hooks):
        def __init__(self):
            ida_hexrays.Hexrays_Hooks.__init__(self)

        def func_printed(self, cfunc):
            if not _string_fixups_enabled or not cfunc:
                return 0
            if not is_probable_rust_binary():
                return 0
            try:
                _apply_rust_string_fixups(cfunc)
            except Exception as exc:
                ida_kernwin.msg("[Genesect] Rust string display fixups skipped: %s\n" % exc)
            return 0

    return RustStringFixupHooks


def set_rust_string_fixups_enabled(enabled, persist=True, refresh=True):
    global _string_fixups_enabled, _rust_detection_cache
    _string_fixups_enabled = bool(enabled)
    _rust_detection_cache = None
    if persist:
        config = _config()
        config.rust_string_fixups_enabled = _string_fixups_enabled
        config.save()
    _set_string_fixups_checked(_string_fixups_enabled)
    if refresh:
        _refresh_open_pseudocode_views()
    return _string_fixups_enabled


def create_rust_string_fixup_hooks():
    global _string_fixup_hooks
    if _string_fixup_hooks is not None:
        return _string_fixup_hooks
    try:
        import ida_hexrays
    except Exception:
        return None
    if not ida_hexrays.init_hexrays_plugin():
        return None
    hooks_class = _make_rust_string_fixup_hooks_class()
    candidate = hooks_class()
    if not candidate.hook():
        return None
    _string_fixup_hooks = candidate
    set_rust_string_fixups_enabled(
        getattr(_config(), "rust_string_fixups_enabled", True), persist=False, refresh=False
    )
    return candidate


def destroy_rust_string_fixup_hooks():
    global _string_fixup_hooks, _string_fixups_enabled, _rust_detection_cache
    _string_fixups_enabled = False
    _rust_detection_cache = None
    if _string_fixup_hooks is not None:
        try:
            _string_fixup_hooks.unhook()
        except Exception:
            pass
    _string_fixup_hooks = None


def demangle_rust_symbols():
    renamed = 0
    skipped = 0
    candidates = []
    for ea, name in _iter_function_names():
        if name.startswith(IDA_PREFIXES) and not looks_like_rust_mangled(name):
            continue
        if looks_like_rust_mangled(name):
            candidates.append((ea, name))
    for ea, name in candidates:
        demangled = demangle_rust_symbol(name)
        if not demangled or demangled == name:
            skipped += 1
            continue
        safe_name = _ida_safe_name(demangled, ea)
        if _set_name(ea, safe_name):
            renamed += 1
        else:
            skipped += 1
    return {"candidates": len(candidates), "renamed": renamed, "skipped": skipped}


def show_demangle_summary(parent=None):
    try:
        summary = demangle_rust_symbols()
    except Exception as exc:
        ida_kernwin.warning("Rust demangling failed:\n%s" % exc)
        return None
    idaapi.request_refresh(idaapi.IWID_DISASM)
    message = (
        "Processed %(candidates)d Rust-looking function symbols.\n"
        "Renamed %(renamed)d functions.\n"
        "Skipped %(skipped)d symbols that were already clean or unsupported."
    ) % summary
    QtWidgets.QMessageBox.information(parent or QtWidgets.QApplication.activeWindow(), "Rust Symbol Demangler", message)
    return summary


class RustTriageHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        show_rust_triage_report()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class RustDemangleHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        show_demangle_summary()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class ToggleRustStringFixupsHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        create_rust_string_fixup_hooks()
        enabled = set_rust_string_fixups_enabled(not _string_fixups_enabled)
        ida_kernwin.msg("[Genesect] Rust string display fixups %s\n" % ("enabled" if enabled else "disabled"))
        return 1

    def update(self, ctx):
        _set_string_fixups_checked(_string_fixups_enabled)
        return idaapi.AST_ENABLE_ALWAYS
