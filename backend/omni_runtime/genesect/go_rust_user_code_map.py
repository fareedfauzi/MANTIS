# -*- coding: utf-8 -*-
"""Go/Rust user-code map, runtime filter, and IDB marking helpers."""

from __future__ import annotations

from collections import Counter, defaultdict
import csv
import io
import os
import re

import ida_bytes
import ida_funcs
import ida_kernwin
import ida_lines
import idaapi
import idautils
import idc

from genesect.qt_compat import QtCore, QtWidgets
from genesect.rust_analysis_tools import demangle_rust_symbol, looks_like_rust_mangled
from genesect.ui.components import Card, PageHeader, ToggleSwitch
from genesect.ui.mac_workspace import apply_mac_workspace


_explorer = None
MAX_GROUP_STRINGS = 80
COMMENT_MARKER = "[Genesect Go/Rust]"

CATEGORY_COLORS = {
    "User": 0xC8FACC,
    "ThirdParty": 0xDDEBFF,
    "Uncategorized": 0xE8E8E8,
    "Stdlib": 0xE0E0E0,
    "Runtime": 0xC8C8C8,
}

GO_STD_ROOTS = {
    "archive", "bufio", "builtin", "bytes", "cmp", "compress", "container",
    "context", "crypto", "database", "debug", "embed", "encoding", "errors",
    "expvar", "flag", "fmt", "go", "hash", "html", "image", "index", "io",
    "iter", "log", "maps", "math", "mime", "net", "os", "path", "plugin",
    "reflect", "regexp", "runtime", "slices", "sort", "strconv", "strings",
    "sync", "syscall", "testing", "text", "time", "unicode", "unsafe",
}

GO_RUNTIME_ROOTS = {
    "abi", "asan", "atomic", "cgo", "cpu", "gc", "godebug", "goexperiment",
    "internal", "msan", "race", "runtime", "setg", "sys", "type",
}

GO_THIRD_PARTY_ROOTS = {
    "bitbucket.org", "cloud.google.com", "github.com", "gitlab.com", "go.etcd.io",
    "go.opencensus.io", "go.opentelemetry.io", "go.uber.org", "golang.org",
    "gonum.org", "google.golang.org", "gopkg.in", "honnef.co", "k8s.io",
    "modernc.org", "rsc.io",
}

RUST_STD_ROOTS = {
    "alloc", "core", "std", "test", "proc_macro", "compiler_builtins",
    "panic_abort", "panic_unwind", "unwind", "rustc_demangle",
}

RUST_RUNTIME_MARKERS = (
    "rust_begin_unwind", "lang_start_internal", "rust_eh_personality",
    "panic_fmt", "drop_in_place", "__rust_alloc", "__rust_dealloc",
    "__rust_realloc", "__rust_alloc_zeroed",
)

NOISE_CATEGORIES = {"Runtime", "Stdlib"}
IDA_PREFIXES = ("sub_", "loc_", "j_", "nullsub_", "byte_", "word_", "dword_", "qword_", "off_", "unk_")


def _hex(ea):
    return "0x%X" % int(ea)


def _plain(value):
    try:
        return ida_lines.tag_remove(str(value or ""))
    except Exception:
        return str(value or "")


def _truncate(value, limit=180):
    value = " ".join(str(value or "").split())
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def _clean_name(name):
    value = str(name or "")
    for prefix in ("j_", "__imp_", "__imp__", "_imp__"):
        if value.startswith(prefix):
            return value[len(prefix):]
    return value


def _go_package_from_name(name):
    name = _clean_name(name)
    if not name or name.startswith(IDA_PREFIXES) or "." not in name:
        return ""
    package, _func = name.rsplit(".", 1)
    return package.strip("._/")


def _go_package_root(package):
    if not package:
        return ""
    normalized = package.replace("\\", "/")
    if "/" in normalized:
        return normalized.split("/", 1)[0]
    underscored = normalized.replace(".", "_")
    for root in GO_THIRD_PARTY_ROOTS:
        prefix = root.replace(".", "_") + "_"
        if underscored.startswith(prefix):
            return root
    return normalized.split(".", 1)[0]


def _is_go_third_party(package):
    value = package.replace("\\", "/")
    underscored = value.replace(".", "_")
    for root in GO_THIRD_PARTY_ROOTS:
        if value == root or value.startswith(root + "/"):
            return True
        root_us = root.replace(".", "_")
        if underscored == root_us or underscored.startswith(root_us + "_"):
            return True
    return False


def _classify_go(name):
    package = _go_package_from_name(name)
    if not package:
        return None
    root = _go_package_root(package)
    if root in GO_RUNTIME_ROOTS or package.startswith("runtime."):
        category = "Runtime"
    elif _is_go_third_party(package):
        category = "ThirdParty"
    elif root in GO_STD_ROOTS:
        category = "Stdlib"
    else:
        category = "User"
    return {
        "language": "Go",
        "category": category,
        "group": package,
        "module": root or package,
        "display_name": name,
    }


def _rust_readable_name(name):
    name = _clean_name(name)
    demangled = demangle_rust_symbol(name) if looks_like_rust_mangled(name) else ""
    if demangled:
        return demangled
    if "::" in name:
        return name
    if "__" in name and not name.startswith(IDA_PREFIXES):
        return name.replace("__", "::")
    return name


def _rust_root(readable):
    value = str(readable or "").strip(":")
    if not value:
        return ""
    return value.split("::", 1)[0].strip("<>&* ")


def _classify_rust(name):
    readable = _rust_readable_name(name)
    root = _rust_root(readable)
    if not readable:
        return None
    lower = readable.lower()
    if not (
        looks_like_rust_mangled(name)
        or "::" in readable
        or any(marker in lower for marker in RUST_RUNTIME_MARKERS)
    ):
        return None
    if any(marker in lower for marker in RUST_RUNTIME_MARKERS):
        category = "Runtime"
    elif root in RUST_STD_ROOTS:
        category = "Stdlib"
    elif root and not readable.startswith(IDA_PREFIXES):
        category = "User"
    else:
        category = "Uncategorized"
    parts = [part for part in readable.split("::") if part]
    group = "::".join(parts[:2]) if len(parts) > 1 else (root or "Rust/Uncategorized")
    return {
        "language": "Rust",
        "category": category,
        "group": group,
        "module": root or "Rust",
        "display_name": readable,
    }


def classify_function(name):
    rust = _classify_rust(name)
    if rust:
        return rust
    go = _classify_go(name)
    if go:
        return go
    return {
        "language": "Unknown",
        "category": "Uncategorized",
        "group": "Uncategorized",
        "module": "Uncategorized",
        "display_name": name,
    }


def _function_for_ea(ea):
    func = ida_funcs.get_func(int(ea))
    return int(func.start_ea) if func else idaapi.BADADDR


def _collect_string_refs():
    strings_by_func = defaultdict(list)
    try:
        strings = idautils.Strings()
        strings.setup(strtypes=getattr(idautils.Strings, "STR_C", 0))
    except Exception:
        strings = idautils.Strings()
    for item in strings:
        if ida_kernwin.user_cancelled():
            break
        try:
            string_ea = int(item.ea)
            text = str(item)
        except Exception:
            continue
        for xref in idautils.XrefsTo(string_ea):
            func_ea = _function_for_ea(xref.frm)
            if func_ea != idaapi.BADADDR:
                values = strings_by_func[func_ea]
                if len(values) < MAX_GROUP_STRINGS:
                    values.append((string_ea, text))
    return strings_by_func


def _collect_import_refs():
    imports = {}
    try:
        for index in range(int(idaapi.get_import_module_qty())):
            module = str(idaapi.get_import_module_name(index) or "")

            def collect(ea, name, ordinal, module_name=module):
                imports[int(ea)] = "%s!%s" % (module_name, name or ordinal)
                return True

            idaapi.enum_import_names(index, collect)
    except Exception:
        pass
    imports_by_func = defaultdict(set)
    for ea, api in imports.items():
        try:
            for xref in idautils.XrefsTo(ea):
                func_ea = _function_for_ea(xref.frm)
                if func_ea != idaapi.BADADDR:
                    imports_by_func[func_ea].add(api)
        except Exception:
            continue
    return imports_by_func


def collect_language_map():
    strings_by_func = _collect_string_refs()
    imports_by_func = _collect_import_refs()
    rows = []
    groups = {}
    for func_ea in idautils.Functions():
        if ida_kernwin.user_cancelled():
            break
        name = ida_funcs.get_func_name(func_ea) or idc.get_func_name(func_ea) or ""
        info = classify_function(name)
        strings = strings_by_func.get(int(func_ea), [])
        imports = sorted(imports_by_func.get(int(func_ea), set()))
        row = {
            "ea": int(func_ea),
            "name": name,
            "display_name": info["display_name"],
            "language": info["language"],
            "category": info["category"],
            "module": info["module"],
            "group": info["group"],
            "strings": strings,
            "imports": imports,
            "size": _function_size(func_ea),
        }
        rows.append(row)
        key = (row["language"], row["category"], row["group"])
        group = groups.setdefault(key, {
            "language": row["language"],
            "category": row["category"],
            "group": row["group"],
            "module": row["module"],
            "functions": [],
            "strings": [],
            "imports": Counter(),
        })
        group["functions"].append(row)
        for string in strings:
            if len(group["strings"]) < MAX_GROUP_STRINGS:
                group["strings"].append(string)
        group["imports"].update(imports)
    return sorted(rows, key=_row_sort_key), sorted(groups.values(), key=_group_sort_key)


def _function_size(func_ea):
    func = ida_funcs.get_func(func_ea)
    if not func:
        return 0
    return max(0, int(func.end_ea) - int(func.start_ea))


def _category_rank(category):
    return {"User": 0, "ThirdParty": 1, "Uncategorized": 2, "Stdlib": 3, "Runtime": 4}.get(category, 9)


def _row_sort_key(row):
    return (_category_rank(row["category"]), row["language"], row["group"].casefold(), row["display_name"].casefold(), row["ea"])


def _group_sort_key(group):
    return (_category_rank(group["category"]), group["language"], group["group"].casefold())


def _classification_comment(row):
    return "%s %s %s | %s" % (
        COMMENT_MARKER,
        row["language"],
        row["category"],
        row["group"],
    )


def _set_function_color(ea, color):
    if not color:
        return False
    try:
        return bool(idc.set_color(int(ea), idc.CIC_FUNC, int(color)))
    except Exception:
        try:
            return bool(idc.set_color(int(ea), idc.CIC_ITEM, int(color)))
        except Exception:
            return False


def _set_classification_comment(row):
    func = ida_funcs.get_func(row["ea"])
    if not func:
        return False
    new_line = _classification_comment(row)
    old = ida_funcs.get_func_cmt(func, True) or ""
    kept = [
        line for line in str(old).splitlines()
        if COMMENT_MARKER not in line
    ]
    kept.append(new_line)
    return bool(ida_funcs.set_func_cmt(func, "\n".join(line for line in kept if line), True))


def apply_classification_to_idb(rows=None, include_noise=False, target_language=None):
    rows = rows if rows is not None else collect_language_map()[0]
    annotated = 0
    colored = 0
    skipped = 0
    for row in rows:
        if target_language:
            if row["language"] != target_language:
                skipped += 1
                continue
        else:
            if row["language"] not in ("Go", "Rust"):
                skipped += 1
                continue
        if not include_noise and row["category"] in NOISE_CATEGORIES:
            skipped += 1
            continue
        if _set_classification_comment(row):
            annotated += 1
        if _set_function_color(row["ea"], CATEGORY_COLORS.get(row["category"])):
            colored += 1
    return {"annotated": annotated, "colored": colored, "skipped": skipped, "total": len(rows)}


def _default_color():
    return int(getattr(idc, "DEFCOLOR", 0xFFFFFFFF))


def clear_classification_from_idb(rows=None, target_language=None):
    if rows is None:
        rows = []
        for func_ea in idautils.Functions():
            name = ida_funcs.get_func_name(func_ea) or idc.get_func_name(func_ea) or ""
            info = classify_function(name)
            rows.append({
                "ea": int(func_ea),
                "language": info["language"],
                "category": info["category"],
                "group": info["group"],
                "display_name": info["display_name"],
            })
    cleared_comments = 0
    cleared_colors = 0
    skipped = 0
    for row in rows:
        if target_language:
            if row["language"] != target_language:
                skipped += 1
                continue
        else:
            if row["language"] not in ("Go", "Rust"):
                skipped += 1
                continue
        func = ida_funcs.get_func(row["ea"])
        if not func:
            skipped += 1
            continue
        old = ida_funcs.get_func_cmt(func, True) or ""
        kept = [
            line for line in str(old).splitlines()
            if COMMENT_MARKER not in line
        ]
        if old != "\n".join(kept):
            if ida_funcs.set_func_cmt(func, "\n".join(line for line in kept if line), True):
                cleared_comments += 1
        if _set_function_color(row["ea"], _default_color()):
            cleared_colors += 1
    return {"cleared_comments": cleared_comments, "cleared_colors": cleared_colors, "skipped": skipped, "total": len(rows)}


class GoRustUserCodeMap(ida_kernwin.PluginForm):
    def __init__(self, target_language=None):
        super().__init__()
        self.rows = []
        self.groups = []
        self.target_language = target_language

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        apply_mac_workspace(self.parent)
        root = QtWidgets.QVBoxLayout(self.parent)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)
        if self.target_language in ("Go", "Rust"):
            header_title = "%s User Code Map" % self.target_language
            header_sub = "Classify %s runtime, stdlib, third-party, and likely user code" % self.target_language
        else:
            header_title = "Go/Rust User Code Map"
            header_sub = "Classify runtime, stdlib, third-party, and likely user code"
        header = PageHeader(header_title, header_sub)
        refresh = QtWidgets.QPushButton("Refresh")
        refresh.setProperty("pnVariant", "primary")
        refresh.clicked.connect(self.refresh)
        header.add_action(refresh)
        mark = QtWidgets.QPushButton("Mark IDB")
        mark.clicked.connect(self.mark_idb)
        header.add_action(mark)
        clear = QtWidgets.QPushButton("Clear Marks")
        clear.clicked.connect(self.clear_marks)
        header.add_action(clear)
        export = QtWidgets.QPushButton("Export CSV")
        export.clicked.connect(self.export_csv)
        header.add_action(export)
        root.addWidget(header)

        filters = QtWidgets.QHBoxLayout()
        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("Filter by language, category, package/crate, function, string, or import...")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.apply_filter)
        filters.addWidget(self.filter_edit, 1)
        self.language_combo = QtWidgets.QComboBox()
        self.language_combo.addItems(["Go/Rust only", "All", "Go", "Rust", "Unknown"])
        if self.target_language in ("Go", "Rust"):
            self.language_combo.setCurrentText(self.target_language)
        self.language_combo.currentTextChanged.connect(self.apply_filter)
        filters.addWidget(self.language_combo)
        self.category_combo = QtWidgets.QComboBox()
        self.category_combo.addItems(["Actionable", "All", "User", "ThirdParty", "Uncategorized", "Stdlib", "Runtime"])
        self.category_combo.currentTextChanged.connect(self.apply_filter)
        filters.addWidget(self.category_combo)
        self.include_noise = ToggleSwitch("Include runtime/stdlib in copied context")
        filters.addWidget(self.include_noise)
        root.addLayout(filters)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        group_card = Card("Package and crate groups")
        self.group_table = QtWidgets.QTableWidget(0, 7)
        self.group_table.setHorizontalHeaderLabels(["Language", "Category", "Group", "Functions", "Strings", "Imports", "Top Imports"])
        self.group_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.group_table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.group_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.group_table.setAlternatingRowColors(True)
        self.group_table.verticalHeader().setVisible(False)
        self.group_table.itemSelectionChanged.connect(self.show_group_details)
        group_card.add_widget(self.group_table)
        splitter.addWidget(group_card)

        function_card = Card("Functions")
        self.function_table = QtWidgets.QTableWidget(0, 7)
        self.function_table.setHorizontalHeaderLabels(["Address", "Language", "Category", "Group", "Function", "Strings", "Imports"])
        self.function_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.function_table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.function_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.function_table.setAlternatingRowColors(True)
        self.function_table.verticalHeader().setVisible(False)
        self.function_table.itemDoubleClicked.connect(self.navigate_selected_function)
        self.function_table.itemSelectionChanged.connect(self.show_function_details)
        function_card.add_widget(self.function_table)
        splitter.addWidget(function_card)

        detail_card = Card("Evidence")
        self.details = QtWidgets.QPlainTextEdit()
        self.details.setReadOnly(True)
        detail_card.add_widget(self.details)
        splitter.addWidget(detail_card)
        splitter.setSizes([260, 430, 240])
        root.addWidget(splitter, 1)
        self.status = QtWidgets.QLabel("Ready")
        self.status.setProperty("pnMuted", True)
        root.addWidget(self.status)
        QtCore.QTimer.singleShot(0, self.refresh)

    def refresh(self):
        ida_kernwin.show_wait_box("Building Go/Rust user-code map...\nPress Cancel to stop safely.")
        try:
            self.rows, self.groups = collect_language_map()
        except Exception as exc:
            self.rows, self.groups = [], []
            ida_kernwin.warning("Go/Rust User Code Map failed:\n%s" % exc)
        finally:
            ida_kernwin.hide_wait_box()
        self.populate_groups()
        self.populate_functions()
        counts = Counter((row["language"], row["category"]) for row in self.rows)
        self.status.setText(
            "%d functions | Go user: %d | Rust user: %d | Third-party: %d | Runtime/stdlib: %d"
            % (
                len(self.rows),
                counts.get(("Go", "User"), 0),
                counts.get(("Rust", "User"), 0),
                sum(count for (lang, cat), count in counts.items() if lang in ("Go", "Rust") and cat == "ThirdParty"),
                sum(count for (lang, cat), count in counts.items() if lang in ("Go", "Rust") and cat in NOISE_CATEGORIES),
            )
        )

    def populate_groups(self):
        self.group_table.setSortingEnabled(False)
        self.group_table.setRowCount(max(1, len(self.groups)))
        if not self.groups:
            self._empty_table(self.group_table, "No Go/Rust groups found.")
        else:
            for index, group in enumerate(self.groups):
                top_imports = ", ".join(name for name, _count in group["imports"].most_common(4))
                values = [
                    group["language"], group["category"], group["group"], str(len(group["functions"])),
                    str(len(group["strings"])), str(sum(group["imports"].values())), top_imports,
                ]
                for column, value in enumerate(values):
                    item = QtWidgets.QTableWidgetItem(value)
                    item.setData(QtCore.Qt.UserRole, index)
                    self.group_table.setItem(index, column, item)
        self.group_table.resizeColumnsToContents()
        self.group_table.horizontalHeader().setStretchLastSection(True)
        self.group_table.setSortingEnabled(True)
        self.apply_filter()

    def populate_functions(self):
        self.function_table.setSortingEnabled(False)
        self.function_table.setRowCount(max(1, len(self.rows)))
        if not self.rows:
            self._empty_table(self.function_table, "No functions found.")
        else:
            for index, row in enumerate(self.rows):
                values = [
                    _hex(row["ea"]), row["language"], row["category"], row["group"], row["display_name"],
                    str(len(row["strings"])), str(len(row["imports"])),
                ]
                for column, value in enumerate(values):
                    item = QtWidgets.QTableWidgetItem(value)
                    item.setData(QtCore.Qt.UserRole, index)
                    self.function_table.setItem(index, column, item)
        self.function_table.resizeColumnsToContents()
        self.function_table.setColumnWidth(4, max(420, self.function_table.columnWidth(4)))
        self.function_table.setSortingEnabled(True)
        self.apply_filter()

    def _empty_table(self, table, text):
        item = QtWidgets.QTableWidgetItem(text)
        item.setFlags(QtCore.Qt.ItemIsEnabled)
        item.setTextAlignment(QtCore.Qt.AlignCenter)
        table.setItem(0, 0, item)
        table.setSpan(0, 0, 1, max(1, table.columnCount()))

    def _row_visible(self, row):
        language = self.language_combo.currentText()
        category = self.category_combo.currentText()
        if language == "Go/Rust only" and row["language"] not in ("Go", "Rust"):
            return False
        if language not in ("All", "Go/Rust only") and row["language"] != language:
            return False
        if category == "Actionable" and row["category"] in NOISE_CATEGORIES:
            return False
        if category not in ("All", "Actionable") and row["category"] != category:
            return False
        needle = self.filter_edit.text().strip().lower()
        if not needle:
            return True
        haystack = " ".join([
            row["language"], row["category"], row["group"], row["display_name"],
            " ".join(text for _ea, text in row["strings"][:12]),
            " ".join(row["imports"][:12]),
        ]).lower()
        return needle in haystack

    def apply_filter(self, *_args):
        for table_row in range(self.function_table.rowCount()):
            item = self.function_table.item(table_row, 0)
            if not item or item.data(QtCore.Qt.UserRole) is None:
                continue
            row = self.rows[int(item.data(QtCore.Qt.UserRole))]
            self.function_table.setRowHidden(table_row, not self._row_visible(row))
        visible_groups = set()
        for row in self.rows:
            if self._row_visible(row):
                visible_groups.add((row["language"], row["category"], row["group"]))
        for table_row in range(self.group_table.rowCount()):
            item = self.group_table.item(table_row, 0)
            if not item or item.data(QtCore.Qt.UserRole) is None:
                continue
            group = self.groups[int(item.data(QtCore.Qt.UserRole))]
            key = (group["language"], group["category"], group["group"])
            self.group_table.setRowHidden(table_row, key not in visible_groups)

    def selected_function(self):
        selected = self.function_table.selectionModel().selectedRows() if self.function_table.selectionModel() else []
        if not selected:
            return None
        item = self.function_table.item(selected[0].row(), 0)
        index = item.data(QtCore.Qt.UserRole) if item else None
        return self.rows[int(index)] if index is not None else None

    def selected_group(self):
        selected = self.group_table.selectionModel().selectedRows() if self.group_table.selectionModel() else []
        if not selected:
            return None
        item = self.group_table.item(selected[0].row(), 0)
        index = item.data(QtCore.Qt.UserRole) if item else None
        return self.groups[int(index)] if index is not None else None

    def show_group_details(self):
        group = self.selected_group()
        if not group:
            return
        lines = [
            "%s %s group: %s" % (group["language"], group["category"], group["group"]),
            "Functions: %d" % len(group["functions"]),
            "Referenced strings: %d" % len(group["strings"]),
            "Imports:",
        ]
        lines.extend("  - %s (%d)" % (name, count) for name, count in group["imports"].most_common(20))
        lines.append("")
        lines.append("Sample strings:")
        lines.extend("  - %s %s" % (_hex(ea), _truncate(text, 220)) for ea, text in group["strings"][:30])
        lines.append("")
        lines.append("Functions:")
        lines.extend("  - %s %s" % (_hex(row["ea"]), row["display_name"]) for row in group["functions"][:80])
        self.details.setPlainText("\n".join(lines))

    def show_function_details(self):
        row = self.selected_function()
        if not row:
            return
        lines = [
            "%s %s function" % (row["language"], row["category"]),
            "Address: %s" % _hex(row["ea"]),
            "Name: %s" % row["display_name"],
            "Original: %s" % row["name"],
            "Group: %s" % row["group"],
            "Size: %d bytes" % row["size"],
            "",
            "Imports:",
        ]
        lines.extend("  - %s" % value for value in row["imports"][:40])
        lines.append("")
        lines.append("Referenced strings:")
        lines.extend("  - %s %s" % (_hex(ea), _truncate(text, 240)) for ea, text in row["strings"][:60])
        self.details.setPlainText("\n".join(lines))

    def navigate_selected_function(self, *_args):
        row = self.selected_function()
        if row:
            ida_kernwin.jumpto(row["ea"])

    def mark_idb(self):
        if not self.rows:
            ida_kernwin.info("Refresh the map before marking the IDB.")
            return
        answer = QtWidgets.QMessageBox.question(
            self.parent,
            "Mark Go/Rust Classification",
            "Add repeatable function comments and colors for the current Go/Rust classifications?\n\n"
            "Runtime and standard-library functions are skipped unless the runtime/stdlib context toggle is enabled.",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
            QtWidgets.QMessageBox.No,
        )
        if answer != QtWidgets.QMessageBox.Yes:
            return
        summary = apply_classification_to_idb(self.rows, include_noise=self.include_noise.isChecked())
        idaapi.request_refresh(idaapi.IWID_DISASM)
        self.status.setText(
            "Marked IDB: %(annotated)d comments, %(colored)d colors, %(skipped)d skipped." % summary
        )

    def clear_marks(self):
        if not self.rows:
            ida_kernwin.info("Refresh the map before clearing marks.")
            return
        answer = QtWidgets.QMessageBox.question(
            self.parent,
            "Clear Go/Rust Marks",
            "Remove Genesect Go/Rust classification comments and reset marked function colors to IDA defaults?",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
            QtWidgets.QMessageBox.No,
        )
        if answer != QtWidgets.QMessageBox.Yes:
            return
        summary = clear_classification_from_idb(self.rows)
        idaapi.request_refresh(idaapi.IWID_DISASM)
        self.status.setText(
            "Cleared marks: %(cleared_comments)d comments, %(cleared_colors)d colors reset." % summary
        )

    def export_csv(self):
        if not self.rows:
            ida_kernwin.info("Refresh the map before exporting.")
            return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self.parent, "Export Go/Rust User Code Map", "go_rust_user_code_map.csv", "CSV files (*.csv)")
        if not path:
            return
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Address", "Language", "Category", "Group", "Function", "Original Name", "Strings", "Imports", "Size"])
        for row in self.rows:
            writer.writerow([_hex(row["ea"]), row["language"], row["category"], row["group"], row["display_name"], row["name"], len(row["strings"]), len(row["imports"]), row["size"]])
        with open(path, "w", encoding="utf-8-sig", newline="") as handle:
            handle.write(output.getvalue())
        self.status.setText("Exported %d functions to %s" % (len(self.rows), os.path.basename(path)))

    def OnClose(self, form):
        global _explorer
        if _explorer is self:
            _explorer = None


def show_go_rust_user_code_map(target_language=None):
    global _explorer
    if _explorer is None:
        _explorer = GoRustUserCodeMap(target_language=target_language)
    elif target_language in ("Go", "Rust"):
        _explorer.target_language = target_language
        if hasattr(_explorer, "language_combo"):
            idx = _explorer.language_combo.findText(target_language)
            if idx >= 0:
                _explorer.language_combo.setCurrentIndex(idx)
    title = f"Genesect - {target_language} User Code Map" if target_language in ("Go", "Rust") else "Genesect - Go/Rust User Code Map"
    _explorer.Show(title, options=ida_kernwin.PluginForm.WOPN_PERSIST)
    if target_language in ("Go", "Rust") and hasattr(_explorer, "language_combo"):
        idx = _explorer.language_combo.findText(target_language)
        if idx >= 0:
            _explorer.language_combo.setCurrentIndex(idx)


class LanguageUserCodeMapHandler(idaapi.action_handler_t):
    def __init__(self, target_language=None):
        super().__init__()
        self.target_language = target_language

    def activate(self, ctx):
        show_go_rust_user_code_map(self.target_language)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class GoRustUserCodeMapHandler(LanguageUserCodeMapHandler):
    def __init__(self):
        super().__init__(None)


class GoUserCodeMapHandler(LanguageUserCodeMapHandler):
    def __init__(self):
        super().__init__("Go")


class RustUserCodeMapHandler(LanguageUserCodeMapHandler):
    def __init__(self):
        super().__init__("Rust")


class LanguageMarkIDBHandler(idaapi.action_handler_t):
    def __init__(self, target_language=None):
        super().__init__()
        self.target_language = target_language

    def activate(self, ctx):
        lang_label = self.target_language or "Go/Rust"
        answer = ida_kernwin.ask_yn(
            0,
            f"Add repeatable function comments and colors for likely {lang_label} user and third-party code?\n\n"
            "Runtime and standard-library functions will be skipped.",
        )
        if answer != 1:
            return 0
        ida_kernwin.show_wait_box(f"Classifying and marking {lang_label} functions...\nPress Cancel to stop safely.")
        try:
            summary = apply_classification_to_idb(include_noise=False, target_language=self.target_language)
        except Exception as exc:
            ida_kernwin.warning(f"{lang_label} IDB marking failed:\n{exc}")
            return 0
        finally:
            ida_kernwin.hide_wait_box()
        idaapi.request_refresh(idaapi.IWID_DISASM)
        ida_kernwin.info(
            f"{lang_label} IDB marking complete.\n\n"
            f"Added {summary['annotated']} comments and {summary['colored']} colors.\n"
            f"Skipped {summary['skipped']} functions."
        )
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class GoRustMarkIDBHandler(LanguageMarkIDBHandler):
    def __init__(self):
        super().__init__(None)


class GoMarkIDBHandler(LanguageMarkIDBHandler):
    def __init__(self):
        super().__init__("Go")


class RustMarkIDBHandler(LanguageMarkIDBHandler):
    def __init__(self):
        super().__init__("Rust")


