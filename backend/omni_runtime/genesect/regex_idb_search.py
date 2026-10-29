# -*- coding: utf-8 -*-
"""Regex search across decompilation, disassembly, strings, names, and comments."""
import csv
import io
import os
import re
import time

import idaapi
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import idautils
import idc

from genesect.qt_compat import QtCore, QtWidgets
from genesect.ui.components import PageHeader, Card, ToggleSwitch
from genesect.ui.mac_workspace import apply_mac_workspace


_searcher = None
_MAX_RESULTS = 100000
_MAX_PATTERN_LENGTH = 2048
_MAX_TEXT_LENGTH = 1024 * 1024
_MAX_EXCERPT = 320


def _hex(ea):
    return "0x%X" % int(ea)


def _func_name(ea):
    func = ida_funcs.get_func(ea)
    return idc.get_func_name(func.start_ea) if func else ""


def compile_pattern(pattern, case_sensitive=False):
    pattern = str(pattern or "")
    if not pattern:
        raise ValueError("Enter a regular expression.")
    if len(pattern) > _MAX_PATTERN_LENGTH:
        raise ValueError("The regular expression exceeds %d characters." % _MAX_PATTERN_LENGTH)
    flags = 0 if case_sensitive else re.IGNORECASE
    return re.compile(pattern, flags)


def _excerpt(text, start, end):
    text = str(text or "").replace("\r", " ").replace("\n", " ").replace("\t", " ")
    left = max(0, int(start) - 100)
    right = min(len(text), int(end) + 180)
    value = text[left:right]
    if left:
        value = "…" + value
    if right < len(text):
        value += "…"
    return value[:_MAX_EXCERPT]


def _append_matches(results, regex, scope, ea, text, detail=""):
    if text is None or len(results) >= _MAX_RESULTS:
        return
    text = str(text)[:_MAX_TEXT_LENGTH]
    for match in regex.finditer(text):
        results.append({
            "scope": scope, "ea": int(ea), "function": _func_name(ea),
            "match": match.group(0)[:_MAX_EXCERPT], "excerpt": _excerpt(text, match.start(), match.end()),
            "detail": detail,
        })
        if len(results) >= _MAX_RESULTS:
            break


def search_names(regex, results):
    for ea, name in idautils.Names():
        _append_matches(results, regex, "Name", ea, name)
        if len(results) >= _MAX_RESULTS or ida_kernwin.user_cancelled():
            break


def search_strings(regex, results):
    for item in idautils.Strings():
        length = int(getattr(item, "length", len(str(item))))
        _append_matches(results, regex, "String", int(item.ea), str(item), "length %d" % length)
        if len(results) >= _MAX_RESULTS or ida_kernwin.user_cancelled():
            break


def search_disassembly(regex, results):
    for func_ea in idautils.Functions():
        for ea in idautils.FuncItems(func_ea):
            if not ida_bytes.is_code(ida_bytes.get_flags(ea)):
                continue
            line = ida_lines.tag_remove(idc.generate_disasm_line(ea, 0) or idc.GetDisasm(ea) or "")
            _append_matches(results, regex, "Disassembly", ea, line)
            if len(results) >= _MAX_RESULTS:
                return
        if ida_kernwin.user_cancelled():
            break


def search_comments(regex, results):
    for func_ea in idautils.Functions():
        for repeatable in (0, 1):
            comment = idc.get_func_cmt(func_ea, repeatable)
            _append_matches(results, regex, "Function comment", func_ea, comment, "repeatable" if repeatable else "regular")
        for ea in idautils.FuncItems(func_ea):
            for repeatable in (0, 1):
                comment = idc.get_cmt(ea, repeatable)
                _append_matches(results, regex, "Comment", ea, comment, "repeatable" if repeatable else "regular")
            if len(results) >= _MAX_RESULTS:
                return
        if ida_kernwin.user_cancelled():
            break


def search_decompilation(regex, results):
    if not ida_hexrays.init_hexrays_plugin():
        return 0
    failures = 0
    for func_ea in idautils.Functions():
        try:
            cfunc = ida_hexrays.decompile(func_ea)
            pseudocode = cfunc.get_pseudocode() if cfunc else []
            for line_number, line in enumerate(pseudocode, 1):
                text = ida_lines.tag_remove(str(getattr(line, "line", line)))
                _append_matches(results, regex, "Decompilation", func_ea, text, "pseudocode line %d" % line_number)
                if len(results) >= _MAX_RESULTS:
                    return failures
        except Exception:
            failures += 1
        if ida_kernwin.user_cancelled():
            break
    return failures


def search_idb(regex, scopes):
    results, failures = [], 0
    scanners = (
        ("names", search_names), ("strings", search_strings),
        ("disassembly", search_disassembly), ("comments", search_comments),
    )
    for scope, scanner in scanners:
        if scope in scopes and len(results) < _MAX_RESULTS:
            scanner(regex, results)
        if ida_kernwin.user_cancelled():
            break
    if "decompilation" in scopes and len(results) < _MAX_RESULTS and not ida_kernwin.user_cancelled():
        failures = search_decompilation(regex, results)
    return results, failures


class RegexIDBSearch(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.results = []

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        apply_mac_workspace(self.parent)
        root = QtWidgets.QVBoxLayout(self.parent)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)
        header = PageHeader("Regex Search Across IDB", "Search decompilation, disassembly, strings, names, and comments")
        self.export_btn = QtWidgets.QPushButton("Export CSV")
        self.export_btn.clicked.connect(self.export_csv)
        header.add_action(self.export_btn)
        root.addWidget(header)

        search_card = Card()
        search_row = QtWidgets.QHBoxLayout()
        self.pattern_edit = QtWidgets.QLineEdit()
        self.pattern_edit.setPlaceholderText(r"Regular expression, for example: https?://|CreateProcess(?:A|W)")
        self.pattern_edit.setClearButtonEnabled(True)
        self.pattern_edit.returnPressed.connect(self.run_search)
        search_row.addWidget(self.pattern_edit, 1)
        self.case_toggle = ToggleSwitch("Case sensitive")
        search_row.addWidget(self.case_toggle)
        self.search_btn = QtWidgets.QPushButton("Search")
        self.search_btn.setProperty("pnVariant", "primary")
        self.search_btn.clicked.connect(self.run_search)
        search_row.addWidget(self.search_btn)
        search_card.add_layout(search_row)
        scope_row = QtWidgets.QHBoxLayout()
        self.scope_toggles = {}
        for key, label, checked in (
            ("decompilation", "Decompilation", True), ("disassembly", "Disassembly", True),
            ("strings", "Strings", True), ("names", "Names", True), ("comments", "Comments", True),
        ):
            toggle = ToggleSwitch(label)
            toggle.setChecked(checked)
            self.scope_toggles[key] = toggle
            scope_row.addWidget(toggle)
        scope_row.addStretch()
        search_card.add_layout(scope_row)
        root.addWidget(search_card)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        table_card = Card()
        self.table = QtWidgets.QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Scope", "Address", "Function", "Match", "Preview", "Detail"])
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
        details_card = Card("Match context")
        self.details = QtWidgets.QTextBrowser()
        details_card.add_widget(self.details)
        splitter.addWidget(details_card)
        splitter.setSizes([720, 220])
        root.addWidget(splitter, 1)
        self.status = QtWidgets.QLabel("Enter a regular expression and choose the scopes to search.")
        self.status.setProperty("pnMuted", True)
        root.addWidget(self.status)

    def run_search(self):
        try:
            regex = compile_pattern(self.pattern_edit.text(), self.case_toggle.isChecked())
        except (ValueError, re.error) as exc:
            ida_kernwin.warning("Invalid regular expression:\n%s" % exc)
            return
        scopes = {key for key, toggle in self.scope_toggles.items() if toggle.isChecked()}
        if not scopes:
            ida_kernwin.warning("Select at least one IDB search scope.")
            return
        started = time.monotonic()
        ida_kernwin.show_wait_box("Searching the IDB…\nPress Cancel to stop safely.")
        try:
            self.results, failures = search_idb(regex, scopes)
        except Exception as exc:
            self.results, failures = [], 0
            ida_kernwin.warning("Regex IDB search failed:\n%s" % exc)
        finally:
            ida_kernwin.hide_wait_box()
        self.populate()
        elapsed = time.monotonic() - started
        suffix = " • %d functions could not be decompiled" % failures if failures else ""
        capped = " • result limit reached" if len(self.results) >= _MAX_RESULTS else ""
        self.status.setText("%d matches in %.2fs%s%s" % (len(self.results), elapsed, suffix, capped))

    def populate(self):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(max(1, len(self.results)))
        if not self.results:
            item = QtWidgets.QTableWidgetItem('No results found.')
            item.setFlags(QtCore.Qt.ItemIsEnabled)
            item.setTextAlignment(QtCore.Qt.AlignCenter)
            self.table.setItem(0, 0, item)
            self.table.setSpan(0, 0, 1, max(1, self.table.columnCount()))
        else:
            for row_index, result in enumerate(self.results):
                values = [result["scope"], _hex(result["ea"]), result["function"], result["match"], result["excerpt"], result["detail"]]
                for column, value in enumerate(values):
                    item = QtWidgets.QTableWidgetItem(value)
                    item.setData(QtCore.Qt.UserRole, row_index)
                    self.table.setItem(row_index, column, item)
        self.table.resizeColumnsToContents()
        self.table.setColumnWidth(4, max(460, self.table.columnWidth(4)))
        self.table.setSortingEnabled(True)

    def selected_result(self):
        selected = self.table.selectionModel().selectedRows() if self.table.selectionModel() else []
        if not selected:
            return None
        item = self.table.item(selected[0].row(), 0)
        index = item.data(QtCore.Qt.UserRole) if item else None
        return self.results[int(index)] if index is not None and 0 <= int(index) < len(self.results) else None

    def show_details(self):
        result = self.selected_result()
        if not result:
            self.details.setPlainText("Select a result to inspect its complete match context.")
            return
        self.details.setPlainText("Scope: %s\nAddress: %s\nFunction: %s\nMatch: %s\nDetail: %s\n\n%s" % (result["scope"], _hex(result["ea"]), result["function"] or "N/A", result["match"], result["detail"] or "N/A", result["excerpt"]))

    def navigate_selected(self, *_args):
        result = self.selected_result()
        if result:
            ida_kernwin.jumpto(result["ea"])

    def _csv_text(self, rows):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Scope", "Address", "Function", "Match", "Preview", "Detail"])
        for result in rows:
            writer.writerow([result["scope"], _hex(result["ea"]), result["function"], result["match"], result["excerpt"], result["detail"]])
        return output.getvalue()

    def export_csv(self):
        if not self.results:
            ida_kernwin.info("Run a search before exporting results.")
            return
        path, _selected = QtWidgets.QFileDialog.getSaveFileName(self.parent, "Export Regex Search Results", "regex_idb_results.csv", "CSV files (*.csv)")
        if path:
            with open(path, "w", encoding="utf-8-sig", newline="") as handle:
                handle.write(self._csv_text(self.results))
            self.status.setText("Exported %d matches to %s" % (len(self.results), os.path.basename(path)))

    def OnClose(self, form):
        global _searcher
        if _searcher is self:
            _searcher = None


def show_regex_idb_search():
    global _searcher
    if _searcher is None:
        _searcher = RegexIDBSearch()
    _searcher.Show("Genesect - Regex Search Across IDB", options=ida_kernwin.PluginForm.WOPN_PERSIST)


class RegexIDBSearchHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        show_regex_idb_search()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
