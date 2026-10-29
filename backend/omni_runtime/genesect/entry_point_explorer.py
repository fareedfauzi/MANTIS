# -*- coding: utf-8 -*-
"""Unified executable, export, TLS, constructor, initializer, and thread entry explorer."""
import csv
import io
import os
import re

import idaapi
import ida_bytes
import ida_funcs
import ida_ida
import ida_kernwin
import ida_nalt
import ida_segment
import idautils
import idc

from genesect.qt_compat import QtCore, QtWidgets
from genesect.ui.components import PageHeader, Card
from genesect.ui.mac_workspace import apply_mac_workspace
from genesect.thread_sync_explorer import scan_thread_entries


_explorer = None
_INIT_SEGMENT = re.compile(r"(?:\.init_array|\.preinit_array|\.fini_array|\.ctors|\.dtors|__mod_init_func|__mod_term_func|\.crt|xc[auz]|xl[auz])", re.I)
_TLS_NAME = re.compile(r"(?:tls.*callback|callback.*tls|__xl_[a-z]|_xl_[a-z]|\.crt\$xl)", re.I)
_CONSTRUCTOR_NAME = re.compile(r"(?:_global__sub_i|static_initialization|dynamic initializer for|global constructors keyed to|__cxx_global_var_init|mod_init|initializer)", re.I)
_ENTRY_NAME = re.compile(r"^(?:_?main|wmain|winmain|wwinmain|dllmain|driverentry|start|_start|moduleentry|service_main)$", re.I)
_MAX_ARRAY_BYTES = 128 * 1024 * 1024
_MAX_RESULTS = 200000


def _hex(ea):
    return "0x%X" % int(ea)


def _pointer_size():
    return 8 if ida_ida.inf_is_64bit() else 4


def _read_pointer(ea):
    if not ida_bytes.is_loaded(ea):
        return idaapi.BADADDR
    return ida_bytes.get_qword(ea) if _pointer_size() == 8 else ida_bytes.get_dword(ea)


def _func_start(ea):
    func = ida_funcs.get_func(ea)
    return int(func.start_ea) if func else idaapi.BADADDR


def _func_name(ea):
    start = _func_start(ea)
    return idc.get_func_name(start) or ("sub_%X" % start if start != idaapi.BADADDR else idc.get_name(ea) or "")


def _start_ea():
    getter = getattr(ida_ida, "inf_get_start_ea", None)
    if getter:
        try:
            return int(getter())
        except Exception:
            pass
    try:
        return int(idaapi.get_inf_structure().start_ea)
    except Exception:
        return idaapi.BADADDR


def _row(category, ea, name="", origin="", ordinal="", evidence="", confidence="high"):
    start = _func_start(ea)
    target = start if start != idaapi.BADADDR else int(ea)
    return {
        "category": category, "ea": target, "name": name or _func_name(target) or "entry_%X" % target,
        "origin": origin, "ordinal": str(ordinal) if ordinal not in (None, "") else "",
        "evidence": evidence, "confidence": confidence,
    }


def scan_executable_entry_and_exports():
    rows = []
    start = _start_ea()
    if start != idaapi.BADADDR:
        rows.append(_row("Executable entry", start, _func_name(start), "IDA start address", evidence="database executable start address"))
    for index, ordinal, ea, name in idautils.Entries():
        category = "Executable entry" if int(ea) == start else "Export"
        rows.append(_row(category, ea, name, "IDA entry/export table", ordinal, "entry index %s" % index))
    return rows


def scan_named_startup_functions():
    rows = []
    for ea in idautils.Functions():
        name = idc.get_func_name(ea) or ""
        if _ENTRY_NAME.search(name):
            rows.append(_row("Named startup routine", ea, name, "function symbol", evidence="well-known process/module/driver entry name", confidence="symbol-backed"))
        elif _CONSTRUCTOR_NAME.search(name):
            rows.append(_row("Constructor / initializer", ea, name, "function symbol", evidence="compiler startup naming pattern", confidence="symbol-backed"))
    return rows


def scan_tls_callbacks():
    rows = []
    for ea, name in idautils.Names():
        if not _TLS_NAME.search(name or ""):
            continue
        target = _read_pointer(ea)
        if _func_start(target) != idaapi.BADADDR:
            rows.append(_row("TLS callback", target, _func_name(target), name, evidence="function pointer in named TLS callback slot", confidence="high"))
        elif _func_start(ea) != idaapi.BADADDR:
            rows.append(_row("TLS callback", ea, name, "function symbol", evidence="TLS callback naming pattern", confidence="symbol-backed"))
        else:
            rows.append(_row("TLS callback table", ea, name, "named TLS metadata", evidence="TLS callback symbol; target unresolved", confidence="unresolved"))
    return rows


def scan_initialization_arrays():
    rows, scanned = [], 0
    ptr_size = _pointer_size()
    for seg_ea in idautils.Segments():
        segment = ida_segment.getseg(seg_ea)
        if not segment:
            continue
        name = ida_segment.get_segm_name(segment) or ""
        if not _INIT_SEGMENT.search(name):
            continue
        ea = (int(segment.start_ea) + ptr_size - 1) & ~(ptr_size - 1)
        while ea + ptr_size <= segment.end_ea:
            if scanned >= _MAX_ARRAY_BYTES or len(rows) >= _MAX_RESULTS or ida_kernwin.user_cancelled():
                return rows
            scanned += ptr_size
            target = _read_pointer(ea)
            target_start = _func_start(target)
            if target_start != idaapi.BADADDR:
                category = "Finalization array" if re.search(r"fini|dtor|term", name, re.I) else "Initialization array"
                rows.append(_row(category, target_start, _func_name(target_start), name, evidence="function pointer at %s" % _hex(ea), confidence="metadata-backed"))
            ea += ptr_size
    return rows


def scan_named_initialization_ranges():
    """Recover linker arrays even when their subsections were merged into generic data segments."""
    names = {str(name).lower(): int(ea) for ea, name in idautils.Names() if name}
    boundary_patterns = (
        (r"(?:__)?init_array_start", r"(?:__)?init_array_end", "Initialization array"),
        (r"(?:__)?preinit_array_start", r"(?:__)?preinit_array_end", "Initialization array"),
        (r"(?:__)?fini_array_start", r"(?:__)?fini_array_end", "Finalization array"),
        (r"(?:__)?xc_a$", r"(?:__)?xc_z$", "Initialization array"),
        (r"(?:__)?xi_a$", r"(?:__)?xi_z$", "Initialization array"),
        (r"(?:__)?xp_a$", r"(?:__)?xp_z$", "Finalization array"),
        (r"(?:__)?xt_a$", r"(?:__)?xt_z$", "Finalization array"),
    )
    rows, ptr_size = [], _pointer_size()
    for start_pattern, end_pattern, category in boundary_patterns:
        starts = [(name, ea) for name, ea in names.items() if re.search(start_pattern, name, re.I)]
        ends = [(name, ea) for name, ea in names.items() if re.search(end_pattern, name, re.I)]
        for start_name, start_ea in starts:
            later = [(name, ea) for name, ea in ends if ea > start_ea]
            if not later:
                continue
            end_name, end_ea = min(later, key=lambda item: item[1])
            if end_ea - start_ea > _MAX_ARRAY_BYTES:
                continue
            ea = start_ea + ptr_size
            while ea + ptr_size <= end_ea:
                target = _read_pointer(ea)
                target_start = _func_start(target)
                if target_start != idaapi.BADADDR:
                    rows.append(_row(category, target_start, _func_name(target_start), "%s … %s" % (start_name, end_name), evidence="function pointer at %s" % _hex(ea), confidence="metadata-backed"))
                ea += ptr_size
    return rows


def scan_thread_entry_points():
    _thread_rows, entries = scan_thread_entries()
    return [_row("Thread entry", ea, _func_name(ea), api_name, evidence="resolved thread-creation callback argument", confidence="inferred argument") for ea, api_name in entries.items()]


def explore_entry_points():
    rows = []
    for scanner in (scan_executable_entry_and_exports, scan_tls_callbacks, scan_initialization_arrays, scan_named_initialization_ranges, scan_named_startup_functions, scan_thread_entry_points):
        rows.extend(scanner())
        if ida_kernwin.user_cancelled() or len(rows) >= _MAX_RESULTS:
            break
    unique = {}
    for item in rows[:_MAX_RESULTS]:
        unique[(item["category"], item["ea"], item["name"], item["origin"])] = item
    return sorted(unique.values(), key=lambda item: (item["category"], item["ea"], item["name"].lower()))


class EntryPointExplorer(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.rows = []

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        apply_mac_workspace(self.parent)
        root = QtWidgets.QVBoxLayout(self.parent)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)
        header = PageHeader("Entry-Point Explorer", "Executable entries, exports, TLS callbacks, constructors, initialization arrays, and thread starts")
        refresh = QtWidgets.QPushButton("Refresh")
        refresh.setProperty("pnVariant", "primary")
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
        self.filter_edit.setPlaceholderText("Filter by category, name, address, export ordinal, origin, or evidence…")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.apply_filter)
        root.addWidget(self.filter_edit)
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        table_card = Card()
        self.table = QtWidgets.QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["Category", "Address", "Name", "Ordinal", "Origin", "Confidence", "Evidence"])
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
        detail_card = Card("Entry evidence")
        self.details = QtWidgets.QTextBrowser()
        detail_card.add_widget(self.details)
        splitter.addWidget(detail_card)
        splitter.setSizes([980, 400])
        root.addWidget(splitter, 1)
        self.status = QtWidgets.QLabel("Ready")
        self.status.setProperty("pnMuted", True)
        root.addWidget(self.status)
        QtCore.QTimer.singleShot(0, self.refresh)

    def refresh(self):
        ida_kernwin.show_wait_box("Discovering executable and runtime entry points…\nPress Cancel to stop safely.")
        try:
            self.rows = explore_entry_points()
        except Exception as exc:
            self.rows = []
            ida_kernwin.warning("Entry-Point Explorer failed:\n%s" % exc)
        finally:
            ida_kernwin.hide_wait_box()
        self.populate()

    def populate(self):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(max(1, len(self.rows)))
        if not self.rows:
            item = QtWidgets.QTableWidgetItem('No results found.')
            item.setFlags(QtCore.Qt.ItemIsEnabled)
            item.setTextAlignment(QtCore.Qt.AlignCenter)
            self.table.setItem(0, 0, item)
            self.table.setSpan(0, 0, 1, max(1, self.table.columnCount()))
        else:
            for row_index, row in enumerate(self.rows):
                values = [row["category"], _hex(row["ea"]), row["name"], row["ordinal"], row["origin"], row["confidence"], row["evidence"]]
                for column, value in enumerate(values):
                    item = QtWidgets.QTableWidgetItem(value)
                    item.setData(QtCore.Qt.UserRole, row_index)
                    self.table.setItem(row_index, column, item)
        self.table.resizeColumnsToContents()
        self.table.setColumnWidth(6, max(360, self.table.columnWidth(6)))
        self.table.setSortingEnabled(True)
        self.apply_filter(self.filter_edit.text())
        counts = {}
        for row in self.rows:
            counts[row["category"]] = counts.get(row["category"], 0) + 1
        self.status.setText("%d entries • %s" % (len(self.rows), " • ".join("%s: %d" % item for item in sorted(counts.items()))))

    def selected_row(self):
        selected = self.table.selectionModel().selectedRows() if self.table.selectionModel() else []
        if not selected:
            return None
        item = self.table.item(selected[0].row(), 0)
        index = item.data(QtCore.Qt.UserRole) if item else None
        return self.rows[int(index)] if index is not None and 0 <= int(index) < len(self.rows) else None

    def apply_filter(self, text):
        if not getattr(self, 'rows', None):
            return
        needle = str(text or "").strip().lower()
        for row in range(self.table.rowCount()):
            haystack = " ".join(self.table.item(row, column).text() for column in range(self.table.columnCount()) if self.table.item(row, column)).lower()
            self.table.setRowHidden(row, bool(needle and needle not in haystack))

    def show_details(self):
        row = self.selected_row()
        if not row:
            self.details.setPlainText("Select an entry point to inspect its origin and evidence.")
            return
        self.details.setPlainText(
            "Category: %s\nAddress: %s\nName: %s\nExport ordinal: %s\nOrigin: %s\nConfidence: %s\n\nEvidence: %s\n\nThe category identifies why this routine can execute independently of ordinary direct-call flow." % (
                row["category"], _hex(row["ea"]), row["name"], row["ordinal"] or "N/A", row["origin"], row["confidence"], row["evidence"],
            )
        )

    def navigate_selected(self, *_args):
        row = self.selected_row()
        if row:
            ida_kernwin.jumpto(row["ea"])

    def _csv_text(self, rows):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Category", "Address", "Name", "Ordinal", "Origin", "Confidence", "Evidence"])
        for row in rows:
            writer.writerow([row["category"], _hex(row["ea"]), row["name"], row["ordinal"], row["origin"], row["confidence"], row["evidence"]])
        return output.getvalue()

    def copy_selected(self):
        row = self.selected_row()
        if row:
            QtWidgets.QApplication.clipboard().setText(self._csv_text([row]))
            self.status.setText("Copied %s" % row["name"])

    def export_csv(self):
        path, _selected = QtWidgets.QFileDialog.getSaveFileName(self.parent, "Export Entry Points", "entry_points.csv", "CSV files (*.csv)")
        if path:
            with open(path, "w", encoding="utf-8-sig", newline="") as handle:
                handle.write(self._csv_text(self.rows))
            self.status.setText("Exported %d entries to %s" % (len(self.rows), os.path.basename(path)))

    def OnClose(self, form):
        global _explorer
        if _explorer is self:
            _explorer = None


def show_entry_point_explorer():
    global _explorer
    if _explorer is None:
        _explorer = EntryPointExplorer()
    _explorer.Show("Genesect - Entry-Point Explorer", options=ida_kernwin.PluginForm.WOPN_PERSIST)


class EntryPointExplorerHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        show_entry_point_explorer()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
