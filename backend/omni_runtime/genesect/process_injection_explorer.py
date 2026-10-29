# -*- coding: utf-8 -*-
"""Map process-injection primitives, correlated chains, and execution transitions."""
import csv
import io
import os
import re

import idaapi
import ida_funcs
import ida_kernwin
import idautils
import idc

from genesect.qt_compat import QtCore, QtWidgets
from genesect.ui.components import PageHeader, Card
from genesect.ui.mac_workspace import apply_mac_workspace
from genesect.api_knowledge import normalize_api_name, taxonomy_entry


_explorer = None
_MAX_RESULTS = 200000
_PRIMITIVES = (
    ("Process access", re.compile(r"^(?:__imp_)?(?:OpenProcess|NtOpenProcess|ZwOpenProcess)$", re.I)),
    ("Remote allocation", re.compile(r"^(?:__imp_)?(?:VirtualAllocEx|NtAllocateVirtualMemory|ZwAllocateVirtualMemory)$", re.I)),
    ("Cross-process write", re.compile(r"^(?:__imp_)?(?:WriteProcessMemory|NtWriteVirtualMemory|ZwWriteVirtualMemory)$", re.I)),
    ("Remote protection", re.compile(r"^(?:__imp_)?(?:VirtualProtectEx|NtProtectVirtualMemory|ZwProtectVirtualMemory)$", re.I)),
    ("Remote thread", re.compile(r"^(?:__imp_)?(?:CreateRemoteThread|CreateRemoteThreadEx|NtCreateThreadEx|RtlCreateUserThread)$", re.I)),
    ("APC queue", re.compile(r"^(?:__imp_)?(?:QueueUserAPC|NtQueueApcThread|NtQueueApcThreadEx|ZwQueueApcThread)$", re.I)),
    ("Section creation", re.compile(r"^(?:__imp_)?(?:CreateFileMapping|CreateFileMappingW|CreateFileMappingA|NtCreateSection|ZwCreateSection)$", re.I)),
    ("Section mapping", re.compile(r"^(?:__imp_)?(?:MapViewOfFile|MapViewOfFileEx|NtMapViewOfSection|ZwMapViewOfSection)$", re.I)),
    ("Process creation", re.compile(r"^(?:__imp_)?(?:CreateProcessA|CreateProcessW|CreateProcessAsUserA|CreateProcessAsUserW|NtCreateUserProcess)$", re.I)),
    ("Image unmap", re.compile(r"^(?:__imp_)?(?:NtUnmapViewOfSection|ZwUnmapViewOfSection)$", re.I)),
    ("Thread context", re.compile(r"^(?:__imp_)?(?:GetThreadContext|SetThreadContext|Wow64GetThreadContext|Wow64SetThreadContext|NtGetContextThread|NtSetContextThread)$", re.I)),
    ("Execution resume", re.compile(r"^(?:__imp_)?(?:ResumeThread|NtResumeThread|ZwResumeThread)$", re.I)),
    ("Thread hijack", re.compile(r"^(?:__imp_)?(?:SuspendThread|NtSuspendThread|SetThreadContext|NtSetContextThread)$", re.I)),
)


def _hex(value):
    return "0x%X" % int(value)


def _func_start(ea):
    func = ida_funcs.get_func(ea)
    return int(func.start_ea) if func else idaapi.BADADDR


def _func_name(ea):
    start = _func_start(ea)
    return idc.get_func_name(start) or ("sub_%X" % start if start != idaapi.BADADDR else "")


def _row(category, site, primitive="", technique="", confidence="high", evidence="", detail=""):
    owner = _func_start(site)
    return {
        "category": category, "site": int(site), "owner_ea": owner,
        "function": _func_name(site), "primitive": primitive, "technique": technique,
        "confidence": confidence, "evidence": evidence, "detail": detail,
    }


def _api_calls():
    for api_ea, api_name in idautils.Names():
        normalized = normalize_api_name(api_name)
        category = next((label for label, pattern in _PRIMITIVES if pattern.search(normalized)), None)
        if not category:
            continue
        for xref in idautils.XrefsTo(api_ea, 0):
            if xref.type in (getattr(idaapi, "fl_CF", 16), getattr(idaapi, "fl_CN", 17)):
                owner = _func_start(xref.frm)
                if owner != idaapi.BADADDR:
                    yield category, int(xref.frm), normalized


def _has_create_suspended(site, limit=20):
    """Require local CREATE_SUSPENDED (0x4) argument evidence; do not infer it from CreateProcess alone."""
    owner = _func_start(site)
    cursor = int(site)
    for _index in range(limit):
        cursor = idc.prev_head(cursor)
        if cursor == idaapi.BADADDR or _func_start(cursor) != owner:
            break
        mnemonic = (idc.print_insn_mnem(cursor) or "").lower()
        operand = 0 if mnemonic == "push" else 1 if mnemonic in ("mov", "movz", "orr") else -1
        if operand >= 0 and idc.get_operand_type(cursor, operand) == 5:
            value = int(idc.get_operand_value(cursor, operand))
            destination = (idc.print_operand(cursor, 0) or "").lower()
            plausible_destination = mnemonic == "push" or destination in ("r9", "r9d") or "sp" in destination
            if plausible_destination and value and value & 0x4:
                return cursor
    return idaapi.BADADDR


def scan_injection_primitives():
    rows, by_function = [], {}
    for category, site, api_name in _api_calls():
        detail = idc.generate_disasm_line(site, 0) or ""
        taxonomy = taxonomy_entry(api_name)
        if taxonomy:
            detail += "\nTaxonomy: %s (%s)" % (taxonomy["category"], taxonomy["severity"])
        if category == "Process creation":
            flag_site = _has_create_suspended(site)
            if flag_site != idaapi.BADADDR:
                category = "Suspended process"
                detail += "\nCREATE_SUSPENDED flag evidence at %s" % _hex(flag_site)
        by_function.setdefault(_func_start(site), {}).setdefault(category, []).append((site, api_name))
        rows.append(_row(category, site, api_name, evidence="direct call to injection-relevant API", detail=detail))
    return rows, by_function


def _stage_summary(stages, required):
    parts = []
    for stage in required:
        calls = stages.get(stage, [])
        if calls:
            site, name = calls[0]
            parts.append("%s: %s at %s" % (stage, name, _hex(site)))
    return "; ".join(parts)


def _chain(rows, func_ea, stages, technique, required, optional=()):
    if not all(stage in stages for stage in required):
        return
    matched = list(required) + [stage for stage in optional if stage in stages]
    sites = [stages[stage][0][0] for stage in matched]
    rows.append(_row(
        "Correlated injection chain", min(sites), ", ".join(matched), technique,
        "high" if len(required) >= 3 else "medium",
        "compatible injection stages occur in the same function",
        _stage_summary(stages, matched),
    ))


def correlate_injection_chains(by_function):
    rows = []
    for func_ea, stages in by_function.items():
        _chain(rows, func_ea, stages, "Remote-thread injection",
               ("Process access", "Remote allocation", "Cross-process write", "Remote thread"),
               ("Remote protection",))
        _chain(rows, func_ea, stages, "APC injection",
               ("Cross-process write", "APC queue"),
               ("Process access", "Remote allocation", "Execution resume"))
        _chain(rows, func_ea, stages, "Section-mapping injection",
               ("Section creation", "Section mapping"),
               ("Process access", "Remote thread", "APC queue"))
        _chain(rows, func_ea, stages, "Process hollowing",
               ("Suspended process", "Image unmap", "Cross-process write", "Thread context", "Execution resume"),
               ("Remote allocation", "Section mapping"))
        _chain(rows, func_ea, stages, "Thread-context hijacking",
               ("Thread hijack", "Thread context", "Execution resume"),
               ("Process access", "Cross-process write"))
    return rows


def scan_execution_transitions(by_function):
    rows = []
    transition_categories = {"Remote thread", "APC queue", "Execution resume", "Thread context"}
    for func_ea, stages in by_function.items():
        for category in transition_categories:
            for site, api_name in stages.get(category, []):
                rows.append(_row("Execution transition", site, api_name, category,
                                 "high", "API can transfer execution into a target thread/process",
                                 idc.generate_disasm_line(site, 0) or ""))
    return rows


def explore_process_injection():
    primitives, by_function = scan_injection_primitives()
    rows = primitives + correlate_injection_chains(by_function) + scan_execution_transitions(by_function)
    unique = {}
    for item in rows[:_MAX_RESULTS]:
        unique[(item["category"], item["site"], item["primitive"], item["technique"])] = item
    return sorted(unique.values(), key=lambda item: (item["function"], item["site"], item["category"]))


class ProcessInjectionExplorer(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.rows = []

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        apply_mac_workspace(self.parent)
        root = QtWidgets.QVBoxLayout(self.parent)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)
        header = PageHeader("Process Injection Explorer", "Allocation, cross-process writes, APCs, remote threads, section mapping, hollowing, and execution transitions")
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
        self.filter_edit.setPlaceholderText("Filter functions, APIs, injection techniques, transitions, or evidence...")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.apply_filter)
        root.addWidget(self.filter_edit)
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        table_card = Card()
        self.table = QtWidgets.QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["Category", "Site", "Function", "Primitive / stages", "Technique", "Confidence", "Evidence"])
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
        detail_card = Card("Injection evidence")
        self.details = QtWidgets.QTextBrowser()
        detail_card.add_widget(self.details)
        splitter.addWidget(detail_card)
        splitter.setSizes([1000, 430])
        root.addWidget(splitter, 1)
        self.status = QtWidgets.QLabel("Ready")
        self.status.setProperty("pnMuted", True)
        root.addWidget(self.status)
        QtCore.QTimer.singleShot(0, self.refresh)

    def refresh(self):
        ida_kernwin.show_wait_box("Mapping process-injection behavior...\nPress Cancel to stop safely.")
        try:
            self.rows = explore_process_injection()
        except Exception as exc:
            self.rows = []
            ida_kernwin.warning("Process Injection Explorer failed:\n%s" % exc)
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
                values = [row["category"], _hex(row["site"]), row["function"], row["primitive"], row["technique"], row["confidence"], row["evidence"]]
                for column, value in enumerate(values):
                    item = QtWidgets.QTableWidgetItem(value)
                    item.setData(QtCore.Qt.UserRole, row_index)
                    self.table.setItem(row_index, column, item)
        self.table.resizeColumnsToContents()
        self.table.setColumnWidth(6, max(400, self.table.columnWidth(6)))
        self.table.setSortingEnabled(True)
        self.apply_filter(self.filter_edit.text())
        chains = sum(1 for row in self.rows if row["category"] == "Correlated injection chain")
        self.status.setText("%d records | %d correlated injection chains" % (len(self.rows), chains))

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
        for row_index in range(self.table.rowCount()):
            source = self.rows[int(self.table.item(row_index, 0).data(QtCore.Qt.UserRole))]
            haystack = " ".join(str(value) for value in source.values()).lower()
            self.table.setRowHidden(row_index, bool(needle and needle not in haystack))

    def show_details(self):
        row = self.selected_row()
        if not row:
            self.details.setPlainText("Select a record to inspect its evidence.")
            return
        self.details.setPlainText(
            "Category: %s\nSite: %s\nFunction: %s (%s)\nPrimitive / stages: %s\nTechnique: %s\nConfidence: %s\n\nEvidence: %s\n\nDetails:\n%s\n\nA primitive alone is not proof of injection; correlated chains require compatible stages in one function." % (
                row["category"], _hex(row["site"]), row["function"], _hex(row["owner_ea"]),
                row["primitive"], row["technique"] or "N/A", row["confidence"], row["evidence"], row["detail"],
            )
        )

    def navigate_selected(self, *_args):
        row = self.selected_row()
        if row:
            ida_kernwin.jumpto(row["site"])

    def _csv_text(self, rows):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Category", "Site", "Function", "Function address", "Primitive / stages", "Technique", "Confidence", "Evidence", "Details"])
        for row in rows:
            writer.writerow([row["category"], _hex(row["site"]), row["function"], _hex(row["owner_ea"]), row["primitive"], row["technique"], row["confidence"], row["evidence"], row["detail"]])
        return output.getvalue()

    def copy_selected(self):
        row = self.selected_row()
        if row:
            QtWidgets.QApplication.clipboard().setText(self._csv_text([row]))
            self.status.setText("Copied selected injection record")

    def export_csv(self):
        path, _selected = QtWidgets.QFileDialog.getSaveFileName(self.parent, "Export Process Injection Results", "process_injection.csv", "CSV files (*.csv)")
        if path:
            with open(path, "w", encoding="utf-8-sig", newline="") as handle:
                handle.write(self._csv_text(self.rows))
            self.status.setText("Exported %d records to %s" % (len(self.rows), os.path.basename(path)))

    def OnClose(self, form):
        global _explorer
        if _explorer is self:
            _explorer = None


def show_process_injection_explorer():
    global _explorer
    if _explorer is None:
        _explorer = ProcessInjectionExplorer()
    _explorer.Show("Genesect - Process Injection Explorer", options=ida_kernwin.PluginForm.WOPN_PERSIST)


class ProcessInjectionExplorerHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        show_process_injection_explorer()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
