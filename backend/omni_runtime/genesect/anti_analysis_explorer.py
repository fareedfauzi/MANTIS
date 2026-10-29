# -*- coding: utf-8 -*-
"""Detect debugger, VM, sandbox, timing, fingerprinting, and control-flow evasion evidence."""
import csv
import io
import os
import re

import idaapi
import ida_funcs
import ida_kernwin
import ida_ua
import idautils
import idc

from genesect.qt_compat import QtCore, QtWidgets
from genesect.ui.components import PageHeader, Card
from genesect.ui.components import ToggleSwitch
from genesect.ui.mac_workspace import apply_mac_workspace
from genesect.api_knowledge import normalize_api_name, taxonomy_entry


_explorer = None
_MAX_RESULTS = 200000
_DEBUG_API = re.compile(r"^(?:__imp_)?(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|ZwQueryInformationProcess|DebugActiveProcess|OutputDebugString[AW]?|NtSetInformationThread)$", re.I)
_TIMING_API = re.compile(r"^(?:__imp_)?(?:GetTickCount64?|QueryPerformanceCounter|QueryPerformanceFrequency|timeGetTime|NtQuerySystemTime|GetSystemTimeAsFileTime|clock_gettime|rdtsc)$", re.I)
_DELAY_API = re.compile(r"^(?:__imp_)?(?:Sleep|SleepEx|NtDelayExecution|ZwDelayExecution|WaitForSingleObject|select|nanosleep|usleep)$", re.I)
_FINGERPRINT_API = re.compile(r"^(?:__imp_)?(?:GetComputerName[AW]?|GetUserName[AW]?|GetVolumeInformation[AW]?|GlobalMemoryStatusEx|GetSystemInfo|GetNativeSystemInfo|EnumProcesses|CreateToolhelp32Snapshot|Process32First[AW]?|Process32Next[AW]?|GetAdaptersAddresses|GetAdaptersInfo|RegQueryValueEx[AW]?|sysctl|uname|gethostname|getuid)$", re.I)
_EXCEPTION_API = re.compile(r"^(?:__imp_)?(?:RaiseException|AddVectoredExceptionHandler|SetUnhandledExceptionFilter|NtRaiseException|signal|sigaction)$", re.I)
_VM_STRING = re.compile(r"(?:\bvmware\b|\bvirtualbox\b|\bvbox(?:guest|service|tray)?\b|\bqemu\b|\bxen\b|\bhyper-?v\b|\bparallels\b|\bsandboxie\b|\bbochs\b|\bkvm\b|\bvirtio\b|\bvmmouse\b|\bvmtoolsd?\b|\bwireshark\b|\bprocmon(?:64)?\b|\bprocess\s+hacker\b|\bida(?:q|64)?(?:\.exe)?\b|\bx64dbg\b|\bollydbg\b)", re.I)
_ENV_STRING = re.compile(r"(?:\\registry\\machine\\hardware|systemmanufacturer|systemproductname|biosversion|videobiosversion|processorname(?:string)?|machineguid|numberofprocessors)", re.I)
_CONDITIONAL_BRANCHES = {"jz", "je", "jnz", "jne", "ja", "jae", "jb", "jbe", "jg", "jge", "jl", "jle", "b.eq", "b.ne", "cbz", "cbnz"}


def _hex(value):
    return "0x%X" % int(value)


def _func_start(ea):
    func = ida_funcs.get_func(ea)
    return int(func.start_ea) if func else idaapi.BADADDR


def _func_name(ea):
    start = _func_start(ea)
    return idc.get_func_name(start) or ("sub_%X" % start if start != idaapi.BADADDR else "")


def _row(category, ea, indicator="", confidence="high", evidence="", detail="", score=100):
    return {
        "category": category, "ea": int(ea), "function": _func_name(ea),
        "indicator": indicator, "confidence": confidence, "evidence": evidence,
        "detail": detail, "score": max(0, min(100, int(score))),
    }


def _api_calls(pattern):
    for api_ea, api_name in idautils.Names():
        normalized = normalize_api_name(api_name)
        if not pattern.search(normalized):
            continue
        for xref in idautils.XrefsTo(api_ea, 0):
            if xref.type in (getattr(idaapi, "fl_CF", 16), getattr(idaapi, "fl_CN", 17)) and _func_start(xref.frm) != idaapi.BADADDR:
                yield int(xref.frm), normalized


def _has_nearby_immediate(site, expected, radius=12):
    """Look around a call for argument constants without assuming one ABI."""
    func_ea = _func_start(site)
    if func_ea == idaapi.BADADDR:
        return False
    items = list(idautils.FuncItems(func_ea))
    try:
        center = items.index(site)
    except ValueError:
        return False
    wanted = {int(value) for value in expected}
    for ea in items[max(0, center - radius):center + radius + 1]:
        for operand in range(3):
            if idc.get_operand_type(ea, operand) == getattr(ida_ua, "o_imm", 5):
                if int(idc.get_operand_value(ea, operand)) in wanted:
                    return True
    return False


def scan_direct_checks():
    rows = []
    explicit_debug = {"isdebuggerpresent", "checkremotedebuggerpresent", "debugactiveprocess"}
    for site, api_name in _api_calls(_DEBUG_API):
        normalized = normalize_api_name(api_name).lower()
        taxonomy = taxonomy_entry(api_name)
        if normalized in explicit_debug:
            score = 90
        elif normalized in ("ntsetinformationthread",) and _has_nearby_immediate(site, {0x11}):
            score = 80  # ThreadHideFromDebugger
        elif normalized in ("ntqueryinformationprocess", "zwqueryinformationprocess") and _has_nearby_immediate(site, {7, 0x1E, 0x1F}):
            score = 75  # debug port/object/flags information classes
        else:
            score = 40
        taxonomy_note = " Taxonomy: %s/%s." % (taxonomy["category"], taxonomy["severity"]) if taxonomy else ""
        rows.append(_row(
            "Debugger check", site, api_name,
            "high" if score >= 80 else ("medium" if score >= 60 else "low"),
            ("explicit debugger check or anti-debug information class" if score >= 75 else "dual-use debugger/process API without a confirmed anti-debug argument") + taxonomy_note,
            idc.generate_disasm_line(site, 0) or "", score,
        ))

    fingerprint_by_func = {}
    for site, api_name in _api_calls(_FINGERPRINT_API):
        fingerprint_by_func.setdefault(_func_start(site), []).append((site, api_name))
    for func_ea, calls in fingerprint_by_func.items():
        distinct = sorted(set(name for _site, name in calls), key=str.lower)
        score = 65 if len(distinct) >= 2 else 30
        rows.append(_row(
            "Environment fingerprint", calls[0][0], ", ".join(distinct[:8]),
            "medium" if score >= 60 else "low",
            "multiple host-characteristic APIs in one function" if score >= 60 else "single host-information API",
            "\n".join("%s: %s" % (_hex(site), name) for site, name in calls[:24]), score,
        ))

    for category, pattern, evidence, score in (
        ("Exception-based anti-analysis", _EXCEPTION_API, "exception API without corroborating debugger behavior", 30),
        ("Delay / sleep", _DELAY_API, "delay primitive without corroborating anti-analysis behavior", 20),
    ):
        for site, api_name in _api_calls(pattern):
            rows.append(_row(category, site, api_name, "low", evidence, idc.generate_disasm_line(site, 0) or "", score))
    return rows


def scan_vm_and_analysis_artifacts():
    rows = []
    environment_by_function = {}
    for item in idautils.Strings():
        text = str(item)
        vm = _VM_STRING.search(text)
        env = _ENV_STRING.search(text)
        if not vm and not env:
            continue
        refs = list(idautils.XrefsTo(int(item.ea), 0))
        if vm:
            # Unreferenced strings are often library/help/debug residue. Keep
            # them available only as weak signals.
            sites = [int(xref.frm) for xref in refs] or [int(item.ea)]
            for site in sites:
                rows.append(_row(
                    "VM / sandbox artifact", site, vm.group(0),
                    "high" if refs else "low",
                    "referenced analysis-environment string" if refs else "unreferenced analysis-tool string",
                    text[:1024], 80 if refs else 25,
                ))
        elif env:
            for xref in refs:
                site = int(xref.frm)
                environment_by_function.setdefault(_func_start(site), []).append(
                    (site, env.group(0), text[:1024])
                )

    for _func_ea, matches in environment_by_function.items():
        indicators = sorted(set(match for _site, match, _text in matches), key=str.lower)
        score = 65 if len(indicators) >= 2 else 30
        rows.append(_row(
            "Environment fingerprint artifact", matches[0][0], ", ".join(indicators[:8]),
            "medium" if score >= 60 else "low",
            "multiple referenced hardware identity strings" if score >= 60 else "single referenced hardware identity string",
            "\n".join("%s: %s" % (_hex(site), text) for site, _match, text in matches[:24]), score,
        ))
    return rows


def scan_special_instructions():
    rows = []
    for func_ea in idautils.Functions():
        items = list(idautils.FuncItems(func_ea))
        for index, ea in enumerate(items):
            mnemonic = (idc.print_insn_mnem(ea) or "").lower()
            if mnemonic == "cpuid":
                follow = items[index + 1:index + 13]
                hypervisor_test = any(
                    (idc.print_insn_mnem(test_ea) or "").lower() in ("bt", "test", "tst")
                    and any(
                        idc.get_operand_type(test_ea, operand) == getattr(ida_ua, "o_imm", 5)
                        and int(idc.get_operand_value(test_ea, operand)) in (0x1F, 0x80000000)
                        for operand in range(3)
                    )
                    for test_ea in follow
                )
                score = 75 if hypervisor_test else 30
                detail_lines = [idc.generate_disasm_line(ea, 0) or ""]
                detail_lines.extend(idc.generate_disasm_line(test_ea, 0) or "" for test_ea in follow[:6])
                rows.append(_row(
                    "VM / CPU probe", ea, "cpuid",
                    "medium" if hypervisor_test else "low",
                    "CPUID followed by a hypervisor-bit test" if hypervisor_test else "CPU identification alone is common and needs a hypervisor-result check",
                    "\n".join(detail_lines), score,
                ))
            elif mnemonic in ("int", "icebp") and (mnemonic == "icebp" or "2d" in (idc.print_operand(ea, 0) or "").lower() or "3" == (idc.print_operand(ea, 0) or "")):
                rows.append(_row("Debugger trap", ea, mnemonic, "high", "debug exception/trap instruction", idc.generate_disasm_line(ea, 0) or "", 90))
        if ida_kernwin.user_cancelled():
            break
    return rows


def scan_correlated_timing_checks():
    rows = []
    timing_by_function = {}
    for site, api_name in _api_calls(_TIMING_API):
        timing_by_function.setdefault(_func_start(site), []).append((site, api_name))
    for func_ea in idautils.Functions():
        for ea in idautils.FuncItems(func_ea):
            mnemonic = (idc.print_insn_mnem(ea) or "").lower()
            if mnemonic in ("rdtsc", "rdtscp"):
                timing_by_function.setdefault(int(func_ea), []).append((int(ea), mnemonic))
    for func_ea, calls in timing_by_function.items():
        arithmetic, comparison = [], []
        for ea in idautils.FuncItems(func_ea):
            mnemonic = (idc.print_insn_mnem(ea) or "").lower()
            if mnemonic in ("sub", "sbb", "subs"):
                arithmetic.append(ea)
            elif mnemonic in ("cmp", "test", "cmn"):
                comparison.append(ea)
        if len(calls) >= 2 and arithmetic and comparison:
            detail = "Sources: %s\nDelta operations: %s\nComparisons: %s" % (
                ", ".join("%s@%s" % (name, _hex(site)) for site, name in calls),
                ", ".join(_hex(ea) for ea in arithmetic[:12]), ", ".join(_hex(ea) for ea in comparison[:12]))
            rows.append(_row("Timing check", calls[0][0], "%d timestamp reads" % len(calls), "medium", "multiple timestamps plus delta arithmetic and comparison in one function", detail, 70))
        else:
            # A timestamp source by itself is normal application behavior and
            # is intentionally omitted. Only the correlated delta/check chain
            # above is useful anti-analysis evidence.
            continue
    return rows


def scan_opaque_predicates():
    rows = []
    zeroing = {"xor", "sub", "eor"}
    for func_ea in idautils.Functions():
        items = list(idautils.FuncItems(func_ea))
        for index, ea in enumerate(items):
            mnemonic = (idc.print_insn_mnem(ea) or "").lower()
            left = (idc.print_operand(ea, 0) or "").strip().lower()
            right = (idc.print_operand(ea, 1) or "").strip().lower()
            if mnemonic not in zeroing or not left or left != right:
                continue
            for later in items[index + 1:index + 5]:
                later_mnemonic = (idc.print_insn_mnem(later) or "").lower()
                if later_mnemonic in _CONDITIONAL_BRANCHES:
                    rows.append(_row("Opaque predicate candidate", later, "%s %s,%s" % (mnemonic, left, right), "low", "deterministic branch pattern; may be ordinary compiler output", "%s\n%s" % (idc.generate_disasm_line(ea, 0) or "", idc.generate_disasm_line(later, 0) or ""), 35))
                    break
                if later_mnemonic == "nop":
                    continue
                if later_mnemonic == "test" and (idc.print_operand(later, 0) or "").strip().lower() == left and (idc.print_operand(later, 1) or "").strip().lower() == left:
                    continue
                if later_mnemonic == "cmp" and (idc.print_operand(later, 0) or "").strip().lower() == left and idc.get_operand_type(later, 1) == getattr(ida_ua, "o_imm", 5):
                    continue
                # Any other flag-writing or unknown instruction invalidates the proof.
                if later_mnemonic:
                    break
    return rows


def scan_control_flow_tricks():
    rows = []
    for func_ea in idautils.Functions():
        indirect = []
        items = list(idautils.FuncItems(func_ea))
        for index, ea in enumerate(items):
            mnemonic = (idc.print_insn_mnem(ea) or "").lower()
            if mnemonic in ("call", "jmp", "br", "blr") and idc.get_operand_type(ea, 0) in (getattr(ida_ua, "o_reg", 1), getattr(ida_ua, "o_phrase", 3), getattr(ida_ua, "o_displ", 4)):
                indirect.append(ea)
            if mnemonic == "ret" and index and (idc.print_insn_mnem(items[index - 1]) or "").lower() == "push":
                push_ea = items[index - 1]
                immediate_target = idc.get_operand_type(push_ea, 0) == getattr(ida_ua, "o_imm", 5)
                rows.append(_row(
                    "Push/return control transfer", ea, "push; ret",
                    "medium" if immediate_target else "low",
                    "immediate target transferred through the stack" if immediate_target else "stack-manipulated return needs review",
                    "%s\n%s" % (idc.generate_disasm_line(push_ea, 0) or "", idc.generate_disasm_line(ea, 0) or ""),
                    65 if immediate_target else 35,
                ))
        if len(indirect) >= 8:
            rows.append(_row("Indirect control-flow cluster", indirect[0], "%d indirect transfers" % len(indirect), "low", "dense indirect transfers may indicate dispatching, virtualization, or ordinary polymorphism", "\n".join("%s: %s" % (_hex(ea), idc.generate_disasm_line(ea, 0) or "") for ea in indirect[:32]), 25))
    return rows


def explore_anti_analysis(include_weak=False):
    rows = []
    for scanner in (scan_direct_checks, scan_vm_and_analysis_artifacts, scan_special_instructions, scan_correlated_timing_checks, scan_opaque_predicates, scan_control_flow_tricks):
        rows.extend(scanner())
        if ida_kernwin.user_cancelled() or len(rows) >= _MAX_RESULTS:
            break
    # A delay becomes meaningful when the same function already contains a
    # substantive debugger, VM, or timing check. Standalone sleeps stay weak.
    corroborated_functions = {
        row["function"] for row in rows
        if row["score"] >= 60 and row["category"] != "Delay / sleep"
    }
    for row in rows:
        if row["category"] == "Delay / sleep" and row["function"] in corroborated_functions:
            row["score"] = 65
            row["confidence"] = "medium"
            row["evidence"] = "delay primitive correlated with anti-analysis evidence in the same function"

    unique = {}
    for row in rows[:_MAX_RESULTS]:
        unique[(row["category"], row["ea"], row["indicator"], row["evidence"])] = row
    filtered = [row for row in unique.values() if include_weak or row["score"] >= 60]
    return sorted(filtered, key=lambda row: (-row["score"], row["category"], row["function"], row["ea"]))


class AntiAnalysisExplorer(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.rows = []

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.settings = QtCore.QSettings("Genesect", "AntiAnalysisExplorer")
        apply_mac_workspace(self.parent)
        root = QtWidgets.QVBoxLayout(self.parent)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)
        header = PageHeader("Anti-Analysis Explorer", "Debugger checks, VM and sandbox probes, timing, fingerprinting, opaque predicates, and control-flow tricks")
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
        self.show_weak = ToggleSwitch("Weak signals")
        self.show_weak.setToolTip("Include standalone, low-confidence indicators such as Sleep, CPUID, timestamp reads, and dispatch clusters")
        self.show_weak.setChecked(str(self.settings.value("show_weak", "false")).lower() == "true")
        self.show_weak.toggled.connect(self.refresh)
        header.add_action(self.show_weak)
        root.addWidget(header)
        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("Filter category, function, indicator, confidence, or evidence...")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.apply_filter)
        root.addWidget(self.filter_edit)
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        table_card = Card()
        self.table = QtWidgets.QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Category", "Address", "Function", "Indicator", "Confidence", "Evidence"])
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
        detail_card = Card("Anti-analysis evidence")
        self.details = QtWidgets.QTextBrowser()
        detail_card.add_widget(self.details)
        splitter.addWidget(detail_card)
        splitter.setSizes([980, 450])
        root.addWidget(splitter, 1)
        self.status = QtWidgets.QLabel("Ready")
        self.status.setProperty("pnMuted", True)
        root.addWidget(self.status)
        QtCore.QTimer.singleShot(0, self.refresh)

    def refresh(self, *_args):
        ida_kernwin.show_wait_box("Scanning anti-analysis behavior...\nPress Cancel to stop safely.")
        try:
            self.rows = explore_anti_analysis(include_weak=self.show_weak.isChecked())
        except Exception as exc:
            self.rows = []
            ida_kernwin.warning("Anti-Analysis Explorer failed:\n%s" % exc)
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
                for column, value in enumerate([row["category"], _hex(row["ea"]), row["function"], row["indicator"], row["confidence"], row["evidence"]]):
                    item = QtWidgets.QTableWidgetItem(value)
                    item.setData(QtCore.Qt.UserRole, row_index)
                    self.table.setItem(row_index, column, item)
        self.table.resizeColumnsToContents()
        self.table.setColumnWidth(5, max(420, self.table.columnWidth(5)))
        self.table.setSortingEnabled(True)
        self.apply_filter(self.filter_edit.text())
        mode = "including weak signals" if self.show_weak.isChecked() else "corroborated signals only"
        self.status.setText("%d anti-analysis records | %s" % (len(self.rows), mode))

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
            row = self.rows[int(self.table.item(row_index, 0).data(QtCore.Qt.UserRole))]
            self.table.setRowHidden(row_index, bool(needle and needle not in " ".join(str(value) for value in row.values()).lower()))

    def show_details(self):
        row = self.selected_row()
        if not row:
            self.details.setPlainText("Select a record to inspect its evidence.")
            return
        self.details.setPlainText("Category: %s\nAddress: %s\nFunction: %s\nIndicator: %s\nConfidence: %s\nEvidence score: %d/100\n\nEvidence: %s\n\nDetails:\n%s\n\nWeak heuristic results can describe legitimate runtime behavior and must be reviewed." % (row["category"], _hex(row["ea"]), row["function"], row["indicator"], row["confidence"], row["score"], row["evidence"], row["detail"]))

    def navigate_selected(self, *_args):
        row = self.selected_row()
        if row:
            ida_kernwin.jumpto(row["ea"])

    def _csv_text(self, rows):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Category", "Address", "Function", "Indicator", "Confidence", "Score", "Evidence", "Details"])
        for row in rows:
            writer.writerow([row["category"], _hex(row["ea"]), row["function"], row["indicator"], row["confidence"], row["score"], row["evidence"], row["detail"]])
        return output.getvalue()

    def copy_selected(self):
        row = self.selected_row()
        if row:
            QtWidgets.QApplication.clipboard().setText(self._csv_text([row]))
            self.status.setText("Copied selected anti-analysis record")

    def export_csv(self):
        path, _selected = QtWidgets.QFileDialog.getSaveFileName(self.parent, "Export Anti-Analysis Results", "anti_analysis.csv", "CSV files (*.csv)")
        if path:
            with open(path, "w", encoding="utf-8-sig", newline="") as handle:
                handle.write(self._csv_text(self.rows))
            self.status.setText("Exported %d records to %s" % (len(self.rows), os.path.basename(path)))

    def OnClose(self, form):
        global _explorer
        self.settings.setValue("show_weak", self.show_weak.isChecked())
        if _explorer is self:
            _explorer = None


def show_anti_analysis_explorer():
    global _explorer
    if _explorer is None:
        _explorer = AntiAnalysisExplorer()
    _explorer.Show("Genesect - Anti-Analysis Explorer", options=ida_kernwin.PluginForm.WOPN_PERSIST)


class AntiAnalysisExplorerHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        show_anti_analysis_explorer()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
