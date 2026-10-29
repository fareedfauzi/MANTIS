# -*- coding: utf-8 -*-
"""Static thread, synchronization, shared-state, race, and deadlock explorer."""
import csv
import io
import os
import re

import idaapi
import ida_funcs
import ida_kernwin
import ida_segment
import ida_ua
import idautils
import idc

from genesect.qt_compat import QtCore, QtWidgets
from genesect.ui.components import PageHeader, Card
from genesect.ui.mac_workspace import apply_mac_workspace
from genesect.global_explorer import scan_globals
from genesect.api_knowledge import normalize_api_name


_thread_explorer = None
_synchronization_explorer = None
_THREAD_API = re.compile(r"(?:createthread|createremotethread|_beginthreadex?|pthread_create|std::thread|rtlcreateuserthread|ntcreatethread)", re.I)
_SYNC_API = re.compile(
    r"(?:initializecriticalsection(?:ex|andspincount)?|deletecriticalsection|"
    r"(?:enter|tryenter|leave)criticalsection|(?:acquire|release)srwlock(?:exclusive|shared)|"
    r"(?:create|open|release)mutex(?:a|w)?|(?:create|open|release)semaphore(?:ex)?(?:a|w)?|"
    r"(?:create|open|set|reset|pulse)event(?:ex)?(?:a|w)?|"
    r"waitforsingleobject(?:ex)?|waitformultipleobjects(?:ex)?|signalobjectandwait|"
    r"pthread_(?:mutex|rwlock|cond|spin)_(?:init|destroy|lock|trylock|unlock|wait|signal|broadcast)|"
    r"monitorenter|monitorexit|interlocked[a-z0-9_]*|(?:^|_)futex(?:$|_)|std::(?:recursive_)?mutex::(?:lock|try_lock|unlock))", re.I,
)
_QUEUE_API = re.compile(r"(?:queueuserapc|postthreadmessage(?:a|w)?|postmessage(?:a|w)?|sendmessage(?:a|w)?|createiocompletionport|(?:get|post)queuedcompletionstatus(?:ex)?|dispatch_async)", re.I)
_ACQUIRE = re.compile(r"(?:entercriticalsection|acquiresrwlock|waitforsingleobject|waitformultipleobjects|pthread_(?:mutex|rwlock|spin)_lock|monitorenter)", re.I)
_RELEASE = re.compile(r"(?:leavecriticalsection|releasesrwlock|releasemutex|releasesemaphore|setevent|pthread_(?:mutex|rwlock|spin)_unlock|monitorexit)", re.I)
_MAX_GRAPH_FUNCTIONS = 5000
_MAX_GRAPH_DEPTH = 16


def _hex(ea):
    return "0x%X" % int(ea)


def _func_start(ea):
    func = ida_funcs.get_func(ea)
    return int(func.start_ea) if func else idaapi.BADADDR


def _func_name(ea):
    start = _func_start(ea)
    return idc.get_func_name(start) or ("sub_%X" % start if start != idaapi.BADADDR else "")


def _row(category, site, operation, resource="", target=idaapi.BADADDR, evidence="", risk="info", detail=""):
    return {
        "category": category, "site": int(site), "function": _func_name(site) or "<outside function>",
        "operation": operation, "resource": resource or "Unresolved", "target": int(target),
        "target_name": _func_name(target) if target != idaapi.BADADDR else "", "evidence": evidence,
        "risk": risk, "detail": detail,
    }


def _nearby_function_addresses(call_ea, limit=14):
    owner = _func_start(call_ea)
    candidates = {}
    ea = int(call_ea)
    for _index in range(limit):
        ea = idc.prev_head(ea)
        if ea == idaapi.BADADDR or _func_start(ea) != owner:
            break
        for operand in range(3):
            if idc.get_operand_type(ea, operand) in (
                getattr(ida_ua, "o_imm", 5), getattr(ida_ua, "o_mem", 2),
                getattr(ida_ua, "o_near", 7), getattr(ida_ua, "o_far", 6),
            ):
                value = idc.get_operand_value(ea, operand)
                if _func_start(value) != idaapi.BADADDR:
                    candidates[_func_start(value)] = ea
    return candidates


def _nearby_resource(call_ea, limit=10):
    """Find the closest named non-code address used while preparing a synchronization call."""
    owner = _func_start(call_ea)
    ea = int(call_ea)
    for _index in range(limit):
        ea = idc.prev_head(ea)
        if ea == idaapi.BADADDR or _func_start(ea) != owner:
            break
        for operand in range(3):
            operand_type = idc.get_operand_type(ea, operand)
            if operand_type not in (getattr(ida_ua, "o_mem", 2), getattr(ida_ua, "o_imm", 5)):
                continue
            value = idc.get_operand_value(ea, operand)
            segment = ida_segment.getseg(value)
            if segment and not (segment.perm & ida_segment.SEGPERM_EXEC):
                return idc.get_name(value) or _hex(value), int(value), ea
    return "", idaapi.BADADDR, idaapi.BADADDR


def _api_calls(pattern):
    for api_ea, api_name in idautils.Names():
        normalized = normalize_api_name(api_name)
        if not pattern.search(normalized):
            continue
        for xref in idautils.XrefsTo(api_ea, 0):
            if xref.type in (getattr(idaapi, "fl_CF", 16), getattr(idaapi, "fl_CN", 17)) and _func_start(xref.frm) != idaapi.BADADDR:
                yield int(xref.frm), normalized


def scan_thread_entries():
    rows, entries = [], {}
    for call_ea, api_name in _api_calls(_THREAD_API):
        candidates = _nearby_function_addresses(call_ea)
        if candidates:
            for target, setup_ea in candidates.items():
                entries[target] = api_name
                rows.append(_row("Thread entry", call_ea, api_name, target=_func_start(target), evidence="function address prepared before thread creation", risk="high-confidence", detail="argument setup at %s" % _hex(setup_ea)))
        else:
            rows.append(_row("Thread creation", call_ea, api_name, evidence="thread API call; entry argument unresolved", risk="unresolved"))
    return rows, entries


def scan_synchronization():
    rows, sync_by_function = [], {}
    for call_ea, api_name in _api_calls(_SYNC_API):
        resource, resource_ea, setup_ea = _nearby_resource(call_ea)
        owner = _func_start(call_ea)
        operation = "acquire" if _ACQUIRE.search(api_name) else "release/signal" if _RELEASE.search(api_name) else api_name
        evidence = "explicit synchronization API call to %s" % api_name
        if setup_ea != idaapi.BADADDR:
            evidence += "; resource prepared at %s" % _hex(setup_ea)
        item = _row("Synchronization", call_ea, operation, resource, resource_ea, evidence, "high-confidence" if resource else "resource unresolved", api_name)
        rows.append(item)
        sync_by_function.setdefault(owner, []).append(item)
    for items in sync_by_function.values():
        items.sort(key=lambda item: item["site"])
    return rows, sync_by_function


def scan_queue_activity():
    rows = []
    for call_ea, api_name in _api_calls(_QUEUE_API):
        rows.append(_row("Queue / message", call_ea, api_name, evidence="explicit thread queue or message API call", risk="high-confidence"))
    return rows


def scan_sync_and_queues():
    """Compatibility helper for scripts that still request the combined scan."""
    sync_rows, sync_by_function = scan_synchronization()
    return sync_rows + scan_queue_activity(), sync_by_function


def _direct_internal_callees(func_ea):
    result = set()
    func = ida_funcs.get_func(func_ea)
    if not func:
        return result
    for ea in idautils.FuncItems(func.start_ea):
        for target in idautils.CodeRefsFrom(ea, False):
            start = _func_start(target)
            if start != idaapi.BADADDR and start != func.start_ea:
                result.add(start)
    return result


def reachable_functions(entry_ea):
    seen, queue = set(), [(int(entry_ea), 0)]
    while queue and len(seen) < _MAX_GRAPH_FUNCTIONS:
        ea, depth = queue.pop(0)
        if ea in seen:
            continue
        seen.add(ea)
        if depth >= _MAX_GRAPH_DEPTH:
            continue
        queue.extend((callee, depth + 1) for callee in sorted(_direct_internal_callees(ea)) if callee not in seen)
    return seen


def analyze_lock_order(sync_by_function):
    rows, graph = [], {}
    for func_ea, items in sync_by_function.items():
        held = []
        for item in items:
            resource = item["resource"]
            if resource == "Unresolved":
                continue
            if item["operation"] == "acquire":
                for earlier in held:
                    if earlier != resource:
                        graph.setdefault(earlier, set()).add(resource)
                if resource not in held:
                    held.append(resource)
            elif item["operation"] == "release/signal" and resource in held:
                held.remove(resource)

    def path_to(start, goal, visited=None):
        visited = set() if visited is None else visited
        if start == goal:
            return [start]
        if start in visited:
            return []
        visited.add(start)
        for nxt in graph.get(start, ()):
            path = path_to(nxt, goal, visited)
            if path:
                return [start] + path
        return []

    reported = set()
    for left, targets in graph.items():
        for right in targets:
            cycle = path_to(right, left)
            key = tuple(sorted(set([left, right] + cycle)))
            if cycle and key not in reported:
                reported.add(key)
                rows.append(_row("Possible deadlock", 0, "lock-order cycle", " → ".join([left] + cycle), evidence="opposing static lock acquisition order", risk="heuristic", detail="Confirm path feasibility and lock identity dynamically."))
    return rows


def analyze_shared_state(thread_entries, sync_by_function):
    rows = []
    reachable = {entry: reachable_functions(entry) for entry in thread_entries}
    function_to_threads = {}
    for entry, functions in reachable.items():
        for function in functions:
            function_to_threads.setdefault(function, set()).add(entry)
    for global_item in scan_globals():
        write_functions = {_func_start(access["ea"]) for access in global_item["writes"]}
        access_functions = write_functions | {_func_start(access["ea"]) for access in global_item["reads"]}
        involved_threads = set()
        for function in access_functions:
            involved_threads.update(function_to_threads.get(function, set()))
        if len(involved_threads) < 2 or not write_functions:
            continue
        synchronized = any(function in sync_by_function for function in access_functions)
        risk = "review" if synchronized else "possible race"
        evidence = "%d thread entry graphs access this global; %d write sites" % (len(involved_threads), len(global_item["writes"]))
        if synchronized:
            evidence += "; synchronization exists in at least one accessor but protection coverage is unproven"
        rows.append(_row("Shared state", global_item["ea"], "read/write", global_item["name"], global_item["ea"], evidence, risk, "Threads: %s" % ", ".join(_func_name(entry) for entry in sorted(involved_threads))))
    return rows


def explore_threads():
    thread_rows, _entries = scan_thread_entries()
    return sorted(thread_rows + scan_queue_activity(), key=lambda item: (item["category"], item["site"], item["operation"]))


def explore_synchronization():
    _thread_rows, entries = scan_thread_entries()
    sync_rows, sync_by_function = scan_synchronization()
    rows = sync_rows + analyze_lock_order(sync_by_function)
    if entries and not ida_kernwin.user_cancelled():
        rows.extend(analyze_shared_state(entries, sync_by_function))
    return sorted(rows, key=lambda item: (item["category"], item["site"], item["operation"]))


def explore_threads_and_sync():
    """Backward-compatible aggregate used by external scripts."""
    return sorted(explore_threads() + explore_synchronization(), key=lambda item: (item["category"], item["site"], item["operation"]))


class ThreadSynchronizationExplorer(ida_kernwin.PluginForm):
    def __init__(self, mode):
        super().__init__()
        self.mode = mode
        self.rows = []

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        apply_mac_workspace(self.parent)
        root = QtWidgets.QVBoxLayout(self.parent)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)
        is_thread = self.mode == "thread"
        title = "Thread Explorer" if is_thread else "Synchronization Explorer"
        subtitle = "Thread creation, entry points, APCs, queues, and messages" if is_thread else "Explicit locks, waits, signals, shared state, and concurrency-risk candidates"
        header = PageHeader(title, subtitle)
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
        self.filter_edit.setPlaceholderText("Filter thread entries, queues, messages, functions, or risk…" if is_thread else "Filter locks, waits, signals, globals, functions, or risk…")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.apply_filter)
        root.addWidget(self.filter_edit)
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        table_card = Card()
        self.table = QtWidgets.QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels(["Category", "Site", "Function", "Operation", "Resource", "Target", "Risk", "Evidence"])
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
        detail_card = Card("Thread evidence" if is_thread else "Synchronization evidence")
        self.details = QtWidgets.QTextBrowser()
        detail_card.add_widget(self.details)
        splitter.addWidget(detail_card)
        splitter.setSizes([1000, 420])
        root.addWidget(splitter, 1)
        self.status = QtWidgets.QLabel("Ready")
        self.status.setProperty("pnMuted", True)
        root.addWidget(self.status)
        QtCore.QTimer.singleShot(0, self.refresh)

    def refresh(self):
        is_thread = self.mode == "thread"
        activity = "Mapping thread activity…" if is_thread else "Mapping explicit synchronization and shared state…"
        ida_kernwin.show_wait_box(activity + "\nPress Cancel to stop safely.")
        try:
            self.rows = explore_threads() if is_thread else explore_synchronization()
        except Exception as exc:
            self.rows = []
            ida_kernwin.warning(("Thread Explorer" if is_thread else "Synchronization Explorer") + " failed:\n%s" % exc)
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
                values = [row["category"], _hex(row["site"]) if row["site"] else "—", row["function"], row["operation"], row["resource"], _hex(row["target"]) if row["target"] != idaapi.BADADDR else "—", row["risk"], row["evidence"]]
                for column, value in enumerate(values):
                    item = QtWidgets.QTableWidgetItem(value)
                    item.setData(QtCore.Qt.UserRole, row_index)
                    self.table.setItem(row_index, column, item)
        self.table.resizeColumnsToContents()
        self.table.setColumnWidth(7, max(380, self.table.columnWidth(7)))
        self.table.setSortingEnabled(True)
        self.apply_filter(self.filter_edit.text())
        counts = {}
        for row in self.rows:
            counts[row["category"]] = counts.get(row["category"], 0) + 1
        self.status.setText("%d findings • %s" % (len(self.rows), " • ".join("%s: %d" % item for item in sorted(counts.items()))))

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
            source = self.rows[int(self.table.item(row, 0).data(QtCore.Qt.UserRole))]
            haystack += " " + source["detail"].lower()
            self.table.setRowHidden(row, bool(needle and needle not in haystack))

    def show_details(self):
        row = self.selected_row()
        if not row:
            self.details.setPlainText("Select a result to inspect its %s evidence." % ("thread" if self.mode == "thread" else "synchronization"))
            return
        caution = "Thread entry and queue targets are recovered from static call-site evidence; confirm indirect arguments manually." if self.mode == "thread" else "Race and deadlock findings are static candidates; confirm path feasibility and runtime scheduling."
        self.details.setPlainText(
            "Category: %s\nSite: %s\nFunction: %s\nOperation: %s\nResource: %s\nTarget: %s %s\nRisk: %s\n\nEvidence: %s\n\nDetails:\n%s\n\n%s" % (
                row["category"], _hex(row["site"]) if row["site"] else "N/A", row["function"], row["operation"], row["resource"],
                _hex(row["target"]) if row["target"] != idaapi.BADADDR else "N/A", row["target_name"], row["risk"], row["evidence"], row["detail"], caution,
            )
        )

    def navigate_selected(self, *_args):
        row = self.selected_row()
        if row and row["site"]:
            ida_kernwin.jumpto(row["site"])

    def _csv_text(self, rows):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Category", "Site", "Function", "Operation", "Resource", "Target", "Target name", "Risk", "Evidence", "Detail"])
        for row in rows:
            writer.writerow([row["category"], _hex(row["site"]) if row["site"] else "", row["function"], row["operation"], row["resource"], _hex(row["target"]) if row["target"] != idaapi.BADADDR else "", row["target_name"], row["risk"], row["evidence"], row["detail"]])
        return output.getvalue()

    def copy_selected(self):
        row = self.selected_row()
        if row:
            QtWidgets.QApplication.clipboard().setText(self._csv_text([row]))
            self.status.setText("Copied selected %s finding" % ("thread" if self.mode == "thread" else "synchronization"))

    def export_csv(self):
        is_thread = self.mode == "thread"
        title = "Export Thread Results" if is_thread else "Export Synchronization Results"
        filename = "threads.csv" if is_thread else "synchronization.csv"
        path, _selected = QtWidgets.QFileDialog.getSaveFileName(self.parent, title, filename, "CSV files (*.csv)")
        if path:
            with open(path, "w", encoding="utf-8-sig", newline="") as handle:
                handle.write(self._csv_text(self.rows))
            self.status.setText("Exported %d findings to %s" % (len(self.rows), os.path.basename(path)))

    def OnClose(self, form):
        global _thread_explorer, _synchronization_explorer
        if _thread_explorer is self:
            _thread_explorer = None


def show_thread_explorer():
    global _thread_explorer
    if _thread_explorer is None:
        _thread_explorer = ThreadSynchronizationExplorer("thread")
    _thread_explorer.Show("Genesect - Thread Explorer", options=ida_kernwin.PluginForm.WOPN_PERSIST)


class ThreadExplorerHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        show_thread_explorer()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
