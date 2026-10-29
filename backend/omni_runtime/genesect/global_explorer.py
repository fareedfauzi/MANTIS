# -*- coding: utf-8 -*-
"""Interactive global-variable usage explorer for Genesect."""
import csv
import io
import os

import idaapi
import ida_bytes
import ida_funcs
import ida_kernwin
import ida_name
import ida_segment
import ida_xref
import idautils
import idc

from genesect.qt_compat import QtCore, QtWidgets
from genesect.ui.components import PageHeader, Card
from genesect.ui.mac_workspace import apply_mac_workspace


_explorer = None


def _hex(ea):
    return "0x%X" % int(ea)


def _function_label(ea):
    func = ida_funcs.get_func(ea)
    if not func:
        return "<outside function> @ %s" % _hex(ea)
    start = int(func.start_ea)
    return "%s (%s)" % (idc.get_func_name(start) or "sub_%X" % start, _hex(start))


def _is_global_address(ea):
    segment = ida_segment.getseg(ea)
    if not segment or ida_funcs.get_func(ea):
        return False
    return int(getattr(segment, "type", -1)) != int(getattr(ida_segment, "SEG_CODE", 2))


def _canonical_data_ea(ea):
    try:
        head = ida_bytes.get_item_head(ea)
        return int(head if head != idaapi.BADADDR else ea)
    except Exception:
        return int(ea)


def discover_global_addresses(name_entries=None):
    """Return named globals and unnamed data items referenced by code."""
    name_entries = list(idautils.Names()) if name_entries is None else name_entries
    addresses = {_canonical_data_ea(ea) for ea, _name in name_entries if _is_global_address(ea)}
    for func_ea in idautils.Functions():
        for item_ea in idautils.FuncItems(func_ea):
            for target in idautils.DataRefsFrom(item_ea):
                if _is_global_address(target):
                    addresses.add(_canonical_data_ea(target))
        if hasattr(ida_kernwin, "user_cancelled") and ida_kernwin.user_cancelled():
            break
    return sorted(addresses)


def _inferred_type(ea, size, flags):
    declared = idc.get_type(ea) or ""
    if declared:
        return declared
    if getattr(ida_bytes, "is_strlit", lambda _flags: False)(flags):
        return "string"
    if getattr(ida_bytes, "is_float", lambda _flags: False)(flags):
        return "float" if size == 4 else "double" if size == 8 else "floating data"
    if getattr(ida_bytes, "is_off0", lambda _flags: False)(flags):
        return "pointer"
    integer_types = {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t"}
    return integer_types.get(size, "byte[%d]" % size)


def _initial_value(ea, size, flags):
    if not ida_bytes.has_value(flags):
        return "uninitialized"
    if getattr(ida_bytes, "is_strlit", lambda _flags: False)(flags):
        value = idc.get_strlit_contents(ea, max(1, min(size, 4096)), idc.get_str_type(ea))
        if isinstance(value, bytes):
            value = value.decode("utf-8", "replace")
        return repr(value) if value is not None else "string"
    raw = ida_bytes.get_bytes(ea, max(1, min(size, 16))) or b""
    if size in (1, 2, 4, 8):
        value = int.from_bytes(raw[:size], byteorder="little", signed=False) if len(raw) >= size else 0
        return "%s (%d)" % (_hex(value), value)
    suffix = " …" if size > 16 else ""
    return raw.hex(" ").upper() + suffix


def _aliases(ea, size, primary_name, name_entries=None):
    aliases = []
    end = ea + max(1, size)
    for named_ea, name in (name_entries if name_entries is not None else idautils.Names()):
        if ea <= named_ea < end and name and name != primary_name:
            aliases.append("%s%s" % (name, " +0x%X" % (named_ea - ea) if named_ea != ea else ""))
    if primary_name:
        demangled = idc.demangle_name(primary_name, idc.get_inf_attr(idc.INF_SHORT_DN))
        if demangled and demangled != primary_name:
            aliases.append(demangled)
    return sorted(set(aliases), key=str.lower)


def inspect_global(ea, name_entries=None):
    flags = ida_bytes.get_flags(ea)
    size = max(1, int(ida_bytes.get_item_size(ea) or 1))
    name = idc.get_name(ea) or "global_%X" % ea
    reads, writes, references = [], [], []
    for target in range(ea, ea + min(size, 4096)):
        for xref in idautils.XrefsTo(target, 0):
            item = {"ea": int(xref.frm), "function": _function_label(int(xref.frm))}
            if xref.type == getattr(ida_xref, "dr_W", 2):
                writes.append(item)
            elif xref.type == getattr(ida_xref, "dr_R", 3):
                reads.append(item)
            else:
                references.append(item)
    dedupe = lambda items: list({(item["ea"], item["function"]): item for item in items}.values())
    reads, writes, references = dedupe(reads), dedupe(writes), dedupe(references)
    functions = sorted({item["function"] for item in reads + writes + references}, key=str.lower)
    aliases = _aliases(ea, size, name, name_entries)
    return {
        "ea": ea, "name": name, "segment": ida_segment.get_segm_name(ida_segment.getseg(ea)) or "",
        "size": size, "type": _inferred_type(ea, size, flags),
        "initial": _initial_value(ea, size, flags), "aliases": aliases,
        "reads": reads, "writes": writes, "references": references, "functions": functions,
    }


def scan_globals():
    name_entries = list(idautils.Names())
    return [inspect_global(ea, name_entries) for ea in discover_global_addresses(name_entries)]


class GlobalVariableExplorer(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.rows = []

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        apply_mac_workspace(self.parent)
        root = QtWidgets.QVBoxLayout(self.parent)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)
        header = PageHeader("Global Variable Explorer", "Reads, writes, initialization, inferred types, aliases, and affected functions")
        self.refresh_btn = QtWidgets.QPushButton("Refresh")
        self.refresh_btn.setProperty("pnVariant", "primary")
        self.refresh_btn.clicked.connect(self.refresh)
        header.add_action(self.refresh_btn)
        self.copy_btn = QtWidgets.QPushButton("Copy Selected")
        self.copy_btn.clicked.connect(self.copy_selected)
        header.add_action(self.copy_btn)
        self.export_btn = QtWidgets.QPushButton("Export CSV")
        self.export_btn.clicked.connect(self.export_csv)
        header.add_action(self.export_btn)
        root.addWidget(header)

        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("Filter by name, address, type, value, alias, or affected function…")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.apply_filter)
        root.addWidget(self.filter_edit)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        table_card = Card()
        self.table = QtWidgets.QTableWidget(0, 10)
        self.table.setHorizontalHeaderLabels([
            "Address", "Name", "Segment", "Type", "Size", "Initial value",
            "Reads", "Writes", "Aliases", "Affected functions",
        ])
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

        detail_card = Card("Selected global")
        self.details = QtWidgets.QTextBrowser()
        self.details.setOpenExternalLinks(False)
        self.details.anchorClicked.connect(self.navigate_link)
        detail_card.add_widget(self.details)
        splitter.addWidget(detail_card)
        splitter.setSizes([950, 420])
        root.addWidget(splitter, 1)
        self.status = QtWidgets.QLabel("Ready")
        self.status.setProperty("pnMuted", True)
        root.addWidget(self.status)
        QtCore.QTimer.singleShot(0, self.refresh)

    def refresh(self):
        ida_kernwin.show_wait_box("Scanning global variables and data references…\nPress Cancel to stop safely.")
        try:
            self.rows = scan_globals()
        except Exception as exc:
            ida_kernwin.warning("Global Variable Explorer scan failed:\n%s" % exc)
            self.rows = []
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
                values = [
                    _hex(row["ea"]), row["name"], row["segment"], row["type"], str(row["size"]), row["initial"],
                    str(len(row["reads"])), str(len(row["writes"])), ", ".join(row["aliases"]),
                    ", ".join(row["functions"]),
                ]
                for column, value in enumerate(values):
                    item = QtWidgets.QTableWidgetItem(value)
                    item.setData(QtCore.Qt.UserRole, row_index)
                    self.table.setItem(row_index, column, item)
        self.table.resizeColumnsToContents()
        self.table.setColumnWidth(9, max(260, self.table.columnWidth(9)))
        self.table.setSortingEnabled(True)
        self.apply_filter(self.filter_edit.text())
        self.status.setText("%d globals • double-click a row to navigate" % len(self.rows))
        self.show_details()

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
        for table_row in range(self.table.rowCount()):
            haystack = " ".join(self.table.item(table_row, col).text() for col in range(self.table.columnCount()) if self.table.item(table_row, col)).lower()
            self.table.setRowHidden(table_row, bool(needle and needle not in haystack))

    def show_details(self):
        row = self.selected_row()
        if not row:
            self.details.setHtml("<p>Select a global to inspect every access site and affected function.</p>")
            return
        def access_section(title, items):
            lines = ["<h3>%s (%d)</h3>" % (title, len(items))]
            lines.extend('<div><a href="ida:%X">%s</a> — %s</div>' % (item["ea"], _hex(item["ea"]), item["function"]) for item in items)
            return "".join(lines)
        self.details.setHtml(
            "<h2>%s</h2><p><b>Address:</b> <a href=\"ida:%X\">%s</a><br>"
            "<b>Type:</b> %s<br><b>Size:</b> %d bytes<br><b>Initial value:</b> %s<br>"
            "<b>Aliases:</b> %s</p>%s%s%s<h3>Affected functions (%d)</h3><div>%s</div>" % (
                row["name"], row["ea"], _hex(row["ea"]), row["type"], row["size"], row["initial"],
                ", ".join(row["aliases"]) or "None", access_section("Reads", row["reads"]),
                access_section("Writes", row["writes"]), access_section("Address references", row["references"]),
                len(row["functions"]), "<br>".join(row["functions"]) or "None",
            )
        )

    def navigate_selected(self, *_args):
        row = self.selected_row()
        if row:
            ida_kernwin.jumpto(row["ea"])

    def navigate_link(self, url):
        text = url.toString()
        if text.startswith("ida:"):
            try:
                ida_kernwin.jumpto(int(text[4:], 16))
            except ValueError:
                pass

    def _csv_text(self, rows):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Address", "Name", "Segment", "Type", "Size", "Initial value", "Reads", "Writes", "Aliases", "Affected functions"])
        for row in rows:
            writer.writerow([_hex(row["ea"]), row["name"], row["segment"], row["type"], row["size"], row["initial"], len(row["reads"]), len(row["writes"]), "; ".join(row["aliases"]), "; ".join(row["functions"])])
        return output.getvalue()

    def copy_selected(self):
        row = self.selected_row()
        if row:
            QtWidgets.QApplication.clipboard().setText(self._csv_text([row]))
            self.status.setText("Copied %s" % row["name"])

    def export_csv(self):
        path, _selected = QtWidgets.QFileDialog.getSaveFileName(self.parent, "Export Global Variables", "global_variables.csv", "CSV files (*.csv)")
        if path:
            with open(path, "w", encoding="utf-8-sig", newline="") as handle:
                handle.write(self._csv_text(self.rows))
            self.status.setText("Exported %d globals to %s" % (len(self.rows), os.path.basename(path)))

    def OnClose(self, form):
        global _explorer
        if _explorer is self:
            _explorer = None


def show_global_variable_explorer():
    global _explorer
    if _explorer is None:
        _explorer = GlobalVariableExplorer()
    _explorer.Show("Genesect - Global Variable Explorer", options=ida_kernwin.PluginForm.WOPN_PERSIST)


class GlobalVariableExplorerHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        show_global_variable_explorer()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
