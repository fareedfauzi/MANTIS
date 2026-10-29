# -*- coding: utf-8 -*-
"""Explore and rank functions by their call graph centrality to identify key utilities and APIs."""
import idaapi
import ida_funcs
import ida_kernwin
import idautils
import idc
import ida_segment

from genesect.qt_compat import QtCore, QtWidgets
from genesect.ui.components import PageHeader, Card
from genesect.ui.mac_workspace import apply_mac_workspace


def _hex(ea):
    return "0x%X" % int(ea)


def scan_function_call_rank():
    rows = []
    
    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue
            
        calls_in = 0
        unique_callers = set()
        recursive_calls = 0
        
        for ref in idautils.XrefsTo(func_ea, 0):
            if ref.type in (getattr(idaapi, "fl_CF", 16), getattr(idaapi, "fl_CN", 17)):
                caller_func = ida_funcs.get_func(ref.frm)
                if caller_func:
                    if caller_func.start_ea == func_ea:
                        recursive_calls += 1
                    else:
                        calls_in += 1
                        unique_callers.add(caller_func.start_ea)
                else:
                    calls_in += 1

        calls_out = 0
        unique_callees = set()
        unknown_callees = 0
        
        for head in idautils.FuncItems(func_ea):
            for ref in idautils.XrefsFrom(head, 0):
                if ref.type in (getattr(idaapi, "fl_CF", 16), getattr(idaapi, "fl_CN", 17)):
                    callee_func = ida_funcs.get_func(ref.to)
                    if callee_func:
                        if callee_func.start_ea != func_ea:
                            calls_out += 1
                            unique_callees.add(callee_func.start_ea)
                    else:
                        calls_out += 1
                        unknown_callees += 1
                        
        name = idc.get_func_name(func_ea) or ""
        seg = ida_segment.getseg(func_ea)
        seg_name = ida_segment.get_segm_name(seg) if seg else ""
        
        # Flags calculation for filtering
        is_lib = bool(func.flags & idaapi.FUNC_LIB)
        is_thunk = bool(func.flags & idaapi.FUNC_THUNK)
        is_import = seg_name.lower() in (".idata", "extern")
        
        rows.append({
            "ea": func_ea,
            "name": name,
            "segment": seg_name,
            "unique_callers": len(unique_callers),
            "calls_in": calls_in,
            "unique_callees": len(unique_callees),
            "calls_out": calls_out,
            "recursive": recursive_calls,
            "unknown_callees": unknown_callees,
            "is_lib": is_lib,
            "is_thunk": is_thunk,
            "is_import": is_import
        })
        
        if ida_kernwin.user_cancelled():
            break
            
    # Sort initially by Unique Callers (desc), Calls In (desc), Calls Out (desc), EA
    return sorted(rows, key=lambda item: (-item["unique_callers"], -item["calls_in"], -item["calls_out"], item["ea"]))


class CallRankingExplorer(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.rows = []

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        apply_mac_workspace(self.parent)
        root = QtWidgets.QVBoxLayout(self.parent)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)
        
        header = PageHeader("Call Centrality Explorer", "Rank functions by incoming and outgoing calls to identify key utilities and dispatchers")
        
        # Actions
        refresh = QtWidgets.QPushButton("Refresh")
        refresh.setProperty("pnVariant", "primary")
        refresh.clicked.connect(self.refresh)
        header.add_action(refresh)
        
        copy = QtWidgets.QPushButton("Copy Selected")
        copy.clicked.connect(self.copy_selected)
        header.add_action(copy)
        
        root.addWidget(header)
        
        # Filters toolbar
        filters_layout = QtWidgets.QHBoxLayout()
        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("Filter by function name, segment, or address...")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.apply_filter)
        filters_layout.addWidget(self.filter_edit, 1)
        
        self.chk_hide_libs = QtWidgets.QCheckBox("Hide Library")
        self.chk_hide_libs.setChecked(True)
        self.chk_hide_libs.toggled.connect(self.apply_filter)
        filters_layout.addWidget(self.chk_hide_libs)
        
        self.chk_hide_thunks = QtWidgets.QCheckBox("Hide Thunks")
        self.chk_hide_thunks.setChecked(True)
        self.chk_hide_thunks.toggled.connect(self.apply_filter)
        filters_layout.addWidget(self.chk_hide_thunks)
        
        self.chk_hide_imports = QtWidgets.QCheckBox("Hide Imports")
        self.chk_hide_imports.setChecked(True)
        self.chk_hide_imports.toggled.connect(self.apply_filter)
        filters_layout.addWidget(self.chk_hide_imports)
        
        self.chk_hide_zero_callers = QtWidgets.QCheckBox("Hide Zero Callers")
        self.chk_hide_zero_callers.setChecked(False)
        self.chk_hide_zero_callers.toggled.connect(self.apply_filter)
        filters_layout.addWidget(self.chk_hide_zero_callers)
        
        root.addLayout(filters_layout)
        
        # Table
        table_card = Card()
        self.table = QtWidgets.QTableWidget(0, 9)
        self.table.setHorizontalHeaderLabels([
            "Address", "Function Name", "Segment", "Unique Callers", "Calls In",
            "Unique Callees", "Calls Out", "Recursive", "Unknown"
        ])
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSortingEnabled(True)
        self.table.itemDoubleClicked.connect(self.navigate_selected)
        
        # Custom sorting logic by setting numeric user roles for number columns
        table_card.add_widget(self.table)
        root.addWidget(table_card, 1)
        
        self.status = QtWidgets.QLabel("Ready")
        self.status.setProperty("pnMuted", True)
        root.addWidget(self.status)
        
        QtCore.QTimer.singleShot(0, self.refresh)

    def refresh(self):
        ida_kernwin.show_wait_box("Scanning call relationships...\nPress Cancel to stop.")
        try:
            self.rows = scan_function_call_rank()
        except Exception as exc:
            self.rows = []
            ida_kernwin.warning("Call Centrality Explorer failed:\n%s" % exc)
        finally:
            ida_kernwin.hide_wait_box()
        self.apply_filter()

    def _add_numeric_item(self, row, col, val):
        item = QtWidgets.QTableWidgetItem()
        item.setData(QtCore.Qt.DisplayRole, val)
        item.setTextAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
        self.table.setItem(row, col, item)

    def apply_filter(self):
        query = self.filter_edit.text().strip().lower()
        hide_libs = self.chk_hide_libs.isChecked()
        hide_thunks = self.chk_hide_thunks.isChecked()
        hide_imports = self.chk_hide_imports.isChecked()
        hide_zero = self.chk_hide_zero_callers.isChecked()
        
        self.table.setRowCount(0)
        self.table.setSortingEnabled(False)
        
        for item in self.rows:
            if hide_libs and item["is_lib"]: continue
            if hide_thunks and item["is_thunk"]: continue
            if hide_imports and item["is_import"]: continue
            if hide_zero and item["unique_callers"] == 0: continue
            
            ea_hex = _hex(item["ea"])
            match = not query or query in item["name"].lower() or query in item["segment"].lower() or query in ea_hex.lower()
            if not match:
                continue
                
            row = self.table.rowCount()
            self.table.insertRow(row)
            
            ea_item = QtWidgets.QTableWidgetItem(ea_hex)
            ea_item.setData(QtCore.Qt.UserRole, item["ea"])
            self.table.setItem(row, 0, ea_item)
            self.table.setItem(row, 1, QtWidgets.QTableWidgetItem(item["name"]))
            self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(item["segment"]))
            
            self._add_numeric_item(row, 3, item["unique_callers"])
            self._add_numeric_item(row, 4, item["calls_in"])
            self._add_numeric_item(row, 5, item["unique_callees"])
            self._add_numeric_item(row, 6, item["calls_out"])
            self._add_numeric_item(row, 7, item["recursive"])
            self._add_numeric_item(row, 8, item["unknown_callees"])
            
        self.table.setSortingEnabled(True)
        self.table.resizeColumnsToContents()
        self.status.setText("Showing %d / %d functions" % (self.table.rowCount(), len(self.rows)))

    def navigate_selected(self, table_item):
        row = table_item.row()
        item = self.table.item(row, 0)
        if not item:
            return
        ea = item.data(QtCore.Qt.UserRole)
        ida_kernwin.jumpto(ea)

    def copy_selected(self):
        selected_rows = sorted(list(set(item.row() for item in self.table.selectedItems())))
        if not selected_rows:
            return
        
        lines = []
        # Header
        lines.append("\t".join(self.table.horizontalHeaderItem(col).text() for col in range(self.table.columnCount())))
        for row in selected_rows:
            lines.append("\t".join(self.table.item(row, col).text() if self.table.item(row, col) else "" for col in range(self.table.columnCount())))
            
        QtWidgets.QApplication.clipboard().setText("\n".join(lines))
        self.status.setText("Copied %d row(s) to clipboard." % len(selected_rows))

    def OnClose(self, form):
        pass


class CallRankingExplorerHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        global _explorer_instance
        _explorer_instance = CallRankingExplorer()
        _explorer_instance.Show("Call Centrality Explorer")
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS
