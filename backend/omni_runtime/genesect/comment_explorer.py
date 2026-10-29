# -*- coding: utf-8 -*-
"""Unified disassembly and Hex-Rays comment explorer."""

import csv
import io
import os

import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import idaapi
import idautils
import idc

from genesect.qt_compat import QtCore, QtWidgets
from genesect.ui.components import Card, PageHeader
from genesect.ui.mac_workspace import apply_mac_workspace


def _hex(ea):
    return "0x%X" % int(ea)


def _function_name(ea):
    func = ida_funcs.get_func(int(ea))
    return ida_funcs.get_func_name(func.start_ea) if func else ""


def _text(value):
    if value is None:
        return ""
    for attribute in ("c_str",):
        method = getattr(value, attribute, None)
        if callable(method):
            try:
                return str(method())
            except Exception:
                pass
    return str(value)


def _iter_user_comments(comments):
    if comments is None:
        return
    items = getattr(comments, "items", None)
    if callable(items):
        try:
            for location, comment in items():
                yield location, comment
            return
        except Exception:
            pass
    try:
        for entry in comments:
            if isinstance(entry, tuple) and len(entry) == 2:
                yield entry
            else:
                try:
                    yield entry, comments[entry]
                except Exception:
                    continue
    except Exception:
        return


def collect_comments():
    rows = []
    seen_function_comments = set()
    for func_ea in idautils.Functions():
        for repeatable in (False, True):
            comment = ida_funcs.get_func_cmt(ida_funcs.get_func(func_ea), repeatable)
            if comment:
                rows.append({"scope": "Function", "kind": "Repeatable" if repeatable else "Regular",
                             "ea": int(func_ea), "function": _function_name(func_ea), "text": str(comment),
                             "repeatable": repeatable})
                seen_function_comments.add((int(func_ea), repeatable))
        if ida_hexrays.init_hexrays_plugin():
            try:
                comments = ida_hexrays.restore_user_cmts(func_ea)
                for location, comment in _iter_user_comments(comments):
                    value = _text(comment).strip()
                    if not value:
                        continue
                    ea = int(getattr(location, "ea", func_ea))
                    rows.append({"scope": "Pseudocode", "kind": "Hex-Rays", "ea": ea,
                                 "function_ea": int(func_ea), "function": _function_name(func_ea),
                                 "text": value, "location": location})
            except Exception:
                pass
    for segment_ea in idautils.Segments():
        end_ea = idc.get_segm_end(segment_ea)
        for ea in idautils.Heads(segment_ea, end_ea):
            if ida_kernwin.user_cancelled():
                return rows
            for repeatable in (False, True):
                if (int(ea), repeatable) in seen_function_comments:
                    continue
                comment = idc.get_cmt(ea, repeatable)
                if comment:
                    rows.append({"scope": "Disassembly", "kind": "Repeatable" if repeatable else "Regular",
                                 "ea": int(ea), "function": _function_name(ea), "text": str(comment),
                                 "repeatable": repeatable})
    unique = {}
    for row in rows:
        key = (row["scope"], row["kind"], row["ea"], row["text"])
        unique[key] = row
    return sorted(unique.values(), key=lambda row: (row["ea"], row["scope"], row["kind"]))


def update_comment(row, new_text):
    if row["scope"] == "Disassembly":
        return bool(idc.set_cmt(row["ea"], new_text, row["repeatable"]))
    if row["scope"] == "Function":
        func = ida_funcs.get_func(row["ea"])
        return bool(func and ida_funcs.set_func_cmt(func, new_text, row["repeatable"]))
    if row["scope"] == "Pseudocode":
        cfunc = ida_hexrays.decompile(row["function_ea"])
        if not cfunc:
            return False
        cfunc.set_user_cmt(row["location"], new_text)
        cfunc.save_user_cmts()
        return True
    return False


class CommentExplorer(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.rows = []

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        apply_mac_workspace(self.parent)
        root = QtWidgets.QVBoxLayout(self.parent)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)
        header = PageHeader("Comment Explorer", "Search, review, edit, and remove assembly, function, and Hex-Rays pseudocode comments")
        refresh = QtWidgets.QPushButton("Refresh")
        refresh.setProperty("pnVariant", "primary")
        refresh.clicked.connect(self.refresh)
        header.add_action(refresh)
        edit = QtWidgets.QPushButton("Edit Selected")
        edit.clicked.connect(self.edit_selected)
        header.add_action(edit)
        delete = QtWidgets.QPushButton("Delete Selected")
        delete.setProperty("pnVariant", "danger")
        delete.clicked.connect(self.delete_selected)
        header.add_action(delete)
        export = QtWidgets.QPushButton("Export CSV")
        export.clicked.connect(self.export_csv)
        header.add_action(export)
        root.addWidget(header)
        filters = QtWidgets.QHBoxLayout()
        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("Filter comments by text, address, function, scope, or kind...")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.apply_filter)
        filters.addWidget(self.filter_edit, 1)
        self.scope_combo = QtWidgets.QComboBox()
        self.scope_combo.addItems(["All comments", "Disassembly", "Pseudocode", "Function"])
        self.scope_combo.currentTextChanged.connect(self.apply_filter)
        filters.addWidget(self.scope_combo)
        root.addLayout(filters)
        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        table_card = Card()
        self.table = QtWidgets.QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Scope", "Kind", "Address", "Function", "Comment", "Length"])
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(False)
        self.table.horizontalHeader().setSectionResizeMode(4, QtWidgets.QHeaderView.Stretch)
        self.table.itemSelectionChanged.connect(self.show_details)
        self.table.itemDoubleClicked.connect(self.navigate_selected)
        table_card.add_widget(self.table)
        splitter.addWidget(table_card)
        detail_card = Card("Full comment")
        self.details = QtWidgets.QPlainTextEdit()
        self.details.setReadOnly(True)
        detail_card.add_widget(self.details)
        splitter.addWidget(detail_card)
        splitter.setSizes([680, 220])
        root.addWidget(splitter, 1)
        self.status = QtWidgets.QLabel("Ready")
        self.status.setProperty("pnMuted", True)
        root.addWidget(self.status)
        QtCore.QTimer.singleShot(0, self.refresh)

    def refresh(self):
        ida_kernwin.show_wait_box("Collecting disassembly and pseudocode comments...\nPress Cancel to stop safely.")
        try:
            self.rows = collect_comments()
        except Exception as exc:
            self.rows = []
            ida_kernwin.warning("Comment Explorer failed:\n%s" % exc)
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
                values = [row["scope"], row["kind"], _hex(row["ea"]), row["function"], row["text"].replace("\n", " "), str(len(row["text"]))]
                for column, value in enumerate(values):
                    item = QtWidgets.QTableWidgetItem(value)
                    item.setData(QtCore.Qt.UserRole, row_index)
                    self.table.setItem(row_index, column, item)
        self.table.resizeColumnsToContents()
        self.table.setColumnWidth(4, max(420, self.table.columnWidth(4)))
        self.table.setSortingEnabled(True)
        self.apply_filter()
        counts = {scope: sum(1 for row in self.rows if row["scope"] == scope) for scope in ("Disassembly", "Pseudocode", "Function")}
        self.status.setText("%d comments | Assembly: %d | Pseudocode: %d | Function: %d" %
                            (len(self.rows), counts["Disassembly"], counts["Pseudocode"], counts["Function"]))

    def selected_row(self):
        selected = self.table.selectionModel().selectedRows() if self.table.selectionModel() else []
        if not selected:
            return None
        item = self.table.item(selected[0].row(), 0)
        index = item.data(QtCore.Qt.UserRole) if item else None
        return self.rows[int(index)] if index is not None else None

    def apply_filter(self, *_args):
        if not getattr(self, 'rows', None):
            return
        needle = self.filter_edit.text().strip().lower()
        scope = self.scope_combo.currentText()
        for table_row in range(self.table.rowCount()):
            item = self.table.item(table_row, 0)
            row = self.rows[int(item.data(QtCore.Qt.UserRole))]
            scope_match = scope == "All comments" or row["scope"] == scope
            text_match = not needle or needle in " ".join(str(row.get(key, "")) for key in ("scope", "kind", "ea", "function", "text")).lower()
            self.table.setRowHidden(table_row, not (scope_match and text_match))

    def show_details(self):
        row = self.selected_row()
        if not row:
            self.details.setPlainText("Select a comment to inspect its full text.")
            return
        self.details.setPlainText("%s %s comment\nAddress: %s\nFunction: %s\n\n%s" %
                                  (row["scope"], row["kind"], _hex(row["ea"]), row["function"] or "N/A", row["text"]))

    def navigate_selected(self, *_args):
        row = self.selected_row()
        if row:
            ida_kernwin.jumpto(row["ea"])
            if row["scope"] == "Pseudocode":
                ida_hexrays.open_pseudocode(row["function_ea"], 0)

    def edit_selected(self):
        row = self.selected_row()
        if not row:
            ida_kernwin.info("Select a comment to edit.")
            return
        text, accepted = QtWidgets.QInputDialog.getMultiLineText(self.parent, "Edit Comment", "%s at %s" % (row["scope"], _hex(row["ea"])), row["text"])
        if accepted and text != row["text"]:
            if update_comment(row, text):
                self.refresh()
            else:
                ida_kernwin.warning("IDA rejected the comment update.")

    def delete_selected(self):
        row = self.selected_row()
        if not row:
            ida_kernwin.info("Select a comment to delete.")
            return
        answer = QtWidgets.QMessageBox.question(self.parent, "Delete Comment",
            "Delete the selected %s comment at %s?" % (row["scope"].lower(), _hex(row["ea"])),
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No, QtWidgets.QMessageBox.No)
        if answer == QtWidgets.QMessageBox.Yes:
            if update_comment(row, ""):
                self.refresh()
            else:
                ida_kernwin.warning("IDA rejected the comment deletion.")

    def _csv(self):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Scope", "Kind", "Address", "Function", "Comment"])
        for row in self.rows:
            writer.writerow([row["scope"], row["kind"], _hex(row["ea"]), row["function"], row["text"]])
        return output.getvalue()

    def export_csv(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self.parent, "Export Comments", "genesect_comments.csv", "CSV files (*.csv)")
        if path:
            with open(path, "w", encoding="utf-8-sig", newline="") as handle:
                handle.write(self._csv())
            self.status.setText("Exported %d comments to %s" % (len(self.rows), os.path.basename(path)))

    def OnClose(self, form):
        global _explorer
        if _explorer is self:
            _explorer = None


_explorer = None


def show_comment_explorer():
    global _explorer
    if _explorer is None:
        _explorer = CommentExplorer()
    _explorer.Show("Genesect - Comment Explorer", options=ida_kernwin.PluginForm.WOPN_PERSIST)


class CommentExplorerHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        show_comment_explorer()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
