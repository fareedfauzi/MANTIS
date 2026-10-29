# -*- coding: utf-8 -*-
"""Shared table shell for standalone semantic evidence explorers."""
import csv
import io
import os

import ida_kernwin

from genesect.qt_compat import QtCore, QtWidgets
from genesect.ui.components import Card, PageHeader
from genesect.ui.mac_workspace import apply_mac_workspace


class SemanticExplorerForm(ida_kernwin.PluginForm):
    title = "Semantic Explorer"
    subtitle = "Evidence-backed static analysis"
    columns = ()
    wait_message = "Analyzing semantic evidence..."
    export_name = "semantic_evidence.csv"

    def __init__(self):
        super().__init__()
        self.rows = []

    def scan(self):
        return []

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        apply_mac_workspace(self.parent)
        root = QtWidgets.QVBoxLayout(self.parent)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)
        header = PageHeader(self.title, self.subtitle)
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
        self.filter_edit.setPlaceholderText("Filter findings...")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.apply_filter)
        root.addWidget(self.filter_edit)
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        table_card = Card()
        self.table = QtWidgets.QTableWidget(0, len(self.columns))
        self.table.setHorizontalHeaderLabels([label for _key, label in self.columns])
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
        detail_card = Card("Evidence")
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
        ida_kernwin.show_wait_box(self.wait_message + "\nPress Cancel to stop safely.")
        try:
            self.rows = list(self.scan())
        except Exception as exc:
            self.rows = []
            ida_kernwin.warning("%s failed:\n%s" % (self.title, exc))
        finally:
            ida_kernwin.hide_wait_box()
        self.populate()

    def populate(self):
        self.table.setSortingEnabled(False)
        self.table.clearSpans()
        self.table.clearContents()
        self.table.setRowCount(max(1, len(self.rows)))
        if not self.rows:
            item = QtWidgets.QTableWidgetItem("No results found.")
            item.setFlags(QtCore.Qt.ItemIsEnabled)
            item.setTextAlignment(QtCore.Qt.AlignCenter)
            self.table.setItem(0, 0, item)
            self.table.setSpan(0, 0, 1, max(1, len(self.columns)))
        else:
            for row_index, row in enumerate(self.rows):
                for column, (key, _label) in enumerate(self.columns):
                    item = QtWidgets.QTableWidgetItem(str(row.get(key, "")))
                    item.setData(QtCore.Qt.UserRole, row_index)
                    self.table.setItem(row_index, column, item)
        self.table.resizeColumnsToContents()
        self.table.setSortingEnabled(True)
        self.apply_filter(self.filter_edit.text())
        self.status.setText("%d evidence-backed finding(s)" % len(self.rows))

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
        needle = str(text or "").strip().casefold()
        for row_index in range(self.table.rowCount()):
            item = self.table.item(row_index, 0)
            source = self.rows[int(item.data(QtCore.Qt.UserRole))] if item else {}
            haystack = " ".join(str(value) for value in source.values()).casefold()
            self.table.setRowHidden(row_index, bool(needle and needle not in haystack))

    def show_details(self):
        row = self.selected_row()
        self.details.setPlainText(str(row.get("details", "Select a finding to inspect its evidence.")) if row else "Select a finding to inspect its evidence.")

    def navigate_selected(self, *_args):
        row = self.selected_row()
        if row and row.get("ea") is not None:
            ida_kernwin.jumpto(int(row["ea"]))

    def _csv_text(self, rows):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([label for _key, label in self.columns] + ["Details"])
        for row in rows:
            writer.writerow([row.get(key, "") for key, _label in self.columns] + [row.get("details", "")])
        return output.getvalue()

    def copy_selected(self):
        row = self.selected_row()
        if row:
            QtWidgets.QApplication.clipboard().setText(self._csv_text([row]))
            self.status.setText("Copied selected finding")

    def export_csv(self):
        path, _selected = QtWidgets.QFileDialog.getSaveFileName(self.parent, "Export %s" % self.title, self.export_name, "CSV files (*.csv)")
        if path:
            with open(path, "w", encoding="utf-8-sig", newline="") as handle:
                handle.write(self._csv_text(self.rows))
            self.status.setText("Exported %d findings to %s" % (len(self.rows), os.path.basename(path)))
