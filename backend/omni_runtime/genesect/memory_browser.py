# -*- coding: utf-8 -*-
"""User-facing browser for Genesect durable memory records."""

from __future__ import annotations

import json

import idaapi

from genesect.agent import MemoryStore
from genesect.qt_compat import QtWidgets


class MemoryBrowser(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super(MemoryBrowser, self).__init__(parent)
        self.setWindowTitle("Genesect Memory Browser")
        self.resize(1050, 640)
        self.store = MemoryStore()
        self.records = []
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        layout = QtWidgets.QVBoxLayout(self)
        controls = QtWidgets.QHBoxLayout()
        self.query_edit = QtWidgets.QLineEdit()
        self.query_edit.setPlaceholderText("Search durable memory")
        refresh_btn = QtWidgets.QPushButton("Refresh")
        delete_btn = QtWidgets.QPushButton("Delete")
        export_btn = QtWidgets.QPushButton("Export JSON")
        controls.addWidget(self.query_edit, 1)
        controls.addWidget(refresh_btn)
        controls.addWidget(delete_btn)
        controls.addWidget(export_btn)
        layout.addLayout(controls)

        self.table = QtWidgets.QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["ID", "Kind", "Project", "Scope", "Title", "Updated", "Score"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        layout.addWidget(self.table, 1)

        self.detail = QtWidgets.QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setMaximumHeight(190)
        layout.addWidget(self.detail)

        self.query_edit.textChanged.connect(self.refresh)
        refresh_btn.clicked.connect(self.refresh)
        delete_btn.clicked.connect(self.delete_selected)
        export_btn.clicked.connect(self.export_json)
        self.table.itemSelectionChanged.connect(self.show_selected)

    def refresh(self):
        query = self.query_edit.text().strip()
        if query:
            self.records = self.store.search(query, limit=200, include_cross_project=True)
        else:
            self.records = self.store.list_records(limit=200)
        self.table.setRowCount(len(self.records))
        for row, record in enumerate(self.records):
            values = [
                record.get("id", ""),
                record.get("kind", ""),
                record.get("project_id", ""),
                record.get("scope", ""),
                record.get("title", ""),
                str(record.get("updated_at", "")),
                str(record.get("score", "")),
            ]
            for column, value in enumerate(values):
                self.table.setItem(row, column, QtWidgets.QTableWidgetItem(str(value)))
        self.table.resizeColumnsToContents()
        self.show_selected()

    def current_record(self):
        row = self.table.currentRow()
        if row < 0 or row >= len(self.records):
            return None
        return self.records[row]

    def show_selected(self):
        record = self.current_record()
        if not record:
            self.detail.setPlainText("")
            return
        self.detail.setPlainText(json.dumps(record, indent=2, ensure_ascii=False, default=str))

    def delete_selected(self):
        record = self.current_record()
        if not record:
            return
        answer = QtWidgets.QMessageBox.question(
            self,
            "Delete Memory Record",
            "Delete memory record %s?" % record.get("id", ""),
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
            QtWidgets.QMessageBox.No,
        )
        if answer == QtWidgets.QMessageBox.Yes:
            self.store.delete_record(record.get("id", ""))
            self.refresh()

    def export_json(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export Memory JSON", "genesect-memory.json", "JSON (*.json)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(self.records, indent=2, ensure_ascii=False, default=str))


class MemoryBrowserHandler(idaapi.action_handler_t):
    _dialog = None

    def activate(self, ctx):
        if MemoryBrowserHandler._dialog is None:
            MemoryBrowserHandler._dialog = MemoryBrowser()
        MemoryBrowserHandler._dialog.show()
        MemoryBrowserHandler._dialog.raise_()
        MemoryBrowserHandler._dialog.activateWindow()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
