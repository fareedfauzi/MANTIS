# -*- coding: utf-8 -*-
"""Dockable runtime trace viewer for imported runtime artifacts."""

from __future__ import annotations

import csv
import json

import idaapi

from genesect.config import CONFIG
from genesect.coverage_overlay import apply_coverage_overlay, clear_coverage_overlay
from genesect.qt_compat import QtWidgets
from genesect.runtime_artifacts import artifact_summary, load_artifact_from_idb, save_artifact_to_idb
from genesect.runtime_memory import import_regions_from_artifact
from genesect.speakeasy_import import import_speakeasy_report
from genesect.speakeasy_runner import run_speakeasy


class RuntimeTraceViewer(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super(RuntimeTraceViewer, self).__init__(parent)
        self.setWindowTitle("Genesect Runtime Trace")
        self.resize(980, 620)
        self.artifact = load_artifact_from_idb()
        self.rows = []
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        layout = QtWidgets.QVBoxLayout(self)
        top = QtWidgets.QHBoxLayout()
        self.summary_label = QtWidgets.QLabel("")
        top.addWidget(self.summary_label, 1)
        import_btn = QtWidgets.QPushButton("Import Speakeasy JSON")
        run_btn = QtWidgets.QPushButton("Run Speakeasy")
        overlay_btn = QtWidgets.QPushButton("Apply Coverage")
        clear_btn = QtWidgets.QPushButton("Clear Coverage")
        memory_btn = QtWidgets.QPushButton("Import Memory")
        export_btn = QtWidgets.QPushButton("Export CSV")
        top.addWidget(import_btn)
        top.addWidget(run_btn)
        top.addWidget(overlay_btn)
        top.addWidget(clear_btn)
        top.addWidget(memory_btn)
        top.addWidget(export_btn)
        layout.addLayout(top)

        filter_row = QtWidgets.QHBoxLayout()
        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("Filter by API, address, arguments, or summary")
        filter_row.addWidget(self.filter_edit)
        layout.addLayout(filter_row)

        self.table = QtWidgets.QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["#", "Type", "Address", "API", "Return", "Summary"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        layout.addWidget(self.table, 1)

        import_btn.clicked.connect(self.import_speakeasy)
        run_btn.clicked.connect(self.run_speakeasy)
        overlay_btn.clicked.connect(self.apply_overlay)
        clear_btn.clicked.connect(self.clear_overlay)
        memory_btn.clicked.connect(self.import_memory_regions)
        export_btn.clicked.connect(self.export_csv)
        self.filter_edit.textChanged.connect(self.refresh)
        self.table.itemDoubleClicked.connect(self.jump_selected)

    def refresh(self):
        self.rows = []
        if self.artifact:
            query = self.filter_edit.text().strip().lower()
            for event in self.artifact.get("events", []):
                text = json.dumps(event, ensure_ascii=False).lower()
                if query and query not in text:
                    continue
                self.rows.append(event)
        self.table.setRowCount(len(self.rows))
        for row, event in enumerate(self.rows):
            values = [
                str(event.get("index", row)),
                event.get("type", ""),
                event.get("address", ""),
                event.get("api", ""),
                str(event.get("return_value", "")),
                event.get("summary", ""),
            ]
            for column, value in enumerate(values):
                self.table.setItem(row, column, QtWidgets.QTableWidgetItem(str(value)))
        self.table.resizeColumnsToContents()
        self._refresh_summary()

    def _refresh_summary(self):
        if not self.artifact:
            self.summary_label.setText("No runtime artifact loaded.")
            return
        summary = artifact_summary(self.artifact)
        self.summary_label.setText(
            "Source: {source} | Events: {events} | Coverage: {coverage} | Memory: {memory_regions}".format(**summary)
        )

    def import_speakeasy(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Import Speakeasy JSON", "", "JSON (*.json);;All Files (*)")
        if not path:
            return
        try:
            self.artifact = import_speakeasy_report(path)
            save_artifact_to_idb(self.artifact)
            self.refresh()
        except Exception as exc:
            QtWidgets.QMessageBox.warning(self, "Import Failed", str(exc))

    def run_speakeasy(self):
        try:
            target = idaapi.get_input_file_path() or ""
        except Exception:
            target = ""
        if not target:
            QtWidgets.QMessageBox.warning(self, "Speakeasy", "IDA did not report an input file path.")
            return
        answer = QtWidgets.QMessageBox.question(
            self,
            "Run Speakeasy",
            "Run local Speakeasy against this input file?\n\n%s" % target,
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
            QtWidgets.QMessageBox.No,
        )
        if answer != QtWidgets.QMessageBox.Yes:
            return
        try:
            result = run_speakeasy(CONFIG, target)
            if not result.get("ok"):
                QtWidgets.QMessageBox.warning(
                    self,
                    "Speakeasy Failed",
                    "Return code: %s\n\n%s" % (result.get("returncode"), result.get("stderr") or result.get("stdout")),
                )
                return
            self.artifact = import_speakeasy_report(result["output_path"])
            self.refresh()
        except Exception as exc:
            QtWidgets.QMessageBox.warning(self, "Speakeasy Failed", str(exc))

    def apply_overlay(self):
        result = apply_coverage_overlay(self.artifact)
        QtWidgets.QMessageBox.information(self, "Coverage Overlay", result.get("message", "Done."))

    def clear_overlay(self):
        result = clear_coverage_overlay(self.artifact)
        QtWidgets.QMessageBox.information(self, "Coverage Overlay", result.get("message", "Done."))

    def import_memory_regions(self):
        if not self.artifact:
            QtWidgets.QMessageBox.warning(self, "Runtime Memory", "No runtime artifact loaded.")
            return
        answer = QtWidgets.QMessageBox.question(
            self,
            "Import Runtime Memory",
            "Import referenced runtime memory dumps into the IDB?\n\nThis may create segments and patch bytes.",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
            QtWidgets.QMessageBox.No,
        )
        if answer != QtWidgets.QMessageBox.Yes:
            return
        source_report = self.artifact.get("metadata", {}).get("source_report", "")
        root = ""
        if source_report:
            import os
            root = os.path.dirname(source_report)
        result = import_regions_from_artifact(self.artifact, artifact_root=root)
        QtWidgets.QMessageBox.information(self, "Runtime Memory", result.get("message", "Done."))

    def export_csv(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export Runtime Trace CSV", "genesect-runtime-trace.csv", "CSV (*.csv)")
        if not path:
            return
        with open(path, "w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(["index", "type", "address", "api", "return_value", "summary"])
            for event in self.rows:
                writer.writerow([
                    event.get("index", ""),
                    event.get("type", ""),
                    event.get("address", ""),
                    event.get("api", ""),
                    event.get("return_value", ""),
                    event.get("summary", ""),
                ])

    def jump_selected(self):
        row = self.table.currentRow()
        if row < 0 or row >= len(self.rows):
            return
        ea = _ea(self.rows[row].get("address"))
        if ea != idaapi.BADADDR:
            idaapi.jumpto(ea)


class RuntimeTraceViewerHandler(idaapi.action_handler_t):
    _dialog = None

    def activate(self, ctx):
        if RuntimeTraceViewerHandler._dialog is None:
            RuntimeTraceViewerHandler._dialog = RuntimeTraceViewer()
        RuntimeTraceViewerHandler._dialog.show()
        RuntimeTraceViewerHandler._dialog.raise_()
        RuntimeTraceViewerHandler._dialog.activateWindow()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


def _ea(value):
    try:
        return int(str(value), 0) if isinstance(value, str) else int(value)
    except Exception:
        return idaapi.BADADDR
