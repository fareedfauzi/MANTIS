# -*- coding: utf-8 -*-
"""Extract typed IOCs and configuration evidence from the active IDB."""
import base64
import csv
import io
import ipaddress
import math
import os
import re
from collections import Counter
from urllib.parse import urlparse

import idaapi
import ida_funcs
import ida_kernwin
import idautils
import idc

from genesect.qt_compat import QtCore, QtWidgets
from genesect.ui.components import PageHeader, Card
from genesect.ui.mac_workspace import apply_mac_workspace
from genesect.api_knowledge import normalize_api_name


_extractor = None
_MAX_RESULTS = 200000
_URL = re.compile(r"\b(?:https?|wss?|ftp)://[^\s\"'<>]+", re.I)
_DOMAIN = re.compile(r"(?<![\w.-])(?:[A-Za-z0-9-]{1,63}\.)+(?:com|net|org|io|dev|ru|cn|info|biz|xyz|top|local|onion)(?::\d{1,5})?(?![\w.-])", re.I)
_IP = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?![\w.])")
_WIN_PATH = re.compile(r"(?:[A-Za-z]:\\|\\\\)[^\r\n\"<>|]{3,}")
_UNIX_PATH = re.compile(r"(?<![\w.])/(?:etc|tmp|var|usr|opt|home|dev|proc|Library|Users)/[^\s\"']+")
_REGISTRY = re.compile(r"(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS)|HKLM|HKCU)\\[^\r\n\"']+", re.I)
_MUTEX_HINT = re.compile(r"(?:global\\|local\\)[^\r\n\"'\\]+", re.I)
_KEY_HINT = re.compile(r"\b(?:api[_ -]?key|secret|token|password|passwd|public[_ -]?key|private[_ -]?key|aes[_ -]?key|rc4[_ -]?key)\b\s*[:=]\s*[^\r\n\"'\s]+", re.I)
_CAMPAIGN_HINT = re.compile(r"\b(?:campaign|bot[_ -]?id|victim[_ -]?id|install[_ -]?id|affiliate|group[_ -]?id|build[_ -]?id)\b\s*[:=]\s*[^\r\n\"'\s]+", re.I)
_BASE64 = re.compile(r"^(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")
_HEX_BLOB = re.compile(r"^(?:[0-9A-Fa-f]{2}){16,}$")
_CONFIG_APIS = re.compile(r"(?:getprivateprofilestring|readfile|fread|regqueryvalue|getenvironmentvariable|(?:^|_)(?:json|xml|yaml|ini|config|decrypt|decode|base64)(?:_|$))", re.I)


def _hex(value):
    return "0x%X" % int(value)


def _func_start(ea):
    func = ida_funcs.get_func(ea)
    return int(func.start_ea) if func else idaapi.BADADDR


def _func_name(ea):
    start = _func_start(ea)
    return idc.get_func_name(start) or ("sub_%X" % start if start != idaapi.BADADDR else "")


def _entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    length = float(len(data))
    return -sum((count / length) * math.log(count / length, 2) for count in counts.values())


def _row(kind, ea, value, role="indicator", confidence="high", evidence="", detail=""):
    return {
        "kind": kind, "ea": int(ea), "function": _func_name(ea), "value": str(value),
        "role": role, "confidence": confidence, "evidence": evidence, "detail": detail,
    }


def _valid_endpoint(value):
    value = value.strip().rstrip(".,;)")
    if _URL.fullmatch(value):
        parsed = urlparse(value)
        return bool(parsed.scheme and parsed.hostname)
    host = value.rsplit(":", 1)[0] if value.count(":") == 1 else value
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_DOMAIN.fullmatch(value))


def _contextual_kind(text):
    if _REGISTRY.search(text):
        return "Registry path"
    if _MUTEX_HINT.search(text):
        return "Mutex / singleton"
    if _KEY_HINT.search(text):
        return "Key / credential"
    if _CAMPAIGN_HINT.search(text):
        return "Campaign / victim ID"
    if _WIN_PATH.search(text) or _UNIX_PATH.search(text):
        return "Filesystem path"
    return ""


def _encoded_candidate(text):
    compact = text.strip()
    if _HEX_BLOB.fullmatch(compact):
        try:
            raw = bytes.fromhex(compact)
            return "Hex-encoded configuration candidate", _entropy(raw)
        except ValueError:
            return None
    if _BASE64.fullmatch(compact):
        try:
            raw = base64.b64decode(compact, validate=True)
            ent = _entropy(raw)
            if len(raw) >= 16 and ent >= 3.0:
                return "Base64-encoded configuration candidate", ent
        except Exception:
            return None
    raw = compact.encode("utf-8", errors="ignore")
    if len(raw) >= 64 and _entropy(raw) >= 5.5 and not re.search(r"\s", compact):
        return "High-entropy configuration candidate", _entropy(raw)
    return None


def scan_strings_and_iocs():
    rows, by_function = [], {}
    for item in idautils.Strings():
        text = str(item).strip()
        if not text:
            continue
        matches = []
        for pattern, kind in ((_URL, "URL"), (_DOMAIN, "Domain"), (_IP, "IP address")):
            for value in pattern.findall(text):
                if _valid_endpoint(value):
                    matches.append((kind, value, "validated network indicator", "high"))
        contextual = _contextual_kind(text)
        if contextual:
            matches.append((contextual, text[:1024], "contextual string pattern", "medium"))
        # Do not relabel already-recognized readable IOCs/paths as opaque data merely
        # because their character distribution happens to have high entropy.
        encoded = None if matches or contextual else _encoded_candidate(text)
        if encoded:
            kind, entropy = encoded
            matches.append((kind, text[:1024], "encoding/entropy heuristic (%.2f bits/byte)" % entropy, "heuristic"))
        xrefs = list(idautils.XrefsTo(int(item.ea), 0))
        sites = [int(xref.frm) for xref in xrefs] or [int(item.ea)]
        for kind, value, evidence, confidence in matches:
            for site in sites:
                role = "referenced" if xrefs else "unreferenced string"
                row = _row(kind, site, value, role, confidence, evidence, text[:2048])
                rows.append(row)
                owner = _func_start(site)
                if owner != idaapi.BADADDR:
                    by_function.setdefault(owner, []).append(row)
        if ida_kernwin.user_cancelled() or len(rows) >= _MAX_RESULTS:
            break
    return rows, by_function


def scan_configuration_readers(evidence_functions=None):
    rows = []
    evidence_functions = set(evidence_functions or ())
    for api_ea, api_name in idautils.Names():
        normalized = normalize_api_name(api_name)
        if not _CONFIG_APIS.search(normalized):
            continue
        for xref in idautils.XrefsTo(api_ea, 0):
            owner = _func_start(xref.frm)
            if xref.type not in (getattr(idaapi, "fl_CF", 16), getattr(idaapi, "fl_CN", 17)) or owner == idaapi.BADADDR:
                continue
            dual_use = normalized.casefold() in {"readfile", "fread"} or bool(re.search(r"(?:json|xml|yaml|decode|base64|config|decrypt)", normalized, re.I))
            if dual_use and owner not in evidence_functions:
                continue
            evidence = "API call corroborated by typed configuration/IOC references in the same function" if dual_use else "explicit configuration-source API"
            rows.append(_row("Configuration reader / decoder", xref.frm, normalized, "parser/decode primitive", "high", evidence, idc.generate_disasm_line(xref.frm, 0) or ""))
    return rows


def correlate_configuration_clusters(by_function):
    rows = []
    for func_ea, indicators in by_function.items():
        kinds = sorted(set(item["kind"] for item in indicators))
        values = []
        for item in indicators:
            if item["value"] not in values:
                values.append(item["value"])
        if len(kinds) < 2 and len(values) < 3:
            continue
        rows.append(_row(
            "Configuration cluster", func_ea, "%d indicators" % len(values), "configuration owner candidate",
            "medium", "multiple typed indicators are referenced by the same function",
            "Types: %s\nValues:\n%s" % (", ".join(kinds), "\n".join(values[:32])),
        ))
    return rows


def extract_configuration_and_iocs():
    rows, by_function = scan_strings_and_iocs()
    rows.extend(scan_configuration_readers(by_function))
    rows.extend(correlate_configuration_clusters(by_function))
    unique = {}
    for item in rows[:_MAX_RESULTS]:
        unique[(item["kind"], item["ea"], item["value"], item["role"])] = item
    return sorted(unique.values(), key=lambda item: (item["kind"], item["function"], item["ea"]))


class ConfigurationIOCExtractor(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.rows = []

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        apply_mac_workspace(self.parent)
        root = QtWidgets.QVBoxLayout(self.parent)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)
        header = PageHeader("Configuration and IOC Extractor", "Configuration clusters, domains, IPs, paths, mutexes, keys, campaign IDs, and encoded candidates")
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
        self.filter_edit.setPlaceholderText("Filter IOC type, value, function, confidence, or evidence...")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.apply_filter)
        root.addWidget(self.filter_edit)
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        table_card = Card()
        self.table = QtWidgets.QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["Type", "Address", "Function", "Value", "Role", "Confidence", "Evidence"])
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
        detail_card = Card("Configuration evidence")
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
        ida_kernwin.show_wait_box("Extracting configuration and IOCs...\nPress Cancel to stop safely.")
        try:
            self.rows = extract_configuration_and_iocs()
        except Exception as exc:
            self.rows = []
            ida_kernwin.warning("Configuration and IOC Extractor failed:\n%s" % exc)
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
                values = [row["kind"], _hex(row["ea"]), row["function"], row["value"], row["role"], row["confidence"], row["evidence"]]
                for column, value in enumerate(values):
                    item = QtWidgets.QTableWidgetItem(value)
                    item.setData(QtCore.Qt.UserRole, row_index)
                    self.table.setItem(row_index, column, item)
        self.table.resizeColumnsToContents()
        self.table.setColumnWidth(3, min(520, max(260, self.table.columnWidth(3))))
        self.table.setColumnWidth(6, max(380, self.table.columnWidth(6)))
        self.table.setSortingEnabled(True)
        self.apply_filter(self.filter_edit.text())
        clusters = sum(1 for row in self.rows if row["kind"] == "Configuration cluster")
        self.status.setText("%d records | %d configuration clusters" % (len(self.rows), clusters))

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
            self.details.setPlainText("Select an IOC or configuration record to inspect its evidence.")
            return
        self.details.setPlainText(
            "Type: %s\nAddress: %s\nFunction: %s\nValue: %s\nRole: %s\nConfidence: %s\n\nEvidence: %s\n\nDetails:\n%s\n\nEncoded and high-entropy candidates require analyst validation and are not claimed as decoded configuration." % (
                row["kind"], _hex(row["ea"]), row["function"] or "N/A", row["value"], row["role"], row["confidence"], row["evidence"], row["detail"],
            )
        )

    def navigate_selected(self, *_args):
        row = self.selected_row()
        if row:
            ida_kernwin.jumpto(row["ea"])

    def _csv_text(self, rows):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Type", "Address", "Function", "Value", "Role", "Confidence", "Evidence", "Details"])
        for row in rows:
            writer.writerow([row["kind"], _hex(row["ea"]), row["function"], row["value"], row["role"], row["confidence"], row["evidence"], row["detail"]])
        return output.getvalue()

    def copy_selected(self):
        row = self.selected_row()
        if row:
            QtWidgets.QApplication.clipboard().setText(self._csv_text([row]))
            self.status.setText("Copied selected configuration record")

    def export_csv(self):
        path, _selected = QtWidgets.QFileDialog.getSaveFileName(self.parent, "Export Configuration and IOCs", "configuration_iocs.csv", "CSV files (*.csv)")
        if path:
            with open(path, "w", encoding="utf-8-sig", newline="") as handle:
                handle.write(self._csv_text(self.rows))
            self.status.setText("Exported %d records to %s" % (len(self.rows), os.path.basename(path)))

    def OnClose(self, form):
        global _extractor
        if _extractor is self:
            _extractor = None


def show_configuration_ioc_extractor():
    global _extractor
    if _extractor is None:
        _extractor = ConfigurationIOCExtractor()
    _extractor.Show("Genesect - Configuration and IOC Extractor", options=ida_kernwin.PluginForm.WOPN_PERSIST)


class ConfigurationIOCExtractorHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        show_configuration_ioc_extractor()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
