# -*- coding: utf-8 -*-
"""COM GUID reference discovery and reviewable Hex-Rays type inference."""
import csv
import functools
import io
import os
import struct

import idaapi
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_name
import idautils
import idc

from genesect.qt_compat import QtCore, QtWidgets
from genesect.ui.components import PageHeader, Card
from genesect.ui.mac_workspace import apply_mac_workspace

try:
    import winreg
except ImportError:
    winreg = None


_explorer = None
_MAX_CANDIDATES = 250000
_DIRECT_COM_CALLS = {
    "cocreateinstance": (3, 4),
    "cogetcallcontext": (0, 1),
}


def guid_bytes_to_string(data):
    if not data or len(data) < 16:
        return ""
    d1, d2, d3 = struct.unpack("<IHH", bytes(data[:8]))
    tail = bytes(data[8:16])
    return "%08X-%04X-%04X-%s-%s" % (
        d1, d2, d3, tail[:2].hex().upper(), tail[2:].hex().upper()
    )


def _hex(ea):
    return "0x%X" % int(ea)


def _read_guid(ea):
    if ea in (None, idaapi.BADADDR) or not ida_bytes.is_loaded(int(ea)):
        return ""
    raw = ida_bytes.get_bytes(int(ea), 16)
    if not raw or len(raw) != 16 or raw in (b"\0" * 16, b"\xFF" * 16):
        return ""
    return guid_bytes_to_string(raw)


def _registry_value(key, subkey=""):
    if winreg is None:
        return ""
    try:
        target = winreg.OpenKey(key, subkey) if subkey else key
        return str(winreg.QueryValueEx(target, None)[0] or "")
    except OSError:
        return ""


@functools.lru_cache(maxsize=8192)
def resolve_guid(guid):
    """Resolve a GUID from Windows' registered COM classes and interfaces."""
    if winreg is None or not guid:
        return None
    for kind, path in (("Class", "CLSID\\{%s}" % guid), ("Interface", "Interface\\{%s}" % guid)):
        try:
            key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, path)
        except OSError:
            continue
        name = _registry_value(key) or "Unknown %s" % kind
        if kind == "Class":
            module = _registry_value(key, "InprocServer32") or _registry_value(key, "LocalServer32")
        else:
            module = _registry_value(key, "ProxyStubClsid32") or _registry_value(key, "TypeLib")
        return {"kind": kind, "name": name, "module": module or "N/A"}
    return None


def _symbol_identity(ea):
    name = ida_name.get_name(int(ea)) or ""
    lowered = name.lower().lstrip("_")
    if lowered.startswith("clsid_"):
        return {"kind": "Class", "name": name, "module": "IDB symbol"}
    if lowered.startswith(("iid_", "diid_", "libid_", "catid_")):
        return {"kind": "Interface", "name": name, "module": "IDB symbol"}
    return None


def _function_ranges(current_only=False):
    if current_only:
        func = ida_funcs.get_func(ida_kernwin.get_screen_ea())
        return [(int(func.start_ea), int(func.end_ea))] if func else []
    return [(int(ea), int(ida_funcs.get_func(ea).end_ea)) for ea in idautils.Functions() if ida_funcs.get_func(ea)]


def scan_com_guids(current_only=False):
    """Find GUID addresses through real data references, then validate their identity."""
    candidates = {}
    inspected = 0
    for start, end in _function_ranges(current_only):
        for ea in idautils.Heads(start, end):
            inspected += 1
            if inspected > _MAX_CANDIDATES or ida_kernwin.user_cancelled():
                break
            for target in idautils.DataRefsFrom(ea):
                candidates.setdefault(int(target), set()).add(int(ea))
            for operand in range(3):
                if idc.get_operand_type(ea, operand) not in (idc.o_mem, idc.o_imm, idc.o_displ):
                    continue
                target = int(idc.get_operand_value(ea, operand))
                if ida_bytes.is_loaded(target):
                    candidates.setdefault(target, set()).add(int(ea))
        if inspected > _MAX_CANDIDATES or ida_kernwin.user_cancelled():
            break
    # Named GUID constants can be useful even when IDA has not created a data xref.
    if not current_only:
        for ea, name in idautils.Names():
            if str(name).lower().lstrip("_").startswith(("clsid_", "iid_", "diid_", "libid_", "catid_")):
                candidates.setdefault(int(ea), set())

    rows = []
    for guid_ea, use_sites in candidates.items():
        guid = _read_guid(guid_ea)
        identity = resolve_guid(guid) or _symbol_identity(guid_ea)
        if not guid or identity is None:
            continue
        sites = sorted(use_sites) or [guid_ea]
        for use_ea in sites:
            func = ida_funcs.get_func(use_ea)
            func_ea = int(func.start_ea) if func else int(use_ea)
            rows.append({
                "address": int(use_ea), "function_ea": func_ea,
                "function": idc.get_func_name(func_ea) or idc.get_name(func_ea) or "",
                "guid_ea": int(guid_ea), "guid": guid, "name": identity["name"],
                "kind": identity["kind"], "module": identity["module"],
                "evidence": "data reference to GUID at %s" % _hex(guid_ea),
            })
    unique = {(row["address"], row["guid_ea"], row["guid"]): row for row in rows}
    return sorted(unique.values(), key=lambda row: (row["function_ea"], row["address"], row["guid"]))


def _unwrap(expr):
    while expr is not None and expr.op in (ida_hexrays.cot_cast, ida_hexrays.cot_ref):
        expr = expr.x
    return expr


def _expr_guid_ea(expr):
    node = _unwrap(expr)
    if node is not None and node.op == ida_hexrays.cot_obj:
        return int(node.obj_ea)
    ea = int(getattr(expr, "ea", idaapi.BADADDR))
    if ea != idaapi.BADADDR:
        for operand in (1, 0):
            value = idc.get_operand_value(ea, operand)
            if _read_guid(value):
                return int(value)
    return idaapi.BADADDR


def _expr_lvar_index(expr):
    node = _unwrap(expr)
    if node is not None and node.op == ida_hexrays.cot_var:
        return int(node.v.idx)
    return None


def _direct_call_name(call):
    target = _unwrap(call.x)
    if target is None or target.op != ida_hexrays.cot_obj:
        return ""
    name = ida_name.get_name(int(target.obj_ea)) or ""
    return name.lower().replace("__imp_", "").replace("_imp__", "").lstrip("_").split("@", 1)[0]


def _method_name(call):
    node = _unwrap(call.x)
    if node is None or node.op != ida_hexrays.cot_memptr:
        return ""
    try:
        pointed = node.x.type.get_pointed_object()
        member = idaapi.udt_member_t()
        member.offset = int(node.m) * 8
        pointed.find_udt_member(member, idaapi.STRMEM_OFFSET)
        return str(member.name or "")
    except Exception:
        return ""


def _type_candidates(guid_ea, guid):
    names = []
    symbol = ida_name.get_name(int(guid_ea)) or ""
    clean = symbol.lstrip("_")
    for prefix in ("IID_", "DIID_", "CLSID_"):
        if clean.upper().startswith(prefix):
            names.append(clean[len(prefix):])
    resolved = resolve_guid(guid)
    if resolved:
        names.append(resolved["name"])
    result = []
    for value in names:
        value = str(value).strip().replace(" ", "")
        if value and value not in result:
            result.append(value)
    return result


def _find_named_type(candidates):
    for name in candidates:
        tinfo = idaapi.tinfo_t()
        try:
            if tinfo.get_named_type(idaapi.get_idati(), name):
                return name, tinfo
        except Exception:
            continue
    return "", None


class _COMInferenceVisitor(ida_hexrays.ctree_visitor_t):
    def __init__(self, cfunc):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        self.cfunc = cfunc
        self.proposals = []

    def visit_expr(self, expr):
        if expr.op != ida_hexrays.cot_call:
            return 0
        name = _direct_call_name(expr)
        mapping = _DIRECT_COM_CALLS.get(name)
        source = name
        method = _method_name(expr).lower()
        indirect = _unwrap(expr.x)
        looks_like_query_interface = (
            method == "queryinterface" or
            (indirect is not None and indirect.op == ida_hexrays.cot_memptr and int(indirect.m) == 0)
        )
        if mapping is None and looks_like_query_interface and len(expr.a) >= 3:
            mapping, source = (1, 2), "QueryInterface"
        if mapping is None or len(expr.a) <= max(mapping):
            return 0
        guid_ea = _expr_guid_ea(expr.a[mapping[0]])
        variable_index = _expr_lvar_index(expr.a[mapping[1]])
        guid = _read_guid(guid_ea)
        if guid_ea == idaapi.BADADDR or variable_index is None or not guid:
            return 0
        candidates = _type_candidates(guid_ea, guid)
        type_name, tinfo = _find_named_type(candidates)
        variable = self.cfunc.get_lvars()[variable_index]
        self.proposals.append({
            "ea": int(getattr(expr, "ea", self.cfunc.entry_ea)), "guid_ea": guid_ea,
            "guid": guid, "source": source, "variable": str(variable.name),
            "variable_index": variable_index, "type_name": type_name,
            "tinfo": tinfo, "candidates": candidates,
        })
        return 0


def collect_type_inferences(ea=None):
    if not ida_hexrays.init_hexrays_plugin():
        return None, []
    func = ida_funcs.get_func(ida_kernwin.get_screen_ea() if ea is None else ea)
    if not func:
        return None, []
    cfunc = ida_hexrays.decompile(func.start_ea)
    visitor = _COMInferenceVisitor(cfunc)
    visitor.apply_to(cfunc.body, None)
    return cfunc, visitor.proposals


def _pointer_type(base):
    pointer = idaapi.tinfo_t()
    create_ptr = getattr(pointer, "create_ptr", None)
    if callable(create_ptr) and create_ptr(base):
        return pointer
    make_pointer = getattr(idaapi, "make_pointer", None)
    return make_pointer(base) if callable(make_pointer) else None


def apply_type_inferences(cfunc, proposals):
    applied = []
    for proposal in proposals:
        if proposal["tinfo"] is None:
            continue
        pointer = _pointer_type(proposal["tinfo"])
        if pointer is None:
            continue
        try:
            variable = cfunc.get_lvars()[proposal["variable_index"]]
            result = variable.set_final_lvar_type(pointer)
            if result is not False:
                applied.append(proposal)
        except Exception:
            continue
    if applied:
        try:
            cfunc.save_user_lvar_settings()
        except Exception:
            pass
        try:
            cfunc.refresh_func_ctext()
        except Exception:
            idaapi.request_refresh(idaapi.IWID_PSEUDOCODE)
    return applied


class COMExplorer(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.rows = []

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        apply_mac_workspace(self.parent)
        root = QtWidgets.QVBoxLayout(self.parent)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)
        header = PageHeader("COM Explorer", "Track registered COM GUID references and infer Hex-Rays interface types")
        for text, callback, primary in (
            ("Scan Current Function", lambda: self.refresh(True), True),
            ("Scan Entire IDB", lambda: self.refresh(False), False),
            ("Infer Current Function Types", self.infer_types, False),
            ("Export CSV", self.export_csv, False),
        ):
            button = QtWidgets.QPushButton(text)
            if primary:
                button.setProperty("pnVariant", "primary")
            button.clicked.connect(callback)
            header.add_action(button)
        root.addWidget(header)
        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("Filter GUID, COM name, class/interface, function, module, or evidence...")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.apply_filter)
        root.addWidget(self.filter_edit)
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        table_card = Card("COM references")
        self.table = QtWidgets.QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["Address", "Function", "GUID", "Name", "Kind", "Module", "Evidence"])
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
        detail_card = Card("GUID / type evidence")
        self.details = QtWidgets.QTextBrowser()
        detail_card.add_widget(self.details)
        splitter.addWidget(detail_card)
        splitter.setSizes([1050, 420])
        root.addWidget(splitter, 1)
        self.status = QtWidgets.QLabel("Ready")
        self.status.setProperty("pnMuted", True)
        root.addWidget(self.status)
        QtCore.QTimer.singleShot(0, lambda: self.refresh(True))

    def refresh(self, current_only=True):
        ida_kernwin.show_wait_box("Scanning COM GUID references...\nPress Cancel to stop safely.")
        try:
            self.rows = scan_com_guids(current_only)
        except Exception as exc:
            self.rows = []
            ida_kernwin.warning("COM Explorer scan failed:\n%s" % exc)
        finally:
            ida_kernwin.hide_wait_box()
        self.populate()

    def populate(self):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(self.rows))
        for row_index, row in enumerate(self.rows):
            values = [_hex(row["address"]), row["function"], row["guid"], row["name"], row["kind"], row["module"], row["evidence"]]
            for column, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(str(value))
                item.setData(QtCore.Qt.UserRole, row_index)
                self.table.setItem(row_index, column, item)
        self.table.resizeColumnsToContents()
        self.table.setColumnWidth(5, max(220, self.table.columnWidth(5)))
        self.table.setColumnWidth(6, max(300, self.table.columnWidth(6)))
        self.table.setSortingEnabled(True)
        self.apply_filter(self.filter_edit.text())
        self.status.setText("%d COM GUID reference%s" % (len(self.rows), "" if len(self.rows) == 1 else "s"))

    def selected_row(self):
        selected = self.table.selectionModel().selectedRows() if self.table.selectionModel() else []
        if not selected:
            return None
        item = self.table.item(selected[0].row(), 0)
        index = item.data(QtCore.Qt.UserRole) if item else None
        return self.rows[int(index)] if index is not None and 0 <= int(index) < len(self.rows) else None

    def apply_filter(self, text):
        needle = str(text or "").strip().lower()
        for row in range(self.table.rowCount()):
            haystack = " ".join(self.table.item(row, col).text() for col in range(self.table.columnCount()) if self.table.item(row, col)).lower()
            self.table.setRowHidden(row, bool(needle and needle not in haystack))

    def show_details(self):
        row = self.selected_row()
        if not row:
            self.details.setPlainText("Select a COM reference to inspect its GUID, registry identity, and use site.")
            return
        self.details.setPlainText(
            "Use site: %s\nFunction: %s (%s)\nGUID storage: %s\nGUID: {%s}\nKind: %s\nName: %s\nModule / registration: %s\n\nEvidence: %s" % (
                _hex(row["address"]), row["function"], _hex(row["function_ea"]), _hex(row["guid_ea"]),
                row["guid"], row["kind"], row["name"], row["module"], row["evidence"],
            )
        )

    def navigate_selected(self, *_args):
        row = self.selected_row()
        if row:
            ida_kernwin.jumpto(row["address"])

    def infer_types(self):
        try:
            cfunc, proposals = collect_type_inferences()
        except Exception as exc:
            ida_kernwin.warning("COM type inference failed:\n%s" % exc)
            return
        resolved = [item for item in proposals if item["tinfo"] is not None]
        unresolved = [item for item in proposals if item["tinfo"] is None]
        if not proposals:
            ida_kernwin.info("No supported CoCreateInstance, CoGetCallContext, or QueryInterface patterns were found in the current function.")
            return
        preview = "\n".join("%s: %s -> %s * (%s)" % (item["source"], item["variable"], item["type_name"], item["guid"]) for item in resolved[:20])
        message = "Apply %d inferred COM interface type%s to the current function?\n\n%s" % (len(resolved), "" if len(resolved) == 1 else "s", preview or "No matching Local Type is currently loaded.")
        if unresolved:
            message += "\n\n%d GUID%s could not be matched to a loaded IDA Local Type and will remain unchanged." % (len(unresolved), "" if len(unresolved) == 1 else "s")
        if not resolved or ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, message) != ida_kernwin.ASKBTN_YES:
            return
        applied = apply_type_inferences(cfunc, resolved)
        self.status.setText("Applied %d of %d inferred COM interface types" % (len(applied), len(resolved)))
        ida_kernwin.info("Applied %d COM interface type%s. Reopen or refresh pseudocode if needed." % (len(applied), "" if len(applied) == 1 else "s"))

    def _csv_text(self):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Address", "Function", "Function Address", "GUID Address", "GUID", "Name", "Kind", "Module", "Evidence"])
        for row in self.rows:
            writer.writerow([_hex(row["address"]), row["function"], _hex(row["function_ea"]), _hex(row["guid_ea"]), row["guid"], row["name"], row["kind"], row["module"], row["evidence"]])
        return output.getvalue()

    def export_csv(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self.parent, "Export COM References", "com_references.csv", "CSV files (*.csv)")
        if path:
            with open(path, "w", encoding="utf-8-sig", newline="") as handle:
                handle.write(self._csv_text())
            self.status.setText("Exported %d references to %s" % (len(self.rows), os.path.basename(path)))

    def OnClose(self, form):
        global _explorer
        if _explorer is self:
            _explorer = None


def show_com_explorer():
    global _explorer
    if _explorer is None:
        _explorer = COMExplorer()
    _explorer.Show("Genesect - COM Explorer", options=ida_kernwin.PluginForm.WOPN_PERSIST)


class COMExplorerHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        show_com_explorer()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
