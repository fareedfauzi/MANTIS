# -*- coding: utf-8 -*-
"""Evidence-aware virtual class reconstruction for IDA Pro."""
import html
import re

import idaapi
import ida_bytes
import ida_funcs
import ida_kernwin
import ida_name
import ida_segment
import idautils
import idc

from genesect.qt_compat import QtCore, QtWidgets
from genesect.ui.components import PageHeader, Card
from genesect.ui.mac_workspace import apply_mac_workspace
from genesect.vftable import scan_vftables, _pointer_size, _read_pointer, _xref_functions


_explorer = None


def _hex(ea):
    return "0x%X" % int(ea)


def _demangle(name):
    try:
        return idc.demangle_name(name or "", idc.get_inf_attr(idc.INF_SHORT_DN)) or (name or "")
    except Exception:
        return name or ""


def recover_class_identity(table_name):
    """Return class name, optional base, and the evidence quality from a table symbol."""
    text = _demangle(table_name)
    patterns = (
        r"(?:const\s+)?(.+?)::[`']vftable['`]",
        r"(?:construction\s+)?vtable for\s+(.+?)(?:-in-(.+))?$",
        r"virtual table for\s+(.+)$",
    )
    class_name, base_name = "", ""
    for pattern in patterns:
        match = re.search(pattern, text, re.I)
        if match:
            groups = match.groups()
            primary = groups[0] if groups else ""
            enclosing = groups[1] if len(groups) > 1 else ""
            class_name = (enclosing or primary or "").strip(" '`")
            if "-in-" in text.lower() and enclosing:
                base_name = (primary or "").strip(" '`")
            break
    secondary = re.search(r"\{for\s+[`'](.+?)[`']\}", text, re.I)
    if secondary:
        base_name = secondary.group(1).strip()
    if not class_name:
        clean = re.sub(r"^(?:vftable|vtable|virtual_table)_?", "", table_name or "", flags=re.I).strip(" _")
        class_name = clean or "AnonymousClass_%s" % re.sub(r"\D", "", table_name or "0")
        quality = "heuristic"
    else:
        quality = "symbol"
    return class_name, base_name, quality, text


def recover_rtti(table_ea):
    """Parse MSVC CompleteObjectLocator or inspect ABI header words and nearby names."""
    ptr_size = _pointer_size()
    # 1. Try real MSVC CompleteObjectLocator at table_ea - ptr_size
    col_ptr = _read_pointer(table_ea - ptr_size)
    if col_ptr not in (0, idaapi.BADADDR) and ida_bytes.is_loaded(col_ptr):
        try:
            from genesect.rtti_parser import parse_complete_object_locator
            col = parse_complete_object_locator(col_ptr)
            if col:
                return [{
                    "ea": col["col_ea"],
                    "name": f"{col['class_name']} ({col['mangled_name']})",
                    "slot": table_ea - ptr_size,
                    "class_name": col["class_name"],
                    "bases": col["bases"],
                }]
        except Exception:
            pass

    # Fallback heuristic candidates
    candidates = []
    for offset in (-ptr_size, -2 * ptr_size):
        slot_ea = table_ea + offset
        if not ida_bytes.is_loaded(slot_ea):
            continue
        target = _read_pointer(slot_ea)
        if target in (0, idaapi.BADADDR) or not ida_bytes.is_loaded(target):
            continue
        name = ida_name.get_name(target) or ""
        demangled = _demangle(name)
        target_seg = ida_segment.getseg(target)
        if name or (target_seg and not (target_seg.perm & ida_segment.SEGPERM_EXEC)):
            candidates.append({"ea": int(target), "name": demangled or name or "RTTI candidate", "slot": slot_ea})
    # Include named RTTI objects that explicitly reference this table.
    for xref in idautils.XrefsTo(table_ea, 0):
        name = ida_name.get_name(xref.frm) or ""
        if re.search(r"rtti|typeinfo|type_info|complete object locator", _demangle(name), re.I):
            candidates.append({"ea": int(xref.frm), "name": _demangle(name), "slot": int(xref.frm)})
    unique = {(item["ea"], item["name"]): item for item in candidates}
    return list(unique.values())


def _classify_special_method(method_name, class_name):
    demangled = _demangle(method_name)
    short = class_name.rsplit("::", 1)[-1].strip()
    if re.search(r"destructor|deleting destructor|vector deleting|scalar deleting", demangled, re.I) or "~%s" % short in demangled:
        return "destructor"
    if re.search(r"constructor|`ctor'", demangled, re.I) or re.search(r"(?:^|::)%s\s*\(" % re.escape(short), demangled):
        return "constructor"
    return "method"


def recover_virtual_classes():
    rows = scan_vftables()
    tables = {}
    for row in rows:
        table = tables.setdefault(row["table_ea"], {
            "ea": row["table_ea"], "name": row["table_name"], "named": row["named"], "methods": [],
        })
        table["methods"].append(row)

    classes = {}
    for table in tables.values():
        class_name, base_name, quality, demangled_table = recover_class_identity(table["name"])
        rtti_list = recover_rtti(table["ea"])
        table["rtti"] = rtti_list
        if rtti_list and rtti_list[0].get("class_name"):
            class_name = rtti_list[0]["class_name"]
            quality = "RTTI"
            if rtti_list[0].get("bases"):
                for b in rtti_list[0]["bases"]:
                    if b != class_name:
                        base_name = b

        record = classes.setdefault(class_name, {
            "name": class_name, "bases": set(), "tables": [], "methods": {}, "constructors": {},
            "destructors": {}, "initializer_candidates": {}, "rtti": [], "confidence": quality,
        })
        if base_name and base_name != class_name:
            record["bases"].add(base_name)
        table["demangled_name"] = demangled_table
        record["rtti"].extend(table["rtti"])
        record["tables"].append(table)
        users = dict(_xref_functions(table["ea"]))
        for method in table["methods"]:
            users.update(_xref_functions(method["entry_ea"]))
            name = method["method_name"]
            kind = _classify_special_method(name, class_name)
            item = {"ea": method["method_ea"], "name": _demangle(name), "slot": method["slot"], "table": table["ea"]}
            record["methods"][item["ea"]] = item
            if kind == "destructor":
                record["destructors"][item["ea"]] = item
            elif kind == "constructor":
                record["constructors"][item["ea"]] = item
        for ea, name in users.items():
            item = {"ea": int(ea), "name": _demangle(name)}
            kind = _classify_special_method(name, class_name)
            if kind == "constructor":
                record["constructors"][int(ea)] = item
            elif kind == "destructor":
                record["destructors"][int(ea)] = item
            else:
                record["initializer_candidates"][int(ea)] = item

    for record in classes.values():
        record["bases"] = sorted(record["bases"], key=str.lower)
        record["rtti"] = list({(item["ea"], item["name"]): item for item in record["rtti"]}.values())
    return sorted(classes.values(), key=lambda item: item["name"].lower())


class VirtualClassExplorer(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.classes = []

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        apply_mac_workspace(self.parent)
        root = QtWidgets.QVBoxLayout(self.parent)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)
        header = PageHeader("Virtual-Class Explorer", "Vtables, hierarchy, constructors, destructors, methods, RTTI, and inheritance evidence")
        refresh = QtWidgets.QPushButton("Refresh")
        refresh.setProperty("pnVariant", "primary")
        refresh.clicked.connect(self.refresh)
        header.add_action(refresh)
        copy = QtWidgets.QPushButton("Copy Class Report")
        copy.clicked.connect(self.copy_report)
        header.add_action(copy)
        copy_all = QtWidgets.QPushButton("Copy All Classes")
        copy_all.clicked.connect(self.copy_all_reports)
        header.add_action(copy_all)
        root.addWidget(header)
        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("Filter classes, methods, RTTI, constructors, or base classes…")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.apply_filter)
        root.addWidget(self.filter_edit)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        tree_card = Card("Recovered classes")
        self.tree = QtWidgets.QTreeWidget()
        self.tree.setHeaderLabels(["Class / relationship", "Address", "Evidence"])
        self.tree.setAlternatingRowColors(True)
        self.tree.itemSelectionChanged.connect(self.show_selected)
        self.tree.itemDoubleClicked.connect(self.navigate_item)
        tree_card.add_widget(self.tree)
        splitter.addWidget(tree_card)
        detail_card = Card("Class evidence")
        self.details = QtWidgets.QTextBrowser()
        self.details.anchorClicked.connect(self.navigate_link)
        detail_card.add_widget(self.details)
        splitter.addWidget(detail_card)
        splitter.setSizes([620, 760])
        root.addWidget(splitter, 1)
        self.status = QtWidgets.QLabel("Ready")
        self.status.setProperty("pnMuted", True)
        root.addWidget(self.status)
        QtCore.QTimer.singleShot(0, self.refresh)

    def refresh(self):
        ida_kernwin.show_wait_box("Recovering virtual classes and RTTI evidence…\nPress Cancel to stop safely.")
        try:
            self.classes = recover_virtual_classes()
        except Exception as exc:
            self.classes = []
            ida_kernwin.warning("Virtual-Class Explorer failed:\n%s" % exc)
        finally:
            ida_kernwin.hide_wait_box()
        self.populate()

    def _child(self, parent, label, ea=None, evidence=""):
        item = QtWidgets.QTreeWidgetItem(parent, [label, _hex(ea) if ea is not None else "", evidence])
        if ea is not None:
            item.setData(0, QtCore.Qt.UserRole, int(ea))
        return item

    def populate(self):
        self.tree.clear()
        for index, record in enumerate(self.classes):
            root = QtWidgets.QTreeWidgetItem(self.tree, [record["name"], "", record["confidence"]])
            root.setData(0, QtCore.Qt.UserRole + 1, index)
            for base in record["bases"]:
                self._child(root, "inherits: %s" % base, evidence="secondary/construction vtable")
            for table in record["tables"]:
                table_item = self._child(root, "vtable: %s" % table["demangled_name"], table["ea"], "named" if table["named"] else "heuristic")
                for method in table["methods"]:
                    self._child(table_item, "[%d] %s" % (method["slot"], _demangle(method["method_name"])), method["method_ea"], "virtual method")
            for label, key, evidence in (
                ("Constructors", "constructors", "symbol/signature"),
                ("Destructors", "destructors", "symbol/signature"),
                ("Vtable initializer candidates", "initializer_candidates", "inferred from vtable reference"),
            ):
                if record[key]:
                    group = self._child(root, label)
                    for item in record[key].values():
                        self._child(group, item["name"], item["ea"], evidence)
            if record["rtti"]:
                group = self._child(root, "RTTI")
                for item in record["rtti"]:
                    self._child(group, item["name"], item["ea"], "ABI header/reference")
        self.tree.resizeColumnToContents(0)
        self.tree.resizeColumnToContents(1)
        self.status.setText("%d classes recovered • inferred relationships are explicitly labeled" % len(self.classes))
        self.apply_filter(self.filter_edit.text())

    def selected_class(self):
        item = self.tree.currentItem()
        while item is not None:
            index = item.data(0, QtCore.Qt.UserRole + 1)
            if index is not None:
                return self.classes[int(index)]
            item = item.parent()
        return None

    def apply_filter(self, text):
        if not hasattr(self, "tree"):
            return
        needle = str(text or "").strip().lower()
        for index in range(self.tree.topLevelItemCount()):
            root = self.tree.topLevelItem(index)
            record = self.classes[index]
            searchable = [record["name"]] + record["bases"]
            searchable += [item["name"] for item in record["methods"].values()]
            searchable += [item["name"] for item in record["constructors"].values()]
            searchable += [item["name"] for item in record["destructors"].values()]
            searchable += [item["name"] for item in record["rtti"]]
            root.setHidden(bool(needle and needle not in " ".join(searchable).lower()))

    def _report_text(self, record):
        lines = ["Class: %s", "Confidence: %s", "Bases: %s"]
        output = [lines[0] % record["name"], lines[1] % record["confidence"], lines[2] % (", ".join(record["bases"]) or "None")]
        for table in record["tables"]:
            output.append("Vtable %s at %s" % (table["demangled_name"], _hex(table["ea"])))
            output.extend("  [%d] %s (%s)" % (method["slot"], _demangle(method["method_name"]), _hex(method["method_ea"])) for method in table["methods"])
        for title, key in (("Constructors", "constructors"), ("Destructors", "destructors"), ("Initializer candidates", "initializer_candidates")):
            output.append("%s: %s" % (title, ", ".join("%s (%s)" % (item["name"], _hex(item["ea"])) for item in record[key].values()) or "None"))
        output.append("RTTI: %s" % (", ".join("%s (%s)" % (item["name"], _hex(item["ea"])) for item in record["rtti"]) or "None"))
        return "\n".join(output)

    def _all_report_text(self):
        output = [
            "Genesect Virtual-Class Explorer Report",
            "Recovered classes: %d" % len(self.classes),
            "Recovered vtables: %d" % sum(len(record["tables"]) for record in self.classes),
            "",
            "Class / Vtable Summary",
        ]
        if not self.classes:
            output.append("None")
            return "\n".join(output)

        for record in self.classes:
            output.append("- %s | confidence=%s | bases=%s" % (
                record["name"],
                record["confidence"],
                ", ".join(record["bases"]) or "None",
            ))
            for table in record["tables"]:
                output.append("  - vtable %s at %s | methods=%d" % (
                    table["demangled_name"],
                    _hex(table["ea"]),
                    len(table["methods"]),
                ))

        output.extend(["", "Detailed Evidence"])
        for index, record in enumerate(self.classes, 1):
            output.extend([
                "",
                "=" * 78,
                "[%d/%d] %s" % (index, len(self.classes), record["name"]),
                "=" * 78,
                self._report_text(record),
            ])
        return "\n".join(output)

    def show_selected(self):
        record = self.selected_class()
        if not record:
            self.details.setHtml("<p>Select a recovered class to inspect its evidence.</p>")
            return
        report = html.escape(self._report_text(record)).replace("\n", "<br>")
        self.details.setHtml("<h2>%s</h2><p>%s</p>" % (html.escape(record["name"]), report))

    def navigate_item(self, item, _column):
        ea = item.data(0, QtCore.Qt.UserRole)
        if ea is not None:
            ida_kernwin.jumpto(int(ea))

    def navigate_link(self, url):
        text = url.toString()
        if text.startswith("ida:"):
            ida_kernwin.jumpto(int(text[4:], 16))

    def copy_report(self):
        record = self.selected_class()
        if record:
            QtWidgets.QApplication.clipboard().setText(self._report_text(record))
            self.status.setText("Copied class report for %s" % record["name"])

    def copy_all_reports(self):
        text = self._all_report_text()
        QtWidgets.QApplication.clipboard().setText(text)
        self.status.setText(
            "Copied %d recovered classes and %d vtables" % (
                len(self.classes),
                sum(len(record["tables"]) for record in self.classes),
            )
        )

    def OnClose(self, form):
        global _explorer
        if _explorer is self:
            _explorer = None


def show_virtual_class_explorer():
    global _explorer
    if _explorer is None:
        _explorer = VirtualClassExplorer()
    _explorer.Show("Genesect - Virtual-Class Explorer", options=ida_kernwin.PluginForm.WOPN_PERSIST)


class VirtualClassExplorerHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        show_virtual_class_explorer()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
