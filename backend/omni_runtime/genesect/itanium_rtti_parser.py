# -*- coding: utf-8 -*-
"""
Genesect GCC / Clang Itanium C++ ABI RTTI & VTable Parser.

Reconstructs C++ class hierarchies, multiple/virtual inheritance trees, and virtual
method tables for Linux ELF and macOS Mach-O binaries compiled with GCC or Clang.
Generates typed C++ VTable struct definitions for IDA Local Types.
"""

from typing import Dict, List, Optional, Tuple, Any, Set
import csv
import os
import re

try:
    import idaapi
    import ida_bytes
    import ida_funcs
    import ida_ida
    import ida_kernwin
    import ida_name
    import ida_segment
    import ida_typeinf
    import idautils
    import idc
except ImportError:
    idaapi = None
    ida_bytes = None
    ida_funcs = None
    ida_ida = None
    ida_kernwin = None
    ida_name = None
    ida_segment = None
    ida_typeinf = None
    idautils = None
    idc = None

from genesect.qt_compat import QtCore, QtGui, QtWidgets
from genesect.ui.components import PageHeader, Card
from genesect.ui.mac_workspace import apply_mac_workspace
from genesect.ui.theme import current_theme


def _hex(ea: int) -> str:
    return "0x%X" % int(ea)


def _is_64bit() -> bool:
    if ida_ida and hasattr(ida_ida, "inf_is_64bit"):
        return bool(ida_ida.inf_is_64bit())
    return True


def demangle_itanium(mangled: str) -> str:
    """Demangle an Itanium C++ mangled symbol name."""
    if not mangled:
        return ""
    if idaapi and hasattr(idaapi, "demangle_name"):
        dem = idaapi.demangle_name(mangled, getattr(idaapi, "MFF_READABLE", 0))
        if dem:
            return dem
    # Fallback cleanup
    if mangled.startswith("_ZTI"):
        return "typeinfo for " + mangled[4:]
    if mangled.startswith("_ZTV"):
        return "vtable for " + mangled[4:]
    return mangled


def read_ptr(ea: int, is_64: bool) -> int:
    if not ida_bytes:
        return 0
    if is_64:
        return ida_bytes.get_qword(ea)
    return ida_bytes.get_dword(ea)


class ItaniumClassInfo:
    """Model representing an Itanium C++ class reconstructed from RTTI."""

    def __init__(self, raw_name: str, typeinfo_ea: int, vtable_ea: Optional[int] = None):
        self.raw_name = raw_name
        self.typeinfo_ea = typeinfo_ea
        self.vtable_ea = vtable_ea or 0
        self.demangled_name = demangle_itanium(raw_name) or raw_name
        self.clean_name = self._extract_clean_name(self.demangled_name)
        self.base_classes: List[Tuple[str, int, int]] = []  # [(base_name, offset, flags)]
        self.virtual_methods: List[Tuple[int, str]] = []    # [(method_ea, method_name)]
        self.rtti_kind: str = "class_type_info"            # "class_type_info", "si_class_type_info", "vmi_class_type_info"

    @staticmethod
    def _extract_clean_name(demangled: str) -> str:
        name = demangled
        for prefix in ("typeinfo for ", "vtable for ", "typeinfo name for "):
            if name.startswith(prefix):
                name = name[len(prefix):]
        return name.strip() or demangled

    def generate_cpp_struct(self) -> str:
        """Generate a clean C++ struct definition for IDA Local Types."""
        safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", self.clean_name)
        lines = [f"struct {safe_name}_Vtbl {{"]
        if not self.virtual_methods:
            lines.append("    void (*unknown_method_0)();")
        else:
            for idx, (m_ea, m_name) in enumerate(self.virtual_methods):
                clean_m = re.sub(r"[^a-zA-Z0-9_]", "_", m_name) if not m_name.startswith("sub_") else f"method_{idx}"
                lines.append(f"    void (*{clean_m}_{idx:02X})() /* {_hex(m_ea)} */;")
        lines.append("};")
        return "\n".join(lines)


class ItaniumRTTIScanner:
    """Scanner finding all Itanium RTTI descriptors and vtables across the IDB."""

    def __init__(self):
        self.is_64 = _is_64bit()
        self.ptr_size = 8 if self.is_64 else 4
        self.classes: Dict[int, ItaniumClassInfo] = {}

    def scan(self) -> List[ItaniumClassInfo]:
        self.classes.clear()
        if not idautils or not ida_bytes:
            return []

        # 1. Scan for typeinfo symbols (_ZTI) or descriptors
        for name, ea in idautils.Names() if idautils else []:
            if name.startswith("_ZTI") and not name.startswith("_ZTIN10__cxxabiv1"):
                self._parse_typeinfo(ea, name)

        # 2. Correlate with vtables (_ZTV)
        for name, ea in idautils.Names() if idautils else []:
            if name.startswith("_ZTV") and not name.startswith("_ZTVN10__cxxabiv1"):
                self._correlate_vtable(ea, name)

        # 3. For any discovered classes, extract virtual method slots
        for c in self.classes.values():
            if c.vtable_ea:
                self._extract_vtable_methods(c)

        return sorted(self.classes.values(), key=lambda c: c.clean_name)

    def _parse_typeinfo(self, ti_ea: int, name: str):
        if ti_ea in self.classes:
            return

        c_info = ItaniumClassInfo(raw_name=name, typeinfo_ea=ti_ea)

        # Pointer 0 is the vtable for typeinfo class
        # (e.g. __class_type_info, __si_class_type_info, __vmi_class_type_info)
        vptr = read_ptr(ti_ea, self.is_64)
        vptr_name = idc.get_name(vptr) if idc else ""

        if "si_class_type_info" in vptr_name:
            c_info.rtti_kind = "Single Inheritance (si_class_type_info)"
            # Pointer 2 is base class typeinfo
            base_ti = read_ptr(ti_ea + (2 * self.ptr_size), self.is_64)
            if base_ti and base_ti != idaapi.BADADDR:
                base_name = idc.get_name(base_ti) or _hex(base_ti)
                clean_base = ItaniumClassInfo._extract_clean_name(demangle_itanium(base_name))
                c_info.base_classes.append((clean_base, 0, 0))

        elif "vmi_class_type_info" in vptr_name:
            c_info.rtti_kind = "Virtual/Multiple Inheritance (vmi_class_type_info)"
            # Offset 2*ptr_size is flags (4 bytes), 2*ptr_size + 4 is base_count (4 bytes)
            base_count = ida_bytes.get_dword(ti_ea + (2 * self.ptr_size) + 4) if ida_bytes else 0
            if 0 < base_count <= 32:
                # Array of bases begins at offset 2*ptr_size + 8 (aligned to ptr_size)
                base_arr_offset = (2 * self.ptr_size) + (8 if self.is_64 else 8)
                for b in range(base_count):
                    b_ea = ti_ea + base_arr_offset + (b * (self.ptr_size * 2))
                    base_ti = read_ptr(b_ea, self.is_64)
                    off_flags = read_ptr(b_ea + self.ptr_size, self.is_64)
                    base_offset = (off_flags >> 8)
                    if base_ti and base_ti != idaapi.BADADDR:
                        base_name = idc.get_name(base_ti) or _hex(base_ti)
                        clean_base = ItaniumClassInfo._extract_clean_name(demangle_itanium(base_name))
                        c_info.base_classes.append((clean_base, base_offset, off_flags & 0xFF))
        else:
            c_info.rtti_kind = "Base Class (class_type_info)"

        self.classes[ti_ea] = c_info

    def _correlate_vtable(self, vtbl_ea: int, vtbl_name: str):
        # In Itanium ABI, slot 0 of vtbl_ea is typically after offset_to_top and typeinfo
        # Check slot [-1]
        ti_ptr = read_ptr(vtbl_ea + self.ptr_size, self.is_64)
        if ti_ptr in self.classes:
            self.classes[ti_ptr].vtable_ea = vtbl_ea + (2 * self.ptr_size)
            return

        # Try by symbol name match _ZTV<name> <-> _ZTI<name>
        suffix = vtbl_name[4:]
        for c in self.classes.values():
            if c.raw_name.endswith(suffix):
                c.vtable_ea = vtbl_ea + (2 * self.ptr_size)
                break

    def _extract_vtable_methods(self, c_info: ItaniumClassInfo):
        c_info.virtual_methods.clear()
        cur = c_info.vtable_ea
        if not cur or cur == idaapi.BADADDR:
            return

        for idx in range(128): # Reasonable limit on virtual functions
            m_ea = read_ptr(cur + (idx * self.ptr_size), self.is_64)
            if not m_ea or m_ea == idaapi.BADADDR:
                break
            # Check if valid function or code address
            if ida_bytes and not ida_bytes.is_code(ida_bytes.get_flags(m_ea)):
                # If not marked code, check if valid segment
                seg = ida_segment.getseg(m_ea) if ida_segment else None
                if not seg or (seg.perm & 1) == 0: # Not executable
                    break

            m_name = (idc.get_func_name(m_ea) if idc else "") or (idc.get_name(m_ea) if idc else "") or f"sub_{m_ea:X}"
            dem_m = demangle_itanium(m_name) or m_name
            c_info.virtual_methods.append((m_ea, dem_m))


class ItaniumRTTIDialog(QtWidgets.QDialog):
    """Interactive GUI dialog for Itanium C++ ABI RTTI & VTable Reconstructor."""

    def __init__(self, parent=None):
        super(ItaniumRTTIDialog, self).__init__(parent)
        self.setWindowTitle("Genesect - GCC/Clang Itanium C++ RTTI & VTable Explorer")
        self.resize(1120, 680)
        apply_mac_workspace(self)

        self.t = current_theme(self)
        self.scanner = ItaniumRTTIScanner()
        self.classes: List[ItaniumClassInfo] = []
        self.selected_class: Optional[ItaniumClassInfo] = None

        self._setup_ui()
        QtCore.QTimer.singleShot(0, self.refresh_scan)

    def _setup_ui(self):
        t = self.t
        self.setStyleSheet(f"""
            QDialog {{ background: {t.window}; color: {t.text}; }}
            QLineEdit, QTreeWidget, QTableWidget, QTextEdit {{
                background: {t.surface};
                color: {t.text};
                border: 1px solid {t.border};
                border-radius: 6px;
                padding: 6px;
            }}
            QTreeWidget, QTableWidget {{ gridline-color: {t.border}; }}
            QHeaderView::section {{
                background: {t.surface_alt};
                color: {t.text_muted};
                padding: 6px;
                font-weight: 700;
                border: none;
                border-bottom: 1px solid {t.border};
            }}
        """)

        root = QtWidgets.QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)

        header = PageHeader(
            "GCC / Clang Itanium C++ RTTI & VTable Explorer",
            "Scans Itanium ABI typeinfo descriptors and vtables, reconstructs inheritance hierarchies, and exports typed VTable structs."
        )

        btn_rescan = QtWidgets.QPushButton("Rescan Database")
        btn_rescan.setProperty("pnVariant", "primary")
        btn_rescan.clicked.connect(self.refresh_scan)
        header.add_action(btn_rescan)

        btn_copy_report = QtWidgets.QPushButton("Copy Class Report")
        btn_copy_report.clicked.connect(self._copy_class_report)
        header.add_action(btn_copy_report)

        btn_apply_struct = QtWidgets.QPushButton("Apply Struct to Local Types")
        btn_apply_struct.clicked.connect(self._apply_struct)
        header.add_action(btn_apply_struct)

        btn_export = QtWidgets.QPushButton("Export CSV")
        btn_export.clicked.connect(self._export_csv)
        header.add_action(btn_export)

        root.addWidget(header)

        # Search Bar
        card_filter = Card()
        l_filt = QtWidgets.QHBoxLayout(card_filter)
        l_filt.setContentsMargins(12, 8, 12, 8)
        l_filt.addWidget(QtWidgets.QLabel("Search Classes / Methods:"))
        self.edit_search = QtWidgets.QLineEdit()
        self.edit_search.setPlaceholderText("Filter by class name, base class, or method...")
        self.edit_search.textChanged.connect(self._apply_filter)
        l_filt.addWidget(self.edit_search, 1)
        root.addWidget(card_filter)

        # Splitter: Left (Class list & hierarchy), Right (Methods & C++ Struct Preview)
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)

        # Left panel: Class List
        w_left = QtWidgets.QWidget()
        l_left = QtWidgets.QVBoxLayout(w_left)
        l_left.setContentsMargins(0, 0, 0, 0)
        l_left.addWidget(QtWidgets.QLabel("Reconstructed Classes:"))
        self.tbl_classes = QtWidgets.QTableWidget(0, 4)
        self.tbl_classes.setHorizontalHeaderLabels(["Class Name", "Inheritance Kind", "Base Classes", "Methods"])
        self.tbl_classes.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.tbl_classes.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.tbl_classes.horizontalHeader().setStretchLastSection(True)
        self.tbl_classes.itemSelectionChanged.connect(self._on_class_selected)
        l_left.addWidget(self.tbl_classes, 1)
        splitter.addWidget(w_left)

        # Right panel: Virtual Methods and Struct Generator
        w_right = QtWidgets.QWidget()
        l_right = QtWidgets.QVBoxLayout(w_right)
        l_right.setContentsMargins(0, 0, 0, 0)

        l_right.addWidget(QtWidgets.QLabel("Virtual Method Table Slots:"))
        self.tbl_methods = QtWidgets.QTableWidget(0, 3)
        self.tbl_methods.setHorizontalHeaderLabels(["Slot", "Method Address", "Method Demangled Name"])
        self.tbl_methods.horizontalHeader().setStretchLastSection(True)
        self.tbl_methods.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.tbl_methods.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.tbl_methods.itemDoubleClicked.connect(self._on_method_double_clicked)
        l_right.addWidget(self.tbl_methods, 1)

        l_right.addWidget(QtWidgets.QLabel("C++ VTable Struct Definition Preview:"))
        self.txt_struct = QtWidgets.QTextEdit()
        self.txt_struct.setFont(QtGui.QFont("Consolas", 10))
        self.txt_struct.setReadOnly(True)
        l_right.addWidget(self.txt_struct, 1)

        splitter.addWidget(w_right)
        splitter.setSizes([480, 580])
        root.addWidget(splitter, 1)

        # Bottom stats
        bottom = QtWidgets.QHBoxLayout()
        self.lbl_stats = QtWidgets.QLabel("Found 0 Itanium C++ classes.")
        self.lbl_stats.setStyleSheet(f"color: {t.text_muted};")
        bottom.addWidget(self.lbl_stats)
        bottom.addStretch(1)

        btn_close = QtWidgets.QPushButton("Close")
        btn_close.clicked.connect(self.close)
        bottom.addWidget(btn_close)
        root.addLayout(bottom)

    def refresh_scan(self):
        self.classes = self.scanner.scan()
        self._apply_filter()

    def _apply_filter(self):
        query = self.edit_search.text().strip().lower()

        filtered = []
        for c in self.classes:
            bases_str = ", ".join(b[0] for b in c.base_classes)
            if query:
                combined = f"{c.clean_name} {c.demangled_name} {c.rtti_kind} {bases_str}".lower()
                if query not in combined:
                    continue
            filtered.append(c)

        self.tbl_classes.setRowCount(len(filtered))
        for row, c in enumerate(filtered):
            it_name = QtWidgets.QTableWidgetItem(c.clean_name)
            it_name.setData(QtCore.Qt.UserRole, c)
            it_kind = QtWidgets.QTableWidgetItem(c.rtti_kind)
            bases_str = ", ".join(b[0] for b in c.base_classes) or "None (Root)"
            it_bases = QtWidgets.QTableWidgetItem(bases_str)
            it_count = QtWidgets.QTableWidgetItem(str(len(c.virtual_methods)))

            self.tbl_classes.setItem(row, 0, it_name)
            self.tbl_classes.setItem(row, 1, it_kind)
            self.tbl_classes.setItem(row, 2, it_bases)
            self.tbl_classes.setItem(row, 3, it_count)

        self.lbl_stats.setText(f"Found {len(self.classes)} Itanium C++ classes. Showing {len(filtered)}.")
        if filtered:
            self.tbl_classes.selectRow(0)

    def _on_class_selected(self):
        selected = self.tbl_classes.selectedItems()
        if not selected:
            return
        row = selected[0].row()
        it = self.tbl_classes.item(row, 0)
        if not it:
            return
        c: ItaniumClassInfo = it.data(QtCore.Qt.UserRole)
        self.selected_class = c

        # Populate methods
        self.tbl_methods.setRowCount(len(c.virtual_methods))
        for r, (m_ea, m_name) in enumerate(c.virtual_methods):
            self.tbl_methods.setItem(r, 0, QtWidgets.QTableWidgetItem(f"[{r:02d}] +0x{r * self.scanner.ptr_size:02X}"))
            self.tbl_methods.setItem(r, 1, QtWidgets.QTableWidgetItem(_hex(m_ea)))
            self.tbl_methods.setItem(r, 2, QtWidgets.QTableWidgetItem(m_name))

        # Populate struct preview
        self.txt_struct.setText(c.generate_cpp_struct())

    def _on_method_double_clicked(self, item):
        row = item.row()
        it_ea = self.tbl_methods.item(row, 1)
        if it_ea:
            try:
                ea = int(it_ea.text(), 16)
                if ida_kernwin and hasattr(ida_kernwin, "jumpto"):
                    ida_kernwin.jumpto(ea)
            except ValueError:
                pass

    def _apply_struct(self):
        if not self.selected_class:
            return
        decl = self.selected_class.generate_cpp_struct()
        try:
            if idc and hasattr(idc, "parse_decl"):
                res = idc.parse_decl(decl, getattr(idc, "PT_TYP", 0))
                if res:
                    if ida_kernwin and hasattr(ida_kernwin, "info"):
                        ida_kernwin.info(f"Successfully added structure to IDA Local Types:\n{self.selected_class.clean_name}_Vtbl")
                    return
        except Exception:
            pass

        # Fallback copy to clipboard
        QtWidgets.QApplication.clipboard().setText(decl)
        if ida_kernwin and hasattr(ida_kernwin, "info"):
            ida_kernwin.info("C++ struct copied to clipboard! (Paste into Local Types window)")

    def _copy_class_report(self):
        if not self.selected_class:
            return
        c = self.selected_class
        lines = [
            f"=== Class: {c.clean_name} ===",
            f"Typeinfo Address: {_hex(c.typeinfo_ea)}",
            f"VTable Address: {_hex(c.vtable_ea)}",
            f"RTTI Kind: {c.rtti_kind}",
            f"Base Classes: {', '.join(b[0] for b in c.base_classes) or 'None'}",
            f"Virtual Methods ({len(c.virtual_methods)}):",
        ]
        for idx, (m_ea, m_name) in enumerate(c.virtual_methods):
            lines.append(f"  [{idx:02d}] {_hex(m_ea)}: {m_name}")
        lines.append("")
        lines.append("C++ Struct Definition:")
        lines.append(c.generate_cpp_struct())

        text = "\n".join(lines)
        QtWidgets.QApplication.clipboard().setText(text)
        if ida_kernwin and hasattr(ida_kernwin, "info"):
            ida_kernwin.info(f"Report for {c.clean_name} copied to clipboard!")

    def _export_csv(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export Itanium C++ Classes CSV", "itanium_classes.csv", "CSV Files (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as fp:
                writer = csv.writer(fp)
                writer.writerow(["Class Name", "Typeinfo Address", "VTable Address", "Inheritance Kind", "Base Classes", "Method Count"])
                for c in self.classes:
                    writer.writerow([
                        c.clean_name, _hex(c.typeinfo_ea), _hex(c.vtable_ea),
                        c.rtti_kind, "; ".join(b[0] for b in c.base_classes), len(c.virtual_methods)
                    ])
            if ida_kernwin and hasattr(ida_kernwin, "info"):
                ida_kernwin.info(f"Saved {len(self.classes)} class records to:\n{path}")
        except Exception as exc:
            if ida_kernwin and hasattr(ida_kernwin, "warning"):
                ida_kernwin.warning(f"Failed to export CSV:\n{exc}")


class ItaniumRTTIExplorerHandler(idaapi.action_handler_t if idaapi else object):
    def activate(self, ctx):
        global _itanium_rtti_instance
        try:
            _itanium_rtti_instance = ItaniumRTTIDialog()
            _itanium_rtti_instance.show()
            _itanium_rtti_instance.raise_()
            _itanium_rtti_instance.activateWindow()
        except Exception as exc:
            if ida_kernwin and hasattr(ida_kernwin, "warning"):
                ida_kernwin.warning(f"Failed to open Itanium RTTI Explorer:\n{exc}")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS if idaapi else 0


_itanium_rtti_instance = None
