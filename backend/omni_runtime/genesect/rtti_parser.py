# -*- coding: utf-8 -*-
"""
MSVC RTTI Deep Parser & VTable Struct Generator for IDA Pro.

Parses MSVC 32-bit and 64-bit Run-Time Type Information (RTTI):
- RTTICompleteObjectLocator (COL)
- TypeDescriptor (.?AV...@@)
- RTTIClassHierarchyDescriptor
- RTTIBaseClassArray & BaseClassDescriptor
Recovers exact class names, inheritance chains, virtual method tables,
and generates ready-to-use C VTable structs for IDA Local Types.
"""
import re
import html

try:
    import idaapi
    import ida_bytes
    import ida_funcs
    import ida_ida
    import ida_kernwin
    import ida_name
    import ida_nalt
    import ida_segment
    import idautils
    import idc
except ImportError:
    idaapi = None
    ida_bytes = None
    ida_funcs = None
    ida_ida = None
    ida_kernwin = None
    ida_name = None
    ida_nalt = None
    ida_segment = None
    idautils = None
    idc = None

from genesect.qt_compat import QtCore, QtGui, QtWidgets
from genesect.ui.theme import current_theme
from genesect.ui.mac_workspace import apply_mac_workspace
from genesect.ui.components import PageHeader, Card


def _is_64bit():
    if ida_ida and hasattr(ida_ida, "inf_is_64bit"):
        return bool(ida_ida.inf_is_64bit())
    return True


def _ptr_size():
    return 8 if _is_64bit() else 4


def _image_base():
    if not idaapi:
        return 0
    if hasattr(idaapi, "get_imagebase"):
        return int(idaapi.get_imagebase())
    if hasattr(ida_nalt, "get_imagebase"):
        return int(ida_nalt.get_imagebase())
    return 0


def _read_dword(ea):
    if not ida_bytes or not ida_bytes.is_loaded(ea):
        return None
    return ida_bytes.get_dword(ea)


def _read_ptr(ea):
    if not ida_bytes or not ida_bytes.is_loaded(ea):
        return None
    return ida_bytes.get_qword(ea) if _is_64bit() else ida_bytes.get_dword(ea)


def _demangle_name(name):
    if not name:
        return ""
    if idc and hasattr(idc, "demangle_name"):
        flags = idc.get_inf_attr(idc.INF_SHORT_DN) if hasattr(idc, "get_inf_attr") else 0
        res = idc.demangle_name(name, flags)
        if res:
            return res
    return name


def _clean_class_name(demangled_str):
    """Strip compiler prefixes like 'class ', 'struct ' from demangled type info."""
    clean = re.sub(r"^(?:(?:class|struct|union|const|volatile)\s+)+", "", demangled_str.strip()).strip()
    clean = re.sub(r"\s+`RTTI.*$", "", clean)
    return clean or demangled_str


def _demangle_msvc_type_name(mangled):
    """Demangle MSVC TypeDescriptor string (.?AVclass@namespace@@)."""
    if not mangled:
        return ""

    stripped = mangled.lstrip(".")
    raw = stripped if stripped.startswith("?") else "?" + stripped

    if idc and hasattr(idc, "demangle_name"):
        flags = idc.get_inf_attr(idc.INF_SHORT_DN) if hasattr(idc, "get_inf_attr") else 0
        candidate = f"??_R0{raw}@8"
        try:
            res = idc.demangle_name(candidate, flags)
            if res:
                return _clean_class_name(res)
        except Exception:
            pass
        try:
            res = idc.demangle_name(raw, flags)
            if res:
                return _clean_class_name(res)
        except Exception:
            pass

    # Pure Python fallback parser for MSVC mangled class/struct names:
    # .?AVname@namespace@@ -> namespace::name
    m = re.match(r"^\.?\?A[VU]([a-zA-Z0-9_@]+)@@", mangled)
    if m:
        parts = [p for p in m.group(1).split("@") if p]
        if parts:
            parts.reverse()
            return "::".join(parts)

    return _clean_class_name(mangled)


def _read_type_descriptor(type_desc_ea):
    """Read and decode MSVC TypeDescriptor at type_desc_ea."""
    if not ida_bytes or not ida_bytes.is_loaded(type_desc_ea):
        return None, ""

    ptr_sz = _ptr_size()
    # In MSVC TypeDescriptor:
    # 0x00: vtable pointer (to type_info::vftable)
    # 0x04/0x08: spare pointer
    # 0x08/0x10: name string starting with .?AV (class) or .?AU (struct)
    name_ea = type_desc_ea + (2 * ptr_sz)
    if not ida_bytes.is_loaded(name_ea):
        return None, ""

    # Read null-terminated string
    buf = bytearray()
    for i in range(512):
        b = ida_bytes.get_byte(name_ea + i)
        if b == 0:
            break
        buf.append(b)

    if not buf:
        return None, ""

    mangled = buf.decode("utf-8", "ignore")
    if not (mangled.startswith(".?A") or mangled.startswith("?")):
        return None, mangled

    clean = _demangle_msvc_type_name(mangled)
    return clean, mangled


def parse_complete_object_locator(col_ea):
    """
    Parse an MSVC RTTICompleteObjectLocator at col_ea.
    Returns dict with RTTI metadata or None if invalid.
    """
    if not ida_bytes or not ida_bytes.is_loaded(col_ea):
        return None

    is_64 = _is_64bit()
    img_base = _image_base()

    sig = _read_dword(col_ea)
    if sig is None:
        return None

    if is_64:
        # 64-bit MSVC COL layout:
        # +0x00: DWORD signature (0 or 1)
        # +0x04: DWORD offset
        # +0x08: DWORD cdOffset
        # +0x0C: DWORD pTypeDescriptor (RVA)
        # +0x10: DWORD pClassDescriptor (RVA)
        # +0x14: DWORD pSelf (RVA of COL)
        if sig not in (0, 1):
            return None
        offset = _read_dword(col_ea + 4)
        cd_offset = _read_dword(col_ea + 8)
        p_type_desc = _read_dword(col_ea + 12)
        p_class_desc = _read_dword(col_ea + 16)
        p_self = _read_dword(col_ea + 20)

        if p_type_desc is None or p_class_desc is None or p_self is None:
            return None

        # Sanity check: pSelf + img_base must point to col_ea
        if (img_base + p_self) != col_ea:
            # Check if image base delta matches
            calc_base = col_ea - p_self
            if calc_base > 0:
                img_base = calc_base
            else:
                return None

        type_desc_ea = img_base + p_type_desc
        class_desc_ea = img_base + p_class_desc
    else:
        # 32-bit MSVC COL layout:
        # +0x00: DWORD signature (0)
        # +0x04: DWORD offset
        # +0x08: DWORD cdOffset
        # +0x0C: DWORD pTypeDescriptor (VA)
        # +0x10: DWORD pClassDescriptor (VA)
        if sig != 0:
            return None
        offset = _read_dword(col_ea + 4)
        cd_offset = _read_dword(col_ea + 8)
        type_desc_ea = _read_ptr(col_ea + 12)
        class_desc_ea = _read_ptr(col_ea + 16)

    clean_name, mangled = _read_type_descriptor(type_desc_ea)
    if not clean_name:
        return None

    # Parse ClassHierarchyDescriptor if available
    bases = []
    if class_desc_ea and ida_bytes.is_loaded(class_desc_ea):
        num_bases = _read_dword(class_desc_ea + 8)
        if num_bases and 0 < num_bases <= 128:
            if is_64:
                p_base_array = _read_dword(class_desc_ea + 12)
                base_array_ea = img_base + p_base_array if p_base_array else 0
            else:
                base_array_ea = _read_ptr(class_desc_ea + 12) or 0

            if base_array_ea and ida_bytes.is_loaded(base_array_ea):
                for i in range(num_bases):
                    if is_64:
                        p_base_desc = _read_dword(base_array_ea + (i * 4))
                        base_desc_ea = img_base + p_base_desc if p_base_desc else 0
                    else:
                        base_desc_ea = _read_ptr(base_array_ea + (i * 4)) or 0

                    if base_desc_ea and ida_bytes.is_loaded(base_desc_ea):
                        if is_64:
                            p_b_type = _read_dword(base_desc_ea)
                            b_type_ea = img_base + p_b_type if p_b_type else 0
                        else:
                            b_type_ea = _read_ptr(base_desc_ea) or 0

                        if b_type_ea:
                            b_name, _ = _read_type_descriptor(b_type_ea)
                            if b_name and b_name != clean_name and b_name not in bases:
                                bases.append(b_name)

    return {
        "col_ea": int(col_ea),
        "class_name": clean_name,
        "mangled_name": mangled,
        "offset": offset or 0,
        "cd_offset": cd_offset or 0,
        "type_desc_ea": int(type_desc_ea),
        "class_desc_ea": int(class_desc_ea),
        "bases": bases,
    }


def scan_vtable_methods(vtable_ea, max_methods=512):
    """
    Read contiguous virtual function pointers beginning at vtable_ea.
    Returns list of method dicts: [{'slot': 0, 'ea': 0x..., 'name': '...'}].
    """
    methods = []
    if not ida_bytes or not ida_segment:
        return methods

    ptr_sz = _ptr_size()
    cur_ea = vtable_ea

    for slot in range(max_methods):
        if not ida_bytes.is_loaded(cur_ea) or not ida_bytes.is_loaded(cur_ea + ptr_sz - 1):
            break
        func_ea = _read_ptr(cur_ea)
        if func_ea in (None, 0, getattr(idaapi, "BADADDR", 0xFFFFFFFF)):
            break

        seg = ida_segment.getseg(func_ea)
        if not seg or not (seg.perm & ida_segment.SEGPERM_EXEC):
            break

        # Check if this pointer is actually the start of another vtable's COL
        if slot > 0:
            col_check = parse_complete_object_locator(func_ea)
            if col_check is not None:
                break

        name = idc.get_func_name(func_ea) or ida_name.get_name(func_ea) or ""
        methods.append({
            "slot": slot,
            "method_ea": int(func_ea),
            "table_slot_ea": int(cur_ea),
            "name": name,
            "demangled": _demangle_name(name),
        })
        cur_ea += ptr_sz

    return methods


def generate_vtable_struct(class_name, methods):
    """
    Generate C struct declarations for the vtable and the class object.
    Ready for insertion into IDA Local Types.
    """
    # Sanitize class name to valid C identifier
    clean_id = re.sub(r"[^a-zA-Z0-9_]", "_", class_name)
    clean_id = re.sub(r"_+", "_", clean_id).strip("_")
    if not clean_id or clean_id[0].isdigit():
        clean_id = "Class_" + clean_id

    vtbl_type = f"{clean_id}_vtbl"
    lines = [
        f"// ============================================================",
        f"// Reconstructed C++ VTable for: {class_name}",
        f"// Total Virtual Methods: {len(methods)}",
        f"// ============================================================",
        f"struct {vtbl_type} {{",
    ]

    for m in methods:
        slot = m["slot"]
        demangled = m.get("demangled") or ""
        name = m.get("name") or ""
        # Create a readable method field name
        short_name = ""
        if demangled and not demangled.startswith("sub_"):
            clean_m = re.sub(r"^(?:virtual|public|protected|private)\s+", "", demangled).strip()
            clean_m = clean_m.split("(")[0].strip()
            short_name = clean_m.split("::")[-1].strip()
        elif name and not name.startswith("sub_"):
            short_name = name.split("::")[-1].strip()

        if not short_name or not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", short_name):
            short_name = f"Method_{slot}"

        lines.append(f"    void* {short_name}; // slot {slot} (0x{m['method_ea']:X})")

    lines.append(f"}};\n")
    lines.append(f"struct {clean_id} {{")
    lines.append(f"    struct {vtbl_type}* vfptr;")
    lines.append(f"}};\n")

    return "\n".join(lines)


def scan_all_msvc_rtti():
    """
    Enumerate all vtables with authentic MSVC RTTI in the database.
    Returns list of dicts with complete class, inheritance, and vtable info.
    """
    results = []
    if not ida_segment or not idautils:
        return results

    ptr_sz = _ptr_size()
    seen_vtables = set()

    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        # Search in data/read-only data segments
        if not seg or (seg.perm & ida_segment.SEGPERM_EXEC):
            continue

        ea = int(seg.start_ea)
        end_ea = int(seg.end_ea)

        # Align to pointer size
        ea = (ea + ptr_sz - 1) & ~(ptr_sz - 1)

        while ea < end_ea - ptr_sz:
            col_ptr = _read_ptr(ea)
            if col_ptr and col_ptr not in (0, getattr(idaapi, "BADADDR", 0xFFFFFFFF)):
                col = parse_complete_object_locator(col_ptr)
                if col is not None:
                    vtable_ea = ea + ptr_sz
                    if vtable_ea not in seen_vtables:
                        seen_vtables.add(vtable_ea)
                        methods = scan_vtable_methods(vtable_ea)
                        if methods:
                            struct_code = generate_vtable_struct(col["class_name"], methods)
                            results.append({
                                **col,
                                "vtable_ea": int(vtable_ea),
                                "methods": methods,
                                "method_count": len(methods),
                                "struct_code": struct_code,
                            })
            ea += ptr_sz

    return results


def apply_rtti_symbols_to_idb(class_record, rename_methods=True):
    """
    Apply recovered RTTI names to the database:
    - Sets vtable name: vftable_ClassName
    - Sets method names: ClassName::Method_X (if unnamed)
    """
    if not ida_name or not idc:
        return 0

    class_name = class_record["class_name"]
    clean_id = re.sub(r"[^a-zA-Z0-9_:]", "_", class_name)
    vtable_ea = class_record["vtable_ea"]

    renamed = 0
    # Set vtable name
    vt_name = f"vftable_{clean_id}"
    if ida_name.set_name(vtable_ea, vt_name, ida_name.SN_NOWARN):
        renamed += 1

    if rename_methods:
        for m in class_record.get("methods", []):
            m_ea = m["method_ea"]
            cur_name = idc.get_func_name(m_ea) or ""
            # If function is default sub_XXXX or nameless, give it ClassName::Method_X
            if not cur_name or cur_name.startswith("sub_"):
                m_name = f"{clean_id}__Method_{m['slot']}"
                if ida_name.set_name(m_ea, m_name, ida_name.SN_NOWARN):
                    renamed += 1

    return renamed


def import_vtable_struct_to_idb(struct_code):
    """Parse and import C struct declaration into IDA Local Types."""
    if not idc or not hasattr(idc, "parse_decls"):
        return False
    try:
        res = idc.parse_decls(struct_code, 0)
        return res == 0
    except Exception:
        return False


# =============================================================================
# UI Dialog for MSVC RTTI & VTable Struct Generator
# =============================================================================

class RTTIExplorerDialog(QtWidgets.QDialog):
    """Interactive GUI for browsing recovered MSVC C++ classes and generating structs."""

    def __init__(self, parent=None):
        super(RTTIExplorerDialog, self).__init__(parent)
        self.setWindowTitle("Genesect - MSVC RTTI & VTable Struct Generator")
        self.resize(960, 680)
        apply_mac_workspace(self)
        self.t = current_theme(self)
        self.records = []
        self._setup_ui()
        QtCore.QTimer.singleShot(0, self.refresh)

    def _setup_ui(self):
        t = self.t
        self.setStyleSheet(f"""
            QDialog {{ background: {t.window}; color: {t.text}; }}
            QLabel {{ color: {t.text}; }}
            QTreeWidget, QPlainTextEdit {{
                background: {t.surface};
                color: {t.text};
                border: 1px solid {t.border};
                border-radius: 6px;
                font-family: monospace;
            }}
            QTreeWidget::item:selected {{
                background: {t.accent};
                color: white;
            }}
        """)

        root = QtWidgets.QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)

        # Header
        header = PageHeader(
            "MSVC RTTI & VTable Struct Generator",
            "Discovers C++ classes, vtables, and inheritance hierarchies from MSVC RTTI. Generates typed VTable structs.",
        )
        root.addWidget(header)

        # Filter row
        filter_row = QtWidgets.QHBoxLayout()
        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("Filter classes, methods, or base types…")
        self.filter_edit.textChanged.connect(self._apply_filter)
        filter_row.addWidget(self.filter_edit, 1)

        btn_rescan = QtWidgets.QPushButton("Rescan RTTI")
        btn_rescan.clicked.connect(self.refresh)
        filter_row.addWidget(btn_rescan)
        root.addLayout(filter_row)

        # Splitter: Left tree, Right struct preview
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)

        left_widget = QtWidgets.QWidget()
        left_layout = QtWidgets.QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(6)

        self.tree = QtWidgets.QTreeWidget()
        self.tree.setHeaderLabels(["C++ Class / VTable", "Address", "Virtual Methods / Bases"])
        self.tree.setColumnWidth(0, 320)
        self.tree.setColumnWidth(1, 140)
        self.tree.itemSelectionChanged.connect(self._on_item_selected)
        left_layout.addWidget(self.tree)
        splitter.addWidget(left_widget)

        right_widget = QtWidgets.QWidget()
        right_layout = QtWidgets.QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(6)

        struct_lbl = QtWidgets.QLabel("Generated C++ VTable Struct Declaration:")
        struct_lbl.setStyleSheet(f"font-weight: 700; color: {t.text_muted};")
        right_layout.addWidget(struct_lbl)

        self.struct_preview = QtWidgets.QPlainTextEdit()
        self.struct_preview.setReadOnly(True)
        right_layout.addWidget(self.struct_preview)
        splitter.addWidget(right_widget)

        splitter.setSizes([540, 420])
        root.addWidget(splitter, 1)

        # Action bar
        actions_bar = QtWidgets.QFrame()
        actions_bar.setStyleSheet(f"""
            QFrame {{
                background: {t.surface};
                border: 1px solid {t.border};
                border-radius: 8px;
                padding: 4px;
            }}
        """)
        actions_layout = QtWidgets.QHBoxLayout(actions_bar)
        actions_layout.setContentsMargins(12, 8, 12, 8)
        actions_layout.setSpacing(10)

        self.status_lbl = QtWidgets.QLabel("Ready")
        self.status_lbl.setProperty("pnMuted", True)
        actions_layout.addWidget(self.status_lbl, 1)

        btn_apply_idb = QtWidgets.QPushButton("Apply Names to IDB")
        btn_apply_idb.setToolTip("Rename vtables and virtual methods in IDA database")
        btn_apply_idb.clicked.connect(self._apply_names)
        actions_layout.addWidget(btn_apply_idb)

        btn_import_types = QtWidgets.QPushButton("Import Structs to Local Types")
        btn_import_types.setProperty("pnVariant", "primary")
        btn_import_types.setToolTip("Import all reconstructed VTable structs into IDA Local Types")
        btn_import_types.clicked.connect(self._import_structs)
        actions_layout.addWidget(btn_import_types)

        btn_copy_hdr = QtWidgets.QPushButton("Copy C Header")
        btn_copy_hdr.clicked.connect(self._copy_header)
        actions_layout.addWidget(btn_copy_hdr)

        root.addWidget(actions_bar)

    def refresh(self):
        if ida_kernwin:
            ida_kernwin.show_wait_box("Scanning MSVC RTTI metadata…\nPress Cancel to stop.")
        try:
            self.records = scan_all_msvc_rtti()
        finally:
            if ida_kernwin:
                ida_kernwin.hide_wait_box()
        self._populate_tree()

    def _populate_tree(self):
        self.tree.clear()
        for idx, rec in enumerate(self.records):
            cls_name = rec["class_name"]
            vtable_str = f"0x{rec['vtable_ea']:X}"
            bases_str = f"{rec['method_count']} methods"
            if rec["bases"]:
                bases_str += f" • inherits {', '.join(rec['bases'])}"

            root_item = QtWidgets.QTreeWidgetItem(self.tree, [cls_name, vtable_str, bases_str])
            root_item.setData(0, QtCore.Qt.UserRole, idx)

            # Add bases child item
            if rec["bases"]:
                b_item = QtWidgets.QTreeWidgetItem(root_item, ["Base Classes:", "", ", ".join(rec["bases"])])
                b_item.setForeground(0, QtGui.QColor("#4EA8DE"))

            # Add methods
            for m in rec["methods"]:
                m_ea_str = f"0x{m['method_ea']:X}"
                m_lbl = f"[{m['slot']}] {m.get('demangled') or m.get('name') or 'unnamed'}"
                m_item = QtWidgets.QTreeWidgetItem(root_item, [m_lbl, m_ea_str, "virtual method"])
                m_item.setData(0, QtCore.Qt.UserRole + 1, m["method_ea"])

        self.tree.expandAll()
        self.status_lbl.setText(f"{len(self.records)} MSVC C++ classes recovered from RTTI")

    def _apply_filter(self, text):
        needle = str(text or "").strip().lower()
        for i in range(self.tree.topLevelItemCount()):
            root = self.tree.topLevelItem(i)
            matches = needle in root.text(0).lower() or needle in root.text(2).lower()
            root.setHidden(not matches)

    def _on_item_selected(self):
        item = self.tree.currentItem()
        if not item:
            return
        # Navigate to address on double click / selection if method
        ea = item.data(0, QtCore.Qt.UserRole + 1)
        if ea and ida_kernwin:
            ida_kernwin.jumpto(int(ea))

        # Find class record
        while item.parent():
            item = item.parent()
        idx = item.data(0, QtCore.Qt.UserRole)
        if idx is not None and 0 <= idx < len(self.records):
            self.struct_preview.setPlainText(self.records[idx]["struct_code"])

    def _apply_names(self):
        total_renamed = 0
        for rec in self.records:
            total_renamed += apply_rtti_symbols_to_idb(rec, rename_methods=True)
        if ida_kernwin:
            ida_kernwin.info(f"Applied RTTI symbols:\nRenamed {total_renamed} vtables and virtual methods in database.")
        self.status_lbl.setText(f"Applied {total_renamed} names to IDB")

    def _import_structs(self):
        success_count = 0
        for rec in self.records:
            if import_vtable_struct_to_idb(rec["struct_code"]):
                success_count += 1
        if ida_kernwin:
            ida_kernwin.info(f"Imported {success_count} VTable struct definitions into IDA Local Types.")
        self.status_lbl.setText(f"Imported {success_count} structs into Local Types")

    def _copy_header(self):
        all_headers = "\n\n".join(rec["struct_code"] for rec in self.records)
        QtWidgets.QApplication.clipboard().setText(all_headers)
        self.status_lbl.setText("Copied all C++ structs to clipboard!")


class RTTIExplorerHandler(getattr(idaapi, "action_handler_t", object)):
    """IDA action handler to open MSVC RTTI & VTable Struct Generator."""

    def activate(self, ctx):
        dlg = RTTIExplorerDialog()
        exec_fn = getattr(dlg, "exec_", getattr(dlg, "exec", None))
        if callable(exec_fn):
            exec_fn()
        return 1

    def update(self, ctx):
        return getattr(idaapi, "AST_ENABLE_ALWAYS", 1)
