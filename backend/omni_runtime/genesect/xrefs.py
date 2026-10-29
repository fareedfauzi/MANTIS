import idaapi
import idc
import idautils
import ida_funcs
import ida_hexrays
import ida_bytes
import ida_kernwin
from genesect.qt_compat import QtWidgets, QtCore, QtGui, QDialog, QVBoxLayout, QTreeWidget, QTreeWidgetItem
from genesect.ui.mac_workspace import apply_mac_workspace
from genesect.ui.components import ToggleSwitch

_xrefs_win = None

_icon_cache = {}
MAX_CHILDREN_PER_NODE = 2000
MAX_INSTRUCTIONS_PER_EXPANSION = 100000
_CALL_XREF_TYPES = {
    value for value in (
        getattr(idaapi, "fl_CF", None),
        getattr(idaapi, "fl_CN", None),
    ) if value is not None
}
_DATA_XREF_TYPES = {
    value for value in (
        getattr(idaapi, "dr_O", None), getattr(idaapi, "dr_W", None),
        getattr(idaapi, "dr_R", None), getattr(idaapi, "dr_T", None),
        getattr(idaapi, "dr_I", None),
    ) if value is not None
}


def _is_call_or_tail_jump(ea):
    """Recognize common call/tail-call mnemonics across IDA processors."""
    mnem = (idc.print_insn_mnem(ea) or "").lower()
    return mnem in {"call", "callq", "jmp", "jmpq", "bl", "blx", "blr", "b", "jal", "jalr", "bal", "bctrl"}


def _is_tail_jump(ea):
    mnem = (idc.print_insn_mnem(ea) or "").lower()
    return mnem in {"jmp", "jmpq", "b", "br", "bx"}


def _is_unresolved_indirect_instruction(ea):
    """Identify register/memory calls or jumps without treating local branches as calls."""
    mnem = (idc.print_insn_mnem(ea) or "").lower()
    if mnem in {"call", "callq", "blr", "blx", "jalr", "bctrl"}:
        return True
    if mnem not in {"jmp", "jmpq", "br", "bx"}:
        return False
    indirect_types = {
        value for value in (
            getattr(idaapi, "o_reg", None), getattr(idaapi, "o_phrase", None),
            getattr(idaapi, "o_displ", None), getattr(idaapi, "o_mem", None),
        ) if value is not None
    }
    return idc.get_operand_type(ea, 0) in indirect_types


def _is_real_call_edge(source_ea, target_ea, xref_type):
    """Accept typed calls and cross-function tail jumps; reject local CFG edges."""
    if xref_type in _CALL_XREF_TYPES:
        return True
    if not _is_tail_jump(source_ea):
        return False
    source_func = ida_funcs.get_func(source_ea)
    target_func = ida_funcs.get_func(target_ea)
    return bool(
        source_func and target_func
        and source_func.start_ea != target_func.start_ea
        and target_ea == target_func.start_ea
    )


def _is_api_function(func):
    if not func:
        return False
    lib_flag = getattr(ida_funcs, "FUNC_LIB", getattr(idaapi, "FUNC_LIB", 0))
    thunk_flag = getattr(ida_funcs, "FUNC_THUNK", getattr(idaapi, "FUNC_THUNK", 0))
    return bool(func.flags & (lib_flag | thunk_flag))


def _is_ancestor_target(item, target_ea):
    """Stop a lazy A -> B -> A hierarchy from expanding forever."""
    current = item
    while current is not None:
        if getattr(current, "target_func_ea", idaapi.BADADDR) == target_ea:
            return True
        current = current.parent()
    return False

def get_badge_icon(typ):
    """
    Generate a dynamic badge icon for the Call Hierarchy.
    typ: 'dir', 'api', or 'func'
    """
    if typ in _icon_cache:
        return _icon_cache[typ]
        
    try:
        pixmap = QtGui.QPixmap(16, 16)
        pixmap.fill(QtGui.QColor(0, 0, 0, 0)) # Safe transparent
        painter = QtGui.QPainter(pixmap)
        
        # Safely handle Antialiasing for PySide6 vs PyQt5
        try:
            if hasattr(QtGui.QPainter, 'RenderHint') and hasattr(QtGui.QPainter.RenderHint, 'Antialiasing'):
                painter.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing, True)
            elif hasattr(QtGui.QPainter, 'Antialiasing'):
                painter.setRenderHint(QtGui.QPainter.Antialiasing, True)
        except Exception:
            pass
            
        if typ == 'api':
            bg_color = QtGui.QColor("#2E7D32") # Dark green for API
            text = "API"
            font_size = 7
        elif typ == 'func':
            bg_color = QtGui.QColor("#0277BD") # Deep blue for Function
            text = "Fn"
            font_size = 9
        else:
            painter.end()
            return QtWidgets.QApplication.style().standardIcon(QtWidgets.QStyle.SP_DirIcon)
            
        path = QtGui.QPainterPath()
        path.addRoundedRect(0, 0, 16, 16, 3, 3)
        painter.fillPath(path, bg_color)
        
        font = painter.font()
        font.setPixelSize(font_size)
        font.setBold(True)
        painter.setFont(font)
        painter.setPen(QtGui.QColor(255, 255, 255)) # Safe white
        
        rect = QtCore.QRect(0, 0, 16, 16)
        
        # Safe AlignmentCenter
        align = QtCore.Qt.AlignCenter if hasattr(QtCore.Qt, 'AlignCenter') else QtCore.Qt.AlignmentFlag.AlignCenter
        painter.drawText(rect, align, text)
        painter.end()
        
        icon = QtGui.QIcon(pixmap)
        _icon_cache[typ] = icon
        return icon
    except Exception:
        style = QtWidgets.QApplication.style()
        if typ == 'api':
            return style.standardIcon(QtWidgets.QStyle.SP_ComputerIcon)
        return style.standardIcon(QtWidgets.QStyle.SP_FileIcon)

class XrefTreeItem(QtWidgets.QTreeWidgetItem):
    def __init__(self, parent, text, target_func_ea, exact_ea, is_ref_to,
                 is_root=False, is_api=False, edge_kind="call"):
        super().__init__(parent)
        self.setText(0, text)
        self.target_func_ea = target_func_ea
        self.exact_ea = exact_ea
        self.is_ref_to = is_ref_to
        self.loaded = False
        self.is_root = is_root
        self.is_api = is_api
        self.edge_kind = edge_kind
        
        # Apply specialized icons based on context
        if text in ["Used By", "Uses"]:
            style = QtWidgets.QApplication.style()
            icon = style.standardIcon(QtWidgets.QStyle.SP_DirIcon)
        elif self.is_api:
            icon = get_badge_icon('api')
        else:
            icon = get_badge_icon('func')
        self.setIcon(0, icon)
        
        if self.is_root:
            font = self.font(0)
            font.setBold(True)
            self.setFont(0, font)

        if not self.is_root:
            kind_label = {
                "call": "Direct call",
                "tail": "Tail call",
                "address": "Address-taken / callback reference",
                "indirect": "Unresolved indirect call",
            }.get(edge_kind, "Call relationship")
            target = "unresolved" if target_func_ea == idaapi.BADADDR else f"0x{target_func_ea:X}"
            site = "unknown" if exact_ea == idaapi.BADADDR else f"0x{exact_ea:X}"
            self.setToolTip(0, f"{kind_label}\nTarget: {target}\nReference site: {site}")

        # Child dummy item
        dummy = QtWidgets.QTreeWidgetItem(self)
        dummy.setText(0, "Loading...")

class XrefsDialog(QtWidgets.QDialog):
    def __init__(self, target_ea, parent=None):
        parent = QtWidgets.QApplication.activeWindow()
        super().__init__(parent)
        apply_mac_workspace(self)
        # Title will be set by reload_tree()
        self.resize(550, 600)
        self.setWindowFlags(self.windowFlags() | QtCore.Qt.Window | QtCore.Qt.WindowMaximizeButtonHint | QtCore.Qt.WindowMinimizeButtonHint | QtCore.Qt.WindowCloseButtonHint)
        
        self.target_ea = target_ea
        self.settings = QtCore.QSettings("Genesect", "XrefsDialog")
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)
        
        # Top Toolbar Area
        header_layout = QtWidgets.QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 0)
        
        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("Filter functions (e.g. memset)...")
        if hasattr(self.filter_edit, 'setClearButtonEnabled'):
            self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self.on_filter_changed)
        self.filter_edit.setMinimumWidth(200)
        header_layout.addWidget(self.filter_edit)
        
        self.show_api_cb = ToggleSwitch("API functions")
        self.show_api_cb.setToolTip("Include imported and library API functions")
        self.show_api_cb.setChecked(str(self.settings.value("show_api", "true")).lower() == "true")
        self.show_api_cb.toggled.connect(self.reload_tree)
        header_layout.addWidget(self.show_api_cb)
        
        self.show_reg_calls_cb = ToggleSwitch("Indirect calls")
        self.show_reg_calls_cb.setChecked(str(self.settings.value("show_indirect", "false")).lower() == "true")
        self.show_reg_calls_cb.setToolTip("Show register calls (e.g. call eax)")
        self.show_reg_calls_cb.toggled.connect(self.reload_tree)
        header_layout.addWidget(self.show_reg_calls_cb)
        
        # Add a refresh button
        self.refresh_btn = QtWidgets.QPushButton("Refresh")
        self.refresh_btn.setToolTip("Reload the cross-references")
        self.refresh_btn.clicked.connect(self.reload_tree)
        header_layout.addWidget(self.refresh_btn)
        
        # Add a sync button
        self.sync_btn = QtWidgets.QPushButton("Sync")
        self.sync_btn.setToolTip("Sync to current function in IDA")
        self.sync_btn.clicked.connect(self.sync_to_current)
        header_layout.addWidget(self.sync_btn)
        
        layout.addLayout(header_layout)
        
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setAlternatingRowColors(True)
        self.tree.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.on_context_menu)
        self.tree.itemExpanded.connect(self.on_expand)
        self.tree.itemDoubleClicked.connect(self.on_double_click)
        layout.addWidget(self.tree)
        
        self.reload_tree()
        geometry = self.settings.value("geometry")
        if geometry:
            self.restoreGeometry(geometry)
        
    def reload_tree(self):
        self.tree.clear()
        name = idc.get_func_name(self.target_ea)
        if not name:
            name = idc.get_name(self.target_ea, idaapi.GN_VISIBLE)
        
        if name:
            self.setWindowTitle("Genesect - Call Tree")
        else:
            self.setWindowTitle("Genesect - Call Tree")
            
        f = idaapi.get_func(self.target_ea)
        is_api = _is_api_function(f)
        
        top = XrefTreeItem(self.tree, f"Function: {name}()" if name else f"Function: 0x{self.target_ea:X}", self.target_ea, self.target_ea, is_ref_to=True, is_root=True, is_api=is_api)
        top.loaded = True
        top.takeChild(0)
        
        self.root_to = XrefTreeItem(top, "Used By", self.target_ea, self.target_ea, is_ref_to=True, is_root=True)
        self.root_from = XrefTreeItem(top, "Uses", self.target_ea, self.target_ea, is_ref_to=False, is_root=True)
        
        top.setExpanded(True)
        self.root_to.setExpanded(True)
        self.root_from.setExpanded(True)
        if self.filter_edit.text():
            self.on_filter_changed(self.filter_edit.text())
        
    def on_expand(self, item):
        if getattr(item, 'loaded', True): return
        item.takeChild(0)
        item.loaded = True
        visited = set()
        truncated = False
        scan_limited = False

        def add_function_child(text, target_ea, exact_ea, is_ref_to, is_api, edge_kind="call"):
            child = XrefTreeItem(
                item, text, target_ea, exact_ea, is_ref_to,
                is_api=is_api, edge_kind=edge_kind,
            )
            if _is_ancestor_target(item, target_ea):
                child.setText(0, child.text(0) + " (cycle)")
                child.takeChild(0)
                child.loaded = True
                child.setForeground(0, QtGui.QColor("gray"))
            return child

        try:
            if item.is_ref_to:
                refs = sorted(
                    idautils.XrefsTo(item.target_func_ea, 0),
                    key=lambda ref: (ref.frm, ref.to, ref.type),
                )
                for ref in refs:
                    xref = ref.frm
                    if not _is_real_call_edge(xref, item.target_func_ea, ref.type):
                        continue
                    f = ida_funcs.get_func(xref)
                    if not f:
                        continue
                    is_api = _is_api_function(f)
                    if is_api and not self.show_api_cb.isChecked():
                        continue
                    key = (xref, f.start_ea)
                    if key in visited:
                        continue
                    name = idc.get_func_name(f.start_ea) or f"sub_{f.start_ea:X}"
                    edge_kind = "tail" if _is_tail_jump(xref) and ref.type not in _CALL_XREF_TYPES else "call"
                    add_function_child(
                        f"{name} (0x{xref:X})", f.start_ea, xref, True, is_api, edge_kind
                    )
                    visited.add(key)
                    if len(visited) >= MAX_CHILDREN_PER_NODE:
                        truncated = True
                        break

                # Address-taken references are useful callback evidence, but
                # they are not calls and therefore live behind Indirect calls.
                if self.show_reg_calls_cb.isChecked() and not truncated:
                    for xref in sorted(set(idautils.DataRefsTo(item.target_func_ea))):
                        f = ida_funcs.get_func(xref)
                        if not f:
                            continue
                        key = (xref, f.start_ea, "address")
                        if key in visited:
                            continue
                        name = idc.get_func_name(f.start_ea) or f"sub_{f.start_ea:X}"
                        add_function_child(
                            f"{name} · address reference (0x{xref:X})",
                            f.start_ea, xref, True, False, edge_kind="address",
                        )
                        visited.add(key)
                        if len(visited) >= MAX_CHILDREN_PER_NODE:
                            truncated = True
                            break
            else:
                source_func = ida_funcs.get_func(item.target_func_ea)
                source_start = source_func.start_ea if source_func else item.target_func_ea
                for instruction_index, ea in enumerate(sorted(idautils.FuncItems(item.target_func_ea))):
                    if instruction_index >= MAX_INSTRUCTIONS_PER_EXPANSION:
                        scan_limited = True
                        break
                    if len(visited) >= MAX_CHILDREN_PER_NODE:
                        truncated = True
                        break
                    refs = sorted(
                        idautils.XrefsFrom(ea, 0),
                        key=lambda ref: (ref.to, ref.type),
                    )
                    has_func_call = False
                    is_call_insn = _is_unresolved_indirect_instruction(ea)
                    for ref in refs:
                        xref = ref.to
                        f = ida_funcs.get_func(xref)
                        direct_edge = _is_real_call_edge(ea, xref, ref.type)
                        if direct_edge and f:
                            is_api = _is_api_function(f)
                            has_func_call = True
                            if is_api and not self.show_api_cb.isChecked():
                                continue
                            key = (ea, f.start_ea)
                            if key not in visited:
                                name = idc.get_func_name(f.start_ea) or f"sub_{f.start_ea:X}"
                                edge_kind = "tail" if _is_tail_jump(ea) and ref.type not in _CALL_XREF_TYPES else "call"
                                add_function_child(
                                    f"{name} (0x{ea:X})", f.start_ea, ea, False, is_api, edge_kind
                                )
                                visited.add(key)
                        elif direct_edge and not f and self.show_api_cb.isChecked():
                            name = idc.get_name(xref, idaapi.GN_VISIBLE)
                            if name and (ea, xref) not in visited:
                                has_func_call = True
                                child = XrefTreeItem(
                                    item, f"{name} (0x{ea:X})", xref, ea, False,
                                    is_api=True, edge_kind="call",
                                )
                                child.takeChild(0)
                                child.loaded = True
                                visited.add((ea, xref))
                        elif (self.show_reg_calls_cb.isChecked()
                              and ref.type in _DATA_XREF_TYPES and f
                              and f.start_ea != source_start):
                            key = (ea, f.start_ea, "address")
                            if key not in visited:
                                name = idc.get_func_name(f.start_ea) or f"sub_{f.start_ea:X}"
                                add_function_child(
                                    f"{name} · address reference (0x{ea:X})",
                                    f.start_ea, ea, False, False, edge_kind="address",
                                )
                                visited.add(key)

                    if self.show_reg_calls_cb.isChecked() and not has_func_call and is_call_insn:
                        disasm = idc.generate_disasm_line(ea, 0)
                        if disasm and (ea, 0) not in visited:
                            clean_disasm = idaapi.tag_remove(disasm)
                            child = XrefTreeItem(
                                item, f"{clean_disasm} (0x{ea:X})", idaapi.BADADDR,
                                ea, False, is_api=False, edge_kind="indirect",
                            )
                            child.takeChild(0)
                            child.loaded = True
                            visited.add((ea, 0))
        except Exception as exc:
            error = QtWidgets.QTreeWidgetItem(item)
            error.setText(0, f"Unable to load references: {exc}")
            error.setDisabled(True)

        if truncated:
            notice = QtWidgets.QTreeWidgetItem(item)
            notice.setText(0, f"Results limited to {MAX_CHILDREN_PER_NODE} entries")
            notice.setDisabled(True)
        if scan_limited:
            notice = QtWidgets.QTreeWidgetItem(item)
            notice.setText(0, f"Scan limited to {MAX_INSTRUCTIONS_PER_EXPANSION:,} instructions")
            notice.setDisabled(True)
        if item.childCount() == 0:
            empty = QtWidgets.QTreeWidgetItem(item)
            empty.setText(0, "No references found")
            empty.setDisabled(True)

    def closeEvent(self, event):
        global _xrefs_win
        self.settings.setValue("geometry", self.saveGeometry())
        self.settings.setValue("show_api", self.show_api_cb.isChecked())
        self.settings.setValue("show_indirect", self.show_reg_calls_cb.isChecked())
        if _xrefs_win is self:
            _xrefs_win = None
        super().closeEvent(event)
                            
    def sync_to_current(self):
        ea = idaapi.get_screen_ea()
        f = idaapi.get_func(ea)
        if f:
            self.target_ea = f.start_ea
            self.reload_tree()
        else:
            # Try to see if we are on an API call or something
            view = idaapi.get_current_viewer()
            wtype = idaapi.get_widget_type(view)
            target_ea = idaapi.BADADDR
            
            if wtype == idaapi.BWN_PSEUDOCODE:
                vu = idaapi.get_widget_vdui(view)
                if vu and vu.item.citype == idaapi.VDI_EXPR:
                    if vu.item.e.op == idaapi.cot_obj:
                        target_ea = vu.item.e.obj_ea
                    elif vu.item.e.op == idaapi.cot_call and vu.item.e.x.op == idaapi.cot_obj:
                        target_ea = vu.item.e.x.obj_ea
            
            if target_ea == idaapi.BADADDR:
                hl = ida_kernwin.get_highlight(ida_kernwin.get_current_viewer())
                if hl and hl[0]:
                    h_ea = idc.get_name_ea_simple(hl[0])
                    if h_ea != idaapi.BADADDR:
                        target_ea = h_ea
            
            if target_ea != idaapi.BADADDR:
                self.target_ea = target_ea
                self.reload_tree()
            else:
                print("[Genesect] No function at current EA to sync.")
                            
    def on_double_click(self, item, col):
        if hasattr(item, 'exact_ea') and item.exact_ea != idaapi.BADADDR and not getattr(item, 'is_root', False):
            ida_kernwin.jumpto(item.exact_ea)

    def on_context_menu(self, pos):
        item = self.tree.itemAt(pos)
        if not item or getattr(item, "is_root", False):
            return
        menu = QtWidgets.QMenu(self)
        target_ea = getattr(item, "target_func_ea", idaapi.BADADDR)
        exact_ea = getattr(item, "exact_ea", idaapi.BADADDR)
        go_target = menu.addAction("Go to function")
        go_target.setEnabled(target_ea != idaapi.BADADDR)
        go_site = menu.addAction("Go to reference site")
        go_site.setEnabled(exact_ea != idaapi.BADADDR)
        menu.addSeparator()
        copy_line = menu.addAction("Copy entry")
        chosen = menu.exec_(self.tree.viewport().mapToGlobal(pos))
        if chosen == go_target:
            ida_kernwin.jumpto(target_ea)
        elif chosen == go_site:
            ida_kernwin.jumpto(exact_ea)
        elif chosen == copy_line:
            QtWidgets.QApplication.clipboard().setText(item.text(0))

    def on_filter_changed(self, text):
        if text:
            # Search immediate callers/callees even when lazy folders have not
            # been manually expanded yet.
            for root in (self.root_to, self.root_from):
                if not root.loaded:
                    self.on_expand(root)
        self._apply_filter(self.tree.invisibleRootItem(), text.lower())
        
    def _apply_filter(self, item, text):
        visible = False
        if text in item.text(0).lower():
            visible = True
            
        for i in range(item.childCount()):
            child = item.child(i)
            if self._apply_filter(child, text):
                visible = True
                
        # Root items ("Used By", "Uses") should always be visible if text is empty
        if getattr(item, 'is_root', False) and not text:
            visible = True
            
        # Top-level should always be visible
        if item.parent() is None:
            visible = True
            
        item.setHidden(not visible)
        return visible

def show_dnspy_xrefs():
    global _xrefs_win
    ea = idaapi.get_screen_ea()
    target_ea = idaapi.BADADDR
    
    view = idaapi.get_current_viewer()
    wtype = idaapi.get_widget_type(view)
    
    if wtype == idaapi.BWN_PSEUDOCODE:
        vu = idaapi.get_widget_vdui(view)
        if vu and vu.item.citype == idaapi.VDI_EXPR:
            if vu.item.e.op == idaapi.cot_obj:
                target_ea = vu.item.e.obj_ea
            elif vu.item.e.op == idaapi.cot_call and vu.item.e.x.op == idaapi.cot_obj:
                target_ea = vu.item.e.x.obj_ea

    if target_ea == idaapi.BADADDR:
        hl = ida_kernwin.get_highlight(ida_kernwin.get_current_viewer())
        if hl and hl[0]:
            h_ea = idc.get_name_ea_simple(hl[0])
            if h_ea != idaapi.BADADDR:
                target_ea = h_ea
                
    if target_ea == idaapi.BADADDR:
        target_ea = ea
        
    f = idaapi.get_func(target_ea)
    if not f:
        print("No function found for call hierarchy.")
        return
        
    if _xrefs_win:
        _xrefs_win.close()
        
    _xrefs_win = XrefsDialog(f.start_ea)
    _xrefs_win.show()

class DnspyXrefsHandler(idaapi.action_handler_t):
    def __init__(self):
        super().__init__()
    def activate(self, ctx):
        show_dnspy_xrefs()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
