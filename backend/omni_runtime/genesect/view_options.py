# -*- coding: utf-8 -*-
"""
View & Display Options dialog consolidating call highlighting,
pseudocode visual overlays, indentation guides, and view zoom.
"""
try:
    import idaapi
    import ida_kernwin
    import ida_hexrays
except ImportError:
    idaapi = None
    ida_kernwin = None
    ida_hexrays = None

from genesect.qt_compat import QtCore, QtGui, QtWidgets
from genesect.config import CONFIG
from genesect.ui.theme import current_theme
from genesect.ui.mac_workspace import apply_mac_workspace
import genesect.highlight as _hl
import genesect.indent as _indent
import genesect.pseudocode_folding as _folding
import genesect.argument_hints as _hints
import genesect.zoom as _zoom
import genesect.side_by_side_sync as _sync


class ViewDisplayOptionsDialog(QtWidgets.QDialog):
    """Unified modal dialog for editor appearance and navigation options."""

    def __init__(self, parent=None):
        super(ViewDisplayOptionsDialog, self).__init__(parent)
        self.setWindowTitle("Genesect - View & Display Options")
        self.setMinimumWidth(560)
        self.resize(580, 620)
        apply_mac_workspace(self)

        self.t = current_theme(self)
        self._init_state()
        self._setup_ui()

    def _init_state(self):
        self.hl_color = getattr(CONFIG, "highlight_color", "#FFAAFF").upper()
        self.indent_color = getattr(CONFIG, "indent_guides_color", "#57CFDC").upper()
        self.fold_color = getattr(CONFIG, "pseudocode_folding_color", "#3F3F3F").upper()

    def _setup_ui(self):
        t = self.t
        self.setStyleSheet(f"""
            QDialog {{
                background: {t.window};
                color: {t.text};
            }}
            QLabel {{
                color: {t.text};
            }}
        """)

        root = QtWidgets.QVBoxLayout(self)
        root.setContentsMargins(22, 20, 22, 20)
        root.setSpacing(16)

        # Header
        header = QtWidgets.QVBoxLayout()
        header.setSpacing(4)
        title = QtWidgets.QLabel("View & Display Options")
        title.setStyleSheet(f"font-size: 15pt; font-weight: 700; color: {t.text};")
        sub = QtWidgets.QLabel("Configure visual overlays, call highlighting, and editor navigation helpers.")
        sub.setStyleSheet(f"font-size: 9.5pt; color: {t.text_muted};")
        header.addWidget(title)
        header.addWidget(sub)
        root.addLayout(header)

        # Helper for cards
        def create_card(title_text):
            grp = QtWidgets.QGroupBox(title_text)
            grp.setStyleSheet(f"""
                QGroupBox {{
                    background: {t.surface};
                    border: 1px solid {t.border};
                    border-radius: 10px;
                    font-weight: 700;
                    font-size: 10pt;
                    margin-top: 14px;
                    padding: 16px 14px 14px 14px;
                }}
                QGroupBox::title {{
                    subcontrol-origin: margin;
                    subcontrol-position: top left;
                    left: 14px;
                    padding: 0 6px;
                    color: {t.text};
                    background: {t.surface};
                }}
                QCheckBox {{
                    font-size: 9.5pt;
                    color: {t.text};
                    spacing: 8px;
                }}
                QCheckBox::indicator {{
                    width: 16px;
                    height: 16px;
                    border-radius: 4px;
                    border: 1px solid {t.border_strong};
                    background: {t.surface};
                }}
                QCheckBox::indicator:checked {{
                    background: {t.accent};
                    border-color: {t.accent};
                }}
            """)
            layout = QtWidgets.QVBoxLayout(grp)
            layout.setSpacing(10)
            return grp, layout

        # Card 1: Call Highlighting
        card1, l1 = create_card("Call Highlighting")
        self.cb_hl_pseudo = QtWidgets.QCheckBox("Highlight function calls in Pseudocode (Right margin 120)")
        self.cb_hl_pseudo.setChecked(_hl.is_pseudocode_highlight_enabled())
        self.cb_hl_disasm = QtWidgets.QCheckBox("Highlight function calls in Assembly (Graph/Linear view)")
        self.cb_hl_disasm.setChecked(_hl.is_disasm_highlight_enabled())
        l1.addWidget(self.cb_hl_pseudo)
        l1.addWidget(self.cb_hl_disasm)

        hl_color_row = QtWidgets.QHBoxLayout()
        hl_color_lbl = QtWidgets.QLabel("Highlight Color:")
        hl_color_lbl.setStyleSheet(f"font-size: 9.5pt; color: {t.text_muted};")
        self.btn_hl_color = QtWidgets.QPushButton(self.hl_color)
        self.btn_hl_color.setFixedHeight(26)
        self.btn_hl_color.setFixedWidth(110)
        self._update_color_button(self.btn_hl_color, self.hl_color)
        self.btn_hl_color.clicked.connect(self._pick_hl_color)
        hl_color_row.addWidget(hl_color_lbl)
        hl_color_row.addSpacing(8)
        hl_color_row.addWidget(self.btn_hl_color)
        hl_color_row.addStretch(1)
        l1.addLayout(hl_color_row)
        root.addWidget(card1)

        # Card 2: Pseudocode Overlays & Inlays
        card2, l2 = create_card("Pseudocode Overlays && Inlays")
        self.cb_indent = QtWidgets.QCheckBox("Show colorful indentation nesting marks (VS Code style)")
        self.cb_indent.setChecked(bool(getattr(CONFIG, "indent_guides_enabled", True)))
        l2.addWidget(self.cb_indent)

        indent_color_row = QtWidgets.QHBoxLayout()
        indent_color_lbl = QtWidgets.QLabel("Indent Guide Color:")
        indent_color_lbl.setStyleSheet(f"font-size: 9.5pt; color: {t.text_muted};")
        self.btn_indent_color = QtWidgets.QPushButton(self.indent_color)
        self.btn_indent_color.setFixedHeight(26)
        self.btn_indent_color.setFixedWidth(110)
        self._update_color_button(self.btn_indent_color, self.indent_color)
        self.btn_indent_color.clicked.connect(self._pick_indent_color)
        indent_color_row.addWidget(indent_color_lbl)
        indent_color_row.addSpacing(8)
        indent_color_row.addWidget(self.btn_indent_color)
        indent_color_row.addStretch(1)
        l2.addLayout(indent_color_row)

        self.cb_folding = QtWidgets.QCheckBox("Interactive code block folding && brace selection")
        self.cb_folding.setChecked(bool(getattr(CONFIG, "pseudocode_folding_enabled", True)))
        l2.addWidget(self.cb_folding)

        fold_color_row = QtWidgets.QHBoxLayout()
        fold_color_lbl = QtWidgets.QLabel("Code Block Color:")
        fold_color_lbl.setStyleSheet(f"font-size: 9.5pt; color: {t.text_muted};")
        self.btn_fold_color = QtWidgets.QPushButton(self.fold_color)
        self.btn_fold_color.setFixedHeight(26)
        self.btn_fold_color.setFixedWidth(110)
        self._update_color_button(self.btn_fold_color, self.fold_color)
        self.btn_fold_color.clicked.connect(self._pick_fold_color)
        fold_color_row.addWidget(fold_color_lbl)
        fold_color_row.addSpacing(8)
        fold_color_row.addWidget(self.btn_fold_color)
        fold_color_row.addStretch(1)
        l2.addLayout(fold_color_row)

        self.cb_hints = QtWidgets.QCheckBox("Display parameter / argument name hints in calls (Inlay hints)")
        self.cb_hints.setChecked(bool(getattr(CONFIG, "argument_name_hints_enabled", False)))
        l2.addWidget(self.cb_hints)

        self.cb_explain = QtWidgets.QCheckBox("Explain calls && bitmask constants dynamically (open, mmap RWX, syscalls)")
        self.cb_explain.setChecked(bool(getattr(CONFIG, "call_explanations_enabled", True)))
        l2.addWidget(self.cb_explain)
        root.addWidget(card2)

        # Card 3: Navigation & Zoom
        card3, l3 = create_card("Navigation && Zoom")
        self.cb_side_by_side = QtWidgets.QCheckBox("Side-by-side assembly && pseudocode sync (Ghidra style)")
        self.cb_side_by_side.setChecked(_sync.is_side_by_side_synced())
        l3.addWidget(self.cb_side_by_side)

        self.cb_zoom = QtWidgets.QCheckBox("Synchronize font zoom across views (Ctrl + Mouse Wheel)")
        self.cb_zoom.setChecked(bool(getattr(CONFIG, "zoom_all_views_enabled", True)))
        l3.addWidget(self.cb_zoom)
        root.addWidget(card3)

        root.addStretch(1)

        # Footer Buttons
        footer = QtWidgets.QHBoxLayout()
        self.btn_reset = QtWidgets.QPushButton("Reset Defaults")
        self.btn_reset.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                color: {t.text_muted};
                border: 1px solid {t.border};
                border-radius: 6px;
                padding: 6px 14px;
                font-weight: 500;
            }}
            QPushButton:hover {{
                background: {t.surface_hover};
                color: {t.text};
            }}
        """)
        self.btn_reset.clicked.connect(self._reset_defaults)
        footer.addWidget(self.btn_reset)

        footer.addStretch(1)

        self.btn_cancel = QtWidgets.QPushButton("Cancel")
        self.btn_cancel.setStyleSheet(f"""
            QPushButton {{
                background: {t.surface_alt};
                color: {t.text};
                border: 1px solid {t.border};
                border-radius: 6px;
                padding: 6px 16px;
                font-weight: 600;
                min-width: 75px;
            }}
            QPushButton:hover {{
                background: {t.surface_hover};
                border-color: {t.border_strong};
            }}
        """)
        self.btn_cancel.clicked.connect(self.reject)
        footer.addWidget(self.btn_cancel)

        self.btn_apply = QtWidgets.QPushButton("Save && Apply")
        self.btn_apply.setStyleSheet(f"""
            QPushButton {{
                background: {t.accent};
                color: white;
                border: 1px solid {t.accent};
                border-radius: 6px;
                padding: 6px 18px;
                font-weight: 700;
                min-width: 90px;
            }}
            QPushButton:hover {{
                background: {t.accent_hover};
                border-color: {t.accent_hover};
            }}
        """)
        self.btn_apply.clicked.connect(self._apply_and_close)
        footer.addWidget(self.btn_apply)

        root.addLayout(footer)

    def _update_color_button(self, btn, hex_color):
        color = QtGui.QColor(hex_color)
        c_sum = color.red() + color.green() + color.blue()
        text_color = "#000000" if c_sum > 382 else "#FFFFFF"
        btn.setText(color.name().upper())
        btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {color.name().upper()};
                color: {text_color};
                font-weight: 700;
                font-family: monospace;
                border: 1px solid {self.t.border_strong};
                border-radius: 6px;
                padding: 3px 8px;
            }}
            QPushButton:hover {{
                border: 2px solid {self.t.accent};
            }}
        """)

    def _pick_hl_color(self):
        col = QtWidgets.QColorDialog.getColor(QtGui.QColor(self.hl_color), self, "Pick Highlight Color")
        if col.isValid():
            self.hl_color = col.name().upper()
            self._update_color_button(self.btn_hl_color, self.hl_color)

    def _pick_indent_color(self):
        col = QtWidgets.QColorDialog.getColor(QtGui.QColor(self.indent_color), self, "Pick Indent Mark Color")
        if col.isValid():
            self.indent_color = col.name().upper()
            self._update_color_button(self.btn_indent_color, self.indent_color)

    def _pick_fold_color(self):
        col = QtWidgets.QColorDialog.getColor(QtGui.QColor(self.fold_color), self, "Pick Code Block Highlight Color")
        if col.isValid():
            self.fold_color = col.name().upper()
            self._update_color_button(self.btn_fold_color, self.fold_color)

    def _reset_defaults(self):
        self.cb_hl_pseudo.setChecked(False)
        self.cb_hl_disasm.setChecked(False)
        self.hl_color = "#FFAAFF"
        self._update_color_button(self.btn_hl_color, self.hl_color)

        self.cb_indent.setChecked(True)
        self.indent_color = "#57CFDC"
        self._update_color_button(self.btn_indent_color, self.indent_color)

        self.cb_folding.setChecked(True)
        self.fold_color = "#3F3F3F"
        self._update_color_button(self.btn_fold_color, self.fold_color)

        self.cb_hints.setChecked(False)
        self.cb_explain.setChecked(True)
        self.cb_zoom.setChecked(True)
        self.cb_side_by_side.setChecked(False)

    def _apply_and_close(self):
        # 1. Colors
        CONFIG.highlight_color = self.hl_color
        CONFIG.indent_guides_color = self.indent_color
        CONFIG.pseudocode_folding_color = self.fold_color

        # 2. Call highlighting
        cur_pseudo_hl = _hl.is_pseudocode_highlight_enabled()
        new_pseudo_hl = self.cb_hl_pseudo.isChecked()
        if new_pseudo_hl != cur_pseudo_hl:
            if new_pseudo_hl:
                _hl.enable_highlighting()
            else:
                _hl.disable_highlighting()
        elif new_pseudo_hl and ida_hexrays and ida_kernwin:
            try:
                vu = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_viewer())
                if vu:
                    vu.refresh_view(True)
            except Exception:
                pass

        cur_disasm_hl = _hl.is_disasm_highlight_enabled()
        new_disasm_hl = self.cb_hl_disasm.isChecked()
        if new_disasm_hl != cur_disasm_hl:
            if new_disasm_hl:
                _hl.enable_disasm_highlighting()
            else:
                _hl.disable_disasm_highlighting()
        elif new_disasm_hl:
            try:
                _hl.refresh_disasm_highlighting()
            except Exception:
                pass

        # 3. Indent guides
        _indent.set_indent_guides_enabled(self.cb_indent.isChecked(), persist=False)
        CONFIG.indent_guides_enabled = self.cb_indent.isChecked()

        # 4. Pseudocode folding
        _folding.set_pseudocode_folding_enabled(self.cb_folding.isChecked(), persist=False)
        CONFIG.pseudocode_folding_enabled = self.cb_folding.isChecked()

        # 5. Argument hints
        _hints.set_argument_name_hints_enabled(self.cb_hints.isChecked(), persist=False)
        CONFIG.argument_name_hints_enabled = self.cb_hints.isChecked()

        # 6. Call explanations
        try:
            import genesect.call_explainer as _explainer
            _explainer.set_call_explanations_enabled(self.cb_explain.isChecked(), persist=False, refresh=False)
        except Exception:
            pass
        CONFIG.call_explanations_enabled = self.cb_explain.isChecked()

        # 7. Zoom
        _zoom.set_zoom_all_views_enabled(self.cb_zoom.isChecked(), persist=False)
        CONFIG.zoom_all_views_enabled = self.cb_zoom.isChecked()

        # 8. Side-by-side sync (Ghidra style)
        target_sync = self.cb_side_by_side.isChecked()
        if target_sync != _sync.is_side_by_side_synced():
            _sync.toggle_side_by_side_sync(target_sync)

        # Persist all config
        CONFIG.save()

        # Refresh pseudocode views
        try:
            _indent.refresh_open_pseudocode_widgets()
        except Exception:
            pass
        try:
            _hints.refresh_open_pseudocode_views()
        except Exception:
            pass

        if ida_kernwin:
            ida_kernwin.msg("[Genesect] View & Display options applied.\n")

        self.accept()


class ViewDisplayOptionsHandler(getattr(idaapi, "action_handler_t", object)):
    """IDA action handler to open the View & Display Options dialog."""

    def activate(self, ctx):
        dlg = ViewDisplayOptionsDialog()
        exec_fn = getattr(dlg, "exec_", getattr(dlg, "exec", None))
        if callable(exec_fn):
            exec_fn()
        return 1

    def update(self, ctx):
        return getattr(idaapi, "AST_ENABLE_ALWAYS", 1)
