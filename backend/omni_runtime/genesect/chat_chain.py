# -*- coding: utf-8 -*-
"""
AI Chat interface for multiple functions in a chain.
Allows users to select specific functions from a call graph and chat about them.
"""

import idaapi
from genesect.qt_compat import PluginFormWrapper
import ida_kernwin
import ida_nalt
import ida_funcs
import idautils
import idc
import html
import time
import json
import threading
from genesect.qt_compat import (
    QtWidgets, QtCore, QtGui, QThread, Signal, Slot, QDialog,
    QVBoxLayout, QHBoxLayout, QSplitter, QTextBrowser, QPushButton,
    QLabel, QProgressBar, QSpinBox, QGroupBox, QLineEdit,
    QHeaderView, QCheckBox, QTreeWidget, QTreeWidgetItem
)
import genesect.ai_client as _ai_mod
from genesect.config import CONFIG, LOGGER
from genesect.deep_analyzer import build_call_graph, FuncNode, STYLES_ANALYZER
from genesect.renamer import get_code_fast
from genesect.chat import (
    ChatBubble, ChatInput, ResponsiveChatScrollArea, get_ida_colors, get_chat_font,
)
from genesect.idb_storage import save_to_idb, load_from_idb
from genesect.chat_export import export_chat_log
from genesect.deep_session import binary_fingerprint
from genesect.chat_state import (
    build_context_snapshot, normalize_chat_history, selection_signature,
)
from genesect.ui.workspace import RequestGate
from genesect.ui.mac_workspace import apply_mac_workspace
from genesect.ui.theme import current_theme

CHAIN_CHAT_HISTORY_TAG = 97


class ChatChainWorker(QThread):
    log_signal = Signal(str, str)
    finished_signal = Signal(object)
    
    def __init__(self, entry_ea, max_depth, max_funcs):
        super().__init__()
        self.entry_ea = entry_ea
        self.max_depth = max_depth
        self.max_funcs = max_funcs
        self._stop = False
        
    def stop(self):
        self._stop = True
        
    def run(self):
        self.log_signal.emit(f"Building function graph from 0x{self.entry_ea:X}...", "info")
        
        graph = build_call_graph(
            self.entry_ea,
            stop_checker=lambda: self._stop,
            log_fn=lambda m, l: self.log_signal.emit(m, l),
            max_depth=self.max_depth,
            max_nodes=max(25, self.max_funcs * 3),
        )
            
        if self._stop:
            return
        
        if not graph:
            self.log_signal.emit("No function graph could be built.", "err")
            print(f"[Genesect] ERROR: build_call_graph returned empty for 0x{self.entry_ea:X}")
            return
            
        print(f"[Genesect] Graph discovery for 0x{self.entry_ea:X} found {len(graph)} total nodes.")
        self.log_signal.emit(f"Found {len(graph)} total functions.", "ok")
        self.finished_signal.emit(graph)


class ChatChainDialog(QtWidgets.QDialog):
    def __init__(self, entry_ea=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Genesect - AI Chat: Function Chain")
        self.resize(1240, 820)
        self.setWindowFlags(
            self.windowFlags() |
            QtCore.Qt.WindowMaximizeButtonHint |
            QtCore.Qt.WindowMinimizeButtonHint |
            QtCore.Qt.WindowCloseButtonHint
        )
        
        self.entry_ea = entry_ea or idc.get_screen_ea()
        self.graph = {}
        self.worker = None
        self.history = []
        self.request_gate = RequestGate()
        self._active_request_id = None
        self._context_signature = ()
        self._context_snapshot = ""
        self._closed = False
        self._updating_checks = False
        
        self.setup_ui()
        self.on_use_current_function()
        self.load_history()

    def setup_ui(self):
        theme = current_theme(self, "system")
        apply_mac_workspace(self)
        
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # -------------------------------------------------------------
        # Header Panel
        # -------------------------------------------------------------
        header = QtWidgets.QFrame()
        header.setObjectName("chatChainHeader")
        header.setStyleSheet(f"""
            QFrame#chatChainHeader {{
                background-color: {theme.surface};
                border-bottom: 1px solid {theme.border};
            }}
        """)
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(16, 12, 16, 12)
        header_layout.setSpacing(10)
        
        # Row 1: Primary Action & Function Selection
        entry_row = QHBoxLayout()
        entry_row.setSpacing(8)
        
        self.entry_label = QLabel("Entry Function:")
        self.entry_label.setStyleSheet(f"color: {theme.text}; font-weight: 700; font-size: 12px;")
        entry_row.addWidget(self.entry_label)
        
        self.entry_combo = QtWidgets.QComboBox()
        self.entry_combo.setEditable(True)
        self.entry_combo.setInsertPolicy(QtWidgets.QComboBox.NoInsert)
        self.entry_combo.setMaxVisibleItems(24)
        self.entry_combo.setToolTip("Select or search for a function by name or address")
        self.entry_combo.lineEdit().setPlaceholderText("Search function name or address...")
        self.entry_combo.setStyleSheet(f"""
            QComboBox {{
                color: {theme.text}; font-family: monospace; font-size: 12px;
                background: {theme.code_background}; border: 1px solid {theme.border}; border-radius: 6px;
                padding: 4px 8px; min-height: 24px;
            }}
            QComboBox:focus {{ border-color: {theme.accent}; }}
        """)
        self._populate_function_selector()
        completer = self.entry_combo.completer()
        if completer:
            completer.setCaseSensitivity(QtCore.Qt.CaseInsensitive)
            match_contains = getattr(QtCore.Qt, "MatchContains", None)
            if match_contains is None and hasattr(QtCore.Qt, "MatchFlag"):
                match_contains = QtCore.Qt.MatchFlag.MatchContains
            if match_contains is not None and hasattr(completer, "setFilterMode"):
                completer.setFilterMode(match_contains)
            completer.setCompletionMode(QtWidgets.QCompleter.PopupCompletion)
        self.entry_combo.activated.connect(self.on_entry_selected)
        self.entry_combo.lineEdit().returnPressed.connect(self.on_entry_search_submitted)
        entry_row.addWidget(self.entry_combo, 1)

        self.entry_dropdown_btn = QtWidgets.QToolButton()
        self.entry_dropdown_btn.setText("\u25be")
        self.entry_dropdown_btn.setFixedSize(30, 30)
        self.entry_dropdown_btn.setToolTip("Show all entry functions")
        self.entry_dropdown_btn.setAccessibleName("Show entry function list")
        self.entry_dropdown_btn.setStyleSheet(f"""
            QToolButton {{
                color: {theme.text};
                background: {theme.surface_alt};
                border: 1px solid {theme.border};
                border-radius: 6px;
                font-size: 13px;
                font-weight: bold;
            }}
            QToolButton:hover {{
                background: {theme.surface_hover};
                border-color: {theme.border_strong};
            }}
        """)
        self.entry_dropdown_btn.clicked.connect(self.entry_combo.showPopup)
        entry_row.addWidget(self.entry_dropdown_btn)
        
        load_btn = QPushButton("📍 Current Func")
        load_btn.setToolTip("Switch entry point to IDA's active cursor function")
        load_btn.clicked.connect(self.on_use_current_function)
        entry_row.addWidget(load_btn)

        self.build_btn = QPushButton("⚡ Build Chain Graph")
        self.build_btn.setObjectName("buildFunctionGraphButton")
        self.build_btn.setProperty("pnVariant", "primary")
        self.build_btn.setStyleSheet(f"""
            QPushButton#buildFunctionGraphButton {{
                min-height: 28px; padding: 0 14px; border-radius: 6px;
                background: {theme.accent}; border: 1px solid {theme.accent};
                color: {theme.accent_text}; font-weight: 700; font-size: 12px;
            }}
            QPushButton#buildFunctionGraphButton:hover {{
                background: {theme.accent_hover}; border-color: {theme.accent_hover};
            }}
            QPushButton#buildFunctionGraphButton:pressed {{
                background: {theme.accent_pressed}; border-color: {theme.accent_pressed};
            }}
            QPushButton#buildFunctionGraphButton:disabled {{
                background: {theme.surface_alt}; border-color: {theme.border};
                color: {theme.text_disabled};
            }}
        """)
        self.build_btn.setToolTip("Build or rebuild the selectable caller/callee function graph")
        self.build_btn.clicked.connect(self.start_build)
        entry_row.addWidget(self.build_btn)

        entry_row.addSpacing(12)

        # Header utility buttons
        preview_btn = QPushButton("👁 Preview Context")
        preview_btn.setToolTip("View the formatted code snapshot that will be sent to the AI")
        preview_btn.clicked.connect(self.show_context_preview)
        entry_row.addWidget(preview_btn)

        export_btn = QPushButton("💾 Export Log")
        export_btn.setToolTip("Export entire conversation to a Markdown file")
        export_btn.clicked.connect(self.export_conversation)
        entry_row.addWidget(export_btn)

        clear_btn = QPushButton("🗑 Clear History")
        clear_btn.setToolTip("Reset conversation history for this function chain")
        clear_btn.clicked.connect(self.clear_chat)
        entry_row.addWidget(clear_btn)

        header_layout.addLayout(entry_row)
        
        # Row 2: Scope Parameters & Context Budget Meter
        config_row = QHBoxLayout()
        config_row.setSpacing(10)

        scope_lbl = QLabel("Scope:")
        scope_lbl.setStyleSheet(f"color: {theme.text_muted}; font-weight: 600; font-size: 11px;")
        config_row.addWidget(scope_lbl)
        
        depth_lbl = QLabel("Depth:")
        depth_lbl.setStyleSheet(f"color: {theme.text}; font-size: 11px;")
        config_row.addWidget(depth_lbl)
        self.depth_sp = QSpinBox()
        self.depth_sp.setRange(1, 20)
        self.depth_sp.setValue(10)
        self.depth_sp.setToolTip("Maximum call depth (levels away from entry point)")
        self.depth_sp.setFixedWidth(56)
        config_row.addWidget(self.depth_sp)
        
        max_funcs_lbl = QLabel("Max Funcs:")
        max_funcs_lbl.setStyleSheet(f"color: {theme.text}; font-size: 11px;")
        config_row.addWidget(max_funcs_lbl)
        self.func_sp = QSpinBox()
        self.func_sp.setRange(1, 1000)
        self.func_sp.setValue(100)
        self.func_sp.setToolTip("Maximum total functions discovered in graph")
        self.func_sp.setFixedWidth(70)
        config_row.addWidget(self.func_sp)
        
        config_row.addStretch(1)

        # Context Budget Meter Pill
        self.context_estimate = QLabel("0 selected • 0 chars")
        self.context_estimate.setStyleSheet(f"""
            QLabel {{
                background-color: {theme.surface_alt};
                color: {theme.accent};
                border: 1px solid {theme.border};
                border-radius: 12px;
                padding: 3px 12px;
                font-weight: 600;
                font-size: 11px;
            }}
        """)
        config_row.addWidget(self.context_estimate)

        self.cancel_context_btn = QPushButton("⏹ Stop Request")
        self.cancel_context_btn.setProperty("pnVariant", "danger")
        self.cancel_context_btn.setEnabled(False)
        self.cancel_context_btn.setVisible(False)
        self.cancel_context_btn.clicked.connect(self.cancel_context_injection)
        config_row.addWidget(self.cancel_context_btn)

        header_layout.addLayout(config_row)
        main_layout.addWidget(header)

        # -------------------------------------------------------------
        # Main Splitter
        # -------------------------------------------------------------
        self.splitter = QSplitter(QtCore.Qt.Horizontal)
        self.splitter.setStyleSheet(f"QSplitter::handle {{ background-color: {theme.border}; }}")
        
        # -------------------------------------------------------------
        # Left Side: Call Chain Explorer (Tree View)
        # -------------------------------------------------------------
        left_widget = QtWidgets.QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(12, 12, 12, 12)
        left_layout.setSpacing(8)
        
        # Search & Filter Bar
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("🔍 Filter functions by name or address...")
        self.filter_input.textChanged.connect(self.filter_tree)
        left_layout.addWidget(self.filter_input)

        # Quick Batch Actions
        batch_layout = QHBoxLayout()
        batch_layout.setSpacing(6)

        all_btn = QPushButton("Select All")
        all_btn.clicked.connect(lambda: self.set_all_checks(True))
        batch_layout.addWidget(all_btn)

        none_btn = QPushButton("Deselect All")
        none_btn.clicked.connect(lambda: self.set_all_checks(False))
        batch_layout.addWidget(none_btn)

        entry_only_btn = QPushButton("Entry Only")
        entry_only_btn.clicked.connect(self.select_entry_only)
        batch_layout.addWidget(entry_only_btn)

        expand_btn = QPushButton("Expand")
        expand_btn.clicked.connect(self.func_tree_expand_all)
        batch_layout.addWidget(expand_btn)

        collapse_btn = QPushButton("Collapse")
        collapse_btn.clicked.connect(self.func_tree_collapse_all)
        batch_layout.addWidget(collapse_btn)

        left_layout.addLayout(batch_layout)

        # Hierarchical Function Tree Widget
        self.func_tree = QTreeWidget()
        self.func_tree.setHeaderLabels(["Function", "Address", "Depth", "Calls"])
        self.func_tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.func_tree.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.func_tree.header().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.func_tree.header().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.func_tree.setAlternatingRowColors(True)
        self.func_tree.setAnimated(True)
        self.func_tree.setIndentation(18)
        self.func_tree.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.func_tree.customContextMenuRequested.connect(self.show_tree_context_menu)
        self.func_tree.itemDoubleClicked.connect(self.navigate_to_tree_item)
        self.func_tree.itemChanged.connect(self.on_tree_item_changed)
        self.func_tree.setStyleSheet(f"""
            QTreeWidget {{
                background-color: {theme.code_background};
                border: 1px solid {theme.border};
                border-radius: 8px;
                padding: 4px;
            }}
            QTreeWidget::item {{
                padding: 4px 2px;
                border-radius: 4px;
            }}
            QTreeWidget::item:hover {{
                background-color: {theme.surface_hover};
            }}
            QTreeWidget::item:selected {{
                background-color: {theme.selection};
                color: {theme.text};
            }}
        """)
        left_layout.addWidget(self.func_tree, 1)

        self.splitter.addWidget(left_widget)
        
        # -------------------------------------------------------------
        # Right Side: AI Chain Chat
        # -------------------------------------------------------------
        right_widget = QtWidgets.QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)
        
        self.chat_area = ResponsiveChatScrollArea()
        self.chat_area.setWidgetResizable(True)
        self.chat_area.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.chat_area.setStyleSheet(f"background-color: {theme.window};")
        
        self.chat_content = QtWidgets.QWidget()
        self.chat_layout = QVBoxLayout(self.chat_content)
        self.chat_layout.setContentsMargins(12, 12, 12, 12)
        self.chat_layout.setSpacing(10)
        self.chat_layout.addStretch()  # Push messages to top
        
        self.chat_area.setWidget(self.chat_content)
        self.chat_area.viewportResized.connect(self._resize_chat_bubbles)
        right_layout.addWidget(self.chat_area, 1)
        
        # Quick Prompt Chips Strip
        quick_prompts_wrap = QtWidgets.QWidget()
        quick_layout = QHBoxLayout(quick_prompts_wrap)
        quick_layout.setContentsMargins(16, 6, 16, 4)
        quick_layout.setSpacing(6)
        
        qp_label = QLabel("Quick Prompts:")
        qp_label.setStyleSheet(f"color: {theme.text_muted}; font-size: 11px; font-weight: 600;")
        quick_layout.addWidget(qp_label)
        
        prompt_presets = [
            ("🔍 Trace Dataflow", "Trace parameter and data flow from the entry point through all called functions."),
            ("🛡️ Security Audit", "Audit this call chain for memory safety flaws, input validation gaps, buffer overflows, or dangerous API usage."),
            ("📋 Chain Overview", "Explain the high-level architecture of this call chain and the specific role of each called function."),
            ("⚠️ Error Paths", "Analyze error handling, return value checks, and failure propagation paths across this call chain.")
        ]
        
        for chip_title, prompt_text in prompt_presets:
            btn = QPushButton(chip_title)
            btn.setCursor(QtCore.Qt.PointingHandCursor)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background: {theme.surface_alt};
                    border: 1px solid {theme.border};
                    border-radius: 12px;
                    padding: 3px 10px;
                    font-size: 11px;
                    font-weight: 500;
                    color: {theme.text};
                }}
                QPushButton:hover {{
                    background: {theme.surface_hover};
                    border-color: {theme.accent};
                    color: {theme.accent};
                }}
            """)
            btn.clicked.connect(lambda _checked=False, p=prompt_text: self._apply_quick_prompt(p))
            quick_layout.addWidget(btn)
            
        quick_layout.addStretch(1)
        right_layout.addWidget(quick_prompts_wrap)

        # Typing Indicator Container
        self.typing_container = QtWidgets.QFrame()
        self.typing_container.setObjectName("typingContainer")
        self.typing_container.setVisible(False)
        self.typing_container.setStyleSheet(f"""
            QFrame#typingContainer {{
                background-color: {theme.surface};
                border-top: 1px solid {theme.border};
                border-bottom: 1px solid {theme.border};
            }}
            QLabel {{
                border: none;
                background: transparent;
            }}
        """)
        ti_layout = QHBoxLayout(self.typing_container)
        ti_layout.setContentsMargins(16, 8, 16, 8)
        ti_layout.setSpacing(10)
        
        self.typing_lbl = QLabel("AI is analyzing function chain...")
        self.typing_lbl.setStyleSheet(f"color: {theme.accent}; font-weight: 600; font-size: 11px;")
        ti_layout.addWidget(self.typing_lbl)
        
        self.chat_progress = QProgressBar()
        self.chat_progress.setRange(0, 0)
        self.chat_progress.setFixedHeight(4)
        self.chat_progress.setTextVisible(False)
        self.chat_progress.setStyleSheet(f"""
            QProgressBar {{ background-color: {theme.surface_alt}; border: none; border-radius: 2px; }}
            QProgressBar::chunk {{ background-color: {theme.accent}; border-radius: 2px; }}
        """)
        ti_layout.addWidget(self.chat_progress, 1)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setProperty("pnVariant", "danger")
        self.stop_btn.clicked.connect(self.cancel_context_injection)
        ti_layout.addWidget(self.stop_btn)

        right_layout.addWidget(self.typing_container)
        
        # Composer Input
        self.chat_input = ChatInput()
        self.chat_input.input_box.setPlaceholderText(
            "Ask AI about this function chain (Enter to send, Shift+Enter for newline)..."
        )
        self.chat_input.submitted.connect(self.on_chat_submit)
        
        input_wrap = QtWidgets.QWidget()
        input_wrap_layout = QVBoxLayout(input_wrap)
        input_wrap_layout.setContentsMargins(16, 8, 16, 14)
        input_wrap_layout.addWidget(self.chat_input)
        right_layout.addWidget(input_wrap)
        
        self.splitter.addWidget(right_widget)
        self.splitter.setSizes([420, 820])
        main_layout.addWidget(self.splitter, 1)
        
        # -------------------------------------------------------------
        # Status Bar
        # -------------------------------------------------------------
        self.status_bar = QHBoxLayout()
        self.status_bar.setContentsMargins(16, 4, 16, 4)
        self.status_lbl = QLabel("Ready")
        self.status_lbl.setStyleSheet(f"color: {theme.text_muted}; font-size: 11px;")
        self.status_bar.addWidget(self.status_lbl)
        main_layout.addLayout(self.status_bar)

    def _apply_quick_prompt(self, text):
        self.chat_input.input_box.setPlainText(text)
        self.chat_input.input_box.setFocus()

    def func_tree_expand_all(self):
        self.func_tree.expandAll()

    def func_tree_collapse_all(self):
        self.func_tree.collapseAll()

    def _populate_function_selector(self):
        """Load every IDB function into the searchable entry dropdown."""
        functions = []
        for ea in idautils.Functions():
            name = idc.get_func_name(ea) or f"sub_{ea:X}"
            functions.append((int(ea), str(name)))
        functions.sort(key=lambda item: (item[1].lower(), item[0]))
        self.entry_combo.blockSignals(True)
        self.entry_combo.clear()
        for ea, name in functions:
            self.entry_combo.addItem(f"0x{ea:X}  -  {name}", ea)
        self.entry_combo.blockSignals(False)

    def _select_entry_in_dropdown(self, ea):
        index = self.entry_combo.findData(int(ea))
        if index >= 0:
            self.entry_combo.blockSignals(True)
            self.entry_combo.setCurrentIndex(index)
            self.entry_combo.blockSignals(False)

    def _switch_entry_function(self, ea):
        f = ida_funcs.get_func(int(ea))
        if not f:
            self.status_lbl.setText("Selected address is not inside a function.")
            return False
        target_ea = int(f.start_ea)
        self._select_entry_in_dropdown(target_ea)
        self.build_btn.setEnabled(True)
        if self.entry_ea == target_ea:
            return True

        self._cancel_active_request()
        self.save_history()
        self.entry_ea = target_ea
        self.history = []
        self.graph = {}
        self._context_signature = ()
        self._context_snapshot = ""
        self.func_tree.clear()
        self.context_estimate.setText("0 selected • 0 chars")
        self._clear_chat_widgets()
        self.load_history()
        self.status_lbl.setText(f"Entry set to {idc.get_func_name(target_ea) or hex(target_ea)}.")
        return True

    def on_entry_selected(self, index):
        ea = self.entry_combo.itemData(int(index))
        if ea is not None:
            self._switch_entry_function(int(ea))

    def on_entry_search_submitted(self):
        text = self.entry_combo.currentText().strip()
        index = self.entry_combo.findText(text, QtCore.Qt.MatchFixedString)
        if index >= 0:
            self.on_entry_selected(index)
            return
        token = text.split("-", 1)[0].strip()
        try:
            ea = int(token, 16) if token.lower().startswith("0x") else idc.get_name_ea_simple(text)
        except Exception:
            ea = idaapi.BADADDR
        if ea not in (None, idaapi.BADADDR) and self._switch_entry_function(int(ea)):
            return
        self.status_lbl.setText("No matching function. Choose an item from the search results.")

    def on_use_current_function(self):
        ea = idc.get_screen_ea()
        f = ida_funcs.get_func(ea)
        if f:
            self._switch_entry_function(f.start_ea)
        else:
            self.build_btn.setEnabled(False)
            self.status_lbl.setText("No function at cursor.")

    def start_build(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.build_btn.setEnabled(False)
            self.status_lbl.setText("Cancelling graph build...")
            return
            
        self.build_btn.setEnabled(True)
        self.build_btn.setText("Cancel Build")
        self.func_tree.clear()
        self.graph = {}
        self.status_lbl.setText("Building graph...")
        
        self.worker = ChatChainWorker(self.entry_ea, self.depth_sp.value(), self.func_sp.value())
        self.worker.log_signal.connect(lambda m, l: self.status_lbl.setText(m))
        self.worker.finished_signal.connect(self.on_graph_built)
        self.worker.finished.connect(self.on_graph_worker_finished)
        self.worker.start()

    def on_graph_worker_finished(self):
        self.build_btn.setEnabled(True)
        self.build_btn.setText("⚡ Build Chain Graph")
        if not self.graph and "Cancelling" in self.status_lbl.text():
            self.status_lbl.setText("Graph build cancelled.")
        self.worker = None

    def on_graph_built(self, graph):
        self.build_btn.setEnabled(True)
        self.build_btn.setText("⚡ Build Chain Graph")
        self.graph = graph
        self.func_tree.clear()

        if not graph:
            self.status_lbl.setText("No function graph could be built.")
            self.update_context_estimate()
            return

        entry_node = graph.get(self.entry_ea)
        if not entry_node:
            entry_node = next(iter(graph.values()))

        # Recursively build hierarchical tree starting from entry point
        visited_nodes = set()
        max_funcs_limit = self.func_sp.value()
        created_count = [0]

        def add_node_to_tree(node, parent_item, call_path):
            if created_count[0] >= max_funcs_limit:
                return None
            created_count[0] += 1
            visited_nodes.add(node.ea)

            name_text = node.name
            if node.ea == self.entry_ea:
                name_text = f"★ {node.name} (Entry)"
            elif getattr(node, "is_library", False):
                name_text = f"📦 {node.name}"

            callee_count = len(getattr(node, "callees", []))
            calls_text = f"{callee_count} callee{'s' if callee_count != 1 else ''}"
            depth_str = f"Depth {getattr(node, 'depth', 0)}"

            item = QTreeWidgetItem([
                name_text,
                f"0x{node.ea:X}",
                depth_str,
                calls_text
            ])
            item.setData(0, QtCore.Qt.UserRole, node.ea)
            item.setCheckState(0, QtCore.Qt.Checked)

            if node.ea == self.entry_ea:
                font = item.font(0)
                font.setBold(True)
                item.setFont(0, font)

            if parent_item is None:
                self.func_tree.addTopLevelItem(item)
            else:
                parent_item.addChild(item)

            # Prevent infinite recursion in call cycles
            if node.ea in call_path:
                item.setText(0, f"{name_text} ↻")
                item.setToolTip(0, "Recursive call cycle detected")
                return item

            new_path = call_path | {node.ea}
            for callee_ea in getattr(node, "callees", []):
                if created_count[0] >= max_funcs_limit:
                    break
                callee_node = graph.get(callee_ea)
                if callee_node and (not getattr(callee_node, "is_library", False) or getattr(callee_node, "depth", 1) == 0):
                    add_node_to_tree(callee_node, item, new_path)

            return item

        self._updating_checks = True
        try:
            add_node_to_tree(entry_node, None, set())

            # Catch any other non-library nodes not connected in the primary descent
            for ea, node in graph.items():
                if ea not in visited_nodes and created_count[0] < max_funcs_limit:
                    if not getattr(node, "is_library", False) or getattr(node, "depth", 1) == 0:
                        add_node_to_tree(node, None, set())
        finally:
            self._updating_checks = False

        self.func_tree.expandAll()
        self.status_lbl.setText(f"Graph built: {created_count[0]} functions available in chain.")
        self.update_context_estimate()

    def filter_tree(self, text):
        query = text.strip().lower()

        def check_item(item):
            name = item.text(0).lower()
            addr = item.text(1).lower()
            matches = (query in name) or (query in addr)
            child_matches = False
            for i in range(item.childCount()):
                if check_item(item.child(i)):
                    child_matches = True
            visible = matches or child_matches
            item.setHidden(not visible)
            if visible and query:
                item.setExpanded(True)
            return visible

        for i in range(self.func_tree.topLevelItemCount()):
            check_item(self.func_tree.topLevelItem(i))

    def on_tree_item_changed(self, item, column):
        if column != 0 or getattr(self, "_updating_checks", False):
            return
        self._updating_checks = True
        try:
            new_state = item.checkState(0)
            ea = item.data(0, QtCore.Qt.UserRole)
            if ea is not None:
                self._sync_check_state_for_ea(self.func_tree.invisibleRootItem(), ea, new_state)
        finally:
            self._updating_checks = False
        self.update_context_estimate()

    def _sync_check_state_for_ea(self, parent_item, target_ea, state):
        for i in range(parent_item.childCount()):
            child = parent_item.child(i)
            if child.data(0, QtCore.Qt.UserRole) == target_ea:
                if child.checkState(0) != state:
                    child.setCheckState(0, state)
            self._sync_check_state_for_ea(child, target_ea, state)

    def set_all_checks(self, checked):
        state = QtCore.Qt.Checked if checked else QtCore.Qt.Unchecked
        self._updating_checks = True

        def set_state(parent_item):
            for i in range(parent_item.childCount()):
                child = parent_item.child(i)
                child.setCheckState(0, state)
                set_state(child)

        try:
            set_state(self.func_tree.invisibleRootItem())
        finally:
            self._updating_checks = False
        self.update_context_estimate()

    def select_entry_only(self):
        self._updating_checks = True

        def set_state(parent_item):
            for i in range(parent_item.childCount()):
                child = parent_item.child(i)
                ea = child.data(0, QtCore.Qt.UserRole)
                child.setCheckState(0, QtCore.Qt.Checked if ea == self.entry_ea else QtCore.Qt.Unchecked)
                set_state(child)

        try:
            set_state(self.func_tree.invisibleRootItem())
        finally:
            self._updating_checks = False
        self.update_context_estimate()

    def update_context_estimate(self):
        selected = self.get_selected_eas()
        num_funcs = len(selected)
        estimated_chars = sum(len(getattr(self.graph.get(ea), "name", "")) + 8000 for ea in selected)
        estimated_tokens = int(estimated_chars / 4)

        theme = current_theme(self, "system")
        if estimated_chars > 100000:
            badge_color = theme.danger
        elif estimated_chars > 60000:
            badge_color = theme.accent_hover
        else:
            badge_color = theme.accent

        self.context_estimate.setStyleSheet(f"""
            QLabel {{
                background-color: {theme.surface_alt};
                color: {badge_color};
                border: 1px solid {badge_color};
                border-radius: 12px;
                padding: 3px 12px;
                font-weight: 600;
                font-size: 11px;
            }}
        """)
        self.context_estimate.setText(f"{num_funcs} selected • ~{estimated_chars:,} chars (~{estimated_tokens:,} tokens)")

        if self.history and selection_signature(selected) != self._context_signature:
            self.status_lbl.setText("Selection changed; context will rebuild on next question.")

    def _cancel_active_request(self):
        self.request_gate.advance()
        request_id = self._active_request_id
        self._active_request_id = None
        client = _ai_mod.AI_CLIENT
        if request_id is not None and client:
            client.cancel_request(request_id)

    def _request_is_current(self, token):
        return not self._closed and self.request_gate.accepts(token, self.entry_ea)

    def cancel_context_injection(self):
        self._context_cancelled = True
        self._cancel_active_request()
        self.cancel_context_btn.setEnabled(False)
        self.cancel_context_btn.setVisible(False)
        self.chat_input.setEnabled(True)
        self.typing_container.setVisible(False)
        self.status_lbl.setText("Context injection cancelled.")

    def get_selected_eas(self):
        eas = set()

        def collect(parent):
            for i in range(parent.childCount()):
                child = parent.child(i)
                if child.checkState(0) == QtCore.Qt.Checked:
                    ea = child.data(0, QtCore.Qt.UserRole)
                    if ea is not None:
                        eas.add(int(ea))
                collect(child)

        collect(self.func_tree.invisibleRootItem())
        return sorted(list(eas))

    def on_chat_submit(self, text):
        if not _ai_mod.AI_CLIENT:
            QtWidgets.QMessageBox.warning(self, "AI Not Configured", "Configure and test an AI provider first.")
            return
        selected_eas = self.get_selected_eas()
        if not selected_eas:
            QtWidgets.QMessageBox.warning(self, "Selection", "Please select at least one function to talk about.")
            return

        selected_signature = selection_signature(selected_eas)
        if self.history and selected_signature != self._context_signature:
            self._cancel_active_request()
            self.history = []
            self._clear_chat_widgets()
            self.add_chat_message("Function selection changed. A new context snapshot will be created.", is_user=False)
            self.status_lbl.setText("Selection changed; rebuilding AI context...")

        self.add_chat_message(text, is_user=True)
        
        # Prepare context if history is empty
        if not self.history:
            self.status_lbl.setText("Gathering decompiled code...")
            
            code_blocks = []

            def _gather_code():
                for ea in selected_eas:
                    c = get_code_fast(ea, max_len=60000)
                    if c:
                        name = idc.get_func_name(ea) or f"sub_{ea:X}"
                        code_blocks.append(f"### Function: {name} (0x{ea:X})\n```c\n{c}\n```\n")
            
            idaapi.execute_sync(_gather_code, idaapi.MFF_READ)
            
            if not code_blocks:
                self.add_chat_message("Error: Could not retrieve code.", is_user=False)
                return

            self.pending_question = text
            self.start_context_injection(code_blocks)
        else:
            self.history.append({"role": "user", "content": text})
            self.query_ai()

    def start_context_injection(self, blocks):
        """Create one bounded context snapshot and submit the pending question."""
        self._context_cancelled = False
        self._context_signature = selection_signature(self.get_selected_eas())
        self._context_token = self.request_gate.issue(self.entry_ea)
        snapshot, included, truncated = build_context_snapshot(blocks, max_chars=120000)
        self._context_snapshot = snapshot
        truncation_note = (
            f"\n\nContext budget note: {truncated} selected function(s) were omitted or truncated."
            if truncated else ""
        )
        self.history = [{
            "role": "system",
            "content": (
                "You are a professional reverse-engineering assistant. Analyze only the "
                "provided IDA pseudocode and distinguish evidence from inference. The context "
                f"contains {included} selected function(s).{truncation_note}\n\n{snapshot}"
            ),
        }]
        self.history.append({"role": "user", "content": self.pending_question})
        self.status_lbl.setText(
            f"Analyzing {included} function(s), {len(snapshot):,} context characters"
            + (f"; {truncated} truncated/omitted" if truncated else "")
        )
        self.query_ai(token=self._context_token)

    def query_ai(self, token=None):
        AI_CLIENT = _ai_mod.AI_CLIENT
        if not AI_CLIENT:
            self.add_chat_message("Error: AI Client not configured.", is_user=False)
            self.chat_input.setEnabled(True)
            self.typing_container.setVisible(False)
            return

        self.chat_input.setEnabled(False)
        self.typing_container.setVisible(True)
        self.status_lbl.setText("AI is processing function chain...")
        self.cancel_context_btn.setVisible(True)
        self.cancel_context_btn.setEnabled(True)
        
        token = token or self.request_gate.issue(self.entry_ea)

        def fin_cb(response, **kwargs):
            if not self._request_is_current(token):
                return
            self._active_request_id = None
            self.cancel_context_btn.setEnabled(False)
            self.cancel_context_btn.setVisible(False)
            self.typing_container.setVisible(False)
            self.chat_input.setEnabled(True)
            self.chat_input.setFocus()
            
            if response:
                self.history.append({"role": "assistant", "content": response})
                self.add_chat_message(response, is_user=False)
                self.save_history()
                self.status_lbl.setText("Analysis complete.")
            else:
                self.add_chat_message("Error: No response from AI.", is_user=False)
                self.status_lbl.setText("AI Error.")

        self._active_request_id = AI_CLIENT.query_model_async(self.history, fin_cb)

    def add_chat_message(self, text, is_user=True):
        bubble = ChatBubble(text, is_user)
        bubble.set_available_width(self.chat_area.viewport().width())
        
        # Insert before the stretch (which is at index count-1)
        self.chat_layout.insertWidget(self.chat_layout.count() - 1, bubble)
        QtCore.QTimer.singleShot(100, self.scroll_to_bottom)

    def _resize_chat_bubbles(self, width):
        for index in range(self.chat_layout.count()):
            widget = self.chat_layout.itemAt(index).widget()
            if isinstance(widget, ChatBubble):
                widget.set_available_width(width)

    def navigate_to_tree_item(self, item, _column=0):
        if item:
            ea = item.data(0, QtCore.Qt.UserRole)
            if ea is not None:
                ida_kernwin.jumpto(int(ea))

    def show_tree_context_menu(self, pos):
        item = self.func_tree.itemAt(pos)
        if not item:
            return
        ea = item.data(0, QtCore.Qt.UserRole)
        name = item.text(0)
        menu = QtWidgets.QMenu(self)

        jump_act = menu.addAction(f"Jump to 0x{ea:X} in IDA")
        jump_act.triggered.connect(lambda: ida_kernwin.jumpto(int(ea)))

        copy_addr_act = menu.addAction("Copy Address")
        copy_addr_act.triggered.connect(lambda: QtWidgets.QApplication.clipboard().setText(f"0x{ea:X}"))

        clean_name = name.split("(")[0].replace("★", "").replace("📦", "").strip()
        copy_name_act = menu.addAction("Copy Function Name")
        copy_name_act.triggered.connect(lambda: QtWidgets.QApplication.clipboard().setText(clean_name))

        menu.addSeparator()
        check_sub_act = menu.addAction("Select Subtree")
        check_sub_act.triggered.connect(lambda: self._set_subtree_checks(item, True))

        uncheck_sub_act = menu.addAction("Deselect Subtree")
        uncheck_sub_act.triggered.connect(lambda: self._set_subtree_checks(item, False))

        menu.exec_(self.func_tree.viewport().mapToGlobal(pos))

    def _set_subtree_checks(self, parent_item, checked):
        state = QtCore.Qt.Checked if checked else QtCore.Qt.Unchecked
        self._updating_checks = True

        def walk(item):
            item.setCheckState(0, state)
            for i in range(item.childCount()):
                walk(item.child(i))

        try:
            walk(parent_item)
        finally:
            self._updating_checks = False
        self.update_context_estimate()

    def show_context_preview(self):
        dialog = QtWidgets.QDialog(self)
        dialog.setWindowTitle("Function Chain Context Preview")
        dialog.resize(850, 600)
        layout = QVBoxLayout(dialog)
        layout.addWidget(QLabel(
            f"{len(self._context_signature)} functions • {len(self._context_snapshot):,} characters"
        ))
        viewer = QtWidgets.QPlainTextEdit(
            self._context_snapshot or "No context snapshot has been created yet."
        )
        viewer.setReadOnly(True)
        layout.addWidget(viewer)
        dialog.exec_()

    def export_conversation(self):
        path = export_chat_log(
            self, "Export Function Chain Chat Log", f"chain_chat_{self.entry_ea:X}.md",
            {
                "title": "Function Chain Chat",
                "mode": "function_chain",
                "entry_address": f"0x{self.entry_ea:X}",
                "context_function_count": len(self._context_signature)
            },
            self.history,
            {"selected_functions": list(self._context_signature), "context_characters": len(self._context_snapshot)},
        )
        if path:
            self.status_lbl.setText(f"Conversation exported to {path}")

    def _clear_chat_widgets(self):
        while self.chat_layout.count() > 1:
            item = self.chat_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def clear_chat(self):
        if not QtWidgets.QMessageBox.question(self, "Clear Chat", "Clear entire conversation history?") == QtWidgets.QMessageBox.Yes:
            return
        
        self._clear_chat_widgets()
        self._cancel_active_request()
        self.history = []
        self._context_signature = ()
        self._context_snapshot = ""
        self.save_history()
        self.load_history()
        self.status_lbl.setText("History cleared.")

    def save_history(self):
        if self.entry_ea == idaapi.BADADDR:
            return
        try:
            if not self.history:
                save_to_idb(self.entry_ea, "", tag=CHAIN_CHAT_HISTORY_TAG)
                return
            data = json.dumps({
                "schema_version": 2,
                "entry_ea": self.entry_ea,
                "binary_id": binary_fingerprint(ida_nalt.get_input_file_path() or ""),
                "graph_eas": sorted(int(ea) for ea in self.graph),
                "context_eas": list(self._context_signature),
                "history": self.history,
            })
            save_to_idb(self.entry_ea, data, tag=CHAIN_CHAT_HISTORY_TAG)
        except Exception as e:
            print(f"[Genesect] Error saving history: {e}")

    def load_history(self):
        if self.entry_ea == idaapi.BADADDR:
            return
        try:
            data = load_from_idb(self.entry_ea, tag=CHAIN_CHAT_HISTORY_TAG)
            if data:
                saved = json.loads(data)
                if isinstance(saved, dict):
                    if int(saved.get("schema_version", 1)) > 2:
                        self.status_lbl.setText("Saved chain history uses a newer unsupported format.")
                        return
                    expected_id = binary_fingerprint(ida_nalt.get_input_file_path() or "")
                    if saved.get("entry_ea") != self.entry_ea or (saved.get("binary_id") and saved.get("binary_id") != expected_id):
                        self.status_lbl.setText("Saved chain history belongs to a different graph or binary.")
                        return
                    self.history = normalize_chat_history(saved.get("history", []))
                    self._context_signature = selection_signature(saved.get("context_eas", ()))
                else:
                    self.history = normalize_chat_history(saved)
                legacy_injection = any(
                    "System Context Update" in message.get("content", "")
                    for message in self.history
                )
                if legacy_injection:
                    self._context_signature = ()
                    self.status_lbl.setText("Legacy context detected; it will rebuild on the next question.")
                if self.history and self.history[0].get("role") == "system":
                    content = self.history[0].get("content", "")
                    if "\n\n" in content and not legacy_injection:
                        self._context_snapshot = content.split("\n\n", 1)[1]
                # Populate UI (skip system messages)
                for msg in self.history:
                    if msg.get('role') in ('user', 'assistant'):
                        content = msg.get('content', '')
                        is_ack = legacy_injection and msg.get('role') == 'assistant' and content.strip().upper() == "OK"
                        if "System Context Update" not in content and not is_ack:
                            self.add_chat_message(content, is_user=(msg.get('role') == 'user'))
                if not legacy_injection:
                    self.status_lbl.setText("History loaded from IDB.")
            else:
                # Show welcome message for new chain
                welcome = (
                    "### ⚡ Function Chain Analysis Ready\n\n"
                    "1. Pick an **Entry Function** above and click **⚡ Build Chain Graph**.\n"
                    "2. Select or deselect functions in the **Call Chain Explorer** to customize your context.\n"
                    "3. Click a **Quick Prompt** below or type your question to start analyzing!"
                )
                self.add_chat_message(welcome, is_user=False)
        except Exception as e:
            print(f"[Genesect] Error loading history: {e}")

    def scroll_to_bottom(self):
        self.chat_area.verticalScrollBar().setValue(self.chat_area.verticalScrollBar().maximum())

    def closeEvent(self, event):
        self._closed = True
        self._cancel_active_request()
        self.save_history()
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            if not self.worker.wait(3000):
                self._closed = False
                self.status_lbl.setText("Graph cancellation is still finishing; close again shortly.")
                event.ignore()
                return
        super().closeEvent(event)


class ChatChainHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.dlg = None
        
    def activate(self, ctx):
        ea = ctx.cur_ea if ctx.cur_ea != idaapi.BADADDR else idaapi.get_screen_ea()
        f = ida_funcs.get_func(ea)
        if not f:
            print("No function selected.")
            return 1

        self.dlg = ChatChainDialog(f.start_ea, parent=None)
        self._wrapper = PluginFormWrapper(self.dlg, "Genesect - Ask AI Chain")
        self._wrapper.show_form()
        return 1
        
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
