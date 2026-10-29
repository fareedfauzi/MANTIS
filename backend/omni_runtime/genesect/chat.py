# -*- coding: utf-8 -*-
"""
AI Chat interface for Genesect.
Provides a dockable widget to chat with AI about the current function.
"""

import html

import idaapi
import ida_kernwin
import ida_hexrays
import idc
import idautils

import json
from genesect.qt_compat import QtWidgets, QtCore, QtGui, Signal
from genesect.config import LOGGER
import genesect.ai_client as _ai_mod
from genesect.idb_storage import save_to_idb, load_from_idb
from genesect.ui.workspace import RequestGate
from genesect.chat_state import normalize_chat_history
from genesect.ui.typography import ui_font
from genesect.ui.mac_workspace import apply_mac_workspace
from genesect.ui.components import StatusBadge, ToggleSwitch
from genesect.ui.theme import apply_theme, current_theme
from genesect.chat_export import export_chat_log

CHAT_HISTORY_TAG = 96

CHAT_SIDEBAR_GROUPS = (
    ("Prompt Templates", (
        ("Explain function", "prompt", "Explain this function step by step using the supplied pseudocode."),
        ("Summarize behavior", "prompt", "Summarize this function's purpose, inputs, outputs, side effects, and important calls."),
        ("Find IOCs / C2", "prompt", "Look for evidence of IOCs or C2 behavior in this function. Cite exact evidence and state confidence."),
        ("Identify vulnerabilities", "prompt", "Review this function for memory-safety, validation, and logic vulnerabilities. Cite the relevant pseudocode."),
        ("Explain data flow", "prompt", "Explain how important inputs and values flow through this function to its outputs and side effects."),
    )),
    ("Rename & Types", (
        ("Suggest function name", "shortcut", "genesect:rename_function"),
        ("Malware-aware function name", "shortcut", "genesect:rename_function_malware"),
        ("Suggest variable names", "shortcut", "genesect:rename_variables"),
        ("Suggest function prototype", "shortcut", "genesect:suggest_function_prototype"),
        ("Infer / edit structure", "shortcut", "genesect:analyze_struct"),
    )),
    ("Documentation", (
        ("Generate pseudocode comments", "shortcut", "genesect:add_comments"),
        ("Open readable code", "shortcut", "genesect:readable_code"),
        ("Open analyst notes", "shortcut", "genesect:analyst_notes"),
    )),
    ("Inspect", (
        ("Open call tree", "shortcut", "genesect:dnspy_xrefs"),
    )),
)

CONFIRM_SIDEBAR_SHORTCUTS = {
    "genesect:rename_function": "open the function-renaming workflow",
    "genesect:rename_function_malware": "open the malware-aware renaming workflow",
    "genesect:rename_variables": "open the variable-renaming workflow",
    "genesect:add_comments": "open pseudocode-comment generation",
}

def build_chat_prompt(function_name, decompiled_code, caller_context=""):
    """Create the plain-chat system context used by the original Genesect UI."""
    return {
        "role": "system",
        "content": (
            f"You are a helpful reverse-engineering assistant analyzing `{function_name}`. "
            f"Answer the user's questions conversationally from the supplied source. "
            f"Do not request tools, emit tool-call JSON, or make autonomous decisions.\n\n"
            f"Source:\n\n```c\n{decompiled_code}\n```{caller_context}"
        ),
    }

def get_ida_colors():
    """Get theme-aware colors from IDA's palette."""
    app = QtWidgets.QApplication.instance()
    palette = app.palette()

    return {
        "window": palette.color(QtGui.QPalette.Window).name(),
        "window_text": palette.color(QtGui.QPalette.WindowText).name(),
        "base": palette.color(QtGui.QPalette.Base).name(),
        "alt_base": palette.color(QtGui.QPalette.AlternateBase).name(),
        "text": palette.color(QtGui.QPalette.Text).name(),
        "button": palette.color(QtGui.QPalette.Button).name(),
        "button_text": palette.color(QtGui.QPalette.ButtonText).name(),
        "highlight": palette.color(QtGui.QPalette.Highlight).name(),
        "highlight_text": palette.color(QtGui.QPalette.HighlightedText).name(),
        "mid": palette.color(QtGui.QPalette.Mid).name(),
        "dark": palette.color(QtGui.QPalette.Dark).name(),
        "light": palette.color(QtGui.QPalette.Light).name(),
        "link": palette.color(QtGui.QPalette.Link).name(),
    }
def get_chat_font():
    """Get the preferred aesthetic font for chat interactions."""
    return ui_font(11.0)

def markdown_to_html(text):
    """
    Parse Markdown using Qt's native QTextDocument engine for 'proper' results.
    This handles complex structures like lists and nested formatting much better than regex.
    """
    colors = get_ida_colors()
    
    # We use a QTextDocument to convert Markdown to a clean, theme-aware HTML.
    doc = QtGui.QTextDocument()
    
    font = get_chat_font()
    
    # 1. Define a CSS stylesheet that matches IDA's theme for the parsed content
    # Note: QTextDocument supports a limited subset of CSS.
    style = f"""
        body {{ 
            font-family: '{font.family()}';
            font-size: {font.pointSize()}pt;
            color: {colors['text']}; 
            line-height: 1.55;
        }}
        h1, h2, h3 {{ 
            color: {colors['highlight']}; 
            font-weight: bold;
            margin-top: 12px;
            margin-bottom: 4px;
        }}
        h1 {{ font-size: 1.2em; }}
        h2 {{ font-size: 1.1em; border-bottom: 1px solid {colors['mid']}; }}
        h3 {{ font-size: 1.0em; }}
        
        /* Technical terms / Inline code */
        code {{ 
            font-family: 'Consolas', 'Courier New', monospace; 
            color: {colors['link']};
            background-color: transparent;
            font-weight: bold;
        }}
        
        /* Code blocks: Mono with subtle indent, no boxes */
        pre {{ 
            font-family: 'Consolas', 'Courier New', monospace; 
            color: {colors['text']};
            margin: 10px 0;
            padding-left: 10px;
        }}
        
        /* Lists: Proper alignment and spacing */
        li {{ margin-bottom: 2px; }}
        ul, ol {{ margin-left: 15px; padding-left: 5px; }}
        
        a {{ color: {colors['link']}; text-decoration: none; }}
    """
    
    doc.setDefaultStyleSheet(style)
    
    # 2. Native Markdown parsing (Qt 5.14+)
    # This is the "proper" way to handle the conversion.
    doc.setMarkdown(text)
    
    # 3. Handle specific formatting tweaks that setMarkdown might miss in translation
    html_content = doc.toHtml()
    
    # Fix potential 'boxy' behavior in generic HTML generation
    html_content = html_content.replace('border: 1px solid', 'border: none')
    
    return html_content

class ChatBubble(QtWidgets.QWidget):
    def __init__(self, text, is_user=True, parent=None):
        super(ChatBubble, self).__init__(parent)
        self.is_user = is_user
        self.setup_ui(text)

    def setup_ui(self, text):
        colors = get_ida_colors()
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)
        
        main_layout = QtWidgets.QHBoxLayout(self)
        main_layout.setContentsMargins(18, 6, 18, 6)
        main_layout.setSpacing(0)

        # Bubble Container
        self.bubble = QtWidgets.QFrame()
        self.bubble.setObjectName("chatBubble")
        bubble_layout = QtWidgets.QVBoxLayout(self.bubble)
        bubble_layout.setContentsMargins(16, 12, 16, 12)
        bubble_layout.setSpacing(4)

        self.label = QtWidgets.QLabel()
        self.label.setObjectName("chatBubbleLabel")
        self.label.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.label.setWordWrap(True)
        
        # Aesthetic font selection
        font = get_chat_font()
        self.label.setFont(font)

        # Ensure text is selectable by mouse and keyboard, and links are clickable
        self.label.setTextInteractionFlags(QtCore.Qt.TextBrowserInteraction)
        self.label.setOpenExternalLinks(True)
        self.label.setCursor(QtCore.Qt.IBeamCursor)

        if self.is_user:
            # Wrap in a DIV for better selection handling in some Qt versions
            self.label.setTextFormat(QtCore.Qt.RichText)
            self.label.setText(f"<div>{html.escape(text)}</div>")
            
            # Selection visibility fix: Use a slightly different color or specify selection style
            # Actually, using a slightly darker/lighter variant for background or specific selection colors:
            self.bubble.setStyleSheet(f"""
                QFrame#chatBubble {{
                    background-color: {colors['highlight']};
                    border: none;
                    border-radius: 10px;
                    border-bottom-right-radius: 3px;
                }}
                QLabel {{
                    color: {colors['highlight_text']};
                    background: transparent;
                    border: none;
                    selection-background-color: {colors['base']};
                    selection-color: {colors['text']};
                }}
            """)
            main_layout.addStretch()
            main_layout.addWidget(self.bubble)
        else:
            self.label.setTextFormat(QtCore.Qt.RichText)
            # Use the "Proper" Markdown Parser
            self.label.setText(markdown_to_html(text))
            
            self.bubble.setStyleSheet(f"""
                QFrame#chatBubble {{
                    background-color: {colors['base']};
                    border: 1px solid {colors['mid']};
                    border-radius: 10px;
                    border-bottom-left-radius: 3px;
                }}
                QLabel {{
                    color: {colors['text']};
                    background: transparent;
                    border: none;
                }}
            """)
            main_layout.addWidget(self.bubble)
            main_layout.addStretch()

        bubble_layout.addWidget(self.label)
        
        # Reasonable sizing for better readability across various window sizes
        self.set_available_width(720)

    def set_available_width(self, available_width):
        """Keep short messages readable while allowing long answers to breathe."""
        available = max(320, int(available_width or 0) - 24)
        minimum_ratio = 0.24 if self.is_user else 0.38
        minimum_cap = 360 if self.is_user else 440
        minimum = min(minimum_cap, max(260, int(available * minimum_ratio)))
        maximum = min(820, max(minimum, int(available * 0.72)))
        self.bubble.setMinimumWidth(minimum)
        self.bubble.setMaximumWidth(maximum)


class ResponsiveChatScrollArea(QtWidgets.QScrollArea):
    viewportResized = Signal(int)

    def resizeEvent(self, event):
        super(ResponsiveChatScrollArea, self).resizeEvent(event)
        self.viewportResized.emit(self.viewport().width())

class ChatInput(QtWidgets.QWidget):
    submitted = Signal(str)

    def __init__(self, parent=None):
        super(ChatInput, self).__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        input_layout = QtWidgets.QHBoxLayout(self)
        input_layout.setContentsMargins(0, 0, 0, 0)
        input_layout.setSpacing(8)

        theme = current_theme(self)
        self.input_box = QtWidgets.QPlainTextEdit()
        self.input_box.setPlaceholderText("Ask AI about this function...")
        self.input_box.setMaximumHeight(74)
        self.input_box.setMinimumHeight(44)
        self.input_box.setStyleSheet(f"""
            QPlainTextEdit {{
                background-color: {theme.code_background};
                color: {theme.text};
                border: 1px solid {theme.border};
                border-radius: 8px;
                padding-left: 12px;
                padding-right: 12px;
                padding-top: 9px;
                font-size: 13px;
                selection-background-color: {theme.selection};
            }}
            QPlainTextEdit:focus {{
                border-color: {theme.accent};
            }}
        """)
        self.input_box.installEventFilter(self)

        self.send_btn = QtWidgets.QPushButton("Send")
        self.send_btn.setFixedSize(62, 38)
        self.send_btn.setCursor(QtCore.Qt.PointingHandCursor)
        self.send_btn.setToolTip("Send message")
        self.send_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {theme.accent};
                color: {theme.accent_text};
                border: 1px solid {theme.accent};
                border-radius: 8px;
                font-size: 9pt;
                font-weight: 700;
                padding: 0;
            }}
            QPushButton:hover {{
                background-color: {theme.accent_hover};
                border-color: {theme.accent_hover};
            }}
            QPushButton:disabled {{
                background-color: {theme.surface_alt};
                color: {theme.text_disabled};
                border-color: {theme.border};
            }}
        """)
        self.send_btn.clicked.connect(self.submit)

        input_layout.addWidget(self.input_box)
        input_layout.addWidget(self.send_btn)

    def eventFilter(self, obj, event):
        if obj is self.input_box and event.type() == QtCore.QEvent.KeyPress:
            if event.key() in (QtCore.Qt.Key_Return, QtCore.Qt.Key_Enter):
                if not (event.modifiers() & QtCore.Qt.ShiftModifier):
                    self.submit()
                    return True
        return super(ChatInput, self).eventFilter(obj, event)

    def submit(self):
        text = self.input_box.toPlainText().strip()
        if text:
            self.submitted.emit(text)
            self.input_box.clear()

    def setEnabled(self, enabled):
        super(ChatInput, self).setEnabled(enabled)
        self.input_box.setEnabled(enabled)
        self.send_btn.setEnabled(enabled)

    def setFocus(self, reason=QtCore.Qt.OtherFocusReason):
        self.input_box.setFocus(reason)

class IDAChatForm(ida_kernwin.PluginForm):
    def __init__(self, address, function_name, decompiled_code):
        super(IDAChatForm, self).__init__()
        self.address = address
        self.function_name = function_name
        self.decompiled_code = decompiled_code
        self.request_gate = RequestGate()
        self._active_request_id = None
        self._closed = False
        self._continuation_count = 0
        
        # System prompt always reflects the current state of decompilation
        self.system_prompt = build_chat_prompt(function_name, decompiled_code)
        
        # Load messages from IDB
        self.history = []
        saved_history = load_from_idb(self.address, tag=CHAT_HISTORY_TAG)
        if saved_history and saved_history.strip():
            try:
                self.history = json.loads(saved_history)
            except Exception as e:
                LOGGER.log(f"Failed to load chat history: {e}")
        
        self.history = normalize_chat_history(self.history, self.system_prompt)

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.setup_ui()

    def setup_ui(self):
        colors = get_ida_colors()
        apply_mac_workspace(self.parent)
        theme = apply_theme(self.parent)
        
        layout = QtWidgets.QVBoxLayout(self.parent)
        layout.setContentsMargins(16, 14, 16, 12)
        layout.setSpacing(12)

        # Header
        header = QtWidgets.QFrame()
        header.setObjectName("chatHeader")
        header_vbox = QtWidgets.QVBoxLayout(header)
        header_vbox.setContentsMargins(0, 0, 0, 0)
        header_vbox.setSpacing(8)

        h_layout = QtWidgets.QHBoxLayout()
        h_layout.setContentsMargins(0, 0, 0, 0)
        h_layout.setSpacing(8)
        title_stack = QtWidgets.QVBoxLayout()
        title_stack.setContentsMargins(0, 0, 0, 0)
        title_stack.setSpacing(3)
        self.title_label = QtWidgets.QLabel()
        self.title_label.setObjectName("chatTitle")
        self.context_label = QtWidgets.QLabel()
        self.context_label.setObjectName("chatSubtitle")
        title_stack.addWidget(self.title_label)
        title_stack.addWidget(self.context_label)
        h_layout.addLayout(title_stack, 1)

        self.status_badge = StatusBadge("Ready", "neutral")
        h_layout.addWidget(self.status_badge)

        preview_btn = QtWidgets.QPushButton("Context Preview")
        preview_btn.clicked.connect(self.show_context_preview)
        h_layout.addWidget(preview_btn)
        export_btn = QtWidgets.QPushButton("Export Log")
        export_btn.clicked.connect(self.export_conversation)
        h_layout.addWidget(export_btn)
        regen_btn = QtWidgets.QPushButton("Regenerate")
        regen_btn.clicked.connect(self.regenerate_last)
        h_layout.addWidget(regen_btn)

        clear_btn = QtWidgets.QPushButton("Clear Conversation")
        clear_btn.setProperty("pnVariant", "danger")
        clear_btn.clicked.connect(self.clear_chat)
        h_layout.addWidget(clear_btn)
        
        header_vbox.addLayout(h_layout)

        self.auto_context_cb = ToggleSwitch("Follow current IDA function")
        self.auto_context_cb.setChecked(True)
        header_vbox.addWidget(self.auto_context_cb)
        
        layout.addWidget(header)
        self._refresh_title_labels()

        # Chat History
        self.scroll = ResponsiveChatScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.scroll.setStyleSheet(f"""
            QScrollArea {{
                background: {theme.surface};
                border: 0;
                border-radius: 0;
            }}
        """)
        
        self.scroll_content = QtWidgets.QWidget()
        self.scroll_layout = QtWidgets.QVBoxLayout(self.scroll_content)
        self.scroll_layout.setContentsMargins(0, 10, 0, 10)
        self.scroll_layout.setSpacing(4)
        self.scroll_layout.addStretch()
        
        self.scroll.setWidget(self.scroll_content)
        self.scroll.viewportResized.connect(self._resize_message_bubbles)
        workspace = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        workspace.setChildrenCollapsible(False)
        workspace.addWidget(self.scroll)
        workspace.addWidget(self._build_sidebar(colors))
        workspace.setStretchFactor(0, 1)
        workspace.setStretchFactor(1, 0)
        workspace.setHandleWidth(10)
        workspace.setStyleSheet(f"""
            QSplitter::handle {{
                background: {theme.window};
            }}
            QSplitter::handle:hover {{
                background: {theme.border};
            }}
        """)
        workspace.setSizes([960, 300])
        layout.addWidget(workspace, stretch=1)

        # "Asking AI" Indicator with Progress Bar
        self.typing_container = QtWidgets.QFrame()
        self.typing_container.setObjectName("typingContainer")
        self.typing_container.setMinimumHeight(40)
        self.typing_container.setStyleSheet(f"""
            QFrame#typingContainer {{
                background-color: {theme.surface};
                border: 1px solid {theme.border};
                border-radius: 8px;
            }}
            QLabel {{
                border: none;
                background: transparent;
            }}
        """)
        indicator_layout = QtWidgets.QHBoxLayout(self.typing_container)
        indicator_layout.setContentsMargins(12, 0, 12, 0)
        indicator_layout.setSpacing(10)

        self.typing_indicator = QtWidgets.QLabel("Generating response")
        self.typing_indicator.setStyleSheet(f"color: {theme.text}; font-weight: 700; font-size: 11px;")
        indicator_layout.addWidget(self.typing_indicator)

        self.chat_progress = QtWidgets.QProgressBar()
        self.chat_progress.setRange(0, 0) # Marquee
        self.chat_progress.setFixedHeight(4)
        self.chat_progress.setTextVisible(False)
        self.chat_progress.setStyleSheet(f"""
            QProgressBar {{ background-color: {theme.surface_alt}; border: none; border-radius: 2px; }}
            QProgressBar::chunk {{ background-color: {theme.accent}; border-radius: 2px; }}
        """)
        indicator_layout.addWidget(self.chat_progress, 1)

        self.progress_details = QtWidgets.QLabel("")
        self.progress_details.setStyleSheet(f"color: {theme.text_muted}; font-size: 10px; font-family: monospace;")
        indicator_layout.addWidget(self.progress_details)

        self.stop_request_btn = QtWidgets.QPushButton("Stop")
        self.stop_request_btn.setToolTip("Cancel the current AI request")
        self.stop_request_btn.clicked.connect(self.stop_request)
        indicator_layout.addWidget(self.stop_request_btn)

        self.typing_container.setVisible(False)
        layout.addWidget(self.typing_container)
        
        # Internal state for tracking chunks
        self._received_chars = 0

        # Input Area
        input_container = QtWidgets.QFrame()
        input_container.setObjectName("chatComposer")
        input_container.setStyleSheet(f"""
            QFrame#chatComposer {{
                background-color: {theme.surface};
                border: 1px solid {theme.border};
                border-radius: 8px;
            }}
        """)
        input_layout = QtWidgets.QVBoxLayout(input_container)
        input_layout.setContentsMargins(10, 10, 10, 10)
        
        self.input_box = ChatInput()
        self.input_box.submitted.connect(self.send_message)
        input_layout.addWidget(self.input_box)
        layout.addWidget(input_container)

        # Initial or Restored messages
        if len(self.history) <= 1:
            welcome_msg = (
                f"I have analyzed `{self.function_name}`. Ask about behavior, inputs, side effects, "
                "renaming ideas, or anything suspicious in this function."
            )
            self.add_message(welcome_msg, is_user=False)
            self.history.append({"role": "assistant", "content": welcome_msg})
            self.save_history()
        else:
            for msg in self.history[1:]: # Skip system prompt
                content = msg.get('content', '')
                role = msg.get('role', '')
                self.add_message(content, is_user=(role == 'user'))

        self.context_timer = QtCore.QTimer(self.parent)
        self.context_timer.timeout.connect(self.check_context_change)
        self.context_timer.start(500)

    def _refresh_title_labels(self):
        theme = current_theme(self.parent)
        self.title_label.setTextFormat(QtCore.Qt.RichText)
        self.title_label.setText(
            '<span style="font-size:18pt; font-weight:700; color:%s;">Chat</span> '
            '<span style="font-size:18pt; font-weight:700; color:%s;">%s</span>'
            % (theme.text, theme.accent, html.escape(self.function_name))
        )
        self.title_label.setStyleSheet("background: transparent;")
        self.context_label.setText(
            "0x%X  |  %s characters of Hex-Rays context"
            % (self.address, len(self.decompiled_code or ""))
        )
        self.context_label.setStyleSheet(
            "background: transparent; color: %s; font-size: 9.5pt;"
            % theme.text_muted
        )

    def _build_sidebar(self, _colors):
        """Build manual prompt templates and workflow shortcuts."""
        theme = current_theme(self.parent)
        panel = QtWidgets.QFrame()
        panel.setObjectName("chatSidebar")
        panel.setMinimumWidth(260)
        panel.setMaximumWidth(360)
        panel.setStyleSheet(f"""
            QFrame#chatSidebar {{
                background: {theme.surface};
                border: 1px solid {theme.border};
                border-radius: 8px;
            }}
            QLabel#chatSidebarTitle {{
                color: {theme.text};
                font-size: 13px;
                font-weight: 700;
            }}
            QLabel#chatSidebarHint {{ color: {theme.text_muted}; font-size: 10px; }}
            QTreeWidget {{
                background: transparent;
                border: 0;
                outline: 0;
                padding: 2px;
                color: {theme.text};
            }}
            QTreeWidget::item {{
                min-height: 28px;
                padding: 3px 6px;
                border-radius: 6px;
            }}
            QTreeWidget::item:hover {{ background: {theme.surface_hover}; }}
        """)
        panel_layout = QtWidgets.QVBoxLayout(panel)
        panel_layout.setContentsMargins(14, 12, 14, 12)
        panel_layout.setSpacing(8)

        title = QtWidgets.QLabel("Prompts")
        title.setObjectName("chatSidebarTitle")
        panel_layout.addWidget(title)
        hint = QtWidgets.QLabel("Click a prompt to load it. Double-click a shortcut to run it.")
        hint.setObjectName("chatSidebarHint")
        hint.setWordWrap(True)
        panel_layout.addWidget(hint)

        self.sidebar_tree = QtWidgets.QTreeWidget()
        self.sidebar_tree.setHeaderHidden(True)
        self.sidebar_tree.setRootIsDecorated(True)
        self.sidebar_tree.setIndentation(14)
        self.sidebar_tree.setFocusPolicy(QtCore.Qt.NoFocus)
        self.sidebar_tree.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
        role = int(QtCore.Qt.UserRole)
        for group_name, entries in CHAT_SIDEBAR_GROUPS:
            group = QtWidgets.QTreeWidgetItem([group_name])
            group.setFlags(group.flags() & ~QtCore.Qt.ItemIsSelectable)
            self.sidebar_tree.addTopLevelItem(group)
            for label, kind, payload in entries:
                tag = "Prompt" if kind == "prompt" else "Shortcut"
                item = QtWidgets.QTreeWidgetItem([f"{tag}: {label}"])
                item.setData(0, role, kind)
                item.setData(0, role + 1, payload)
                item.setToolTip(
                    0,
                    "Click once to place this template in the chat input."
                    if kind == "prompt" else
                    "Double-click to open this existing Genesect workflow.",
                )
                group.addChild(item)
            group.setExpanded(True)

        self.sidebar_tree.itemClicked.connect(self._sidebar_prompt_clicked)
        self.sidebar_tree.itemDoubleClicked.connect(self._sidebar_shortcut_clicked)
        panel_layout.addWidget(self.sidebar_tree, 1)
        return panel

    def _sidebar_prompt_clicked(self, item, _column=0):
        role = int(QtCore.Qt.UserRole)
        if str(item.data(0, role) or "") != "prompt":
            return
        self.input_box.input_box.setPlainText(str(item.data(0, role + 1) or ""))
        self.input_box.setFocus()

    def _sidebar_shortcut_clicked(self, item, _column=0):
        role = int(QtCore.Qt.UserRole)
        if str(item.data(0, role) or "") != "shortcut":
            return
        action_name = str(item.data(0, role + 1) or "")
        if not action_name:
            return

        confirmation = CONFIRM_SIDEBAR_SHORTCUTS.get(action_name)
        if confirmation:
            answer = QtWidgets.QMessageBox.question(
                self.parent,
                "Confirm Genesect Shortcut",
                f"Are you sure you want to {confirmation}?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                QtWidgets.QMessageBox.No,
            )
            if answer != QtWidgets.QMessageBox.Yes:
                return

        if action_name == "genesect:analyze_struct":
            self.add_message(
                "To infer or edit a structure, right-click the target local variable in "
                "the pseudocode view and choose Genesect → Infer / Edit Structure.",
                is_user=False,
            )
            return

        try:
            vdui = ida_hexrays.open_pseudocode(self.address, 0)
            widget = getattr(vdui, "ct", None) if vdui else None
            if not widget:
                self.add_message("Could not open this function in pseudocode view.", is_user=False)
                return
            ida_kernwin.activate_widget(widget, True)

            def run_shortcut():
                if not ida_kernwin.process_ui_action(action_name):
                    self.add_message(
                        f"Could not start the Genesect shortcut `{action_name}`.",
                        is_user=False,
                    )

            QtCore.QTimer.singleShot(0, run_shortcut)
        except Exception as exc:
            self.add_message(f"Shortcut failed: {exc}", is_user=False)

    def add_message(self, text, is_user=True):
        bubble = ChatBubble(text, is_user)
        bubble.set_available_width(self.scroll.viewport().width())
        self.scroll_layout.insertWidget(self.scroll_layout.count() - 1, bubble)
        QtCore.QTimer.singleShot(
            0, lambda b=bubble: b.set_available_width(self.scroll.viewport().width())
        )
        QtCore.QTimer.singleShot(100, self.scroll_to_bottom)

    def _resize_message_bubbles(self, width):
        for index in range(self.scroll_layout.count()):
            widget = self.scroll_layout.itemAt(index).widget()
            if isinstance(widget, ChatBubble):
                widget.set_available_width(width)

    def _clear_message_widgets(self):
        """Remove message bubbles while preserving the final layout stretch."""
        while self.scroll_layout.count() > 1:
            item = self.scroll_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def _render_history(self):
        self._clear_message_widgets()
        for msg in self.history[1:]:
            role = msg.get("role", "")
            if role in ("user", "assistant"):
                self.add_message(msg.get("content", ""), is_user=(role == "user"))

    def _cancel_active_request(self):
        self.request_gate.advance()
        request_id = self._active_request_id
        self._active_request_id = None
        client = _ai_mod.AI_CLIENT
        if request_id is not None and client:
            client.cancel_request(request_id)

    def _request_is_current(self, token):
        return not self._closed and self.request_gate.accepts(token, self.address)

    def stop_request(self):
        if self._active_request_id is None:
            return
        self._cancel_active_request()
        self.typing_container.setVisible(False)
        self.progress_details.setText("")
        self.input_box.setEnabled(True)
        if hasattr(self, "status_badge"):
            self.status_badge.setText("Ready")
            self.status_badge.set_tone("neutral")
        self.add_message("Request cancelled.", is_user=False)

    def scroll_to_bottom(self):
        self.scroll.verticalScrollBar().setValue(self.scroll.verticalScrollBar().maximum())

    def check_context_change(self):
        if not self.auto_context_cb.isChecked():
            return
            
        ea = idaapi.get_screen_ea()
        func = idaapi.get_func(ea)
        if not func:
            return
            
        if func.start_ea != self.address:
            self.change_context(func.start_ea)

    def change_context(self, new_address):
        self._cancel_active_request()
        try:
            cfunc = ida_hexrays.decompile(new_address)
            if not cfunc:
                return
            new_code = str(cfunc)
        except Exception:
            return
            
        new_name = idc.get_func_name(new_address)
        if not new_name:
            return

        old_address = self.address
        old_name = getattr(self, 'function_name', None)
        old_code = getattr(self, 'decompiled_code', None)

        self.save_history()
        
        self.address = new_address
        self.function_name = new_name
        self.decompiled_code = new_code
        
        is_called_from_old = False
        if old_address is not None:
            for xref in idautils.XrefsTo(new_address):
                func = idaapi.get_func(xref.frm)
                if func and func.start_ea == old_address:
                    is_called_from_old = True
                    break
                    
        caller_context = ""
        if is_called_from_old and old_code:
            caller_context = f"\n\nContext - This function is called by `{old_name}`:\n```c\n{old_code}\n```"
        
        self.system_prompt = build_chat_prompt(
            self.function_name, self.decompiled_code, caller_context,
        )
        
        self._refresh_title_labels()
        
        self._clear_message_widgets()

        self.history = []
        saved_history = load_from_idb(self.address, tag=CHAT_HISTORY_TAG)
        if saved_history and saved_history.strip():
            try:
                self.history = json.loads(saved_history)
            except Exception as e:
                LOGGER.log(f"Failed to load chat history: {e}")
                
        self.history = normalize_chat_history(self.history, self.system_prompt)
            
        for msg in self.history[1:]:
            content = msg.get('content', '')
            role = msg.get('role', '')
            self.add_message(content, is_user=(role == 'user'))
            
        if len(self.history) <= 1 or "Analyzing... OK, I understand everything." not in self.history[-1].get('content', ''):
            if is_called_from_old:
                transition_msg = f"You changed to `{self.function_name}`. I have included `{old_name}` as caller context - Analyzing... OK, I understand everything. Please ask if you have any questions."
            else:
                transition_msg = f"You changed to `{self.function_name}` - Analyzing... OK, I understand everything. Please ask if you have any questions."
            self.add_message(transition_msg, is_user=False)
            self.history.append({"role": "assistant", "content": transition_msg})
            self.save_history()

    def save_history(self):
        """Persist chat history to IDB."""
        try:
            save_to_idb(self.address, json.dumps(self.history), tag=CHAT_HISTORY_TAG)
        except Exception as e:
            LOGGER.log(f"Failed to save chat history: {e}")

    def show_context_preview(self):
        dialog = QtWidgets.QDialog(self.parent)
        dialog.setWindowTitle(f"Context Preview — {self.function_name}")
        dialog.resize(760, 520)
        layout = QtWidgets.QVBoxLayout(dialog)
        label = QtWidgets.QLabel(f"Function 0x{self.address:X} • {len(self.decompiled_code):,} characters")
        layout.addWidget(label)
        viewer = QtWidgets.QPlainTextEdit(self.decompiled_code)
        viewer.setReadOnly(True)
        layout.addWidget(viewer)
        dialog.exec_()

    def export_conversation(self):
        path = export_chat_log(
            self.parent, "Export Genesect Chat Log", f"chat_{self.function_name}.md",
            {"title": "Genesect Chat", "mode": "single_function", "function": self.function_name, "address": f"0x{self.address:X}"},
            self.history,
            {"context": {"decompiled_characters": len(self.decompiled_code)}},
        )
        if path:
            LOGGER.log(f"Chat log exported to {path}")

    def regenerate_last(self):
        if len(self.history) < 2 or self.history[-1].get("role") != "assistant":
            return
        self.history.pop()
        self._continuation_count = 0
        self.save_history()
        self._render_history()
        self.add_message("Regenerating the previous response…", is_user=False)
        client = _ai_mod.AI_CLIENT
        if client:
            self.input_box.setEnabled(False)
            self.typing_container.setVisible(True)
            if hasattr(self, "status_badge"):
                self.status_badge.setText("Running")
                self.status_badge.set_tone("info")
            token = self.request_gate.issue(self.address)
            callback = lambda response, **kwargs: self.handle_response(response, token=token, **kwargs)
            self._active_request_id = client.query_model_async(self.history, callback)

    def clear_chat(self):
        if not ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, "Clear chat?") == idaapi.ASKBTN_YES:
            return
        self._cancel_active_request()
        self._clear_message_widgets()
        self.history = [self.history[0]]
        self.save_history()
        self.add_message("Chat cleared.", is_user=False)

    def send_message(self, text):
        self.add_message(text, is_user=True)
        self.history.append({"role": "user", "content": text})
        self.save_history()

        AI_CLIENT = _ai_mod.AI_CLIENT
        if not AI_CLIENT:
            self.add_message("Error: AI Client not initialized.", is_user=False)
            if hasattr(self, "status_badge"):
                self.status_badge.setText("Error")
                self.status_badge.set_tone("danger")
            return

        self.input_box.setEnabled(False)
        self.typing_container.setVisible(True)
        if hasattr(self, "status_badge"):
            self.status_badge.setText("Running")
            self.status_badge.set_tone("info")
        self._received_chars = 0
        self._continuation_count = 0
        self.progress_details.setText("Connecting...")
        
        # Ensure UI updates immediately
        QtWidgets.QApplication.processEvents()

        def on_chunk(text):
            if not self._request_is_current(token):
                return
            self._received_chars += len(text)
            self.progress_details.setText(f"Streaming: {self._received_chars} chars")

        token = self.request_gate.issue(self.address)
        callback = lambda response, **kwargs: self.handle_response(response, token=token, **kwargs)
        self._active_request_id = AI_CLIENT.query_model_async(self.history, callback, on_chunk=on_chunk)

    def handle_response(self, response, token=None, **kwargs):
        """Finish a normal conversational response without any tool/decision loop."""
        if token is not None and not self._request_is_current(token):
            return
        finish_reason = kwargs.get("finish_reason", "stop")

        if finish_reason == "length" and response and self._continuation_count < 2:
            self._continuation_count += 1
            self.progress_details.setText(f"Continuing... ({len(response)} chars so far)")
            QtWidgets.QApplication.processEvents()
            client = _ai_mod.AI_CLIENT
            if client:
                continuation_history = self.history + [
                    {"role": "assistant", "content": response},
                    {
                        "role": "user",
                        "content": (
                            "The previous response was cut off. Continue from exactly where "
                            "you stopped without repeating earlier text."
                        ),
                    },
                ]

                def on_chunk(text):
                    if token is not None and not self._request_is_current(token):
                        return
                    self._received_chars += len(text)
                    self.progress_details.setText(
                        f"Streaming (Continued): {self._received_chars} chars"
                    )

                def on_finished(new_response, **new_kwargs):
                    combined = response + (new_response or "")
                    self.handle_response(combined, token=token, **new_kwargs)

                self._active_request_id = client.query_model_async(
                    continuation_history, on_finished, on_chunk=on_chunk,
                )
                return

        self._active_request_id = None
        self.typing_container.setVisible(False)
        self.progress_details.setText("")
        self.input_box.setEnabled(True)
        self.input_box.setFocus()
        if hasattr(self, "status_badge"):
            self.status_badge.setText("Ready")
            self.status_badge.set_tone("neutral")

        if response:
            self.history.append({"role": "assistant", "content": response})
            self.add_message(response, is_user=False)
            self.save_history()
        else:
            error_msg = str(kwargs.get("error_msg") or "No response from AI.")
            if hasattr(self, "status_badge"):
                self.status_badge.setText("Error")
                self.status_badge.set_tone("danger")
            self.add_message(f"Error: {error_msg}", is_user=False)

    def OnClose(self, form):
        self._closed = True
        self._cancel_active_request()
        self.save_history()
        if getattr(self, "context_timer", None):
            self.context_timer.stop()

_chat_form_instance = None


def show_chat(address):
    """Open or focus the chat widget for a given function."""
    func = idaapi.get_func(address)
    if not func:
        print("[Genesect] No function at current address.")
        return

    name = idc.get_func_name(func.start_ea)
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
        if not cfunc:
            print("[Genesect] Failed to decompile function.")
            return
        code = str(cfunc)
    except:
        print("[Genesect] Error during decompilation.")
        return

    title = "Genesect - AI Chat: Current Function"
    global _chat_form_instance
    widget = ida_kernwin.find_widget(title)
    if widget:
        ida_kernwin.activate_widget(widget, True)
        if _chat_form_instance and _chat_form_instance.address != func.start_ea:
            _chat_form_instance.change_context(func.start_ea)
    else:
        _chat_form_instance = IDAChatForm(func.start_ea, name, code)
        _chat_form_instance.Show(title, options=ida_kernwin.PluginForm.WOPN_DP_RIGHT | ida_kernwin.PluginForm.WOPN_PERSIST)
