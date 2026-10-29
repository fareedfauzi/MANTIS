# -*- coding: utf-8 -*-
"""Unified launcher for Genesect's function and function-chain AI workflows."""

import ida_funcs
import ida_kernwin
import idaapi
import idc

from genesect.qt_compat import PluginFormWrapper, QtCore, QtWidgets
from genesect.chat_scopes import (
    CHAT_SCOPES,
    SCOPE_CHAIN_SUMMARY,
    SCOPE_CURRENT_FUNCTION,
    SCOPE_FUNCTION_CHAIN,
    chat_scope_definition,
    normalize_chat_scope,
)
from genesect.ui.components import PageHeader
from genesect.ui.mac_workspace import apply_mac_workspace


class UnifiedAIChatDialog(QtWidgets.QDialog):
    """Small scope chooser that routes into the existing specialized workspaces."""

    def __init__(self, entry_ea, default_scope=SCOPE_CURRENT_FUNCTION, parent=None):
        super().__init__(parent)
        self.entry_ea = int(entry_ea)
        self.selected_scope = normalize_chat_scope(default_scope)
        self.setWindowTitle("Genesect - AI Chat")
        self.setMinimumWidth(620)
        self.setWindowFlags(
            self.windowFlags()
            | QtCore.Qt.WindowMaximizeButtonHint
            | QtCore.Qt.WindowCloseButtonHint
        )
        apply_mac_workspace(self)
        self._setup_ui()

    def _setup_ui(self):
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)
        layout.addWidget(PageHeader(
            "AI Chat",
            "Choose the amount of program context needed for this investigation.",
            self,
        ))

        target_card = QtWidgets.QFrame(self)
        target_card.setProperty("pnCard", True)
        target_layout = QtWidgets.QFormLayout(target_card)
        target_layout.setContentsMargins(16, 14, 16, 14)
        target_layout.setHorizontalSpacing(14)
        target_layout.setVerticalSpacing(12)

        function_name = idc.get_func_name(self.entry_ea) or "sub_%X" % self.entry_ea
        target_label = QtWidgets.QLabel("%s  (0x%X)" % (function_name, self.entry_ea))
        target_label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        target_layout.addRow("Target function:", target_label)

        self.scope_combo = QtWidgets.QComboBox(self)
        selected_index = 0
        for index, (scope, label, _description, _action) in enumerate(CHAT_SCOPES):
            self.scope_combo.addItem(label, scope)
            if scope == self.selected_scope:
                selected_index = index
        self.scope_combo.setCurrentIndex(selected_index)
        self.scope_combo.currentIndexChanged.connect(self._update_scope_description)
        target_layout.addRow("Scope:", self.scope_combo)
        layout.addWidget(target_card)

        detail_card = QtWidgets.QFrame(self)
        detail_card.setProperty("pnCard", True)
        detail_layout = QtWidgets.QVBoxLayout(detail_card)
        detail_layout.setContentsMargins(16, 14, 16, 14)
        self.scope_description = QtWidgets.QLabel()
        self.scope_description.setWordWrap(True)
        detail_layout.addWidget(self.scope_description)
        self.scope_note = QtWidgets.QLabel(
            "You can change the target function and context limits inside the selected workspace."
        )
        self.scope_note.setWordWrap(True)
        self.scope_note.setProperty("pnMuted", True)
        detail_layout.addWidget(self.scope_note)
        layout.addWidget(detail_card)

        button_row = QtWidgets.QHBoxLayout()
        button_row.addStretch(1)
        cancel_button = QtWidgets.QPushButton("Cancel", self)
        cancel_button.clicked.connect(self.reject)
        self.open_button = QtWidgets.QPushButton(self)
        self.open_button.setProperty("pnVariant", "primary")
        self.open_button.clicked.connect(self._accept_scope)
        button_row.addWidget(cancel_button)
        button_row.addWidget(self.open_button)
        layout.addLayout(button_row)
        self._update_scope_description()

    def _current_scope(self):
        return normalize_chat_scope(self.scope_combo.currentData())

    def _update_scope_description(self, _index=None):
        _scope, _label, description, action = chat_scope_definition(self._current_scope())
        self.scope_description.setText(description)
        self.open_button.setText(action)

    def _accept_scope(self):
        self.selected_scope = self._current_scope()
        self.accept()


class UnifiedAIChatHandler(idaapi.action_handler_t):
    """Open one scope chooser and route to the matching established backend."""

    _last_scope = SCOPE_CURRENT_FUNCTION

    def __init__(self, default_scope=None):
        idaapi.action_handler_t.__init__(self)
        self.default_scope = default_scope
        self.dialog = None
        self.workspace_dialog = None
        self.workspace_wrapper = None

    def activate(self, ctx):
        ea = getattr(ctx, "cur_ea", idaapi.BADADDR)
        if ea == idaapi.BADADDR:
            ea = idaapi.get_screen_ea()
        function = ida_funcs.get_func(ea)
        if not function:
            print("[Genesect] No function selected.")
            return 1

        initial_scope = self.default_scope or self.__class__._last_scope
        self.dialog = UnifiedAIChatDialog(function.start_ea, initial_scope)
        if not self.dialog.exec_():
            return 1

        scope = self.dialog.selected_scope
        self.__class__._last_scope = scope
        self._open_workspace(function.start_ea, scope)
        return 1

    def _open_workspace(self, entry_ea, scope):
        if scope == SCOPE_CURRENT_FUNCTION:
            from genesect.chat import show_chat
            show_chat(entry_ea)
            return

        if scope == SCOPE_FUNCTION_CHAIN:
            from genesect.chat_chain import ChatChainDialog
            self.workspace_dialog = ChatChainDialog(entry_ea, parent=None)
            self.workspace_wrapper = PluginFormWrapper(
                self.workspace_dialog,
                "Genesect - AI Chat: Function Chain",
            )
            self.workspace_wrapper.show_form()
            return

        from genesect.summarizer import SummarizerDialog
        self.workspace_dialog = SummarizerDialog(entry_ea)
        self.workspace_wrapper = PluginFormWrapper(
            self.workspace_dialog,
            "Genesect - AI Chat: Chain Summary",
        )
        self.workspace_wrapper.show_form()

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
