# -*- coding: utf-8 -*-
"""Unified 3-in-1 Batch AI Workbench combining Function Renamer, Variable Renamer, and Function Analysis."""

from genesect.config import CONFIG
from genesect.qt_compat import QtCore, QtGui, QtWidgets
from genesect.ui.mac_workspace import apply_mac_workspace
from genesect.ui.theme import current_theme

TAB_FUNCTIONS = 0
TAB_VARIABLES = 1
TAB_ANALYSIS = 2

TAB_NAMES = {
    TAB_FUNCTIONS: "Function Renamer",
    TAB_VARIABLES: "Variable Renamer",
    TAB_ANALYSIS: "Function Analysis",
}

TAB_ORDER = (TAB_FUNCTIONS, TAB_VARIABLES, TAB_ANALYSIS)

_TAB_ALIAS_MAP = {
    "functions": TAB_FUNCTIONS,
    "function": TAB_FUNCTIONS,
    "rename": TAB_FUNCTIONS,
    "renamer": TAB_FUNCTIONS,
    "func": TAB_FUNCTIONS,
    "variables": TAB_VARIABLES,
    "variable": TAB_VARIABLES,
    "vars": TAB_VARIABLES,
    "var": TAB_VARIABLES,
    "var_renamer": TAB_VARIABLES,
    "analysis": TAB_ANALYSIS,
    "analyzer": TAB_ANALYSIS,
    "analyze": TAB_ANALYSIS,
    "summary": TAB_ANALYSIS,
}


def normalize_tab(tab):
    """Normalize tab identifier (int or str) into a valid tab index."""
    if isinstance(tab, int) and tab in TAB_ORDER:
        return tab
    if isinstance(tab, str):
        cleaned = tab.strip().lower()
        if cleaned in _TAB_ALIAS_MAP:
            return _TAB_ALIAS_MAP[cleaned]
    return TAB_FUNCTIONS


_workbench = None


class BatchAIWorkbench(QtWidgets.QDialog):
    """Consolidated 3-in-1 Workbench for Function Renaming, Variable Renaming, and Function Analysis."""

    def __init__(self, initial_tab=TAB_FUNCTIONS, parent=None):
        super().__init__(parent)
        self.setWindowFlags(
            self.windowFlags()
            | QtCore.Qt.Window
            | QtCore.Qt.WindowMinimizeButtonHint
            | QtCore.Qt.WindowMaximizeButtonHint
        )
        self.setWindowTitle("Genesect - Batch AI Workbench")
        self.resize(1450, 950)
        apply_mac_workspace(self)

        self.tab_widgets = {}
        self._initial_tab = normalize_tab(initial_tab)

        self._setup_ui()

    def _apply_tabs_style(self):
        t = current_theme(self)
        if hasattr(self.tabs, "tabBar") and self.tabs.tabBar():
            self.tabs.tabBar().setDrawBase(False)
        self.tabs.setStyleSheet(f"""
            QTabWidget {{
                background: transparent;
                border: none;
            }}
            QTabWidget::pane {{
                border: none;
                background: transparent;
                margin: 0px;
                padding: 0px;
                top: 0px;
            }}
            QTabBar {{
                background: transparent;
                border: none;
                qproperty-drawBase: 0;
            }}
            QTabBar::tab {{
                background: {t.surface_alt};
                color: {t.text_muted};
                border: 1px solid {t.border};
                border-radius: 8px;
                font-size: 13px;
                font-weight: 600;
                padding: 8px 24px;
                margin-right: 8px;
                margin-bottom: 8px;
                outline: none;
            }}
            QTabBar::tab:hover {{
                background: {t.surface_hover};
                color: {t.text};
                border-color: {t.border_strong};
            }}
            QTabBar::tab:selected {{
                background: {t.accent};
                color: {t.accent_text};
                border: 1px solid {t.accent};
                font-weight: 700;
            }}
        """)

    def _setup_ui(self):
        root = QtWidgets.QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 16)
        root.setSpacing(0)

        self.tabs = QtWidgets.QTabWidget(self)
        self._apply_tabs_style()

        # Container pages for lazy instantiation
        self.containers = {}
        for tab_idx in TAB_ORDER:
            container = QtWidgets.QWidget(self.tabs)
            layout = QtWidgets.QVBoxLayout(container)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(0)
            self.containers[tab_idx] = container
            self.tabs.addTab(container, TAB_NAMES[tab_idx])

        self.tabs.currentChanged.connect(self._on_tab_changed)
        root.addWidget(self.tabs)

        # Load initial tab
        self.select_tab(self._initial_tab)

    def _ensure_tab_instance(self, tab_idx):
        tab_idx = normalize_tab(tab_idx)
        if tab_idx in self.tab_widgets:
            return self.tab_widgets[tab_idx]

        widget = None
        if tab_idx == TAB_FUNCTIONS:
            from genesect import renamer
            widget = renamer.BulkRenamer(CONFIG, parent=self.containers[tab_idx])
        elif tab_idx == TAB_VARIABLES:
            from genesect import var_renamer
            widget = var_renamer.BulkVariableRenamer(parent=self.containers[tab_idx])
        elif tab_idx == TAB_ANALYSIS:
            from genesect import analyzer
            widget = analyzer.BulkAnalyzer(parent=self.containers[tab_idx])

        if widget is not None:
            widget.setWindowFlags(QtCore.Qt.Widget)
            widget.workbench = self
            if widget.layout():
                widget.layout().setContentsMargins(0, 4, 0, 0)
            self.containers[tab_idx].layout().addWidget(widget)
            self.tab_widgets[tab_idx] = widget

        return widget

    def _on_tab_changed(self, index):
        self._ensure_tab_instance(index)

    def select_tab(self, tab):
        tab_idx = normalize_tab(tab)
        self._ensure_tab_instance(tab_idx)
        if self.tabs.currentIndex() != tab_idx:
            self.tabs.setCurrentIndex(tab_idx)

    def get_tab_instance(self, tab):
        tab_idx = normalize_tab(tab)
        return self._ensure_tab_instance(tab_idx)

    def forward_functions_to_variables(self, eas):
        """Pipeline action: forward selected function EAs from Tab 0 to Tab 1."""
        self.select_tab(TAB_VARIABLES)
        var_renamer = self.get_tab_instance(TAB_VARIABLES)
        if var_renamer and hasattr(var_renamer, "load_eas"):
            var_renamer.load_eas(eas, append=True)

    def changeEvent(self, event):
        if event.type() in (QtCore.QEvent.PaletteChange, QtCore.QEvent.ApplicationPaletteChange):
            self._apply_tabs_style()
        super().changeEvent(event)

    def closeEvent(self, event):
        global _workbench
        if _workbench is self:
            _workbench = None
        super().closeEvent(event)


def show_batch_workbench(initial_tab=TAB_FUNCTIONS):
    """Open or focus the unified Batch AI Workbench at the requested tab."""
    global _workbench
    target_tab = normalize_tab(initial_tab)
    if _workbench is not None:
        _workbench.select_tab(target_tab)
        _workbench.showNormal()
        _workbench.show()
        _workbench.raise_()
        _workbench.activateWindow()
        return _workbench

    _workbench = BatchAIWorkbench(initial_tab=target_tab, parent=None)
    _workbench.show()
    return _workbench
