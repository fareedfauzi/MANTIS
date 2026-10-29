"""In-IDA preview for reviewing the Phase 1 design system."""

import idaapi

from genesect.qt_compat import QtCore, QtWidgets
from genesect.ui.components import configure_content_tabs
from genesect.ui.components import (
    Card, EmptyState, PageHeader, ProfessionalTable, ProgressPanel,
    SearchField, StatusBadge,
)
from genesect.ui.state import UIStateStore
from genesect.ui.theme import ThemeManager

_preview_dialog = None


class UIComponentPreview(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Genesect - UI Component Preview")
        self.resize(1040, 760)
        self.state = UIStateStore("component_preview")
        self._build_ui()
        self.theme = ThemeManager(self, self.state.value("theme", "system"))
        self.state.restore_window(self)

    def _build_ui(self):
        root = QtWidgets.QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(16)

        header = PageHeader(
            "Interface Foundation",
            "Review shared controls, hierarchy, spacing, states, and theme behavior before feature screens are converted.",
        )
        self.theme_combo = QtWidgets.QComboBox()
        self.theme_combo.addItems(["System", "Dark", "Light"])
        saved = str(self.state.value("theme", "system")).capitalize()
        self.theme_combo.setCurrentText(saved)
        self.theme_combo.currentTextChanged.connect(self._change_theme)
        header.add_action(self.theme_combo)
        root.addWidget(header)

        tabs = QtWidgets.QTabWidget()
        configure_content_tabs(tabs)
        root.addWidget(tabs, 1)
        tabs.addTab(self._controls_page(), "Controls")
        tabs.addTab(self._table_page(), "Data & Filters")
        tabs.addTab(self._states_page(), "Progress & Empty States")

        footer = QtWidgets.QHBoxLayout()
        note = QtWidgets.QLabel("Phase 1 preview only — existing feature behavior is unchanged.")
        note.setProperty("pnMuted", True)
        close_button = QtWidgets.QPushButton("Close")
        close_button.clicked.connect(self.close)
        footer.addWidget(note)
        footer.addStretch()
        footer.addWidget(close_button)
        root.addLayout(footer)

    def _controls_page(self):
        page = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(page)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)

        actions = Card("Actions", "Consistent visual priority and interaction states.")
        row = QtWidgets.QHBoxLayout()
        primary = QtWidgets.QPushButton("Analyze Function")
        primary.setProperty("pnVariant", "primary")
        row.addWidget(primary)
        row.addWidget(QtWidgets.QPushButton("Export"))
        danger = QtWidgets.QPushButton("Delete Result")
        danger.setProperty("pnVariant", "danger")
        row.addWidget(danger)
        disabled = QtWidgets.QPushButton("Unavailable")
        disabled.setEnabled(False)
        row.addWidget(disabled)
        row.addStretch()
        actions.add_layout(row)
        layout.addWidget(actions)

        inputs = Card("Inputs", "Focused fields use a single accent treatment and accessible labels.")
        form = QtWidgets.QFormLayout()
        form.addRow("Function", SearchField("Search by name or address"))
        provider = QtWidgets.QComboBox()
        provider.addItems(["OpenAI", "Anthropic", "Gemini", "Local provider"])
        form.addRow("Provider", provider)
        depth = QtWidgets.QSpinBox()
        depth.setRange(1, 100)
        depth.setValue(15)
        form.addRow("Graph depth", depth)
        inputs.add_layout(form)
        layout.addWidget(inputs)

        badges = Card("Status badges")
        badge_row = QtWidgets.QHBoxLayout()
        for text, tone in (("Pending", "neutral"), ("Analyzing", "info"), ("Complete", "success"), ("Deferred", "warning"), ("Failed", "danger")):
            badge_row.addWidget(StatusBadge(text, tone))
        badge_row.addStretch()
        badges.add_layout(badge_row)
        layout.addWidget(badges)
        layout.addStretch()
        return page

    def _table_page(self):
        page = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(page)
        layout.setContentsMargins(16, 16, 16, 16)
        search = SearchField("Filter functions, tags, or addresses")
        layout.addWidget(search)
        table = ProfessionalTable(4, 5)
        table.setHorizontalHeaderLabels(["Address", "Function", "Risk", "Confidence", "Status"])
        rows = [
            ("0x401000", "entry_dispatch", "High", "94%", "Complete"),
            ("0x4012A0", "decrypt_config", "Medium", "87%", "Complete"),
            ("0x401510", "sub_401510", "Pending", "—", "Queued"),
            ("0x401880", "network_beacon", "High", "91%", "Analyzing"),
        ]
        for row_index, row in enumerate(rows):
            for column, value in enumerate(row):
                table.setItem(row_index, column, QtWidgets.QTableWidgetItem(value))
        table.resizeColumnsToContents()
        layout.addWidget(table, 1)
        return page

    def _states_page(self):
        page = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(page)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)
        progress = ProgressPanel("Analysis activity")
        progress.start("Analyzing call graph", "Contextual analysis")
        progress.set_progress(37, 120, 18420)
        layout.addWidget(progress)
        empty = Card()
        empty.add_widget(EmptyState(
            "No analysis selected",
            "Choose a function in IDA or load a saved session to begin.",
            "Use Current Function",
        ))
        layout.addWidget(empty, 1)
        return page

    def _change_theme(self, text):
        preference = str(text).lower()
        self.state.set_value("theme", preference)
        if hasattr(self, "theme"):
            self.theme.set_preference(preference)

    def closeEvent(self, event):
        self.state.save_window(self)
        super().closeEvent(event)


def show_ui_preview():
    global _preview_dialog
    if _preview_dialog is None:
        _preview_dialog = UIComponentPreview()
    _preview_dialog.show()
    return _preview_dialog


class UIPreviewHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        show_ui_preview()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
