"""Reusable review dialogs for AI-generated proposals."""

from genesect.qt_compat import QtCore, QtWidgets
from genesect.ui.components import PageHeader, ProfessionalTable
from genesect.ui.theme import ThemeManager


def _accepted_value():
    accepted = getattr(QtWidgets.QDialog, "Accepted", None)
    if accepted is not None:
        return accepted
    dialog_code = getattr(QtWidgets.QDialog, "DialogCode", None)
    return getattr(dialog_code, "Accepted", 1)


class ChangeReviewDialog(QtWidgets.QDialog):
    def __init__(self, title, original, proposed, apply_label="Apply", parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(820, 480)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.addWidget(PageHeader(title, "Review the AI proposal before modifying the IDB."))
        split = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        split.addWidget(self._panel("Current", original))
        split.addWidget(self._panel("Proposed", proposed))
        layout.addWidget(split, 1)
        buttons = QtWidgets.QDialogButtonBox()
        apply_button = buttons.addButton(apply_label, QtWidgets.QDialogButtonBox.AcceptRole)
        apply_button.setProperty("pnVariant", "primary")
        buttons.addButton(QtWidgets.QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.theme = ThemeManager(self, "system")

    def _panel(self, title, text):
        box = QtWidgets.QGroupBox(title)
        layout = QtWidgets.QVBoxLayout(box)
        editor = QtWidgets.QPlainTextEdit()
        editor.setReadOnly(True)
        editor.setPlainText(str(text or ""))
        layout.addWidget(editor)
        return box


class MappingReviewDialog(QtWidgets.QDialog):
    def __init__(self, title, mapping, source_label="Current", proposal_label="Proposed", parent=None):
        super().__init__(parent)
        self.mapping = dict(mapping)
        self.setWindowTitle(title)
        self.resize(760, 520)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.addWidget(PageHeader(title, "Select the proposals to apply. Unchecked rows leave IDA unchanged."))
        self.table = ProfessionalTable(len(self.mapping), 3)
        self.table.setSortingEnabled(False)
        self.table.setHorizontalHeaderLabels(["Apply", source_label, proposal_label])
        for row, (source, proposal) in enumerate(self.mapping.items()):
            checked = QtWidgets.QTableWidgetItem()
            checked.setFlags(checked.flags() | QtCore.Qt.ItemIsUserCheckable)
            checked.setCheckState(QtCore.Qt.Checked)
            self.table.setItem(row, 0, checked)
            self.table.setItem(row, 1, QtWidgets.QTableWidgetItem(str(source)))
            self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(str(proposal)))
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table, 1)
        buttons = QtWidgets.QDialogButtonBox()
        self.apply_button = buttons.addButton("Apply Selected", QtWidgets.QDialogButtonBox.AcceptRole)
        self.apply_button.setProperty("pnVariant", "primary")
        buttons.addButton(QtWidgets.QDialogButtonBox.Cancel)
        self.apply_button.clicked.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.table.itemChanged.connect(self._update_apply_enabled)
        self._update_apply_enabled()
        self.theme = ThemeManager(self, "system")

    def _update_apply_enabled(self, *_args):
        self.apply_button.setEnabled(bool(self.selected_mapping()))

    def selected_mapping(self):
        selected = {}
        for row in range(self.table.rowCount()):
            if self.table.item(row, 0).checkState() == QtCore.Qt.Checked:
                selected[self.table.item(row, 1).text()] = self.table.item(row, 2).text()
        return selected


def confirm_change(title, original, proposed, apply_label="Apply", parent=None):
    dialog = ChangeReviewDialog(title, original, proposed, apply_label, parent)
    return dialog.exec_() == _accepted_value()


def select_mapping(title, mapping, source_label="Current", proposal_label="Proposed", parent=None):
    dialog = MappingReviewDialog(title, mapping, source_label, proposal_label, parent)
    if dialog.exec_() != _accepted_value():
        return None
    return dialog.selected_mapping()
