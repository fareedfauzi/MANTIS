"""Reusable, behavior-light Qt components for Extended feature screens."""

import time

from genesect.qt_compat import QtCore, QtGui, QtWidgets
from genesect.ui.tokens import SPACING
from genesect.ui.theme import current_theme


def _set_role(widget, name, value=True):
    widget.setProperty(name, value)
    return widget


def configure_settings_tabs(tabs):
    """Use a stable opaque tab bar when Settings sections overflow."""
    tabs.setObjectName("settingsTabs")
    tabs.setUsesScrollButtons(True)
    # QTabWidget document mode plus transparent QSS tabs can leave stale
    # backing-store fragments in IDA's Windows host when overflow arrows move.
    tabs.setDocumentMode(False)
    bar = tabs.tabBar()
    bar.setObjectName("settingsTabBar")
    bar.setExpanding(False)
    bar.setUsesScrollButtons(True)
    bar.setElideMode(QtCore.Qt.ElideNone)
    bar.setDrawBase(False)
    bar.setAutoFillBackground(True)
    bar.setMinimumHeight(34)
    return tabs


def configure_content_tabs(tabs):
    """Prevent ordinary feature tabs from clipping at narrow dock widths."""
    tabs.setUsesScrollButtons(True)
    bar = tabs.tabBar()
    bar.setExpanding(False)
    bar.setUsesScrollButtons(True)
    bar.setElideMode(QtCore.Qt.ElideNone)
    return tabs


class ToggleSwitch(QtWidgets.QCheckBox):
    """Compact accessible on/off switch with a native checkbox behavior."""
    TRACK_WIDTH = 34
    TRACK_HEIGHT = 18
    KNOB_SIZE = 14
    TEXT_GAP = 8

    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self.setCursor(QtCore.Qt.PointingHandCursor)
        self.setMinimumHeight(26)

    def sizeHint(self):
        metrics = self.fontMetrics()
        text_width = (
            metrics.horizontalAdvance(self.text())
            if hasattr(metrics, "horizontalAdvance") else metrics.width(self.text())
        )
        return QtCore.QSize(
            self.TRACK_WIDTH + self.TEXT_GAP + text_width + 4,
            max(26, metrics.height() + 6),
        )

    def paintEvent(self, _event):
        theme = current_theme(self)
        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.Antialiasing, True)
        top = (self.height() - self.TRACK_HEIGHT) / 2.0
        track = QtCore.QRectF(0, top, self.TRACK_WIDTH, self.TRACK_HEIGHT)
        if not self.isEnabled():
            track_color = theme.border
        elif self.isChecked():
            track_color = theme.accent
        else:
            track_color = theme.border_strong
        painter.setPen(QtCore.Qt.NoPen)
        painter.setBrush(QtGui.QColor(track_color))
        painter.drawRoundedRect(track, self.TRACK_HEIGHT / 2, self.TRACK_HEIGHT / 2)

        knob_x = self.TRACK_WIDTH - self.KNOB_SIZE - 2 if self.isChecked() else 2
        knob = QtCore.QRectF(knob_x, top + 2, self.KNOB_SIZE, self.KNOB_SIZE)
        painter.setBrush(QtGui.QColor("#FFFFFF"))
        painter.drawEllipse(knob)

        painter.setFont(self.font())
        painter.setPen(QtGui.QColor(theme.text if self.isEnabled() else theme.text_disabled))
        text_rect = QtCore.QRectF(
            self.TRACK_WIDTH + self.TEXT_GAP, 0,
            max(0, self.width() - self.TRACK_WIDTH - self.TEXT_GAP), self.height(),
        )
        painter.drawText(text_rect, QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter, self.text())
        painter.end()


class PageHeader(QtWidgets.QWidget):
    def __init__(self, title, subtitle="", parent=None):
        super().__init__(parent)
        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(SPACING["md"])
        text_layout = QtWidgets.QVBoxLayout()
        text_layout.setSpacing(2)
        self.title_label = _set_role(QtWidgets.QLabel(title), "pnTitle")
        self.subtitle_label = _set_role(QtWidgets.QLabel(subtitle), "pnMuted")
        self.subtitle_label.setWordWrap(True)
        text_layout.addWidget(self.title_label)
        if subtitle:
            text_layout.addWidget(self.subtitle_label)
        layout.addLayout(text_layout, 1)
        self.actions = QtWidgets.QHBoxLayout()
        self.actions.setSpacing(SPACING["sm"])
        layout.addLayout(self.actions)

    def add_action(self, widget):
        self.actions.addWidget(widget)
        return widget


class Card(QtWidgets.QFrame):
    def __init__(self, title="", description="", parent=None):
        super().__init__(parent)
        _set_role(self, "pnCard")
        self.body = QtWidgets.QVBoxLayout(self)
        self.body.setContentsMargins(16, 14, 16, 16)
        self.body.setSpacing(SPACING["md"])
        if title:
            label = QtWidgets.QLabel(title)
            font = label.font()
            font.setBold(True)
            label.setFont(font)
            self.body.addWidget(label)
        if description:
            desc = _set_role(QtWidgets.QLabel(description), "pnMuted")
            desc.setWordWrap(True)
            self.body.addWidget(desc)

    def add_widget(self, widget, stretch=0):
        self.body.addWidget(widget, stretch)
        return widget

    def add_layout(self, layout, stretch=0):
        self.body.addLayout(layout, stretch)
        return layout


class StatusBadge(QtWidgets.QLabel):
    COLORS = {
        "neutral": ("#667085", "#FFFFFF"),
        "info": ("#147BA8", "#FFFFFF"),
        "success": ("#238A52", "#FFFFFF"),
        "warning": ("#A8660A", "#FFFFFF"),
        "danger": ("#C53A3A", "#FFFFFF"),
    }

    def __init__(self, text, tone="neutral", parent=None):
        super().__init__(text, parent)
        self.setFixedHeight(26)
        self.setMinimumWidth(56)
        self.setAlignment(QtCore.Qt.AlignCenter)
        self.setSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
        self.set_tone(tone)
        self.setMargin(0)

    def set_tone(self, tone):
        background, foreground = self.COLORS.get(tone, self.COLORS["neutral"])
        self.setStyleSheet(
            f"background:{background}; color:{foreground}; border-radius:8px; "
            "padding:2px 8px; font-size:9pt; font-weight:700;"
        )


class SearchField(QtWidgets.QLineEdit):
    def __init__(self, placeholder="Search", parent=None):
        super().__init__(parent)
        self.setPlaceholderText(placeholder)
        try:
            self.setClearButtonEnabled(True)
        except Exception:
            pass
        self.setAccessibleName(placeholder)


class EmptyState(QtWidgets.QWidget):
    def __init__(self, title, message, action_text="", parent=None):
        super().__init__(parent)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(24, 32, 24, 32)
        layout.setSpacing(SPACING["sm"])
        layout.setAlignment(QtCore.Qt.AlignCenter)
        title_label = QtWidgets.QLabel(title)
        title_font = title_label.font()
        title_font.setPointSize(title_font.pointSize() + 2)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(QtCore.Qt.AlignCenter)
        message_label = _set_role(QtWidgets.QLabel(message), "pnMuted")
        message_label.setWordWrap(True)
        message_label.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(title_label)
        layout.addWidget(message_label)
        self.action_button = None
        if action_text:
            self.action_button = QtWidgets.QPushButton(action_text)
            self.action_button.setProperty("pnVariant", "primary")
            layout.addWidget(self.action_button, 0, QtCore.Qt.AlignCenter)


class ProfessionalTable(QtWidgets.QTableWidget):
    def __init__(self, rows=0, columns=0, parent=None):
        super().__init__(rows, columns, parent)
        self.setAlternatingRowColors(True)
        self.setSortingEnabled(True)
        self.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        self.setShowGrid(False)
        self.verticalHeader().setVisible(False)
        self.horizontalHeader().setStretchLastSection(True)


class ProgressPanel(Card):
    def __init__(self, title="Activity", parent=None):
        super().__init__(title, parent=parent)
        self._started_at = None
        self._timer = QtCore.QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._update_elapsed)

        row = QtWidgets.QHBoxLayout()
        self.operation_label = QtWidgets.QLabel("Ready")
        self.stage_badge = StatusBadge("Idle", "neutral")
        row.addWidget(self.operation_label, 1)
        row.addWidget(self.stage_badge)
        self.add_layout(row)

        self.progress = QtWidgets.QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.add_widget(self.progress)

        footer = QtWidgets.QHBoxLayout()
        self.count_label = _set_role(QtWidgets.QLabel("0 / 0 items"), "pnMuted")
        self.character_label = _set_role(QtWidgets.QLabel("0 characters"), "pnMuted")
        self.elapsed_label = _set_role(QtWidgets.QLabel("00:00"), "pnMuted")
        self.cancel_button = QtWidgets.QPushButton("Cancel")
        self.cancel_button.setProperty("pnVariant", "danger")
        footer.addWidget(self.count_label)
        footer.addWidget(self.character_label)
        footer.addStretch()
        footer.addWidget(self.elapsed_label)
        footer.addWidget(self.cancel_button)
        self.add_layout(footer)

    def start(self, operation, stage="Preparing"):
        self._started_at = time.monotonic()
        self.operation_label.setText(operation)
        self.set_stage(stage, "info")
        self._timer.start()

    def set_stage(self, text, tone="info"):
        self.stage_badge.setText(text)
        self.stage_badge.set_tone(tone)

    def set_progress(self, current, total, characters=0):
        total = max(0, int(total))
        current = max(0, int(current))
        self.count_label.setText(f"{current:,} / {total:,} items")
        self.character_label.setText(f"{int(characters):,} characters")
        if total:
            self.progress.setRange(0, total)
            self.progress.setValue(min(current, total))
        else:
            self.progress.setRange(0, 0)

    def finish(self, message="Complete", tone="success"):
        self._timer.stop()
        self.set_stage(message, tone)
        self._update_elapsed()

    def _update_elapsed(self):
        elapsed = 0 if self._started_at is None else int(time.monotonic() - self._started_at)
        self.elapsed_label.setText(f"{elapsed // 60:02d}:{elapsed % 60:02d}")
