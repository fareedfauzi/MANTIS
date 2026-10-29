"""Reusable controls shared by the three Phase 5 batch dialogs."""

from genesect.qt_compat import QtCore, QtWidgets, Signal
from genesect.ui.components import StatusBadge


class BatchWorkbenchBar(QtWidgets.QFrame):
    pauseRequested = Signal()
    resumeRequested = Signal()
    retryRequested = Signal()
    cancelRequested = Signal()
    filterChanged = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("pnBatchWorkbench")
        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        self.search = QtWidgets.QLineEdit()
        self.search.setPlaceholderText("Filter candidates, status, tag or reason...")
        self.search.textChanged.connect(self.filterChanged)
        layout.addWidget(self.search, 1)
        self.estimate = QtWidgets.QLabel("0 selected - 0 requests - 0 chars")
        layout.addWidget(self.estimate)
        self.state = StatusBadge("Ready", "neutral")
        layout.addWidget(self.state)
        self.pause = QtWidgets.QPushButton("Pause")
        self.pause.clicked.connect(self.pauseRequested)
        layout.addWidget(self.pause)
        self.resume = QtWidgets.QPushButton("Resume")
        self.resume.clicked.connect(self.resumeRequested)
        self.resume.setEnabled(False)
        layout.addWidget(self.resume)
        self.retry = QtWidgets.QPushButton("Retry Failed")
        self.retry.clicked.connect(self.retryRequested)
        layout.addWidget(self.retry)
        self.cancel = QtWidgets.QPushButton("Cancel")
        self.cancel.setProperty("pnVariant", "danger")
        self.cancel.clicked.connect(self.cancelRequested)
        layout.addWidget(self.cancel)
        self.set_running(False)

    def set_estimate(self, items, requests, context_chars):
        self.estimate.setText(f"{items:,} selected - {requests:,} requests - {context_chars:,} chars")

    def update_items(self, rows, batch_size=1):
        selected = [row for row in rows if getattr(row, "checked", True)]
        size = max(1, int(batch_size or 1))
        chars = sum(len(getattr(row, "code", "") or "") for row in selected)
        self.set_estimate(len(selected), (len(selected) + size - 1) // size, chars)

    def set_running(self, running, paused=False):
        self.pause.setEnabled(running and not paused)
        self.resume.setEnabled(running and paused)
        self.cancel.setEnabled(running)
        self.state.setText("Paused" if paused else ("Running" if running else "Ready"))
