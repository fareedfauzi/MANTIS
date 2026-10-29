"""Theme detection and centralized Qt stylesheet generation."""

from genesect.qt_compat import QtGui, QtWidgets
from genesect.ui.tokens import DARK, LIGHT
from genesect.ui.typography import apply_ui_font


def detect_theme(widget=None):
    if not QtWidgets:
        return "dark"
    target = widget or QtWidgets.QApplication.instance()
    try:
        palette = target.palette()
        role = getattr(QtGui.QPalette, "Window", None)
        if role is None:
            role = QtGui.QPalette.ColorRole.Window
        return "light" if int(palette.color(role).lightness()) >= 128 else "dark"
    except Exception:
        return "dark"


def current_theme(widget=None, preference="system"):
    choice = str(preference or "system").lower()
    if choice == "light":
        return LIGHT
    if choice == "dark":
        return DARK
    return LIGHT if detect_theme(widget) == "light" else DARK


def build_stylesheet(t):
    return f"""
QWidget[pnRoot="true"] {{ background: {t.window}; color: {t.text}; }}
QWidget {{ color: {t.text}; font-size: 9.5pt; }}
QLabel[pnMuted="true"] {{ color: {t.text_muted}; }}
QLabel[pnTitle="true"] {{ font-size: 18pt; font-weight: 700; }}
QFrame[pnCard="true"] {{ background: {t.surface}; border: 1px solid {t.border}; border-radius: 8px; }}
QPushButton {{ min-height: 26px; padding: 0 9px; border: 1px solid {t.border}; border-radius: 6px; background: {t.surface_alt}; color: {t.text}; font-size: 9pt; font-weight: 600; }}
QPushButton:hover {{ background: {t.surface_hover}; border-color: {t.border_strong}; }}
QPushButton:pressed {{ background: {t.surface}; }}
QPushButton:disabled {{ color: {t.text_disabled}; background: {t.surface}; border-color: {t.border}; }}
QPushButton[pnVariant="primary"] {{ background: {t.accent}; border-color: {t.accent}; color: {t.accent_text}; }}
QPushButton[pnVariant="primary"]:hover {{ background: {t.accent_hover}; border-color: {t.accent_hover}; }}
QPushButton[pnVariant="primary"]:pressed {{ background: {t.accent_pressed}; }}
QPushButton[pnVariant="primary"]:disabled {{ background: {t.surface_alt}; border-color: {t.border_strong}; color: {t.text_muted}; }}
QPushButton[pnVariant="danger"] {{ color: {t.danger}; }}
QLineEdit, QPlainTextEdit, QTextEdit, QComboBox, QSpinBox {{ min-height: 27px; background: {t.code_background}; color: {t.text}; border: 1px solid {t.border}; border-radius: 6px; padding: 2px 7px; selection-background-color: {t.selection}; }}
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QComboBox:focus, QSpinBox:focus {{ border: 1px solid {t.accent}; }}
QComboBox#workspaceLanguageSelector {{ min-height: 22px; max-height: 22px; padding-top: 0; padding-bottom: 0; }}
QTabWidget::pane {{ border: 1px solid {t.border}; background: {t.surface}; }}
QTabBar::tab {{ background: transparent; color: {t.text_muted}; padding: 6px 10px; border-bottom: 2px solid transparent; }}
QTabBar::tab:selected {{ color: {t.text}; border-bottom-color: {t.accent}; }}
QTabWidget#summarizerTabs QTabBar::tab {{ min-width: 150px; padding-left: 14px; padding-right: 14px; }}
QTabBar#settingsTabBar {{ background: {t.window}; border: 0; }}
QTabBar#settingsTabBar::tab {{
    background: {t.surface_alt}; color: {t.text_muted}; min-width: 112px;
    padding: 7px 11px; margin: 0 2px 2px 0; border: 1px solid {t.border};
    border-radius: 6px;
}}
QTabBar#settingsTabBar::tab:hover {{ background: {t.surface_hover}; color: {t.text}; }}
QTabBar#settingsTabBar::tab:selected {{
    background: {t.surface}; color: {t.text}; border-color: {t.accent};
}}
QTabBar#settingsTabBar QToolButton {{
    background: {t.surface_alt}; color: {t.text}; border: 1px solid {t.border};
    border-radius: 5px; min-width: 20px; margin: 2px;
}}
QTabBar#settingsTabBar QToolButton:hover {{ background: {t.surface_hover}; }}
QListWidget#settingsSidebar {{
    background: {t.surface}; border: 1px solid {t.border}; border-radius: 8px;
    padding: 8px; outline: 0;
}}
QListWidget#settingsSidebar::item {{
    min-height: 40px; padding: 8px 12px; margin: 2px 0;
    border-radius: 6px; color: {t.text_muted};
}}
QListWidget#settingsSidebar::item:hover {{ background: {t.surface_hover}; color: {t.text}; }}
QListWidget#settingsSidebar::item:selected {{
    background: {t.selection}; color: {t.text}; font-weight: 700;
}}
QFrame#settingsContentFrame {{
    background: {t.surface}; border: 1px solid {t.border}; border-radius: 8px;
}}
QLabel[pnSectionTitle="true"] {{ font-size: 12pt; font-weight: 700; }}
QHeaderView::section {{ background: {t.surface_alt}; color: {t.text_muted}; border: 0; border-bottom: 1px solid {t.border}; padding: 5px 7px; font-weight: 600; }}
QTableView, QTreeView {{ background: {t.surface}; alternate-background-color: {t.surface_alt}; border: 1px solid {t.border}; border-radius: 6px; selection-background-color: {t.selection}; }}
QProgressBar {{ min-height: 8px; max-height: 8px; border: 0; border-radius: 4px; background: {t.surface_alt}; text-align: center; }}
QProgressBar::chunk {{ border-radius: 4px; background: {t.accent}; }}
QProgressBar[pnProminent="true"] {{ min-height: 20px; max-height: 20px; border-radius: 6px; }}
QProgressBar[pnProminent="true"]::chunk {{ border-radius: 6px; }}
QToolTip {{ background: {t.surface_alt}; color: {t.text}; border: 1px solid {t.border_strong}; padding: 5px; }}
"""


def apply_theme(widget, preference="system"):
    tokens = current_theme(widget, preference)
    apply_ui_font(widget, 9.5)
    widget.setProperty("pnRoot", True)
    widget.setStyleSheet(build_stylesheet(tokens))
    try:
        widget.update()
    except Exception:
        pass
    return tokens


class ThemeManager:
    def __init__(self, widget, preference="system"):
        self.widget = widget
        self.preference = preference
        self.tokens = apply_theme(widget, preference)

    def set_preference(self, preference):
        self.preference = preference
        self.tokens = apply_theme(self.widget, preference)
        return self.tokens

    def refresh_system_theme(self):
        if str(self.preference).lower() == "system":
            self.tokens = apply_theme(self.widget, "system")
        return self.tokens
