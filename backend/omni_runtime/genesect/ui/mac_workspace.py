"""Shared macOS-inspired styling for Genesect's large analysis workspaces."""

from genesect.ui.theme import current_theme
from genesect.ui.typography import apply_ui_font


def mac_workspace_stylesheet(widget=None):
    t = current_theme(widget, "system")
    return f"""
QDialog {{ background: {t.window}; color: {t.text}; }}
QWidget[pnMacWorkspace="true"] {{ background: {t.window}; color: {t.text}; }}
QWidget {{ color: {t.text}; font-size: 9.5pt; }}
QLabel {{ background: transparent; }}
QLabel[pnTitle="true"] {{ font-size: 18pt; font-weight: 700; }}
QLabel[pnMuted="true"] {{ color: {t.text_muted}; }}

QGroupBox {{
    background: {t.surface}; border: 1px solid {t.border}; border-radius: 12px;
    margin-top: 14px; padding: 14px 12px 12px 12px; font-weight: 650;
}}
QGroupBox::title {{
    subcontrol-origin: margin; subcontrol-position: top left; left: 12px;
    padding: 0 5px; color: {t.text};
}}
QFrame[pnCard="true"] {{ background: {t.surface}; border: 1px solid {t.border}; border-radius: 12px; }}

QPushButton {{
    min-height: 26px; padding: 0 9px; background: {t.surface_alt}; color: {t.text};
    border: 1px solid {t.border}; border-radius: 6px; font-size: 9pt; font-weight: 600;
}}
QPushButton:hover {{ background: {t.surface_hover}; border-color: {t.border_strong}; }}
QPushButton:pressed {{ background: {t.surface}; }}
QPushButton:disabled {{ color: {t.text_disabled}; background: {t.surface}; border-color: {t.border}; }}
QPushButton[pnVariant="primary"] {{ background: {t.accent}; border-color: {t.accent}; color: {t.accent_text}; }}
QPushButton[pnVariant="primary"]:hover {{ background: {t.accent_hover}; border-color: {t.accent_hover}; }}
QPushButton[pnVariant="primary"]:disabled {{
    background: {t.surface_alt}; border-color: {t.border_strong}; color: {t.text_muted};
}}
QPushButton[pnVariant="danger"] {{ color: {t.danger}; }}
QPushButton#primary {{ background: {t.accent}; border-color: {t.accent}; color: {t.accent_text}; }}
QPushButton#primary:hover {{ background: {t.accent_hover}; border-color: {t.accent_hover}; }}
QPushButton#primary:disabled {{
    background: {t.surface_alt}; border-color: {t.border_strong}; color: {t.text_muted};
}}
QPushButton#success {{ background: {t.success}; border-color: {t.success}; color: #FFFFFF; }}
QPushButton#danger {{ color: {t.danger}; }}
QPushButton#secondary {{ background: {t.surface}; }}

QLineEdit, QPlainTextEdit, QTextEdit, QTextBrowser, QComboBox, QSpinBox {{
    min-height: 27px; background: {t.code_background}; color: {t.text};
    border: 1px solid {t.border}; border-radius: 6px; padding: 2px 7px;
    selection-background-color: {t.selection};
}}
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QComboBox:focus, QSpinBox:focus {{
    border-color: {t.accent};
}}
QComboBox::drop-down {{ border: 0; width: 24px; }}
QComboBox#workspaceLanguageSelector {{ min-height: 22px; max-height: 22px; padding-top: 0; padding-bottom: 0; }}

QTableView, QTableWidget, QTreeView, QTreeWidget {{
    background: {t.surface}; alternate-background-color: {t.surface_alt}; color: {t.text};
    border: 1px solid {t.border}; border-radius: 9px; gridline-color: {t.border}; outline: 0;
    selection-background-color: {t.selection}; selection-color: {t.text};
}}
QTableView::item, QTableWidget::item, QTreeView::item, QTreeWidget::item {{ padding: 3px 6px; }}
QTableView::item:hover, QTreeView::item:hover {{ background: {t.surface_hover}; }}
QHeaderView::section {{
    background: {t.surface_alt}; color: {t.text_muted}; border: 0;
    border-bottom: 1px solid {t.border}; padding: 5px 7px; font-weight: 650;
}}
QTableCornerButton::section {{ background: {t.surface_alt}; border: 0; border-bottom: 1px solid {t.border}; }}

QTabWidget::pane {{ background: {t.surface}; border: 1px solid {t.border}; border-radius: 10px; top: -1px; }}
QTabBar::tab {{
    background: transparent; color: {t.text_muted}; padding: 6px 11px;
    margin: 0 2px 4px 0; border: 0; border-radius: 7px; font-weight: 600;
}}
QTabBar::tab:hover {{ background: {t.surface_hover}; color: {t.text}; }}
QTabBar::tab:selected {{ background: {t.surface_alt}; color: {t.text}; }}
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

QProgressBar {{
    min-height: 8px; max-height: 8px; background: {t.surface_alt}; border: 0;
    border-radius: 4px; text-align: center;
}}
QProgressBar::chunk {{ background: {t.accent}; border-radius: 4px; }}
QProgressBar[pnProminent="true"] {{
    min-height: 20px; max-height: 20px; border-radius: 6px;
}}
QProgressBar[pnProminent="true"]::chunk {{ border-radius: 6px; }}
QCheckBox {{ spacing: 7px; min-height: 20px; }}
QCheckBox::indicator {{
    width: 14px; height: 14px; border-radius: 4px;
    background: {t.surface}; border: 1px solid {t.border_strong};
}}
QCheckBox::indicator:hover {{ border-color: {t.accent}; }}
QCheckBox::indicator:checked {{
    background: {t.accent}; border: 1px solid {t.accent};
}}
QCheckBox::indicator:disabled {{ background: {t.surface_alt}; border-color: {t.border}; }}
QSplitter::handle {{ background: transparent; width: 8px; height: 8px; }}

QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:vertical, QScrollBar::handle:horizontal {{
    background: {t.border_strong}; border-radius: 4px; min-height: 28px; min-width: 28px;
}}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QToolTip {{ background: {t.surface_alt}; color: {t.text}; border: 1px solid {t.border_strong}; padding: 5px; }}
QMenu {{ 
    background: {t.window}; 
    color: {t.text};
    border: 1px solid {t.border};
    border-radius: 6px;
    padding: 6px;
}}
QMenu::item {{
    padding: 6px 24px 6px 12px;
    border-radius: 4px;
    background: transparent;
}}
QMenu::item:selected {{
    background: {t.accent};
    color: white;
}}
QMenu::separator {{
    height: 1px;
    background: {t.border};
    margin: 4px 0px;
}}
"""


def apply_mac_workspace(widget):
    apply_ui_font(widget, 9.5)
    widget.setProperty("pnMacWorkspace", True)
    widget.setStyleSheet(mac_workspace_stylesheet(widget))
    try:
        widget.update()
    except Exception:
        pass
    return widget
