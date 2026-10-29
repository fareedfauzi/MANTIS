"""Shared, cross-platform typography for Genesect interfaces."""

from genesect.qt_compat import QtGui, QtWidgets


UI_FONT_FAMILIES = (
    "SF Pro Text",
    ".AppleSystemUIFont",
    "Segoe UI Variable Text",
    "Inter",
    "Segoe UI",
    "Noto Sans",
)

MONO_FONT_FAMILIES = (
    "SF Mono",
    "Cascadia Code",
    "JetBrains Mono",
    "Consolas",
    "Menlo",
    "DejaVu Sans Mono",
)


def _families():
    try:
        return {str(name).casefold(): str(name) for name in QtGui.QFontDatabase().families()}
    except Exception:
        return {}


def _font(preferred, point_size):
    installed = _families()
    for candidate in preferred:
        actual = installed.get(candidate.casefold())
        if actual:
            font = QtGui.QFont(actual)
            font.setPointSizeF(float(point_size))
            return font
    font = QtWidgets.QApplication.font()
    font.setPointSizeF(float(point_size))
    return font


def ui_font(point_size=10.5):
    return _font(UI_FONT_FAMILIES, point_size)


def mono_font(point_size=10.0):
    return _font(MONO_FONT_FAMILIES, point_size)


def apply_ui_font(widget, point_size=10.5):
    font = ui_font(point_size)
    widget.setFont(font)
    return font
