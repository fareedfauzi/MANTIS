# -*- coding: utf-8 -*-
"""Ctrl+wheel font zoom for scrollable IDA and Genesect views."""

import idaapi
import ida_kernwin

from genesect.qt_compat import QtCore, QtGui, QtWidgets


MIN_FONT_SIZE = 6.0
MAX_FONT_SIZE = 40.0
ZOOM_STEP = 1.0
DEFAULT_FONT_SIZE = 10.0
ACTION_ID = "genesect:zoom_all_views"
_filter_instance = None


def _wheel_event_type():
    return getattr(QtCore.QEvent, "Wheel", getattr(getattr(QtCore.QEvent, "Type", object), "Wheel", None))


def _control_modifier():
    return getattr(QtCore.Qt, "ControlModifier", getattr(getattr(QtCore.Qt, "KeyboardModifier", object), "ControlModifier", 0))


def _global_position(event):
    if hasattr(event, "globalPosition"):
        return event.globalPosition().toPoint()
    return event.globalPos() if hasattr(event, "globalPos") else None


def _scroll_area_at(obj, event):
    point = _global_position(event)
    widget = QtWidgets.QApplication.widgetAt(point) if point is not None else None
    widget = widget or (obj if isinstance(obj, QtWidgets.QWidget) else None)
    current = widget
    for _depth in range(16):
        if current is None:
            break
        class_name = current.metaObject().className().lower() if hasattr(current, "metaObject") else ""
        # IDA's graph/proximity renderers already implement native Ctrl+wheel zoom.
        if "opengl" in class_name:
            return None
        if isinstance(current, QtWidgets.QAbstractScrollArea):
            return current
        current = current.parentWidget() if hasattr(current, "parentWidget") else None
    return None


def _current_point_size(widget):
    stored = widget.property("pnZoomPointSize")
    try:
        if stored is not None and float(stored) > 0:
            return float(stored)
    except (TypeError, ValueError):
        pass
    font = widget.font()
    size = float(font.pointSizeF())
    return size if size > 0 else DEFAULT_FONT_SIZE


def _apply_zoom(widget, point_size):
    point_size = max(MIN_FONT_SIZE, min(MAX_FONT_SIZE, float(point_size)))
    font = QtGui.QFont(widget.font())
    font.setPointSizeF(point_size)
    widget.setFont(font)
    widget.setProperty("pnZoomPointSize", point_size)
    viewport = widget.viewport() if hasattr(widget, "viewport") else None
    if viewport is not None:
        viewport.setFont(font)
    header = widget.verticalHeader() if hasattr(widget, "verticalHeader") else None
    if header is not None:
        header.setDefaultSectionSize(max(18, QtGui.QFontMetrics(font).height() + 8))
    if hasattr(widget, "doItemsLayout"):
        widget.doItemsLayout()
    if viewport is not None:
        viewport.update()


class ZoomAllViewsFilter(QtCore.QObject):
    def eventFilter(self, obj, event):
        try:
            if event.type() != _wheel_event_type() or not (event.modifiers() & _control_modifier()):
                return False
            target = _scroll_area_at(obj, event)
            if target is None:
                return False
            delta = event.angleDelta().y() if hasattr(event, "angleDelta") else 0
            if not delta:
                return False
            direction = 1.0 if delta > 0 else -1.0
            old_size = _current_point_size(target)
            new_size = max(MIN_FONT_SIZE, min(MAX_FONT_SIZE, old_size + direction * ZOOM_STEP))
            if new_size == old_size:
                return True
            _apply_zoom(target, new_size)
            event.accept()
            return True
        except Exception as exc:
            ida_kernwin.msg("[Genesect] Zoom Views skipped an event: %s\n" % exc)
            return False


def _set_action_checked(enabled):
    setter = getattr(ida_kernwin, "set_action_checked", None)
    if setter:
        try:
            setter(ACTION_ID, bool(enabled))
        except Exception:
            pass


def set_zoom_all_views_enabled(enabled, persist=True):
    global _filter_instance
    app = QtWidgets.QApplication.instance()
    enabled = bool(enabled)
    if app is None:
        return False
    if enabled and _filter_instance is None:
        _filter_instance = ZoomAllViewsFilter(app)
        app.installEventFilter(_filter_instance)
    elif not enabled and _filter_instance is not None:
        app.removeEventFilter(_filter_instance)
        _filter_instance.deleteLater()
        _filter_instance = None
    if persist:
        from genesect.config import CONFIG
        CONFIG.zoom_all_views_enabled = enabled
        CONFIG.save()
    _set_action_checked(enabled)
    return enabled


def initialize_zoom_all_views():
    from genesect.config import CONFIG
    return set_zoom_all_views_enabled(getattr(CONFIG, "zoom_all_views_enabled", True), persist=False)


def is_zoom_all_views_enabled():
    return _filter_instance is not None


def shutdown_zoom_all_views():
    set_zoom_all_views_enabled(False, persist=False)


class ToggleZoomAllViewsHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        enabled = _filter_instance is None
        set_zoom_all_views_enabled(enabled)
        ida_kernwin.msg("[Genesect] Zoom Views %s (Ctrl+wheel)\n" % ("enabled" if enabled else "disabled"))
        return 1

    def update(self, ctx):
        _set_action_checked(_filter_instance is not None)
        return idaapi.AST_ENABLE_ALWAYS
