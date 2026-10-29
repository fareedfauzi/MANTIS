"""Lifecycle activation for default call highlighting and indentation marks."""

import idaapi
import ida_auto
import ida_kernwin

from genesect.qt_compat import QtCore
from genesect.indent import (
    create_indent_guide_hooks,
    refresh_open_pseudocode_widgets,
    refresh_pseudocode_widget,
)


_hooks_instance = None
_activation_generation = 0
_active = False


def _autoanalysis_complete():
    check = getattr(ida_auto, "auto_is_ok", None)
    if not callable(check):
        return True
    try:
        return bool(check())
    except Exception:
        return True


def _apply_to_view(widget=None, scan_pseudocode=False):
    if not _active or not _autoanalysis_complete():
        return
    # PLUGIN_FIX plugins can start before the decompiler is initialized.  The
    # first hook attempt may therefore fail even though Hex-Rays becomes
    # available moments later.  Retry from every bounded UI lifecycle pass;
    # create_indent_guide_hooks() is idempotent once installed.
    from genesect.config import CONFIG
    if bool(getattr(CONFIG, "indent_guides_enabled", True)):
        create_indent_guide_hooks()
    if scan_pseudocode:
        refresh_open_pseudocode_widgets()
    widget = widget or ida_kernwin.get_current_widget()
    if not widget:
        return
    widget_type = idaapi.get_widget_type(widget)
    if widget_type == idaapi.BWN_PSEUDOCODE:
        if bool(getattr(CONFIG, "indent_guides_enabled", True)):
            refresh_pseudocode_widget(widget)
    elif widget_type in (idaapi.BWN_DISASM, idaapi.BWN_DISASMS):
        from genesect.highlight import refresh_disasm_highlighting
        refresh_disasm_highlighting()


def schedule_default_visual_activation(delay_ms=75, coalesce=True, widget=None, scan_pseudocode=False):
    """Run after IDA completes the current widget/session transition."""
    global _activation_generation
    # Fresh-binary loading can generate a huge number of UI notifications.
    # Never allocate Qt timers from that event storm; wait for normal widget
    # lifecycle activity after IDA's auto-analysis has completed.
    if not _active or not _autoanalysis_complete():
        return
    if QtCore:
        if not coalesce:
            QtCore.QTimer.singleShot(
                int(delay_ms),
                lambda target=widget, scan=scan_pseudocode: _apply_to_view(target, scan),
            )
            return
        _activation_generation += 1
        generation = _activation_generation

        def apply_if_latest():
            if generation == _activation_generation:
                _apply_to_view(widget, scan_pseudocode)

        QtCore.QTimer.singleShot(int(delay_ms), apply_if_latest)


class DefaultVisualHooks(idaapi.UI_Hooks):
    """Reapply opt-out visual helpers as IDA restores and changes views."""

    def __init__(self):
        idaapi.UI_Hooks.__init__(self)

    def ready_to_run(self):
        # IDA may restore tabs in several UI-loop passes.
        for delay in (0, 250, 1000, 2500):
            schedule_default_visual_activation(delay, coalesce=False, scan_pseudocode=True)

    def current_widget_changed(self, widget, previous_widget):
        schedule_default_visual_activation(75, widget=widget)

    def widget_visible(self, widget):
        schedule_default_visual_activation(75, widget=widget)


def create_default_visual_hooks():
    global _hooks_instance, _active
    if _hooks_instance is not None:
        return _hooks_instance
    instance = DefaultVisualHooks()
    if not instance.hook():
        return None
    _hooks_instance = instance
    _active = True
    # Cover plugin loading after IDA's ready_to_run notification already fired.
    for delay in (0, 250, 1000, 2500):
        schedule_default_visual_activation(delay, coalesce=False, scan_pseudocode=True)
    return instance


def destroy_default_visual_hooks():
    global _hooks_instance, _active, _activation_generation
    _active = False
    _activation_generation += 1
    if _hooks_instance is not None:
        try:
            _hooks_instance.unhook()
        except Exception:
            pass
    _hooks_instance = None
