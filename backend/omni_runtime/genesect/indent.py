# -*- coding: utf-8 -*-
"""Subtle VS Code-style indentation marks for Hex-Rays pseudocode."""
import math

import idaapi
import ida_hexrays
import ida_kernwin
import ida_lines


_hooks_instance = None
_MAX_LINES = 10000
_FALLBACK_COLOR = "CK_EXTRA14"


def _config():
    from genesect.config import CONFIG
    return CONFIG


def _leading_spaces(line):
    plain = ida_lines.tag_remove(line or "")
    return len(plain) - len(plain.lstrip(" "))


def _detect_indent(lines):
    values = sorted(set(_leading_spaces(line.line) for line in lines if _leading_spaces(line.line) > 0))
    if not values:
        return 2
    candidate = values[0]
    for value in values[1:]:
        candidate = math.gcd(candidate, value)
    if candidate == 1 and len(values) > 1:
        # A one-column GCD is usually caused by aligned continuation arguments,
        # not Hex-Rays' actual BLOCK_INDENT setting.
        divisible_by_two = sum(1 for value in values if value % 2 == 0)
        if divisible_by_two >= max(1, len(values) // 2):
            return 2
    return candidate if 1 <= candidate <= 8 else min(values[0], 8)


def _blank_levels(lines, indent):
    levels = [max(0, _leading_spaces(line.line) // indent) for line in lines]
    return levels


def apply_indent_guides(lines):
    """Calculate guide positions without modifying Hex-Rays-owned text."""
    if not lines or not bool(getattr(_config(), "indent_guides_enabled", True)):
        return 2, []
    indent = _detect_indent(lines)
    return indent, _blank_levels(lines, indent)


def _line_number(place):
    try:
        return int(ida_kernwin.place_t.as_simpleline_place_t(place).n)
    except Exception:
        return -1


def _direct_color(value):
    """Convert #RRGGBB to IDA's direct 0xAABBGGRR overlay color."""
    import re
    match = re.fullmatch(r"#?([0-9A-Fa-f]{6})", str(value or ""))
    if not match:
        return None
    raw = match.group(1)
    red, green, blue = int(raw[0:2], 16), int(raw[2:4], 16), int(raw[4:6], 16)
    alpha = 0x78
    return (alpha << 24) | (blue << 16) | (green << 8) | red


def _render_indent_guides(out, widget, rin):
    """Add transient background ranges through IDA's supported renderer API."""
    if not bool(getattr(_config(), "indent_guides_enabled", True)):
        return
    if not all(hasattr(ida_kernwin, name) for name in (
        "line_rendering_output_entry_t", "LROEF_CPS_RANGE",
    )):
        return
    vu = ida_hexrays.get_widget_vdui(widget) if widget else None
    if not vu or not vu.cfunc:
        return
    lines = vu.cfunc.get_pseudocode()
    indent, levels = apply_indent_guides(lines)
    color = _direct_color(getattr(_config(), "indent_guides_color", ""))
    if color is None:
        color = getattr(ida_kernwin, _FALLBACK_COLOR, None)
    if color is None:
        return
    for section in rin.sections_lines:
        for rendered_line in section:
            index = _line_number(rendered_line.at)
            if index < 0 or index >= min(len(levels), _MAX_LINES):
                continue
            level = levels[index]
            if level <= 0 or not ida_lines.tag_remove(lines[index].line).strip():
                continue
            for nesting in range(level):
                entry = ida_kernwin.line_rendering_output_entry_t(rendered_line)
                entry.flags = ida_kernwin.LROEF_CPS_RANGE
                entry.cpx = nesting * indent
                entry.nchars = 1
                entry.bg_color = color
                out.entries.push_back(entry)


def indent_guide_hooks_installed():
    return _hooks_instance is not None


def refresh_pseudocode_widget(widget):
    """Refresh the supported rendering overlay without regenerating ctree text."""
    if widget:
        try:
            ida_kernwin.refresh_custom_viewer(widget)
        except Exception:
            pass
    idaapi.request_refresh(idaapi.IWID_PSEUDOCODE)


def refresh_current_pseudocode():
    refresh_pseudocode_widget(ida_kernwin.get_current_widget())


def refresh_open_pseudocode_widgets():
    """Refresh every restored pseudocode tab, not only the currently focused one."""
    get_count = getattr(ida_kernwin, "get_widget_qty", None)
    get_widget = getattr(ida_kernwin, "getn_widget", None)
    if not callable(get_count) or not callable(get_widget):
        refresh_current_pseudocode()
        return
    refreshed = False
    try:
        for index in range(int(get_count())):
            widget = get_widget(index)
            if widget and idaapi.get_widget_type(widget) == idaapi.BWN_PSEUDOCODE:
                refresh_pseudocode_widget(widget)
                refreshed = True
    except Exception:
        pass
    if not refreshed:
        refresh_current_pseudocode()


def create_indent_guide_hooks():
    global _hooks_instance
    if _hooks_instance is not None:
        return _hooks_instance
    if not ida_hexrays.init_hexrays_plugin():
        return None
        
    if not hasattr(ida_kernwin.UI_Hooks, "get_lines_rendering_info"):
        return None

    class _IndentGuideHooks(ida_kernwin.UI_Hooks):
        def __init__(self):
            ida_kernwin.UI_Hooks.__init__(self)

        def get_lines_rendering_info(self, out, widget, rin):
            try:
                if idaapi.get_widget_type(widget) == idaapi.BWN_PSEUDOCODE:
                    _render_indent_guides(out, widget, rin)
            except Exception as exc:
                ida_kernwin.msg("[Genesect] Indent mark rendering skipped: %s\n" % exc)

    instance = _IndentGuideHooks()
    if not instance.hook():
        return None
    _hooks_instance = instance
    return instance


def destroy_indent_guide_hooks():
    global _hooks_instance
    if _hooks_instance is not None:
        try:
            _hooks_instance.unhook()
        except Exception:
            pass
    _hooks_instance = None


def is_indent_guides_enabled():
    return bool(getattr(_config(), "indent_guides_enabled", True))


def set_indent_guides_enabled(enabled, persist=True):
    config = _config()
    config.indent_guides_enabled = bool(enabled)
    if persist:
        config.save()
    if config.indent_guides_enabled:
        create_indent_guide_hooks()
    else:
        destroy_indent_guide_hooks()
    refresh_open_pseudocode_widgets()
    return config.indent_guides_enabled


class ToggleIndentGuidesHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        config = _config()
        config.indent_guides_enabled = not bool(getattr(config, "indent_guides_enabled", True))
        config.save()
        create_indent_guide_hooks()
        refresh_open_pseudocode_widgets()
        ida_kernwin.msg("[Genesect] Indent marks %s\n" % ("enabled" if config.indent_guides_enabled else "disabled"))
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS
