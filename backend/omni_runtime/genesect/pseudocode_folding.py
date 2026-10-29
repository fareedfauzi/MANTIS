# -*- coding: utf-8 -*-
"""Interactive folding and persistent block selection for Hex-Rays views."""

import re

import idaapi
import ida_hexrays
import ida_kernwin
import ida_lines


_hooks_instance = None
_highlight_render_hooks = None
_highlight_click_hooks = None
_block_highlights = {}
_STRING_OR_CHAR = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')
_FOLD_MARKER = re.compile(r"^\s*\.\.\.\s+/\*\s+\d+\s+lines?\s+folded\s+\*/\s*$")


def _line_text(line):
    """Normalize IDA simpleline_t/qstring proxies before calling tag_remove."""
    value = getattr(line, "line", line)
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _plain_code(line):
    """Return brace-relevant text without IDA tags, strings, or comments."""
    text = ida_lines.tag_remove(_line_text(line))
    text = _STRING_OR_CHAR.sub("", text)
    return text.split("//", 1)[0]


def _indent(line):
    text = _plain_code(line)
    return len(text) - len(text.lstrip(" "))


def _matching_block(lines, start):
    """Find the exclusive end of a brace block or a switch case."""
    if start < 0 or start >= len(lines):
        return None
    current = _plain_code(lines[start]).strip()
    if current.startswith(("case ", "default:")):
        base_indent = _indent(lines[start])
        for index in range(start + 1, len(lines)):
            stripped = _plain_code(lines[index]).strip()
            if not stripped:
                continue
            if _indent(lines[index]) <= base_indent and stripped.startswith(("case ", "default:", "}")):
                return index
        return len(lines)
    if not current.startswith("{"):
        return None
    depth = 0
    for index in range(start, len(lines)):
        code = _plain_code(lines[index])
        depth += code.count("{") - code.count("}")
        if index > start and depth <= 0:
            return index + 1
    return None


def _brace_block(lines, line_index):
    """Return the inclusive-opening/exclusive-closing range for either brace."""
    if line_index < 0 or line_index >= len(lines):
        return None
    current = _plain_code(lines[line_index]).strip()
    if "{" in current and "}" not in current:
        depth = 0
        for index in range(line_index, len(lines)):
            code = _plain_code(lines[index])
            depth += code.count("{") - code.count("}")
            if index > line_index and depth <= 0:
                return line_index, index + 1
    if "}" in current and "{" not in current:
        depth = 0
        for index in range(line_index, -1, -1):
            code = _plain_code(lines[index])
            depth += code.count("}") - code.count("{")
            if index < line_index and depth <= 0:
                return index, line_index + 1
    return None


def _line_number(place):
    try:
        return int(ida_kernwin.place_t.as_simpleline_place_t(place).n)
    except Exception:
        return -1


def _refresh_block_overlay():
    idaapi.refresh_idaview_anyway()


def _toggle_block_highlight(vu):
    if not vu or not getattr(vu, "cfunc", None):
        return False
    lines = vu.cfunc.get_pseudocode()
    line_index = int(getattr(getattr(vu, "cpos", None), "lnnum", -1))
    block = _brace_block(lines, line_index)
    if block is None:
        return False
    key = int(vu.cfunc.entry_ea)
    if _block_highlights.get(key) == block:
        _block_highlights.pop(key, None)
    else:
        _block_highlights[key] = block
    _refresh_block_overlay()
    return True


def _render_block_highlight(out, widget, rin):
    if not all(hasattr(ida_kernwin, name) for name in (
        "line_rendering_output_entry_t", "LROEF_FULL_LINE",
    )):
        return
    vu = ida_hexrays.get_widget_vdui(widget) if widget else None
    if not vu or not vu.cfunc:
        return
    block = _block_highlights.get(int(vu.cfunc.entry_ea))
    if block is None:
        return
    start, end = block
    from genesect.config import CONFIG
    from genesect.indent import _direct_color
    color = _direct_color(getattr(CONFIG, "pseudocode_folding_color", ""))
    if color is None:
        color = getattr(ida_kernwin, "CK_EXTRA10", None)
    if color is None:
        return
    for section in rin.sections_lines:
        for rendered_line in section:
            index = _line_number(rendered_line.at)
            if start <= index < end:
                entry = ida_kernwin.line_rendering_output_entry_t(rendered_line)
                entry.flags = ida_kernwin.LROEF_FULL_LINE
                entry.bg_color = color
                out.entries.push_back(entry)


def _create_block_highlight_hooks():
    global _highlight_render_hooks, _highlight_click_hooks
    if _highlight_render_hooks is None and hasattr(ida_kernwin.UI_Hooks, "get_lines_rendering_info"):
        class _BlockHighlightRenderHooks(ida_kernwin.UI_Hooks):
            def __init__(self):
                ida_kernwin.UI_Hooks.__init__(self)

            def get_lines_rendering_info(self, out, widget, rin):
                try:
                    if idaapi.get_widget_type(widget) == idaapi.BWN_PSEUDOCODE:
                        _render_block_highlight(out, widget, rin)
                except Exception as exc:
                    ida_kernwin.msg("[Genesect] Code-block highlight skipped: %s\n" % exc)

        candidate = _BlockHighlightRenderHooks()
        if candidate.hook():
            _highlight_render_hooks = candidate
    if _highlight_click_hooks is None and hasattr(ida_kernwin, "View_Hooks"):
        class _BlockHighlightClickHooks(ida_kernwin.View_Hooks):
            def __init__(self):
                ida_kernwin.View_Hooks.__init__(self)

            def view_click(self, view, event):
                if idaapi.get_widget_type(view) != idaapi.BWN_PSEUDOCODE:
                    return
                def apply_after_cursor_update():
                    try:
                        _toggle_block_highlight(ida_hexrays.get_widget_vdui(view))
                    except Exception as exc:
                        ida_kernwin.msg("[Genesect] Code-block selection skipped: %s\n" % exc)
                    return False
                # IDA reports the click before every binding has committed the
                # new vdui.cpos. Defer one UI turn so the clicked brace line is
                # used rather than the previously selected line.
                ida_kernwin.execute_ui_requests((apply_after_cursor_update,))

        candidate = _BlockHighlightClickHooks()
        if candidate.hook():
            _highlight_click_hooks = candidate


class PseudocodeFoldingHooks(ida_hexrays.Hexrays_Hooks):
    """Fold only after an explicit double-click; never install a Qt event filter."""

    def __init__(self):
        ida_hexrays.Hexrays_Hooks.__init__(self)
        self._states = {}

    @staticmethod
    def _key(vu):
        # vdui_t/ct SWIG proxy identities can change between callbacks even
        # while the same pseudocode tab remains open. The function entry is
        # stable and Hex-Rays shares the cfunc text for that function.
        return int(getattr(getattr(vu, "cfunc", None), "entry_ea", 0))

    @staticmethod
    def _snapshot(pseudocode):
        return [_line_text(line) for line in pseudocode]

    def _rebuild(self, vu, state):
        pseudocode = vu.cfunc.get_pseudocode()
        pseudocode.clear()
        cursor = 0
        for start, end in sorted(state["ranges"]):
            for line in state["lines"][cursor:start + 1]:
                pseudocode.push_back(idaapi.simpleline_t(line))
            opening = ida_lines.tag_remove(_line_text(state["lines"][start]))
            padding = len(opening) - len(opening.lstrip(" "))
            hidden = max(1, end - start - 2)
            pseudocode.push_back(idaapi.simpleline_t(
                "%s...  /* %d line%s folded */" % (
                    " " * (padding + 2), hidden, "" if hidden == 1 else "s"
                )
            ))
            cursor = end - 1
        for line in state["lines"][cursor:]:
            pseudocode.push_back(idaapi.simpleline_t(line))
        # refresh_custom_viewer() can emit refresh_pseudocode and discard our
        # state while leaving the shortened line vector on screen. This redraw
        # invalidates the view without asking Hex-Rays to regenerate its text.
        idaapi.refresh_idaview_anyway()

    @staticmethod
    def _visible_to_original(ranges, visible_line):
        original = visible_line
        for start, end in sorted(ranges):
            if start < original:
                original += max(0, end - start - 3)
        return original

    @staticmethod
    def _folded_range_at_visible_line(ranges, visible_line):
        """Return the fold represented by an opening, marker, or closing row."""
        removed = 0
        for item in sorted(ranges):
            start, end = item
            visible_start = start - removed
            # A collapsed block is rendered as exactly three rows:
            # opening brace, generated ellipsis, and closing brace.
            if visible_start <= visible_line <= visible_start + 2:
                return item
            removed += max(0, end - start - 3)
        return None

    def toggle_current_block(self, vu):
        if not vu or not getattr(vu, "cfunc", None):
            return False
        pseudocode = vu.cfunc.get_pseudocode()
        visible_line = int(getattr(getattr(vu, "cpos", None), "lnnum", -1))
        if visible_line < 0 or visible_line >= len(pseudocode):
            return False
        key = self._key(vu)
        state = self._states.get(key)
        if state is None:
            state = {"lines": self._snapshot(pseudocode), "ranges": []}
            self._states[key] = state
        folded = self._folded_range_at_visible_line(state["ranges"], visible_line)
        if folded:
            state["ranges"].remove(folded)
            self._rebuild(vu, state)
            return True
        original_line = self._visible_to_original(state["ranges"], visible_line)
        existing = next((item for item in state["ranges"] if item[0] == original_line), None)
        if existing:
            state["ranges"].remove(existing)
            self._rebuild(vu, state)
            return True
        end = _matching_block(state["lines"], original_line)
        if end is None or end - original_line <= 2:
            if not state["ranges"]:
                self._states.pop(key, None)
            return False
        if any(start < original_line < finish for start, finish in state["ranges"]):
            return False
        state["ranges"] = [item for item in state["ranges"] if not (original_line < item[0] and item[1] <= end)]
        state["ranges"].append((original_line, end))
        self._rebuild(vu, state)
        return True

    def double_click(self, vu, shift_state):
        try:
            _block_highlights.pop(self._key(vu), None)
            self.toggle_current_block(vu)
        except Exception as exc:
            ida_kernwin.msg("[Genesect] Could not fold pseudocode block: %s\n" % exc)
        return 0

    def refresh_pseudocode(self, vu):
        key = self._key(vu)
        if key not in self._states:
            _block_highlights.pop(key, None)
            return 0
        try:
            current = vu.cfunc.get_pseudocode()
            still_folded = any(
                _FOLD_MARKER.match(ida_lines.tag_remove(_line_text(line)))
                for line in current
            )
        except Exception:
            still_folded = False
        # A redraw of our shortened vector is not a decompilation refresh.
        # Preserve its state so a second double-click can restore the snapshot.
        if not still_folded:
            self._states.pop(key, None)
            _block_highlights.pop(key, None)
        return 0

    def close_pseudocode(self, vu):
        key = self._key(vu)
        self._states.pop(key, None)
        _block_highlights.pop(key, None)
        return 0


def create_pseudocode_folding_hooks():
    global _hooks_instance
    from genesect.config import CONFIG
    if not bool(getattr(CONFIG, "pseudocode_folding_enabled", True)):
        return None
    if _hooks_instance is not None:
        _create_block_highlight_hooks()
        return _hooks_instance
    if not ida_hexrays.init_hexrays_plugin():
        return None
    instance = PseudocodeFoldingHooks()
    if not instance.hook():
        return None
    _hooks_instance = instance
    _create_block_highlight_hooks()
    return instance


def destroy_pseudocode_folding_hooks():
    global _hooks_instance, _highlight_render_hooks, _highlight_click_hooks
    if _hooks_instance is not None:
        try:
            _hooks_instance.unhook()
        except Exception:
            pass
    _hooks_instance = None
    for hooks in (_highlight_click_hooks, _highlight_render_hooks):
        if hooks is not None:
            try:
                hooks.unhook()
            except Exception:
                pass
    _highlight_click_hooks = None
    _highlight_render_hooks = None
    _block_highlights.clear()


def is_pseudocode_folding_enabled():
    from genesect.config import CONFIG
    return bool(getattr(CONFIG, "pseudocode_folding_enabled", True))


def set_pseudocode_folding_enabled(enabled, persist=True):
    from genesect.config import CONFIG
    enabled = bool(enabled)
    if persist:
        CONFIG.pseudocode_folding_enabled = enabled
        CONFIG.save()
    if enabled:
        create_pseudocode_folding_hooks()
    else:
        destroy_pseudocode_folding_hooks()
    return enabled


class TogglePseudocodeBlockHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        hooks = create_pseudocode_folding_hooks()
        widget = getattr(ctx, "widget", None) or ida_kernwin.get_current_widget()
        vu = ida_hexrays.get_widget_vdui(widget) if widget else None
        if not hooks or not hooks.toggle_current_block(vu):
            ida_kernwin.msg("[Genesect] Place the cursor on an opening brace or switch case to fold it.\n")
            return 0
        return 1

    def update(self, ctx):
        # This action is attached only to pseudocode popups. Some IDA builds
        # omit ctx.widget while populating nested submenus; disabling in that
        # case makes IDA hide the action completely.
        return ida_kernwin.AST_ENABLE_ALWAYS
