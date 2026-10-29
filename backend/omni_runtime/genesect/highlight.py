# -*- coding: utf-8 -*-
"""
Pseudocode and disassembly highlighting hooks for Genesect.
"""

import re

import idaapi
import ida_kernwin
import ida_hexrays
import ida_lines
import ida_segment
import ida_funcs
import idautils
import idc


HIGHLIGHT_COLOR_LIGHT = 0xFFAAFF  # BGR representation of RGB #ffaaff
HIGHLIGHT_COLOR_DARK = 0xFFAAFF

def get_highlight_color():
    color = HIGHLIGHT_COLOR_DARK

    try:
        from genesect.plugin import CONFIG
        
        def parse_rgb(s, fallback):
            if not s or not s.startswith('#'): return fallback
            try:
                r = int(s[1:3], 16)
                g = int(s[3:5], 16)
                b = int(s[5:7], 16)
                return (b << 16) | (g << 8) | r
            except Exception:
                return fallback

        color = parse_rgb(getattr(CONFIG, 'highlight_color', '#ffaaff'), color)
    except Exception:
        pass

    return color

pseudocode_highlight_enabled = False
# Assembly call highlighting is opt-in. IDA normally opens a linear
# disassembly view, where eagerly scanning a very large function or segment
# can make startup and navigation sluggish. Users can enable it explicitly
# with Toggle Call Highlight (Assembly) / Ctrl+Shift+H.
disasm_highlight_enabled = False
# Backward-compatible alias used by the settings dialog. It reflects the
# pseudocode highlighter, which was the original meaning of this setting.
highlight_plugin_enabled = False

# The Hexrays_Hooks subclass is created lazily via _create_highlight_hooks()
# because ida_hexrays.Hexrays_Hooks may not be fully functional at module parse time.
_HighlightHooksClass = None
_highlight_hooks_instance = None
_disasm_owned_colors = {}  # ea -> (original_color, applied_color)
_MAX_PSEUDOCODE_LINES = 5000
_MAX_DISASM_ITEMS = 200000
PSEUDOCODE_HIGHLIGHT_RIGHT_MARGIN = 120

_highlight_func_call_pattern = re.compile(
    r"\b(?!(?:if|for|while|switch|return|sizeof|catch|else)\b)[a-zA-Z_][a-zA-Z0-9_:]*\s*\(",
    re.IGNORECASE
)
_highlight_prefix_pattern = re.compile(
    r"\b(fn_|wrap_|sub_)[a-zA-Z0-9_]*",
    re.IGNORECASE
)

_CALL_OR_TAIL_MNEMONICS = {
    "call", "callq", "jmp", "jmpq", "bl", "blx", "blr", "b",
    "jal", "jalr", "bal", "bctrl",
}


def configure_highlight_right_margin():
    """Set Hex-Rays' wrapping width when pseudocode highlighting is enabled."""
    if not ida_hexrays.init_hexrays_plugin():
        return False
    change_config = getattr(ida_hexrays, "change_hexrays_config", None)
    if not callable(change_config):
        ida_kernwin.msg("[Genesect] Hex-Rays right-margin configuration is unavailable in this IDA build.\n")
        return False
    try:
        result = change_config("RIGHT_MARGIN = %d" % PSEUDOCODE_HIGHLIGHT_RIGHT_MARGIN)
        return result is not False
    except Exception as exc:
        ida_kernwin.msg("[Genesect] Could not set Hex-Rays right margin: %s\n" % exc)
        return False


def _clean_pseudocode_for_matching(line):
    """Remove strings and comments so call-looking text there is not highlighted."""
    value = ida_lines.tag_remove(line)
    value = re.sub(r'"(?:\\.|[^"\\])*"', '""', value)
    value = re.sub(r"'(?:\\.|[^'\\])*'", "''", value)
    value = value.split("//", 1)[0]
    return value.strip()


def _strip_block_comments(line, in_comment=False):
    value = ida_lines.tag_remove(line)
    output = []
    index = 0
    while index < len(value):
        if in_comment:
            end = value.find("*/", index)
            if end < 0:
                return "", True
            index = end + 2
            in_comment = False
        else:
            start = value.find("/*", index)
            if start < 0:
                output.append(value[index:])
                break
            output.append(value[index:start])
            index = start + 2
            in_comment = True
    return "".join(output), in_comment


def _is_disassembly_call(ea, disasm_line=""):
    mnemonic = (idc.print_insn_mnem(ea) or "").lower()
    operands = ida_lines.tag_remove(disasm_line or "").split(";", 1)[0]
    return mnemonic in _CALL_OR_TAIL_MNEMONICS or bool(_highlight_prefix_pattern.search(operands))


def _create_highlight_hooks():
    """Create and install the Hexrays_Hooks for pseudocode highlighting."""
    global _HighlightHooksClass, _highlight_hooks_instance

    if _highlight_hooks_instance is not None:
        return _highlight_hooks_instance

    if not ida_hexrays.init_hexrays_plugin():
        print("[Genesect] Hex-Rays not available, cannot install highlight hooks")
        return None

    # Define the class HERE, after Hex-Rays is confirmed available
    class _GenesectHighlightHooks(ida_hexrays.Hexrays_Hooks):
        def __init__(self):
            ida_hexrays.Hexrays_Hooks.__init__(self)

        def _apply_highlight(self, pc):
            if pc and pseudocode_highlight_enabled:
                color = get_highlight_color()
                in_block_comment = False
                body_started = False
                for index, sl in enumerate(pc):
                    if index >= _MAX_PSEUDOCODE_LINES:
                        break
                    line, in_block_comment = _strip_block_comments(sl.line, in_block_comment)
                    clean_line = _clean_pseudocode_for_matching(line)
                    # Only suppress the decompiled function's header.  A call
                    # used as an if/while condition also ends in ')' and has no
                    # semicolon, so shape-only detection hid valid call sites.
                    looks_like_declaration = (
                        not body_started and clean_line.endswith(")")
                        and ";" not in clean_line and "=" not in clean_line
                    )
                    if not clean_line or looks_like_declaration:
                        if "{" in clean_line:
                            body_started = True
                        continue
                    if _highlight_func_call_pattern.search(clean_line) or \
                       _highlight_prefix_pattern.search(clean_line):
                        if getattr(sl, "bgcolor", 0xFFFFFFFF) in (0, 0xFFFFFFFF):
                            sl.bgcolor = color
                    if "{" in clean_line:
                        body_started = True
            return

        def func_printed(self, cfunc):
            """IDA 8.x callback fired after pseudocode lines are generated."""
            if pseudocode_highlight_enabled and cfunc:
                self._apply_highlight(cfunc.get_pseudocode())
            return 0

        def text_ready(self, vu):
            """Compatibility callback retained for bindings that expose it."""
            if pseudocode_highlight_enabled:
                pc = vu.cfunc.get_pseudocode()
                if pc:
                    self._apply_highlight(pc)
            return 0

    _HighlightHooksClass = _GenesectHighlightHooks
    instance = _GenesectHighlightHooks()
    if not instance.hook():
        print("[Genesect] Failed to install highlight hooks")
        return None
    _highlight_hooks_instance = instance
    print("[Genesect] Highlight hooks installed successfully")
    return _highlight_hooks_instance


def destroy_highlight_hooks():
    global _highlight_hooks_instance, _HighlightHooksClass
    global pseudocode_highlight_enabled, disasm_highlight_enabled, highlight_plugin_enabled
    pseudocode_highlight_enabled = False
    highlight_plugin_enabled = False
    disasm_highlight_enabled = False
    if _disasm_owned_colors:
        GraphLinearHighlightHooks().refresh_view()
    if _highlight_hooks_instance is not None:
        try:
            _highlight_hooks_instance.unhook()
        except Exception:
            pass
    _highlight_hooks_instance = None
    _HighlightHooksClass = None


class GraphLinearHighlightHooks(idaapi.IDB_Hooks):
    def __init__(self):
        idaapi.IDB_Hooks.__init__(self)

    def _highlight_disassembly_calls(self, ea):
        disasm_line = ida_lines.generate_disasm_line(ea, 0) or ""
        if _is_disassembly_call(ea, disasm_line):
            color = get_highlight_color()
            if ea not in _disasm_owned_colors:
                _disasm_owned_colors[ea] = (idaapi.get_item_color(ea), color)
            else:
                original, _ = _disasm_owned_colors[ea]
                _disasm_owned_colors[ea] = (original, color)
            idaapi.set_item_color(ea, color)

    def _remove_highlight(self, ea):
        owned = _disasm_owned_colors.pop(ea, None)
        if owned is None:
            return
        original, applied = owned
        if idaapi.get_item_color(ea) == applied:
            idaapi.set_item_color(ea, original)

    def refresh_view(self):
        if disasm_highlight_enabled:
            screen_ea = idaapi.get_screen_ea()
            func = ida_funcs.get_func(screen_ea)
            if func:
                addresses = idautils.FuncItems(func.start_ea)
            else:
                seg = ida_segment.getseg(screen_ea)
                if not seg:
                    return
                addresses = idautils.Heads(seg.start_ea, seg.end_ea)
            for index, ea in enumerate(addresses):
                if index >= _MAX_DISASM_ITEMS:
                    ida_kernwin.warning("Call highlighting stopped at the 200,000-item safety limit.")
                    break
                if idaapi.is_code(idaapi.get_full_flags(ea)):
                    self._highlight_disassembly_calls(ea)
        else:
            for ea in list(_disasm_owned_colors):
                self._remove_highlight(ea)
        idaapi.request_refresh(idaapi.IWID_DISASM)


# --- Toggle handlers ---

class toggle_highlight_handler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        if pseudocode_highlight_enabled:
            disable_highlighting()
        else:
            enable_highlighting()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class toggle_disasm_highlight_handler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        if disasm_highlight_enabled:
            disable_disasm_highlighting()
        else:
            enable_disasm_highlighting()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


# --- Enable / Disable functions ---

def enable_highlighting():
    global pseudocode_highlight_enabled, highlight_plugin_enabled
    pseudocode_highlight_enabled = True
    highlight_plugin_enabled = True
    configure_highlight_right_margin()
    _create_highlight_hooks()
    vu = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_viewer())
    if vu:
        vu.refresh_view(True)
    ida_kernwin.msg("[Genesect] Highlighting Enabled (Pseudocode, right margin 120)\n")


def disable_highlighting():
    global pseudocode_highlight_enabled, highlight_plugin_enabled
    pseudocode_highlight_enabled = False
    highlight_plugin_enabled = False
    vu = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_viewer())
    if vu:
        vu.refresh_ctext()
    ida_kernwin.msg("[Genesect] Highlighting Disabled (Pseudocode)\n")


def enable_disasm_highlighting():
    global disasm_highlight_enabled
    disasm_highlight_enabled = True
    ida_kernwin.msg("[Genesect] Highlighting Enabled (Graph/Linear View)\n")
    GraphLinearHighlightHooks().refresh_view()


def refresh_disasm_highlighting():
    """Refresh the current assembly view without changing or logging its state."""
    if disasm_highlight_enabled:
        GraphLinearHighlightHooks().refresh_view()


def disable_disasm_highlighting():
    global disasm_highlight_enabled
    disasm_highlight_enabled = False
    ida_kernwin.msg("[Genesect] Highlighting Disabled (Graph/Linear View)\n")
    GraphLinearHighlightHooks().refresh_view()


def is_pseudocode_highlight_enabled():
    return bool(pseudocode_highlight_enabled)


def is_disasm_highlight_enabled():
    return bool(disasm_highlight_enabled)
