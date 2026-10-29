# -*- coding: utf-8 -*-
"""
Side-by-side synchronized Assembly and Pseudocode view (Ghidra style).

Provides 1-click docking of Pseudocode to the right of Disassembly with
bilateral cursor position and instruction highlight synchronization.
"""

from typing import Optional
import re

try:
    import idaapi
    import ida_kernwin
    import ida_hexrays
except ImportError:
    idaapi = None
    ida_kernwin = None
    ida_hexrays = None

_SYNC_ACTIVE: bool = False


def _clean_title(title: str) -> str:
    """Normalize widget title to canonical docking name (e.g. 'IDA View-A', 'Pseudocode-A')."""
    if not title:
        return ""
    m = re.match(r"^(IDA View-[A-Z]|Pseudocode-[A-Z])", title)
    if m:
        return m.group(1)
    if " (Synchronized with" in title:
        return title.split(" (Synchronized with")[0].strip()
    return title.split(" (")[0].strip()


def find_disasm_widget(candidate_widget=None):
    """Find active or default disassembly widget."""
    if not ida_kernwin:
        return None
    if candidate_widget and hasattr(ida_kernwin, "get_widget_type"):
        if ida_kernwin.get_widget_type(candidate_widget) == ida_kernwin.BWN_DISASM:
            return candidate_widget

    cur = ida_kernwin.get_current_widget()
    if cur and hasattr(ida_kernwin, "get_widget_type"):
        if ida_kernwin.get_widget_type(cur) == ida_kernwin.BWN_DISASM:
            return cur

    for name in ("IDA View-A", "IDA View-B", "IDA View-C", "IDA View-D"):
        w = ida_kernwin.find_widget(name)
        if w:
            return w
    return None


def find_pseudocode_widget(candidate_widget=None):
    """Find active or open pseudocode widget."""
    if not ida_kernwin:
        return None
    if candidate_widget and hasattr(ida_kernwin, "get_widget_type"):
        if ida_kernwin.get_widget_type(candidate_widget) == ida_kernwin.BWN_PSEUDOCODE:
            return candidate_widget

    cur = ida_kernwin.get_current_widget()
    if cur and hasattr(ida_kernwin, "get_widget_type"):
        if ida_kernwin.get_widget_type(cur) == ida_kernwin.BWN_PSEUDOCODE:
            return cur

    for name in ("Pseudocode-A", "Pseudocode-B", "Pseudocode-C", "Pseudocode-D"):
        w = ida_kernwin.find_widget(name)
        if w:
            return w
    return None


def ensure_pseudocode_widget(disasm_widget=None):
    """Find existing pseudocode widget, or automatically decompile current function."""
    w = find_pseudocode_widget()
    if w:
        return w

    if ida_hexrays and hasattr(ida_hexrays, "open_pseudocode"):
        try:
            if hasattr(ida_hexrays, "init_hexrays_plugin") and not ida_hexrays.init_hexrays_plugin():
                return None
            ea = ida_kernwin.get_screen_ea() if ida_kernwin else (getattr(idaapi, "BADADDR", 0) if idaapi else 0)
            badaddr = getattr(idaapi, "BADADDR", 0xffffffffffffffff) if idaapi else 0xffffffffffffffff
            if ea != badaddr and ea != 0:
                vu = ida_hexrays.open_pseudocode(ea, 0)
                if vu and hasattr(vu, "ct") and vu.ct:
                    return vu.ct
        except Exception:
            pass

    return find_pseudocode_widget()


def is_side_by_side_synced(disasm_w=None, pseudo_w=None) -> bool:
    """Return True if disassembly and pseudocode are currently synchronized."""
    global _SYNC_ACTIVE
    if not ida_kernwin:
        return _SYNC_ACTIVE

    disasm_w = disasm_w or find_disasm_widget()
    pseudo_w = pseudo_w or find_pseudocode_widget()
    if not disasm_w or not pseudo_w:
        return _SYNC_ACTIVE

    try:
        if hasattr(ida_kernwin, "get_synced_group"):
            grp = ida_kernwin.get_synced_group(disasm_w)
            if grp and hasattr(grp, "has_widget"):
                if grp.has_widget(pseudo_w):
                    return True
                return False
            grp2 = ida_kernwin.get_synced_group(pseudo_w)
            if grp2 and hasattr(grp2, "has_widget"):
                if grp2.has_widget(disasm_w):
                    return True
                return False
    except Exception:
        pass

    return _SYNC_ACTIVE


def toggle_side_by_side_sync(enable: Optional[bool] = None, restore_tabbed: bool = True) -> bool:
    """Toggle or set side-by-side synchronized view between disassembly and pseudocode."""
    global _SYNC_ACTIVE

    if enable is None:
        enable = not is_side_by_side_synced()

    if not ida_kernwin:
        _SYNC_ACTIVE = enable
        return True

    disasm_w = find_disasm_widget()

    if enable:
        if not disasm_w:
            msg = "[Genesect] Disassembly view (IDA View-A) not found.\n"
            if hasattr(ida_kernwin, "msg"):
                ida_kernwin.msg(msg)
            return False

        pseudo_w = ensure_pseudocode_widget(disasm_w)
        if not pseudo_w:
            msg = "[Genesect] Hex-Rays pseudocode view could not be opened or found.\n"
            if hasattr(ida_kernwin, "msg"):
                ida_kernwin.msg(msg)
            return False

        disasm_title = _clean_title(ida_kernwin.get_widget_title(disasm_w)) or "IDA View-A"
        pseudo_title = _clean_title(ida_kernwin.get_widget_title(pseudo_w)) or "Pseudocode-A"

        # Dock Pseudocode to the right of Disassembly
        dp_right = getattr(ida_kernwin, "DP_RIGHT", 0)
        ida_kernwin.set_dock_pos(pseudo_title, disasm_title, dp_right)

        # Synchronize cursor and navigation
        if hasattr(ida_kernwin, "sync_source_t") and hasattr(ida_kernwin, "sync_sources"):
            ss_disasm = ida_kernwin.sync_source_t(disasm_w)
            ss_pseudo = ida_kernwin.sync_source_t(pseudo_w)
            ida_kernwin.sync_sources(ss_disasm, ss_pseudo, True)

        _SYNC_ACTIVE = True
        if hasattr(ida_kernwin, "msg"):
            ida_kernwin.msg("[Genesect] Assembly and pseudocode synchronized side-by-side (Ghidra style).\n")
        return True

    else:
        pseudo_w = find_pseudocode_widget()

        if disasm_w and pseudo_w:
            if hasattr(ida_kernwin, "sync_source_t") and hasattr(ida_kernwin, "sync_sources"):
                ss_disasm = ida_kernwin.sync_source_t(disasm_w)
                ss_pseudo = ida_kernwin.sync_source_t(pseudo_w)
                ida_kernwin.sync_sources(ss_disasm, ss_pseudo, False)

            if restore_tabbed:
                disasm_title = _clean_title(ida_kernwin.get_widget_title(disasm_w)) or "IDA View-A"
                pseudo_title = _clean_title(ida_kernwin.get_widget_title(pseudo_w)) or "Pseudocode-A"
                dp_inside = getattr(ida_kernwin, "DP_INSIDE", getattr(ida_kernwin, "DP_TAB", 0))
                ida_kernwin.set_dock_pos(pseudo_title, disasm_title, dp_inside)

        _SYNC_ACTIVE = False
        if hasattr(ida_kernwin, "msg"):
            ida_kernwin.msg("[Genesect] Side-by-side synchronization disabled.\n")
        return True


if idaapi:
    class SideBySideSyncHandler(idaapi.action_handler_t):
        """Action handler to toggle side-by-side assembly & pseudocode synchronization."""

        def activate(self, ctx):
            toggle_side_by_side_sync()
            return 1

        def update(self, ctx):
            return getattr(idaapi, "AST_ENABLE_ALWAYS", getattr(idaapi, "AST_ENABLE", 1))
else:
    class SideBySideSyncHandler(object):
        def activate(self, ctx):
            return toggle_side_by_side_sync()

        def update(self, ctx):
            return 1
