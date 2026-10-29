# -*- coding: utf-8 -*-
"""Runtime coverage highlighting for Genesect artifacts."""

from __future__ import annotations

import idaapi
import idc

from genesect.config import CONFIG
from genesect.runtime_artifacts import load_artifact_from_idb


def apply_coverage_overlay(artifact=None, color=None, limit=5000):
    artifact = artifact or load_artifact_from_idb()
    if not artifact:
        return {"ok": False, "message": "No runtime artifact loaded."}
    color_value = _ida_color(color or getattr(CONFIG, "coverage_color", "#2D7D46"))
    count = 0
    for item in artifact.get("coverage", [])[:limit]:
        ea = _ea(item.get("address"))
        if ea == idaapi.BADADDR:
            continue
        try:
            idc.set_color(ea, idc.CIC_ITEM, color_value)
            count += 1
        except Exception:
            continue
    try:
        idaapi.request_refresh(idaapi.IWID_DISASM)
        idaapi.request_refresh(idaapi.IWID_PSEUDOCODE)
    except Exception:
        pass
    return {"ok": True, "count": count, "message": "Highlighted %d runtime-covered addresses." % count}


def clear_coverage_overlay(artifact=None, limit=5000):
    artifact = artifact or load_artifact_from_idb()
    if not artifact:
        return {"ok": False, "message": "No runtime artifact loaded."}
    count = 0
    for item in artifact.get("coverage", [])[:limit]:
        ea = _ea(item.get("address"))
        if ea == idaapi.BADADDR:
            continue
        try:
            idc.set_color(ea, idc.CIC_ITEM, idc.DEFCOLOR)
            count += 1
        except Exception:
            continue
    try:
        idaapi.request_refresh(idaapi.IWID_DISASM)
    except Exception:
        pass
    return {"ok": True, "count": count, "message": "Cleared %d runtime coverage colors." % count}


def _ea(value):
    try:
        return int(str(value), 0) if isinstance(value, str) else int(value)
    except Exception:
        return idaapi.BADADDR


def _ida_color(value):
    text = str(value or "").strip()
    if text.startswith("#") and len(text) == 7:
        r = int(text[1:3], 16)
        g = int(text[3:5], 16)
        b = int(text[5:7], 16)
        return r | (g << 8) | (b << 16)
    try:
        return int(text, 0)
    except Exception:
        return 0x467D2D
