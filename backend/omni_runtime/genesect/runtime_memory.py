# -*- coding: utf-8 -*-
"""Runtime memory region import helpers."""

from __future__ import annotations

import hashlib
import os

import idaapi
import ida_bytes
import ida_segment

from genesect.runtime_artifacts import load_artifact_from_idb


def import_region_file(path, base, name="", permissions="RWX"):
    if not path or not os.path.exists(path):
        return {"ok": False, "message": "Memory dump file does not exist."}
    base = _ea(base)
    if base == idaapi.BADADDR:
        return {"ok": False, "message": "Invalid base address."}
    with open(path, "rb") as stream:
        data = stream.read()
    if not data:
        return {"ok": False, "message": "Memory dump is empty."}
    seg_name = name or "runtime_%X" % base
    end = base + len(data)
    created = False
    try:
        if not idaapi.getseg(base):
            ida_segment.add_segm(0, base, end, seg_name, "DATA")
            created = True
    except Exception:
        pass
    try:
        ida_bytes.patch_bytes(base, data)
    except Exception as exc:
        return {"ok": False, "message": "Could not patch memory bytes: %s" % exc}
    return {
        "ok": True,
        "base": "0x%X" % base,
        "size": len(data),
        "segment_created": created,
        "sha256": hashlib.sha256(data).hexdigest(),
        "message": "Imported %d bytes at 0x%X." % (len(data), base),
    }


def import_regions_from_artifact(artifact=None, artifact_root=""):
    artifact = artifact or load_artifact_from_idb()
    if not artifact:
        return {"ok": False, "message": "No runtime artifact loaded.", "regions": []}
    results = []
    for region in artifact.get("memory_regions", []):
        path = region.get("file", "")
        if path and artifact_root and not os.path.isabs(path):
            path = os.path.join(artifact_root, path)
        if not path:
            continue
        results.append(import_region_file(
            path,
            region.get("base", ""),
            name=region.get("name", ""),
            permissions=region.get("permissions", ""),
        ))
    ok_count = len([item for item in results if item.get("ok")])
    return {"ok": ok_count > 0, "message": "Imported %d runtime memory regions." % ok_count, "regions": results}


def _ea(value):
    try:
        return int(str(value), 0) if isinstance(value, str) else int(value)
    except Exception:
        return idaapi.BADADDR
