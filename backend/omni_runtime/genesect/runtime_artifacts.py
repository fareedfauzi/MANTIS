# -*- coding: utf-8 -*-
"""Generic runtime artifact schema and IDB storage helpers."""

from __future__ import annotations

import datetime
import json
import os
import uuid


RUNTIME_ARTIFACT_SCHEMA = "genesect.runtime_artifact.v1"
RUNTIME_ARTIFACT_TAG = 120


def new_artifact(source="manual", target_path="", metadata=None):
    return {
        "schema": RUNTIME_ARTIFACT_SCHEMA,
        "artifact_id": uuid.uuid4().hex,
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source": str(source or "manual"),
        "target_path": str(target_path or ""),
        "metadata": dict(metadata or {}),
        "events": [],
        "coverage": [],
        "memory_regions": [],
        "strings": [],
        "files": [],
        "network": [],
        "registry": [],
        "findings": [],
    }


def normalize_artifact(data):
    if isinstance(data, str):
        data = json.loads(data)
    if not isinstance(data, dict):
        raise ValueError("runtime artifact must be a JSON object")
    artifact = new_artifact(
        source=data.get("source", "manual"),
        target_path=data.get("target_path", ""),
        metadata=data.get("metadata") if isinstance(data.get("metadata"), dict) else {},
    )
    for key in ("schema", "artifact_id", "created_at"):
        if data.get(key):
            artifact[key] = str(data[key])
    for key in ("events", "coverage", "memory_regions", "strings", "files", "network", "registry", "findings"):
        value = data.get(key, [])
        artifact[key] = value if isinstance(value, list) else []
    artifact["events"] = [normalize_event(item) for item in artifact["events"] if isinstance(item, dict)]
    artifact["coverage"] = [normalize_coverage(item) for item in artifact["coverage"] if isinstance(item, dict)]
    artifact["memory_regions"] = [normalize_memory_region(item) for item in artifact["memory_regions"] if isinstance(item, dict)]
    return artifact


def normalize_event(item):
    return {
        "index": _int(item.get("index"), 0),
        "type": str(item.get("type", "event")),
        "api": str(item.get("api", "")),
        "address": _addr(item.get("address")),
        "thread_id": str(item.get("thread_id", "")),
        "arguments": item.get("arguments") if isinstance(item.get("arguments"), (dict, list)) else {},
        "return_value": item.get("return_value", ""),
        "summary": str(item.get("summary", "")),
        "raw": item.get("raw") if isinstance(item.get("raw"), dict) else {},
    }


def normalize_coverage(item):
    return {
        "address": _addr(item.get("address")),
        "size": _int(item.get("size"), 1),
        "count": _int(item.get("count"), 1),
        "source": str(item.get("source", "")),
    }


def normalize_memory_region(item):
    return {
        "base": _addr(item.get("base")),
        "size": _int(item.get("size"), 0),
        "permissions": str(item.get("permissions", "")),
        "name": str(item.get("name", "")),
        "file": str(item.get("file", "")),
        "sha256": str(item.get("sha256", "")),
        "description": str(item.get("description", "")),
    }


def validate_artifact(artifact):
    artifact = normalize_artifact(artifact)
    errors = []
    if artifact.get("schema") != RUNTIME_ARTIFACT_SCHEMA:
        errors.append("schema must be %s" % RUNTIME_ARTIFACT_SCHEMA)
    for index, event in enumerate(artifact.get("events", [])):
        if event.get("address") and not _looks_like_hex(event["address"]):
            errors.append("events[%d].address is not a hex address" % index)
    for index, item in enumerate(artifact.get("coverage", [])):
        if not item.get("address"):
            errors.append("coverage[%d].address is required" % index)
    return len(errors) == 0, errors, artifact


def load_artifact_file(path):
    with open(path, "r", encoding="utf-8") as stream:
        return normalize_artifact(json.load(stream))


def save_artifact_file(path, artifact):
    artifact = normalize_artifact(artifact)
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as stream:
        json.dump(artifact, stream, indent=2, ensure_ascii=False)
    return path


def save_artifact_to_idb(artifact):
    artifact = normalize_artifact(artifact)
    import idaapi
    from genesect.idb_storage import save_to_idb
    save_to_idb(idaapi.BADADDR, json.dumps(artifact, ensure_ascii=False), tag=RUNTIME_ARTIFACT_TAG)
    return artifact


def load_artifact_from_idb():
    import idaapi
    from genesect.idb_storage import load_from_idb
    raw = load_from_idb(idaapi.BADADDR, tag=RUNTIME_ARTIFACT_TAG)
    return normalize_artifact(raw) if raw else None


def artifact_summary(artifact):
    artifact = normalize_artifact(artifact)
    return {
        "artifact_id": artifact.get("artifact_id", ""),
        "source": artifact.get("source", ""),
        "target_path": artifact.get("target_path", ""),
        "events": len(artifact.get("events", [])),
        "coverage": len(artifact.get("coverage", [])),
        "memory_regions": len(artifact.get("memory_regions", [])),
        "strings": len(artifact.get("strings", [])),
        "files": len(artifact.get("files", [])),
        "network": len(artifact.get("network", [])),
        "registry": len(artifact.get("registry", [])),
        "findings": len(artifact.get("findings", [])),
    }


def _int(value, default=0):
    try:
        return int(str(value), 0) if isinstance(value, str) else int(value)
    except Exception:
        return default


def _addr(value):
    if value in (None, ""):
        return ""
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return ""
        try:
            parsed = int(text, 0)
        except ValueError:
            return text if _looks_like_hex(text) else ""
    else:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return ""
    return "0x%X" % parsed if parsed >= 0 else ""


def _looks_like_hex(value):
    text = str(value or "").strip().lower()
    if not text.startswith("0x"):
        return False
    try:
        int(text, 16)
        return True
    except Exception:
        return False
