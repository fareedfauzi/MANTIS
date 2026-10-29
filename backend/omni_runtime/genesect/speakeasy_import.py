# -*- coding: utf-8 -*-
"""Normalize Speakeasy JSON reports into Genesect runtime artifacts."""

from __future__ import annotations

import json
import os

from genesect.runtime_artifacts import new_artifact, normalize_artifact


def load_speakeasy_report(path):
    with open(path, "r", encoding="utf-8") as stream:
        return json.load(stream)


def speakeasy_report_to_artifact(report, source_path=""):
    if isinstance(report, str):
        report = json.loads(report)
    if not isinstance(report, dict):
        raise ValueError("Speakeasy report must be a JSON object")

    metadata = {
        "source_report": source_path,
        "format": "speakeasy",
    }
    target_path = _first_string(report, ("target", "target_path", "file", "path", "sample_path"))
    artifact = new_artifact(source="speakeasy", target_path=target_path, metadata=metadata)

    calls = []
    for candidate in _walk(report):
        if isinstance(candidate, dict) and _looks_like_api_event(candidate):
            calls.append(candidate)
    for index, item in enumerate(calls):
        artifact["events"].append(_event_from_api_call(item, index))

    for item in _collect_lists(report, ("strings", "decoded_strings")):
        if isinstance(item, str):
            artifact["strings"].append({"value": item, "source": "speakeasy"})
        elif isinstance(item, dict):
            value = item.get("string") or item.get("value") or item.get("data")
            if value:
                artifact["strings"].append({"value": str(value), "source": "speakeasy", "raw": item})

    for item in _collect_lists(report, ("network", "network_events", "dns", "http")):
        if isinstance(item, dict):
            artifact["network"].append(item)

    for item in _collect_lists(report, ("files", "file_access", "dropped_files")):
        if isinstance(item, dict):
            artifact["files"].append(item)

    for item in _collect_lists(report, ("registry", "registry_access")):
        if isinstance(item, dict):
            artifact["registry"].append(item)

    for item in _collect_lists(report, ("memory", "memory_regions", "mem_maps")):
        if isinstance(item, dict):
            region = _memory_region(item)
            if region:
                artifact["memory_regions"].append(region)

    for event in artifact["events"]:
        address = event.get("address")
        if address:
            artifact["coverage"].append({"address": address, "size": 1, "count": 1, "source": "speakeasy"})

    artifact["findings"] = _summarize_findings(artifact)
    return normalize_artifact(artifact)


def import_speakeasy_report(path):
    report = load_speakeasy_report(path)
    artifact = speakeasy_report_to_artifact(report, source_path=os.path.abspath(path))
    from genesect.runtime_artifacts import save_artifact_to_idb
    save_artifact_to_idb(artifact)
    return artifact


def _looks_like_api_event(item):
    keys = {str(key).lower() for key in item.keys()}
    if keys & {"api_name", "api", "function", "func_name"} and keys & {"args", "arguments", "argv", "params"}:
        return True
    if keys & {"return_value", "retval", "ret_val"} and keys & {"api_name", "api", "function", "func_name"}:
        return True
    return False


def _event_from_api_call(item, index):
    api = item.get("api_name") or item.get("api") or item.get("function") or item.get("func_name") or ""
    address = item.get("pc") or item.get("ip") or item.get("address") or item.get("pc_address") or ""
    arguments = item.get("args") or item.get("arguments") or item.get("argv") or item.get("params") or {}
    return_value = item.get("return_value", item.get("retval", item.get("ret_val", "")))
    return {
        "index": index,
        "type": "api_call",
        "api": str(api),
        "address": _hex(address),
        "thread_id": str(item.get("thread_id", item.get("tid", ""))),
        "arguments": arguments if isinstance(arguments, (dict, list)) else {"value": arguments},
        "return_value": return_value,
        "summary": _summarize_api(str(api), arguments, return_value),
        "raw": item,
    }


def _memory_region(item):
    base = item.get("base") or item.get("base_address") or item.get("address") or item.get("addr")
    size = item.get("size") or item.get("length") or item.get("end", 0)
    if item.get("end") and base:
        try:
            size = int(str(item.get("end")), 0) - int(str(base), 0)
        except Exception:
            pass
    if base in (None, ""):
        return None
    return {
        "base": _hex(base),
        "size": _int(size, 0),
        "permissions": str(item.get("permissions", item.get("protect", ""))),
        "name": str(item.get("name", item.get("tag", ""))),
        "file": str(item.get("file", item.get("path", ""))),
        "sha256": str(item.get("sha256", "")),
        "description": str(item.get("description", "")),
    }


def _summarize_findings(artifact):
    findings = []
    api_names = {event.get("api", "") for event in artifact.get("events", [])}
    if any("VirtualAlloc" in name or "VirtualProtect" in name for name in api_names):
        findings.append({"type": "memory", "summary": "Runtime memory allocation or protection changes observed."})
    if any("CreateProcess" in name or "ShellExecute" in name for name in api_names):
        findings.append({"type": "process", "summary": "Process creation behavior observed."})
    if artifact.get("network"):
        findings.append({"type": "network", "summary": "Network artifacts were present in the Speakeasy report."})
    if artifact.get("registry"):
        findings.append({"type": "registry", "summary": "Registry activity was present in the Speakeasy report."})
    return findings


def _summarize_api(api, arguments, return_value):
    return "%s(%s) -> %s" % (api or "api_call", _compact(arguments), return_value)


def _compact(value, limit=160):
    try:
        text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    except Exception:
        text = repr(value)
    return text[:limit] + ("..." if len(text) > limit else "")


def _collect_lists(root, names):
    wanted = {name.lower() for name in names}
    out = []
    for item in _walk(root):
        if isinstance(item, dict):
            for key, value in item.items():
                if str(key).lower() in wanted and isinstance(value, list):
                    out.extend(value)
    return out


def _walk(value):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            for nested in _walk(child):
                yield nested
    elif isinstance(value, list):
        for child in value:
            for nested in _walk(child):
                yield nested


def _first_string(root, keys):
    wanted = {key.lower() for key in keys}
    for item in _walk(root):
        if isinstance(item, dict):
            for key, value in item.items():
                if str(key).lower() in wanted and isinstance(value, str) and value:
                    return value
    return ""


def _hex(value):
    if value in (None, ""):
        return ""
    try:
        return "0x%X" % (int(str(value), 0) if isinstance(value, str) else int(value))
    except Exception:
        text = str(value)
        return text if text.lower().startswith("0x") else ""


def _int(value, default=0):
    try:
        return int(str(value), 0) if isinstance(value, str) else int(value)
    except Exception:
        return default
