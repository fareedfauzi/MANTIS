# -*- coding: utf-8 -*-
"""Cached API semantics shared by structure and malware explorers.

Combines malware_api_tags.json, apilist.txt, and API/Windows XML metadata.
"""
from __future__ import annotations

import os
import re
import threading
import xml.etree.ElementTree as ET

from genesect import api_taxonomy


_ROOT = os.path.dirname(__file__)
_API_ROOT = os.path.join(_ROOT, "API")
_WINDOWS_ROOT = os.path.join(_API_ROOT, "Windows")
_APILIST = os.path.join(_ROOT, "apilist.txt")
_LOCK = threading.RLock()
_SIGNATURES = None
_API_NAMES = None
_API_MODULES = None


def normalize_api_name(name):
    """Strip IDA/import decorations while preserving the actual API name."""
    value = str(name or "").strip()
    if "!" in value:
        value = value.rsplit("!", 1)[-1]
    value = re.sub(r"^(?:cs:|ds:|es:|ss:)", "", value, flags=re.I)
    value = re.sub(r"^(?:__imp_|_imp__|j_)", "", value, flags=re.I)
    value = re.sub(r"@\d+$", "", value)
    return value.strip()


def api_name_variants(name):
    normalized = normalize_api_name(name)
    values = [normalized]
    if len(normalized) > 2 and normalized[-1:] in ("A", "W") and normalized[-2:-1].islower():
        values.append(normalized[:-1])
    if normalized.startswith("Zw"):
        values.append("Nt" + normalized[2:])
    elif normalized.startswith("Nt"):
        values.append("Zw" + normalized[2:])
    return tuple(dict.fromkeys(value.casefold() for value in values if value))


def _load_apilist():
    global _API_NAMES, _API_MODULES
    with _LOCK:
        if _API_NAMES is not None:
            return
        names, modules, current_module = set(), {}, ""
        try:
            with open(_APILIST, "r", encoding="utf-8", errors="replace") as handle:
                for raw in handle:
                    value = raw.strip()
                    if not value:
                        current_module = ""
                        continue
                    if value.lower().endswith((".dll", ".exe", ".sys", ".ocx", ".drv")):
                        current_module = value
                        continue
                    key = normalize_api_name(value).casefold()
                    if key:
                        names.add(key)
                        if current_module:
                            modules.setdefault(key, set()).add(current_module)
        except OSError:
            pass
        _API_NAMES, _API_MODULES = names, modules


def known_api_name(name):
    _load_apilist()
    return any(variant in _API_NAMES for variant in api_name_variants(name))


def api_modules(name):
    _load_apilist()
    result = set()
    for variant in api_name_variants(name):
        result.update(_API_MODULES.get(variant, ()))
    return sorted(result, key=str.casefold)


def taxonomy_entry(name):
    for variant in api_name_variants(name):
        entry = api_taxonomy.API_MAP.get(variant)
        if entry:
            return dict(entry)
    return None


def is_ignored_api(name):
    variants = set(api_name_variants(name))
    return bool(variants.intersection(api_taxonomy.API_IGNORE | api_taxonomy.API_IGNORE_CALLS))


def _load_signatures():
    global _SIGNATURES
    with _LOCK:
        if _SIGNATURES is not None:
            return
        signatures = {}
        try:
            filenames = sorted(os.listdir(_WINDOWS_ROOT), key=str.casefold)
        except OSError:
            filenames = []
        for filename in filenames:
            if not filename.lower().endswith(".xml"):
                continue
            path = os.path.join(_WINDOWS_ROOT, filename)
            try:
                root = ET.parse(path).getroot()
            except (OSError, ET.ParseError):
                continue
            for module in root.iter("Module"):
                module_name = module.get("Name") or filename[:-4]
                category = ""
                for child in list(module):
                    if child.tag == "Category":
                        category = child.get("Name") or ""
                        continue
                    if child.tag != "Api":
                        continue
                    api_name = child.get("Name") or ""
                    if not api_name:
                        continue
                    params = [
                        {"index": index, "name": param.get("Name") or "", "type": param.get("Type") or ""}
                        for index, param in enumerate(child.findall("Param"))
                    ]
                    returned = child.find("Return")
                    record = {
                        "name": api_name,
                        "module": module_name,
                        "category": category,
                        "params": params,
                        "return_type": returned.get("Type") if returned is not None else "",
                    }
                    for variant in api_name_variants(api_name):
                        signatures.setdefault(variant, record)
        _SIGNATURES = signatures


def api_signature(name):
    _load_signatures()
    for variant in api_name_variants(name):
        record = _SIGNATURES.get(variant)
        if record:
            return record
    return None


_CALLBACK_HINT = re.compile(r"(?:callback|handler|routine|proc$|thread_start|completion|notify|enum)", re.I)


def callback_parameters(name):
    signature = api_signature(name)
    if not signature:
        return []
    return [
        param for param in signature["params"]
        if _CALLBACK_HINT.search(param["name"]) or _CALLBACK_HINT.search(param["type"])
    ]


def describe_api(name):
    signature = api_signature(name)
    taxonomy = taxonomy_entry(name)
    return {
        "normalized": normalize_api_name(name),
        "known": bool(signature or known_api_name(name) or taxonomy),
        "signature": signature,
        "taxonomy": taxonomy,
        "ignored": is_ignored_api(name),
        "modules": api_modules(name),
    }
