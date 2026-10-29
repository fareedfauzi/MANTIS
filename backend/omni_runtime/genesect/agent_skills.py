# -*- coding: utf-8 -*-
"""Compact autonomous-agent skill routing profiles."""

from __future__ import annotations

import re


DEFAULT_ROUTE = "triage-router"


_PROFILES = {
    "triage-router": {
        "title": "Triage Router",
        "triggers": (),
        "prompt": (
            "ACTIVE SKILL PROFILE: triage-router\n"
            "- First classify the analyst objective and choose the smallest evidence path.\n"
            "- Separate static facts, runtime observations, inference, and unknowns.\n"
            "- Do not infer a call chain from a string alone.\n"
            "- High confidence requires corroborating evidence or a reachable code path.\n"
            "- Final answer format: route, evidence table, conclusion, limitations, next step."
        ),
    },
    "malware-re": {
        "title": "Malware Reverse Engineering",
        "triggers": (
            "malware", "c2", "config", "inject", "persistence", "anti-analysis",
            "debugger", "sandbox", "ioc", "beacon", "payload", "ransom", "stealer",
            "command", "protocol", "mutex", "registry",
        ),
        "prompt": (
            "ACTIVE SKILL PROFILE: malware-re\n"
            "- Map behavior through code, imports, strings, xrefs, globals, and callgraph evidence.\n"
            "- For config or C2, confirm values reach a use site such as network/API/crypto logic.\n"
            "- Group findings by capability: config, C2/protocol, persistence, injection, crypto, anti-analysis, loader/unpacking.\n"
            "- Record IOCs only when the value is present in evidence; defang network/email indicators in reports.\n"
            "- Final answer format: executive summary, key functions, capabilities/evidence, IOCs/config, confidence/gaps."
        ),
    },
    "ioc-report": {
        "title": "IOC Extraction",
        "triggers": ("ioc", "indicator", "domain", "url", "ip", "hash", "mutex", "user-agent", "registry", "extract"),
        "prompt": (
            "ACTIVE SKILL PROFILE: ioc-report\n"
            "- Extract only indicators explicitly present in collected evidence.\n"
            "- Do not resolve domains, browse URLs, enrich reputation, or invent missing values.\n"
            "- Every IOC must include type, value, confidence, context, source artifact, and evidence snippet.\n"
            "- Defang URL/domain/email indicators in the final report while preserving original-as-seen when useful.\n"
            "- Label ambiguous values as candidate/contextual/incomplete instead of confirmed."
        ),
    },
    "unpacking": {
        "title": "Packing And Unpacking",
        "triggers": ("packed", "packer", "unpack", "upx", "loader", "stub", "overlay", "entropy", "dump", "oep"),
        "prompt": (
            "ACTIVE SKILL PROFILE: unpacking\n"
            "- Use static indicators first: sections/segments, imports, strings, overlays, loader stubs, entrypoints, entropy-like evidence.\n"
            "- Do not claim an unpacked artifact exists unless produced and hashed outside this reasoning step.\n"
            "- Dynamic unpacking requires explicit analyst VM/sandbox approval; do not suggest host execution.\n"
            "- Validate dumps with headers, mappings, imports/relocations, strings increase, and consumer-tool loading.\n"
            "- Final answer format: packing assessment, static evidence, safe plan, produced artifacts if any, next steps."
        ),
    },
    "go-rust": {
        "title": "Go/Rust User Code",
        "triggers": ("golang", "go ", "go/rust", "rust", "crate", "package", "lang_start", "panic", "runtime"),
        "prompt": (
            "ACTIVE SKILL PROFILE: go-rust\n"
            "- Prioritize likely user and third-party code over runtime and standard-library noise.\n"
            "- Treat Go/Rust classification as heuristic unless supported by names, package/crate paths, strings, imports, or callers.\n"
            "- Do not mistake Rust allocator/panic/drop/formatting routines or Go runtime helpers for user behavior.\n"
            "- For renames, include package/crate context and direct function evidence.\n"
            "- Final answer format: user-code groups, key functions, runtime boundaries, evidence, confidence."
        ),
    },
    "cpp-vtable": {
        "title": "C++ Virtual Dispatch",
        "triggers": ("vtable", "vftable", "virtual", "rtti", "class", "constructor", "destructor", "com "),
        "prompt": (
            "ACTIVE SKILL PROFILE: cpp-vtable\n"
            "- Treat recovered classes/vtables as heuristic until validated by xrefs, constructor writes, RTTI, and callsites.\n"
            "- Watch virtual dispatch used as command handlers, parsers, protocol handlers, unpacking stages, or plugin dispatch.\n"
            "- Propose class/method names from behavior, not only table names.\n"
            "- For COM or interface-like code, correlate GUID/interface evidence with callsites.\n"
            "- Final answer format: class/table evidence, key methods, dispatch behavior, proposed names, confidence."
        ),
    },
}


def available_skill_routes():
    return list(_PROFILES)


def skill_profile_prompt(route):
    return _PROFILES.get(route or DEFAULT_ROUTE, _PROFILES[DEFAULT_ROUTE])["prompt"]


def skill_profile_title(route):
    return _PROFILES.get(route or DEFAULT_ROUTE, _PROFILES[DEFAULT_ROUTE])["title"]


def detect_skill_route(text, function_name="", task_profile=""):
    """Select one compact profile from the analyst request and host task shape."""
    haystack = " ".join([str(text or ""), str(function_name or ""), str(task_profile or "")]).lower()
    if task_profile in ("rename_descendants", "rename_prefix"):
        return "triage-router"
    if re.search(r"\b(go|golang|rust|crate|lang_start|panic)\b", haystack):
        return "go-rust"
    for route in ("cpp-vtable", "unpacking", "ioc-report", "malware-re"):
        for trigger in _PROFILES[route]["triggers"]:
            if trigger in haystack:
                return route
    return DEFAULT_ROUTE


def skill_context_block(route):
    route = route or DEFAULT_ROUTE
    return "\n\n" + skill_profile_prompt(route)
