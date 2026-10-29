"""Evidence-gated report model for the autonomous investigation.

Pure standard library and Python 3.8 compatible: this module is imported both by the
Binary Lab host process (to render reports) and by ``scripts/batch_ida_runner.py`` inside
IDA's embedded interpreter (to build the AI synthesis prompt and the model).

The design follows REAI's reporting engine: the model is assembled from validated
facts (imports, strings, functions, findings) and an AI synthesis, and every claim
that has no supporting evidence is dropped before rendering.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List, Optional

SCHEMA = "omni-report-v1"

# ---------------------------------------------------------------- taxonomy
# category -> lower-case API name prefixes (matched after stripping __imp_/underscores)
API_CATEGORIES = {
    "Process injection": (
        "virtualallocex", "writeprocessmemory", "createremotethread", "ntmapviewofsection",
        "queueuserapc", "setthreadcontext", "ntunmapviewofsection", "rtlcreateuserthread",
        "ntwritevirtualmemory", "ntcreatethreadex", "resumethread", "ptrace",
    ),
    "Dynamic code / memory": (
        "virtualalloc", "virtualprotect", "ntprotectvirtualmemory", "ntallocatevirtualmemory",
        "loadlibrary", "getprocaddress", "ldrloaddll", "ldrgetprocedureaddress", "dlopen",
        "dlsym", "mprotect", "mmap",
    ),
    "Network": (
        "internetopen", "internetconnect", "internetreadfile", "httpopenrequest", "httpsendrequest",
        "urldownloadtofile", "winhttp", "wsastartup", "wsasocket", "socket", "connect", "send",
        "recv", "getaddrinfo", "gethostbyname", "inet_addr", "bind", "listen", "accept",
        "dnsquery", "curl_easy",
    ),
    "Persistence / registry": (
        "regsetvalue", "regcreatekey", "regopenkey", "regdeletevalue", "createservice",
        "startservice", "openscmanager", "changeserviceconfig", "wmi", "shgetspecialfolderpath",
    ),
    "File system": (
        "createfile", "writefile", "readfile", "deletefile", "movefile", "copyfile",
        "findfirstfile", "setfileattributes", "createdirectory", "fopen", "unlink", "remove",
    ),
    "Process / execution": (
        "createprocess", "shellexecute", "winexec", "openprocess", "terminateprocess",
        "createthread", "system", "execve", "execl", "popen", "fork", "ntcreateprocess",
    ),
    "Anti-analysis": (
        "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
        "outputdebugstring", "gettickcount", "queryperformancecounter", "ntsetinformationthread",
        "blockinput", "findwindow",
    ),
    "Cryptography": (
        "cryptencrypt", "cryptdecrypt", "cryptacquirecontext", "cryptcreatehash", "cryptderivekey",
        "bcrypt", "crypt32", "cryptunprotectdata", "evp_", "aes_",
    ),
    "Privilege manipulation": (
        "adjusttokenprivileges", "openprocesstoken", "lookupprivilegevalue", "duplicatetoken",
        "impersonateloggedonuser", "setuid",
    ),
    "Surveillance": (
        "getasynckeystate", "setwindowshookex", "getclipboarddata", "bitblt", "getforegroundwindow",
        "getkeystate", "capcreatecapturewindow", "mixerOpen".lower(),
    ),
    "System discovery": (
        "getcomputername", "getusername", "getsysteminfo", "getnativesysteminfo",
        "createtoolhelp32snapshot", "process32first", "process32next", "enumprocesses",
        "getadaptersinfo", "getversion", "globalmemorystatus", "gethostname", "uname",
    ),
}

IOC_PATTERNS = (
    ("url", re.compile(r"https?://[^\s\"'<>\\]{4,}", re.I)),
    ("ipv4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("registry", re.compile(r"(?:HKEY_[A-Z_]+|HK(?:LM|CU|CR|U))\\[^\s\"'<>]+|Software\\Microsoft\\Windows\\CurrentVersion\\Run[^\s\"'<>]*", re.I)),
    ("file_path", re.compile(r"(?:[A-Za-z]:\\|%[A-Za-z_]+%\\)[^\s\"'<>|*?]{3,}")),
    ("pdb_path", re.compile(r"[^\s\"'<>]+\.pdb\b", re.I)),
    ("domain", re.compile(
        r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|club|online|"
        r"site|tk|cc|su|onion|ir|kr|jp|br|pw|ws|to)\b", re.I)),
)

_MITRE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
_NOISE_IPS = ("0.0.0.0", "127.0.0.1", "255.255.255.255")


def normalize_api_name(name: str) -> str:
    name = str(name or "").strip()
    for prefix in ("__imp_", "_imp__", "imp_", "j_"):
        if name.lower().startswith(prefix):
            name = name[len(prefix):]
    return name.lstrip("_.").lower()


def categorize_api(name: str) -> Optional[str]:
    base = normalize_api_name(name)
    if not base:
        return None
    for category, prefixes in API_CATEGORIES.items():
        for prefix in prefixes:
            if base.startswith(prefix):
                return category
    return None


def categorize_imports(imports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for item in imports or []:
        category = categorize_api(item.get("name", ""))
        if category:
            entry = dict(item)
            entry["category"] = category
            out.append(entry)
    return out


def extract_iocs(strings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deterministic indicator extraction from recovered strings."""
    found: Dict[Any, Dict[str, Any]] = {}
    for entry in strings or []:
        text = str(entry.get("value", ""))
        if len(text) < 4 or len(text) > 600:
            continue
        for ioc_type, pattern in IOC_PATTERNS:
            for match in pattern.finditer(text):
                value = match.group(0).rstrip(".,;)")
                if ioc_type == "ipv4" and value in _NOISE_IPS:
                    continue
                if ioc_type == "domain" and (value.lower().endswith((".dll", ".exe")) or "@" in text and ioc_type == "domain"):
                    continue
                if ioc_type == "domain" and re.match(r"^https?://", text, re.I):
                    continue  # already covered by the URL indicator
                key = (ioc_type, value.lower())
                if key not in found:
                    where = entry.get("address") or entry.get("ea") or ""
                    found[key] = {
                        "type": ioc_type,
                        "value": value,
                        "role": "observed in strings",
                        "context": "string %s" % where if where else "recovered string",
                    }
    return list(found.values())


# ---------------------------------------------------------------- prompts
SYNTHESIS_SYSTEM = """You are writing a professional malware / binary analysis report from validated reverse-engineering evidence.

Rules:
- Use ONLY the supplied evidence (imports, strings, function code, agent findings). Do not invent indicators, addresses, APIs or behaviour.
- Every capability, MITRE ATT&CK mapping and indicator MUST cite concrete evidence (an API name, a string, or a function name/address) in its "evidence" field. Entries without evidence are discarded.
- Write formal, direct prose for a security-analyst audience in the style of Mandiant / Kaspersky / Elastic reports: explain WHAT the sample does and WHY it matters. Avoid filler such as "Essentially", "Overall", "It should be noted".
- If the evidence is thin, say so in "analysis_gaps" instead of speculating.
- Reply with ONE JSON object and nothing else (no markdown fences)."""

SYNTHESIS_SCHEMA_HINT = """{
  "category": "short classification, e.g. 'Loader', 'Backdoor', 'Benign utility', 'Unknown'",
  "badges": ["short", "tags"],
  "executive_summary": "2-4 sentence assessment",
  "nutshell": ["3-6 one-line key takeaways"],
  "technical_analysis": "markdown paragraphs (no headings). Include 1-3 short ```c snippets copied from the provided code where they illustrate a critical behaviour",
  "conclusion": "short concluding paragraph",
  "execution_flow": [{"stage": "step name", "description": "what happens", "evidence": "function/API/string"}],
  "capabilities": [{"name": "capability", "description": "what the evidence supports", "evidence": "function/API/string"}],
  "key_functions": [{"name": "function name (renamed or sub_*)", "address": "0x...", "original_name": "sub_... if renamed", "verdict": "Malicious|Suspicious|Core Functionality", "summary": "purpose & assessment", "triage_guidance": "what specific code/APIs/loops/strings to inspect in IDA", "behaviors": ["..."]}],
  "iocs": [{"type": "url|ipv4|domain|file_path|registry|mutex|command_line|other", "value": "exact string from evidence", "role": "e.g. c2, dropped file, persistence key", "context": "where/how used"}],
  "mitre": [{"tactic": "...", "technique": "...", "id": "T1055", "evidence": "..."}],
  "analysis_gaps": ["what could not be determined"],
  "analyst_notes": "markdown, next steps for a reverse engineer"
}"""


def _clip(text: Any, limit: int) -> str:
    text = str(text or "")
    return text if len(text) <= limit else text[:limit] + "\n...[truncated]"


def build_synthesis_prompt(facts: Dict[str, Any], investigation: Optional[Dict[str, Any]], budget: int = 60000) -> str:
    sample = facts.get("sample", {})
    parts = [
        "=== SAMPLE ===",
        "\n".join("%s: %s" % (k, v) for k, v in sample.items() if v not in (None, "")),
        "",
        "=== STATS ===",
        json.dumps(facts.get("stats", {}), sort_keys=True),
        "",
        "=== SUSPICIOUS IMPORTS (category: names) ===",
    ]
    by_cat: Dict[str, List[str]] = {}
    for item in facts.get("imports_categorized", []):
        by_cat.setdefault(item["category"], []).append(item["name"])
    for cat, names in sorted(by_cat.items()):
        parts.append("%s: %s" % (cat, ", ".join(sorted(set(names))[:40])))
    if not by_cat:
        parts.append("(none categorized)")
    parts += ["", "=== NOTABLE STRINGS ==="]
    for s in facts.get("strings", [])[:150]:
        parts.append("%s  %s" % (s.get("address", ""), _clip(s.get("value", ""), 160).replace("\n", " ")))
    parts += ["", "=== KEY FUNCTIONS ==="]
    for fn in facts.get("key_functions", []):
        parts.append("\n--- %s @ %s ---" % (fn.get("name"), fn.get("address")))
        if fn.get("api_calls"):
            parts.append("APIs: " + ", ".join(fn["api_calls"][:30]))
        if fn.get("calls"):
            parts.append("Calls: " + ", ".join(fn["calls"][:30]))
        if fn.get("strings"):
            parts.append("Strings: " + " | ".join(_clip(x, 100) for x in fn["strings"][:12]))
        if fn.get("code"):
            parts.append(_clip(fn["code"], 2500))
    if investigation:
        parts += ["", "=== AGENT FINDINGS ==="]
        for f in investigation.get("findings", []):
            parts.append("- [%s] %s | evidence: %s" % (f.get("confidence"), f.get("claim"), "; ".join(f.get("evidence") or [])))
        if investigation.get("final_report"):
            parts += ["", "=== AGENT FINAL REPORT ===", _clip(investigation["final_report"], 6000)]
    parts += ["", "Return one JSON object with exactly this shape:", SYNTHESIS_SCHEMA_HINT]
    return _clip("\n".join(parts), budget)


def parse_model_json(text: str) -> Optional[Dict[str, Any]]:
    """Extract the first JSON object from a model reply (tolerates code fences / prose)."""
    text = str(text or "").strip()
    if not text:
        return None
    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", text):
        try:
            value, _end = decoder.raw_decode(text[match.start():])
        except ValueError:
            continue
        if isinstance(value, dict) and ("executive_summary" in value or "capabilities" in value or "category" in value):
            return value
    return None


# ---------------------------------------------------------------- assembly
def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _dicts(value: Any, *required: str) -> List[Dict[str, Any]]:
    out = []
    for item in _as_list(value):
        if isinstance(item, dict) and all(str(item.get(k) or "").strip() for k in required):
            out.append({k: (v if isinstance(v, (list, dict, int, float, bool)) else str(v).strip()) for k, v in item.items()})
    return out


def fallback_synthesis(facts: Dict[str, Any]) -> Dict[str, Any]:
    """Deterministic content used when AI synthesis is unavailable."""
    cats: Dict[str, List[str]] = {}
    for item in facts.get("imports_categorized", []):
        cats.setdefault(item["category"], []).append(item["name"])
    caps = [
        {"name": cat, "description": "Imports associated with %s are present." % cat.lower(),
         "evidence": ", ".join(sorted(set(names))[:6])}
        for cat, names in sorted(cats.items(), key=lambda kv: -len(kv[1]))
    ]
    name = facts.get("sample", {}).get("filename", "the sample")
    if cats:
        summary = "Static analysis of %s found API usage in: %s. AI synthesis was unavailable, so this report lists the verified artifacts only." % (
            name, ", ".join(sorted(cats)))
    else:
        summary = "Static analysis of %s found no categorized suspicious API usage. AI synthesis was unavailable." % name
    return {"category": "Unclassified", "executive_summary": summary, "capabilities": caps}


def assemble_model(
    facts: Dict[str, Any],
    synthesis: Optional[Dict[str, Any]],
    investigation: Optional[Dict[str, Any]] = None,
    provider_info: Optional[Dict[str, Any]] = None,
    synthesis_status: str = "ok",
) -> Dict[str, Any]:
    synth = synthesis or fallback_synthesis(facts)
    investigation = investigation or {}
    model = {
        "schema": SCHEMA,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "sample": dict(facts.get("sample", {})),
        "stats": dict(facts.get("stats", {})),
        "category": str(synth.get("category") or "Unclassified").strip(),
        "badges": [str(b) for b in _as_list(synth.get("badges"))][:8],
        "executive_summary": str(synth.get("executive_summary") or "").strip(),
        "nutshell": [str(x).strip() for x in _as_list(synth.get("nutshell")) if str(x).strip()][:8],
        "technical_analysis": str(synth.get("technical_analysis") or "").strip(),
        "conclusion": str(synth.get("conclusion") or "").strip(),
        "execution_flow": _dicts(synth.get("execution_flow"), "stage", "description"),
        "capabilities": _dicts(synth.get("capabilities"), "name", "description"),
        "key_functions": _dicts(synth.get("key_functions"), "name"),
        "iocs": _dicts(synth.get("iocs"), "type", "value"),
        "mitre": _dicts(synth.get("mitre"), "technique", "id"),
        "analysis_gaps": [str(x).strip() for x in _as_list(synth.get("analysis_gaps")) if str(x).strip()],
        "analyst_notes": str(synth.get("analyst_notes") or "").strip(),
        "renamed_functions": list(facts.get("renamed_functions", [])),
        "imports": list(facts.get("imports_categorized", [])),
        "strings": list(facts.get("strings", [])),
        "findings": list(investigation.get("findings", [])),
        "agent_report": str(investigation.get("final_report") or "").strip(),
        "provider": dict(provider_info or {}),
        "synthesis_status": synthesis_status,
    }
    # Add per-function facts (APIs / addresses / original names) and guarantee IDB navigation coverage.
    facts_by_name = {f.get("name"): f for f in facts.get("key_functions", [])}
    facts_by_addr = {str(f.get("address", "")).lower(): f for f in facts.get("key_functions", [])}
    renamed_list = facts.get("renamed_functions") or facts.get("functions_renamed") or []
    renamed_by_addr = {str(r.get("address", "")).lower(): r for r in renamed_list}
    renamed_by_new = {str(r.get("new", "")).lower(): r for r in renamed_list}

    existing_addrs = set()
    for fn in model["key_functions"]:
        name = fn.get("name") or ""
        addr = fn.get("address") or ""
        src = facts_by_name.get(name) or facts_by_addr.get(addr.lower())
        if src:
            fn.setdefault("address", src.get("address", ""))
            fn["apis"] = src.get("api_calls", [])[:12]
        
        cur_addr = str(fn.get("address") or "").lower()
        r_item = renamed_by_addr.get(cur_addr) or renamed_by_new.get(name.lower())
        if r_item and r_item.get("old"):
            fn["original_name"] = r_item["old"]
        else:
            fn["original_name"] = name if name.startswith("sub_") else "-"
        
        v = str(fn.get("verdict") or "").strip().lower()
        if "mal" in v:
            fn["verdict"] = "Malicious"
        elif "core" in v:
            fn["verdict"] = "Core Functionality"
        elif "susp" in v or "inter" in v:
            fn["verdict"] = "Suspicious"
        else:
            fn["verdict"] = "Suspicious"

        if cur_addr:
            existing_addrs.add(cur_addr)

    # If key_functions is missing or sparse, populate from facts deterministically
    for kf in facts.get("key_functions", [])[:15]:
        addr = str(kf.get("address") or "").lower()
        if addr in existing_addrs:
            continue
        name = kf.get("name") or ("sub_" + addr.lstrip("0x"))
        r_item = renamed_by_addr.get(addr) or renamed_by_new.get(name.lower())
        orig_name = r_item.get("old") if r_item else (name if name.startswith("sub_") else "-")
        apis = kf.get("api_calls", [])
        
        apis_lower = [str(a).lower() for a in apis]
        is_mal = any(any(m in a for m in ("virtualallocex", "writeprocessmemory", "createremotethread", "queueuserapc", "setthreadcontext", "ptrace", "adjusttokenprivileges", "getasynckeystate", "setwindowshookex", "task_for_pid", "mach_vm_write", "process_vm_writev", "memfd_create")) for a in apis_lower)
        is_susp = any(any(m in a for m in ("virtualalloc", "virtualprotect", "loadlibrary", "getprocaddress", "crypt", "aes", "socket", "connect", "internetopen", "regsetvalue", "createservice", "isdebuggerpresent", "ntqueryinformationprocess", "mmap", "mprotect", "dlsym", "dlopen", "sysctl")) for a in apis_lower)
        verdict = "Malicious" if is_mal else ("Suspicious" if is_susp else "Core Functionality")
        
        guidance_parts = []
        if apis:
            guidance_parts.append("Calls: " + ", ".join(f"`{a}`" for a in apis[:4]))
        if kf.get("strings"):
            guidance_parts.append("Strings: " + ", ".join(f'"{s}"' for s in kf["strings"][:2]))
        if not guidance_parts:
            guidance_parts.append("Key execution branch (%d calls)" % len(kf.get("calls", [])))
        guidance = ". ".join(guidance_parts) + ". Inspect subroutine flow in IDA."
        
        model["key_functions"].append({
            "name": name,
            "address": kf.get("address", ""),
            "original_name": orig_name,
            "verdict": verdict,
            "summary": "High-signal subroutine (score: %.1f)" % kf.get("score", 0),
            "triage_guidance": guidance,
            "apis": apis[:12],
            "behaviors": [],
        })
        existing_addrs.add(addr)

    return finalize_model(model)


def _evidence_corpus(model: Dict[str, Any]) -> str:
    chunks = [s.get("value", "") for s in model.get("strings", [])]
    chunks += [i.get("name", "") for i in model.get("imports", [])]
    chunks += [r.get("new", "") for r in model.get("renamed_functions", [])]
    chunks += [f.get("name", "") + " " + f.get("address", "") for f in model.get("key_functions", [])]
    for f in model.get("findings", []):
        chunks.append(str(f.get("claim", "")))
        chunks += [str(e) for e in f.get("evidence") or []]
    chunks.append(model.get("agent_report", ""))
    chunks.append(json.dumps(model.get("sample", {})))
    return "\n".join(str(c) for c in chunks).lower()


def _supported(evidence: str, corpus: str) -> bool:
    """True when at least one identifier-like token of the evidence appears in the corpus."""
    tokens = [t for t in re.split(r"[\s,;|()]+", str(evidence or "").lower()) if len(t) >= 3]
    return any(t.strip("`'\".") in corpus for t in tokens)


def finalize_model(model: Dict[str, Any]) -> Dict[str, Any]:
    """Merge deterministic indicators and drop every claim without supporting evidence."""
    corpus = _evidence_corpus(model)
    omitted = {"capabilities": 0, "mitre": 0, "iocs": 0, "execution_flow": 0}

    def keep(items, key, field="evidence"):
        kept = []
        for item in items:
            if _supported(item.get(field), corpus):
                kept.append(item)
            else:
                omitted[key] += 1
        return kept

    model["capabilities"] = keep(model["capabilities"], "capabilities")
    model["execution_flow"] = keep(model["execution_flow"], "execution_flow")
    model["mitre"] = [m for m in keep(model["mitre"], "mitre") if _MITRE_ID.match(str(m.get("id", "")).strip())]

    # IOCs: AI-proposed values must literally occur in the evidence; plus deterministic extraction.
    merged: Dict[Any, Dict[str, Any]] = {}
    for ioc in model["iocs"]:
        value = str(ioc.get("value", ""))
        if value and value.lower() in corpus:
            merged[(str(ioc.get("type", "")).lower(), value.lower())] = ioc
        else:
            omitted["iocs"] += 1
    for ioc in extract_iocs(model.get("strings", [])):
        merged.setdefault((ioc["type"], ioc["value"].lower()), ioc)
    model["iocs"] = list(merged.values())[:200]
    model["omitted_claims"] = omitted
    if sum(omitted.values()):
        model["analysis_gaps"].append(
            "%d AI-proposed claim(s) were omitted because no supporting evidence was found in the recovered artifacts." % sum(omitted.values())
        )
    return model


# ---------------------------------------------------------------- YARA
def yara_rule(model: Dict[str, Any]) -> str:
    """Evidence-based YARA rule from observed indicators; empty when there is nothing distinctive."""
    sample = model.get("sample", {})
    idx = 0
    lines: List[str] = []
    seen = set()
    for ioc in model.get("iocs", []):
        if ioc.get("type") not in ("url", "domain", "file_path", "registry", "pdb_path", "mutex", "command_line"):
            continue
        value = str(ioc.get("value", ""))
        if len(value) < 6 or value.lower() in seen:
            continue
        seen.add(value.lower())
        idx += 1
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        lines.append('        $s%d = "%s" ascii wide nocase' % (idx, escaped))
        if idx >= 15:
            break
    if not lines:
        return ""
    file_type = str(sample.get("file_type", "")).lower()
    cond = []
    if "pe" in file_type or "portable" in file_type:
        cond.append("uint16(0) == 0x5A4D")
    elif "elf" in file_type:
        cond.append("uint32(0) == 0x464C457F")
    elif "mach" in file_type:
        cond.append("(uint32(0) == 0xFEEDFACE or uint32(0) == 0xFEEDFACF or uint32(0) == 0xCEFAEDFE or uint32(0) == 0xCFFAEDFE or uint32(0) == 0xCAFEBABE or uint32(0) == 0xBEBAFECA)")
    size = int(sample.get("size") or 0)
    if size:
        cond.append("filesize < %d" % max(50000, size * 2))
    cond.append("2 of ($s*)" if idx >= 3 else "any of ($s*)")
    name = re.sub(r"[^A-Za-z0-9_]", "_", str(sample.get("filename", "sample"))).strip("_") or "sample"
    meta = [
        '        description = "Indicators observed in %s"' % str(sample.get("filename", "sample")).replace('"', "'"),
        '        author = "Genesect automated analysis"',
        '        date = "%s"' % str(model.get("generated_at", ""))[:10],
    ]
    if sample.get("sha256"):
        meta.append('        sample_sha256 = "%s"' % sample["sha256"])
    return "\n".join(["rule Genesect_%s" % name, "{", "    meta:"] + meta + ["    strings:"] + lines +
                     ["    condition:", "        " + " and ".join(cond), "}"])
