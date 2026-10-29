"""Rust binary support for Binary Lab.

Provides pure-Python demangling, triage detection, crate dependency extraction,
and standard library / runtime noise filtering for Rust executables in IDA.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections import Counter
from typing import Any, Dict, List, Optional, Set, Tuple

PLAIN_RUST_STRINGS = (
    "run with `RUST_BACKTRACE=1` environment variable to display a backtrace",
    "called `Result::unwrap()` on an `Err` value",
    "called `Option::unwrap()` on a `None` value",
    "assertion failed: ",
    "fatal runtime error: ",
)

MINSIZE_RUST_STRINGS = (
    "<unknown>",
    "<redacted>",
    "failed to write whole buffer",
    "failed to write the buffered data",
)

LOCATION_PATH_MARKERS = (
    ".cargo\\registry",
    ".cargo/registry",
    "\\rustc\\",
    "/rustc/",
    "\\library\\core\\src\\",
    "/library/core/src/",
    "\\library\\std\\src\\",
    "/library/std/src/",
    "\\library\\alloc\\src\\",
    "/library/alloc/src/",
)

RUST_LEGACY_ESCAPES = {
    "$SP$": "@",
    "$BP$": "*",
    "$RF$": "&",
    "$LT$": "<",
    "$GT$": ">",
    "$LP$": "(",
    "$RP$": ")",
    "$C$": ",",
}

RUST_STD_ROOTS = {
    "alloc", "core", "std", "test", "proc_macro", "compiler_builtins",
    "panic_abort", "panic_unwind", "unwind", "rustc_demangle",
}

RUST_RUNTIME_MARKERS = (
    "rust_begin_unwind",
    "lang_start_internal",
    "rust_eh_personality",
    "panic_fmt",
    "drop_in_place",
    "__rust_alloc",
    "__rust_dealloc",
    "__rust_realloc",
    "__rust_alloc_zeroed",
)

IDA_PREFIXES = ("sub_", "loc_", "j_", "nullsub_", "byte_", "word_", "dword_", "qword_", "off_", "unk_")


def _symbol_candidate(name: str) -> str:
    value = str(name or "")
    for prefix in ("j_", "__imp_", "__imp__", "_imp__"):
        if value.startswith(prefix):
            value = value[len(prefix):]
    idx = value.find("_ZN")
    if idx > 0:
        return value[idx:]
    idx = value.find("__ZN")
    if idx >= 0:
        return value[idx + 1:]
    idx = value.find("_R")
    if idx > 0:
        return value[idx:]
    return value


def _unescape_legacy_part(part: str) -> str:
    value = str(part or "")
    for escaped, literal in RUST_LEGACY_ESCAPES.items():
        value = value.replace(escaped, literal)

    def _decode_unicode(match):
        try:
            return chr(int(match.group(1), 16))
        except Exception:
            return match.group(0)

    value = re.sub(r"\$u([0-9A-Fa-f]{2,6})\$", _decode_unicode, value)
    return value


def _legacy_demangle(symbol: str) -> str:
    value = _symbol_candidate(symbol)
    if value.startswith("__ZN"):
        value = value[1:]
    if value.startswith("_ZN"):
        cursor = 3
    elif value.startswith("ZN"):
        cursor = 2
    else:
        return ""

    parts = []
    while cursor < len(value):
        if value[cursor] == "E":
            break
        match = re.match(r"\d+", value[cursor:])
        if not match:
            break
        size_text = match.group(0)
        cursor += len(size_text)
        size = int(size_text)
        part = value[cursor: cursor + size]
        if len(part) != size:
            break
        cursor += size
        if re.fullmatch(r"h[0-9A-Fa-f]{16}", part):
            break
        parts.append(_unescape_legacy_part(part))
    return "::".join(parts)


def _resolve_rustfilt() -> str:
    for name in ("rustfilt", "rustfilt.exe"):
        path = shutil.which(name)
        if path:
            return path
    return ""


def _rustfilt_demangle(symbol: str) -> str:
    rustfilt = _resolve_rustfilt()
    if not rustfilt:
        return ""
    try:
        completed = subprocess.run(
            [rustfilt, _symbol_candidate(symbol)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0,
        )
    except Exception:
        return ""
    if completed.returncode != 0:
        return ""
    demangled = (completed.stdout or b"").decode("utf-8", "replace").strip()
    if not demangled or demangled == symbol:
        return ""
    return demangled


def looks_like_rust_mangled(name: str) -> bool:
    cand = _symbol_candidate(name)
    if cand.startswith("_R") or re.match(r"^R[INvMC][A-Za-z0-9_]", cand):
        return True
    return bool(re.search(r"_?ZN\d+", cand) and re.search(r"17h[0-9A-Fa-f]{16}E?$", cand))


def demangle_rust_symbol(symbol: str) -> str:
    return _legacy_demangle(symbol) or _rustfilt_demangle(symbol)


def ida_safe_rust_name(demangled: str, ea: int) -> str:
    value = re.sub(r"\{\{closure\}\}", "closure", demangled)
    value = value.replace("::", "__")
    value = re.sub(r"[^A-Za-z0-9_$@?]+", "_", value)
    value = value.strip("_")
    if not value:
        value = "rust_func"
    if not re.match(r"^[A-Za-z_?$@]", value):
        value = "rust_" + value
    if len(value) > 220:
        value = value[:220].rstrip("_") + "_%X" % int(ea)
    return value


def classify_rust_symbol(name: str) -> Optional[Dict[str, str]]:
    """Determine if a function belongs to User Code, ThirdParty Crate, or Stdlib/Runtime."""
    cand = _symbol_candidate(name)
    demangled = demangle_rust_symbol(cand) if looks_like_rust_mangled(cand) else ""
    readable = demangled or cand
    if not readable or readable.startswith(IDA_PREFIXES):
        return None

    clean = readable.replace("__", "::")
    lower = clean.lower()

    if any(marker in lower for marker in RUST_RUNTIME_MARKERS):
        return {"category": "Runtime", "root": "runtime", "readable": clean}

    root = clean.split("::", 1)[0].strip("<>&* ")
    if root in RUST_STD_ROOTS:
        return {"category": "Stdlib", "root": root, "readable": clean}

    if looks_like_rust_mangled(name) or "::" in clean:
        return {"category": "User", "root": root, "readable": clean}

    return None


def is_rust_noise_function(name: str) -> bool:
    """Return True if the function is identifiable as Rust stdlib/runtime boilerplate."""
    info = classify_rust_symbol(name)
    if not info:
        return False
    return info["category"] in ("Stdlib", "Runtime")


def extract_crates_from_strings(strings: List[str]) -> List[Dict[str, Any]]:
    """Extract used Cargo crates and versions from file paths found in binary strings."""
    crate_re = re.compile(r"[\\/]\.cargo[\\/]registry[\\/]src[\\/][^\\/]+[\\/]([A-Za-z0-9_.-]+)-(\d+\.\d+(?:\.\d+)?(?:[a-zA-Z0-9_.-]*)?)")
    counts: Counter = Counter()
    for s in strings:
        if any(marker.lower() in s.lower() for marker in LOCATION_PATH_MARKERS):
            match = crate_re.search(s)
            if match:
                crate_name, version = match.group(1), match.group(2)
                counts[(crate_name, version)] += 1

    crates = []
    for (crate_name, version), count in counts.most_common():
        crates.append({
            "crate": crate_name,
            "version": version,
            "references": count,
        })
    return crates


def detect_rust_confidence(strings: List[str], function_names: List[str]) -> Dict[str, Any]:
    """Score binary confidence that it was compiled with rustc."""
    plain_hits = [s for s in strings if s in PLAIN_RUST_STRINGS]
    minsize_hits = [s for s in strings if s in MINSIZE_RUST_STRINGS]
    path_hits = [s for s in strings if any(m.lower() in s.lower() for m in LOCATION_PATH_MARKERS)]
    mangled_names = [n for n in function_names if looks_like_rust_mangled(n)]

    score = 0
    score += 45 if len(plain_hits) >= 3 else 18 * len(plain_hits)
    score += 40 if len(minsize_hits) >= 3 else 10 * len(minsize_hits)
    score += min(len(mangled_names), 10) * 4
    score += min(len(path_hits), 8) * 2
    score = min(score, 100)

    confidence = "High" if score >= 70 else "Medium" if score >= 40 else "Low" if score > 0 else "None"
    return {
        "is_rust": score >= 35 or len(mangled_names) >= 2,
        "score": score,
        "confidence": confidence,
        "mangled_count": len(mangled_names),
        "path_count": len(path_hits),
    }
