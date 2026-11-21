"""Language identity features: Go symbols and demangled C++/Rust exports.

Both sources are optional. A missing tool, an unparseable file, or a timeout
returns an empty result and the feature is reported as not analysed. Nothing
here raises into the extractor.

  * go_symbols  - GoReSym's user function names (package.Func) plus module
                  dependencies (dep:path@version). Names do not change when a
                  binary is relocated, so these are stable across rebuilds.
  * lang_symbols - demangled exported C++ / Rust names. The Rust `h<16 hex>`
                  hash suffix is dropped because it changes per build.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from typing import List

try:
    import lief as _lief
except Exception:  # pragma: no cover
    _lief = None
try:
    import cxxfilt as _cxxfilt
except Exception:  # pragma: no cover
    _cxxfilt = None
try:
    import rust_demangler as _rust
except Exception:  # pragma: no cover
    _rust = None

GORESYM_TIMEOUT = 60
MAX_GO_NAMES = 20000
MAX_GO_RANGES = 200000   # exact function bounds from .gopclntab (stripped Go binaries)
MAX_LANG_NAMES = 20000
_RUST_HASH = re.compile(r"::h[0-9a-f]{16}$")
_GO_MAGIC = b"\xff Go buildinf:"   # present in every Go 1.13+ binary's build info block


def goresym_binary() -> str:
    """Installed GoReSym path, or '' when it is not installed."""
    from deployment_config import DATA_DIR
    name = "GoReSym.exe" if sys.platform.startswith("win") else "GoReSym"
    path = os.path.join(DATA_DIR, "tools", "goresym", name)
    return path if os.path.isfile(path) else ""


def looks_like_go(data: bytes) -> bool:
    """Cheap pre-check so non-Go files never spawn GoReSym."""
    return _GO_MAGIC in data


def go_symbols(path_or_data, data: bytes) -> dict:
    """Run GoReSym on a file. Returns {'status', 'names', 'deps', 'version'}."""
    if not looks_like_go(data):
        return {"status": "not go", "names": [], "deps": [], "version": "", "ranges": []}
    tool = goresym_binary()
    if not tool:
        return {"status": "tool missing", "names": [], "deps": [], "version": "", "ranges": []}
    try:
        proc = subprocess.run([tool, "-t", "-d", "-p", path_or_data], capture_output=True,
                              text=True, timeout=GORESYM_TIMEOUT)
        doc = json.loads(proc.stdout or "{}")
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "names": [], "deps": [], "version": "", "ranges": []}
    except (OSError, ValueError):
        return {"status": "failed", "names": [], "deps": [], "version": "", "ranges": []}
    funcs = (doc.get("UserFunctions") or []) + (doc.get("StdFunctions") or [])
    ranges = sorted({(int(f["Start"]), int(f["End"])) for f in funcs
                     if f.get("Start") and f.get("End") and int(f["End"]) > int(f["Start"])})[:MAX_GO_RANGES]
    names = sorted({f["FullName"] for f in (doc.get("UserFunctions") or []) if f.get("FullName")})[:MAX_GO_NAMES]
    build = doc.get("BuildInfo") or {}
    deps = sorted({f"dep:{d.get('Path', '')}@{d.get('Version', '')}" for d in (build.get("Deps") or [])
                   if d.get("Path")})
    if not names and not deps:
        return {"status": "no go symbols", "names": [], "deps": [], "version": doc.get("Version", ""), "ranges": []}
    return {"status": "success", "names": names, "deps": deps, "version": doc.get("Version", ""),
            "ranges": ranges}


def _go_items(result: dict) -> List[str]:
    return [f"go:{n}" for n in result.get("names", [])] + list(result.get("deps", []))


def _demangle(name: str) -> str:
    """Return a readable name, or '' when the name is not a mangled C++/Rust symbol."""
    if name.startswith("_ZN") or name.startswith("_ZTV") or name.startswith("_ZNK") or name.startswith("_Z"):
        if _rust is not None and "17h" in name:
            try:
                out = _rust.demangle(name)
                if out and out != name:
                    return _RUST_HASH.sub("", out)
            except Exception:
                pass
        if _cxxfilt is not None:
            try:
                out = _cxxfilt.demangle(name)
                if out and out != name:
                    return out
            except Exception:
                pass
    return ""


def lang_symbols(path_or_data, data: bytes) -> dict:
    """Demangled exported C++/Rust names. Returns {'status', 'names'}."""
    if _lief is None:
        return {"status": "lief missing", "names": []}
    try:
        binary = _lief.parse(path_or_data)
    except Exception:
        binary = None
    if binary is None:
        return {"status": "unparsed", "names": []}
    seen = set()
    for sym in binary.exported_functions:
        name = str(sym.name)
        out = _demangle(name)
        if out:
            seen.add(out)
        if len(seen) >= MAX_LANG_NAMES:
            break
    if not seen:
        return {"status": "no mangled names", "names": []}
    return {"status": "success", "names": sorted(seen)}


def analyse(data: bytes, file_type: str) -> dict:
    """Identity features for one sample. Writes data to a temp file when a tool needs a path."""
    out = {"go": {"status": "skipped", "names": [], "deps": [], "version": "", "ranges": []},
           "lang": {"status": "skipped", "names": []}}
    if file_type not in ("PE", "ELF", "MACHO"):
        return out
    fd, path = tempfile.mkstemp(suffix=".bin")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        out["go"] = go_symbols(path, data)
        out["lang"] = lang_symbols(path, data)
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
    return out
