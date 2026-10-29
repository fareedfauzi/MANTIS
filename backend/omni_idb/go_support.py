"""Go (Golang) binary support for Binary Lab.

Provides pure-Python detection, package classification, Go runtime/stdlib
noise pruning, and optional GoReSym symbol restoration for Go binaries in IDA.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

GO_STD_ROOTS = {
    "archive", "bufio", "builtin", "bytes", "cmp", "compress", "container",
    "context", "crypto", "database", "debug", "embed", "encoding", "errors",
    "expvar", "flag", "fmt", "go", "hash", "html", "image", "index", "io",
    "iter", "log", "maps", "math", "mime", "net", "os", "path", "plugin",
    "reflect", "regexp", "runtime", "slices", "sort", "strconv", "strings",
    "sync", "syscall", "testing", "text", "time", "unicode", "unsafe",
}

GO_RUNTIME_ROOTS = {
    "abi", "asan", "atomic", "cgo", "cpu", "gc", "godebug", "goexperiment",
    "internal", "msan", "race", "runtime", "setg", "sys", "type",
}

GO_THIRD_PARTY_ROOTS = {
    "bitbucket.org", "cloud.google.com", "github.com", "gitlab.com", "go.etcd.io",
    "go.opencensus.io", "go.opentelemetry.io", "go.uber.org", "golang.org",
    "gonum.org", "google.golang.org", "gopkg.in", "honnef.co", "k8s.io",
    "modernc.org", "rsc.io",
}

IDA_PREFIXES = ("sub_", "loc_", "j_", "nullsub_", "byte_", "word_", "dword_", "qword_", "off_", "unk_")


def _clean_symbol_name(name: str) -> str:
    value = str(name or "")
    for prefix in ("j_", "__imp_", "__imp__", "_imp__"):
        if value.startswith(prefix):
            value = value[len(prefix):]
    return value


def go_package_from_name(name: str) -> str:
    """Extract Go package name from a function symbol (e.g. 'main.init' -> 'main')."""
    clean = _clean_symbol_name(name)
    if not clean or clean.startswith(IDA_PREFIXES) or "." not in clean:
        return ""
    package, _ = clean.rsplit(".", 1)
    return package.strip("._/")


def go_package_root(package: str) -> str:
    if not package:
        return ""
    normalized = package.replace("\\", "/")
    if "/" in normalized:
        return normalized.split("/", 1)[0]
    underscored = normalized.replace(".", "_")
    for root in GO_THIRD_PARTY_ROOTS:
        prefix = root.replace(".", "_") + "_"
        if underscored.startswith(prefix):
            return root
    return normalized.split(".", 1)[0]


def is_go_third_party(package: str) -> bool:
    value = package.replace("\\", "/")
    underscored = value.replace(".", "_")
    for root in GO_THIRD_PARTY_ROOTS:
        if value == root or value.startswith(root + "/"):
            return True
        root_us = root.replace(".", "_")
        if underscored == root_us or underscored.startswith(root_us + "_"):
            return True
    return False


def classify_go_symbol(name: str) -> Optional[Dict[str, str]]:
    """Determine if a function belongs to User, ThirdParty, Stdlib, or Runtime."""
    package = go_package_from_name(name)
    if not package:
        return None
    root = go_package_root(package)
    if root in GO_RUNTIME_ROOTS or package.startswith("runtime.") or package.startswith("type.."):
        category = "Runtime"
    elif is_go_third_party(package):
        category = "ThirdParty"
    elif root in GO_STD_ROOTS:
        category = "Stdlib"
    else:
        category = "User"
    return {
        "category": category,
        "package": package,
        "root": root,
    }


def is_go_noise_function(name: str) -> bool:
    """Return True if the function is Go runtime or standard library boilerplate."""
    info = classify_go_symbol(name)
    if not info:
        return False
    return info["category"] in ("Runtime", "Stdlib")


def detect_go_confidence(strings: List[str], function_names: List[str]) -> Dict[str, Any]:
    """Score binary confidence that it was compiled with Go compiler (gc/gccgo)."""
    has_build_id = any("Go build ID:" in s for s in strings)
    has_runtime_str = any("runtime: " in s or "goroutine " in s or "fatal error: " in s for s in strings)
    go_func_count = sum(1 for n in function_names if "." in n and not n.startswith(IDA_PREFIXES) and classify_go_symbol(n))
    version_match = None
    for s in strings:
        m = re.search(r"\bgo1\.\d+(\.\d+)?\b", s)
        if m:
            version_match = m.group(0)
            break

    score = 0
    if has_build_id:
        score += 50
    if has_runtime_str:
        score += 25
    if go_func_count >= 5:
        score += min(go_func_count, 25)
    if version_match:
        score += 20
    score = min(score, 100)

    is_go = score >= 40 or has_build_id or go_func_count >= 20
    confidence = "High" if score >= 70 else "Medium" if score >= 40 else "Low" if score > 0 else "None"
    return {
        "is_go": is_go,
        "score": score,
        "confidence": confidence,
        "version": version_match or "Unknown",
        "go_functions_count": go_func_count,
    }


def extract_go_packages(function_names: List[str]) -> Dict[str, Any]:
    """Extract and categorize all Go packages present in function names."""
    packages: Dict[str, Counter] = {
        "User": Counter(),
        "ThirdParty": Counter(),
        "Stdlib": Counter(),
        "Runtime": Counter(),
    }
    for name in function_names:
        info = classify_go_symbol(name)
        if info:
            cat = info["category"]
            pkg = info["package"]
            packages[cat][pkg] += 1

    summary = {}
    for cat, counter in packages.items():
        summary[cat] = [
            {"package": pkg, "functions": count}
            for pkg, count in counter.most_common()
        ]
    return summary


def resolve_goresym(configured_path: str = "") -> str:
    """Find GoReSym executable cross-platform (configured path, app dir, tools dir, PATH)."""
    # If a configured path exists and is not inside a PyInstaller temp unpack dir (_MEI...)
    if configured_path:
        cand_p = Path(configured_path)
        if cand_p.is_file() and "_MEI" not in str(cand_p):
            return str(cand_p.resolve())

    is_win = sys.platform == "win32"
    names = ["GoReSym.exe", "goresym.exe"] if is_win else ["GoReSym", "goresym"]

    from .config import app_dir, _config_dir
    search_dirs = [
        app_dir(),
        app_dir() / "tools",
        Path.cwd(),
        Path.cwd() / "tools",
        _config_dir("OmniIDB") / "tools",
        Path.home() / ".local" / "bin",
        Path.home() / ".config" / "OmniIDB" / "tools",
        Path.home() / ".local" / "share" / "OmniIDB" / "tools",
        Path.home() / "Library" / "Application Support" / "OmniIDB" / "tools",
        Path("/usr/local/bin"),
        Path("/opt/homebrew/bin"),
        Path("/usr/bin"),
    ]
    if is_win and os.environ.get("APPDATA"):
        search_dirs.append(Path(os.environ["APPDATA"]) / "OmniIDB" / "tools")

    for d in search_dirs:
        for name in names:
            cand = d / name
            if cand.is_file():
                return str(cand.resolve())

    for name in names:
        p = shutil.which(name)
        if p:
            return p
    return ""



def download_latest_goresym(
    dest_dir: Optional[Path] = None,
    on_progress: Optional[Callable[[str], None]] = None,
) -> Tuple[bool, str]:
    """Download the latest GoReSym release from Mandiant's GitHub repo.

    Downloads the appropriate zip for Windows, Linux, or macOS, extracts the
    executable, marks it executable on Unix/Linux, and returns (success, path_or_err).
    """
    import io
    import urllib.request
    import zipfile

    def log(msg: str) -> None:
        if on_progress:
            try:
                on_progress(msg)
            except Exception:
                pass

    if dest_dir is None:
        from .config import app_dir
        dest_dir = app_dir()

    dest_dir = Path(dest_dir).resolve()
    dest_dir.mkdir(parents=True, exist_ok=True)

    is_win = sys.platform == "win32"
    is_mac = sys.platform == "darwin"
    target_asset = "GoReSym-windows.zip" if is_win else ("GoReSym-mac.zip" if is_mac else "GoReSym-linux.zip")
    bin_name = "GoReSym.exe" if is_win else "GoReSym"

    try:
        api_url = "https://api.github.com/repos/mandiant/GoReSym/releases/latest"
        log("[*] Querying GitHub API for latest release...")
        req = urllib.request.Request(api_url, headers={"User-Agent": "MANTIS-BinaryLab"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        tag = data.get("tag_name", "latest")
        log(f"[*] Latest release tag: {tag}")
        download_url = None
        for asset in data.get("assets", []):
            if asset.get("name") == target_asset:
                download_url = asset.get("browser_download_url")
                break

        if not download_url:
            return False, f"Could not find asset {target_asset} in release {tag}"

        log(f"[*] Downloading {target_asset}...")
        dl_req = urllib.request.Request(download_url, headers={"User-Agent": "MANTIS-BinaryLab"})
        with urllib.request.urlopen(dl_req, timeout=45) as dl_resp:
            chunks = []
            while True:
                chunk = dl_resp.read(65536)
                if not chunk:
                    break
                chunks.append(chunk)
            zip_bytes = b"".join(chunks)

        log(f"[*] Download complete ({len(zip_bytes) / 1024:.1f} KB). Extracting...")
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
            # Look for binary in zip
            matches = [n for n in z.namelist() if Path(n).name.lower() in (bin_name.lower(), "goresym", "goresym.exe")]
            if not matches:
                return False, f"No binary found in {target_asset}"

            extract_target = dest_dir / bin_name
            # If target exists and might be write-locked on Windows, attempt atomic replace
            temp_target = dest_dir / f"{bin_name}.tmp"
            with z.open(matches[0]) as source_file, open(temp_target, "wb") as out_file:
                shutil.copyfileobj(source_file, out_file)

            if extract_target.exists():
                try:
                    extract_target.unlink()
                except Exception:
                    pass
            shutil.move(str(temp_target), str(extract_target))

        if not is_win:
            try:
                extract_target.chmod(extract_target.stat().st_mode | 0o755)
            except Exception:
                pass

        return True, f"Successfully updated GoReSym ({tag}) -> {extract_target}"
    except Exception as exc:
        return False, f"GoReSym download failed: {exc}"




def run_goresym_restore(sample_path: str, goresym_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Execute GoReSym on target executable to extract pclntab symbols if available."""
    exe = goresym_path or resolve_goresym()
    if not exe:
        return None
    try:
        cmd = [exe, "-t", "-d", "-p", str(sample_path)]
        completed = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0,
        )
        if completed.returncode == 0 and completed.stdout:
            stdout_text = completed.stdout.decode("utf-8-sig", "replace")
            return json.loads(stdout_text)
    except Exception:
        pass
    return None

