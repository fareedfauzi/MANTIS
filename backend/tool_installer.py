"""In-app installer for Binary Lab reverse-engineering tools.

Pinned tools (Temurin JDK 25, .NET 8 runtime, Ghidra, GoReSym, ILSpyCmd) are
downloaded from fixed URLs and verified against fixed checksums. IDA Pro is
licensed, so the admin pastes a personal HTTPS download link; it is not pinned.

Progress is kept in memory and polled by the UI.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import tarfile
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from deployment_config import TOOLS_DIR

TOOLS_ROOT = Path(TOOLS_DIR)
CHUNK = 256 * 1024
MAX_IDA_BYTES = 4 * 1024 ** 3

# id -> spec. Checksums are the ones verified in the manual test (see commit notes).
PINNED: Dict[str, Dict[str, Any]] = {
    "jdk": {
        "label": "Java runtime (Temurin JDK 25)",
        "url": "https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.5.1%2B2/OpenJDK25U-jdk_x64_linux_hotspot_25.0.5.1_2.tar.gz",
        "size": 141362230, "algo": "sha256",
        "sha256": "760f91b22c3efc9bd1b64ff950598231be82928cc807e30691a0e7a2995a62c0",
        "kind": "tar.gz", "dest": "jdk", "needed_by": "Ghidra",
    },
    "dotnet": {
        "label": ".NET 8 runtime",
        "url": "https://builds.dotnet.microsoft.com/dotnet/Runtime/8.0.34/dotnet-runtime-8.0.34-linux-x64.tar.gz",
        "size": 31312594, "algo": "sha512",
        "sha512": "3949c533b04b0f2b8ed7f6a595409806857891de07eca5ff2795c3ffecc5c373c8977ce296ea1124cef0890f8afeb3365a3bb8514d11a91ba79adb5c47c27ddb",
        "kind": "tar.gz", "dest": "dotnet", "needed_by": "ILSpyCmd",
    },
    "ghidra": {
        "label": "Ghidra 12.2",
        "url": "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.2_build/ghidra_12.2_PUBLIC_20261016.zip",
        "size": 569712708, "algo": "sha256",
        "sha256": "2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67",
        "kind": "zip", "dest": "ghidra", "needed_by": "Binary Lab (Ghidra engine)",
    },
    "goresym": {
        "label": "GoReSym v3.4.1",
        "url": "https://github.com/mandiant/GoReSym/releases/download/v3.4.1/GoReSym-linux.zip",
        "size": 3500000, "algo": "sha256",
        "sha256": "a557124857f95a589f8ce3525119c2d18c7c7fc7c4225c92ff94e3effb38748d",
        "kind": "zip", "dest": "goresym", "needed_by": "Go binary analysis",
    },
    "ilspycmd": {
        "label": "ILSpyCmd 9.1.0.7988",
        "url": "https://api.nuget.org/v3-flatcontainer/ilspycmd/9.1.0.7988/ilspycmd.9.1.0.7988.nupkg",
        "size": 2900000, "algo": "sha256",
        "sha256": "2b5058f5ccc164c33b7aabf1a5eb0cf3d3a6af6c145aaf58efd3ed891443af7c",
        "kind": "nupkg", "dest": "ilspycmd", "needed_by": ".NET assembly decompilation",
    },
}

_lock = threading.Lock()
_state: Dict[str, Any] = {
    "running": False,
    "phase": "idle",
    "current": None,
    "tools": {},       # id -> {status, downloaded, total, error}
    "ida": {"status": "idle", "downloaded": 0, "total": 0, "error": "", "sha256": ""},
    "finished_at": None,
}


# ---------- runtime environment ----------

def _runtime_dirs() -> Dict[str, Path]:
    return {"java": TOOLS_ROOT / "jdk", "dotnet": TOOLS_ROOT / "dotnet"}


def apply_runtime_env() -> None:
    """Expose installed JDK / .NET runtimes to this server process and its children."""
    dirs = _runtime_dirs()
    java = dirs["java"]
    if (java / "bin" / "java").is_file():
        os.environ["JAVA_HOME"] = str(java)
    dotnet = dirs["dotnet"]
    if (dotnet / "dotnet").is_file():
        os.environ["DOTNET_ROOT"] = str(dotnet)
    extra = [str(p) for p in (java / "bin", dotnet) if p.is_dir()]
    if extra:
        current = os.environ.get("PATH", "")
        os.environ["PATH"] = os.pathsep.join(extra + [current])


# ---------- status ----------

def _installed(tool_id: str) -> bool:
    if tool_id == "jdk":
        return (TOOLS_ROOT / "jdk" / "bin" / "java").is_file()
    if tool_id == "dotnet":
        return (TOOLS_ROOT / "dotnet" / "dotnet").is_file()
    if tool_id == "ghidra":
        return (TOOLS_ROOT / "ghidra" / "support" / "analyzeHeadless").is_file()
    if tool_id == "goresym":
        return any((TOOLS_ROOT / "goresym").glob("GoReSym*")) if (TOOLS_ROOT / "goresym").is_dir() else False
    if tool_id == "ilspycmd":
        return (TOOLS_ROOT / "ilspycmd" / "ilspycmd.dll").is_file()
    if tool_id == "ida":
        d = TOOLS_ROOT / "ida"
        return d.is_dir() and (any(d.glob("idat*")) or any(d.glob("ida*")))
    return False


def status() -> Dict[str, Any]:
    with _lock:
        snap = {
            "running": _state["running"],
            "phase": _state["phase"],
            "current": _state["current"],
            "tools": {k: dict(v) for k, v in _state["tools"].items()},
            "ida": dict(_state["ida"]),
            "finished_at": _state["finished_at"],
        }
    items: List[Dict[str, Any]] = []
    for tid, spec in PINNED.items():
        progress = snap["tools"].get(tid, {})
        items.append({
            "id": tid, "label": spec["label"], "size": spec["size"], "needed_by": spec["needed_by"],
            "installed": _installed(tid), "source": "pinned",
            "status": progress.get("status", "idle"),
            "downloaded": progress.get("downloaded", 0), "total": progress.get("total", spec["size"]),
            "error": progress.get("error", ""),
        })
    ida = snap["ida"]
    items.append({
        "id": "ida", "label": "IDA Pro (licensed, your own copy)", "size": 0,
        "needed_by": "IDA headless disassembly", "installed": _installed("ida"), "source": "user_link",
        "status": ida.get("status", "idle"), "downloaded": ida.get("downloaded", 0),
        "total": ida.get("total", 0), "error": ida.get("error", ""), "sha256": ida.get("sha256", ""),
    })
    return {"running": snap["running"], "phase": snap["phase"], "current": snap["current"],
            "finished_at": snap["finished_at"], "tools": items,
            "disk_free": shutil.disk_usage(TOOLS_ROOT.parent if TOOLS_ROOT.parent.exists() else "/").free}


# ---------- validation ----------

def validate_ida_url(url: str) -> str:
    url = (url or "").strip()
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("IDA link must be an https:// download URL.")
    if parsed.hostname in ("localhost",) or (parsed.hostname or "").startswith(("127.", "10.", "192.168.", "169.254.")):
        raise ValueError("IDA link must point to a public download host.")
    return url


def _required_bytes(ids: List[str]) -> int:
    total = 0
    for tid in ids:
        if tid in PINNED and not _installed(tid):
            total += PINNED[tid]["size"] * 2  # archive + extracted copy
    return total


# ---------- download + extract ----------

def _download(url: str, dest: Path, progress_key: str, expected_total: int, cap: Optional[int] = None) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "MANTIS-tool-installer"})
    digest = hashlib.sha256()
    with urllib.request.urlopen(req, timeout=60) as resp, open(dest, "wb") as fh:
        length = int(resp.headers.get("Content-Length") or 0)
        total = length or expected_total
        _set(progress_key, total=total)
        done = 0
        while True:
            chunk = resp.read(CHUNK)
            if not chunk:
                break
            done += len(chunk)
            if cap and done > cap:
                raise ValueError("Download exceeded the size limit.")
            fh.write(chunk)
            digest.update(chunk)
            _set(progress_key, downloaded=done)
    return digest.hexdigest()


def _verify(spec: Dict[str, Any], path: Path, computed_sha256: str) -> None:
    if spec["algo"] == "sha256":
        if computed_sha256 != spec["sha256"]:
            raise ValueError("Checksum mismatch (sha256); download discarded.")
    else:
        h = hashlib.sha512()
        with open(path, "rb") as fh:
            for block in iter(lambda: fh.read(CHUNK), b""):
                h.update(block)
        if h.hexdigest() != spec["sha512"]:
            raise ValueError("Checksum mismatch (sha512); download discarded.")


def _extract_into(kind: str, archive: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    if kind == "tar.gz":
        with tarfile.open(archive, "r:gz") as tf:
            tf.extractall(dest, filter="data")
        # strip a single top-level folder (jdk-25.../, dotnet-*/ are flat already)
        children = [p for p in dest.iterdir()]
        if len(children) == 1 and children[0].is_dir() and children[0].name.lower().startswith(("jdk", "openjdk")):
            inner = children[0]
            for item in inner.iterdir():
                shutil.move(str(item), str(dest / item.name))
            inner.rmdir()
    elif kind == "zip":
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(dest)
        children = [p for p in dest.iterdir()]
        if len(children) == 1 and children[0].is_dir():
            inner = children[0]
            for item in inner.iterdir():
                shutil.move(str(item), str(dest / item.name))
            inner.rmdir()
    elif kind == "nupkg":
        with zipfile.ZipFile(archive) as zf:
            for name in zf.namelist():
                if name.startswith("tools/net8.0/any/") and not name.endswith("/"):
                    target = dest / name[len("tools/net8.0/any/"):]
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(name) as src, open(target, "wb") as out:
                        shutil.copyfileobj(src, out)
    else:
        raise ValueError(f"Unknown archive kind {kind}")


def _make_executable(dest: Path) -> None:
    for candidate in [dest / "support" / "analyzeHeadless", dest / "ghidraRun", dest / "bin" / "java",
                      dest / "dotnet"]:
        if candidate.is_file():
            candidate.chmod(candidate.stat().st_mode | 0o111)
    for f in dest.glob("GoReSym*"):
        f.chmod(f.stat().st_mode | 0o111)


def _install_pinned(tid: str) -> None:
    spec = PINNED[tid]
    TOOLS_ROOT.mkdir(parents=True, exist_ok=True)
    dest_dir = TOOLS_ROOT / spec["dest"]
    with tempfile.NamedTemporaryFile(dir=TOOLS_ROOT, prefix=f".{tid}-", suffix=".part", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        _set_tool(tid, status="downloading", downloaded=0, total=spec["size"], error="")
        sha = _download(spec["url"], tmp_path, tid, spec["size"], cap=spec["size"] * 2)
        _set_tool(tid, status="verifying")
        _verify(spec, tmp_path, sha)
        _set_tool(tid, status="extracting")
        staging = TOOLS_ROOT / f".{tid}-staging"
        if staging.exists():
            shutil.rmtree(staging)
        _extract_into(spec["kind"], tmp_path, staging)
        if dest_dir.exists():
            shutil.rmtree(dest_dir)
        staging.rename(dest_dir)
        _make_executable(dest_dir)
        _set_tool(tid, status="done")
    finally:
        tmp_path.unlink(missing_ok=True)


def _install_ida(url: str) -> None:
    dest_dir = TOOLS_ROOT / "ida"
    with tempfile.NamedTemporaryFile(dir=TOOLS_ROOT, prefix=".ida-", suffix=".part", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        _set_ida(status="downloading", downloaded=0, total=0, error="", sha256="")
        sha = _download(url, tmp_path, "ida", 0, cap=MAX_IDA_BYTES)
        _set_ida(status="extracting", sha256=sha)
        if not zipfile.is_zipfile(tmp_path):
            raise ValueError("The IDA link did not return a zip archive.")
        staging = TOOLS_ROOT / ".ida-staging"
        if staging.exists():
            shutil.rmtree(staging)
        _extract_into("zip", tmp_path, staging)
        if dest_dir.exists():
            shutil.rmtree(dest_dir)
        staging.rename(dest_dir)
        for f in dest_dir.glob("idat*"):
            f.chmod(f.stat().st_mode | 0o111)
        _set_ida(status="done")
    finally:
        tmp_path.unlink(missing_ok=True)


def start_ida_upload(src_path: Path, original_name: str) -> Dict[str, Any]:
    """Install IDA from a zip the admin uploaded (already saved to src_path)."""
    with _lock:
        if _state["running"]:
            src_path.unlink(missing_ok=True)
            raise RuntimeError("An install is already running.")
        _state.update({"running": True, "phase": "installing", "current": "ida", "finished_at": None,
                       "ida": {"status": "extracting", "downloaded": 0, "total": 0, "error": "",
                               "sha256": "", "source": original_name}})
    threading.Thread(target=_run_ida_upload, args=(src_path,), daemon=True).start()
    return status()


def _run_ida_upload(src_path: Path) -> None:
    try:
        if not zipfile.is_zipfile(src_path):
            raise ValueError("The uploaded file is not a zip archive.")
        digest = hashlib.sha256()
        with open(src_path, "rb") as fh:
            for block in iter(lambda: fh.read(CHUNK), b""):
                digest.update(block)
        _set_ida(sha256=digest.hexdigest())
        dest_dir = TOOLS_ROOT / "ida"
        staging = TOOLS_ROOT / ".ida-staging"
        if staging.exists():
            shutil.rmtree(staging)
        _extract_into("zip", src_path, staging)
        if dest_dir.exists():
            shutil.rmtree(dest_dir)
        staging.rename(dest_dir)
        for f in dest_dir.glob("idat*"):
            f.chmod(f.stat().st_mode | 0o111)
        _set_ida(status="done")
        _set_state(phase="done")
    except Exception as exc:
        _set_ida(status="error", error=str(exc))
        _set_state(phase="error")
    finally:
        src_path.unlink(missing_ok=True)
        with _lock:
            _state["running"] = False
            _state["current"] = None
            _state["finished_at"] = time.time()


def upload_destination() -> Path:
    TOOLS_ROOT.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=TOOLS_ROOT, prefix=".ida-upload-", suffix=".zip")
    os.close(fd)
    return Path(name)


def _run_job(pinned_ids: List[str], ida_url: Optional[str]) -> None:
    try:
        for tid in pinned_ids:
            _set_state(current=tid, phase="installing")
            if _installed(tid):
                _set_tool(tid, status="done")
                continue
            _install_pinned(tid)
        if ida_url:
            _set_state(current="ida", phase="installing")
            _install_ida(ida_url)
        apply_runtime_env()
        _set_state(phase="done")
    except Exception as exc:  # surface the failure in the UI
        current = _state.get("current")
        if current == "ida":
            _set_ida(status="error", error=str(exc))
        elif current:
            _set_tool(current, status="error", error=str(exc))
        _set_state(phase="error")
    finally:
        with _lock:
            _state["running"] = False
            _state["current"] = None
            _state["finished_at"] = time.time()


def start_install(tool_ids: List[str], ida_url: Optional[str] = None) -> Dict[str, Any]:
    with _lock:
        if _state["running"]:
            raise RuntimeError("An install is already running.")
    unknown = [t for t in tool_ids if t not in PINNED]
    if unknown:
        raise ValueError(f"Unknown tool(s): {', '.join(unknown)}")
    if ida_url:
        ida_url = validate_ida_url(ida_url)
    pinned_ids = [t for t in tool_ids if t in PINNED]
    needed = _required_bytes(pinned_ids)
    free = shutil.disk_usage(TOOLS_ROOT.parent).free
    if needed and free < needed:
        raise ValueError(f"Not enough free disk space: need about {needed // 2**20} MB, have {free // 2**20} MB.")
    with _lock:
        _state.update({"running": True, "phase": "starting", "current": None, "finished_at": None,
                       "tools": {t: {"status": "queued", "downloaded": 0, "total": PINNED[t]["size"], "error": ""}
                                 for t in pinned_ids},
                       "ida": {"status": "queued" if ida_url else "idle", "downloaded": 0, "total": 0,
                               "error": "", "sha256": ""}})
    threading.Thread(target=_run_job, args=(pinned_ids, ida_url), daemon=True).start()
    return status()


# ---------- shared state helpers ----------

def _set(key: str, **fields: Any) -> None:
    with _lock:
        if key == "ida":
            _state["ida"].update(fields)
        else:
            _state["tools"].setdefault(key, {}).update(fields)


def _set_tool(tid: str, **fields: Any) -> None:
    with _lock:
        _state["tools"].setdefault(tid, {"status": "idle", "downloaded": 0, "total": 0, "error": ""}).update(fields)


def _set_ida(**fields: Any) -> None:
    with _lock:
        _state["ida"].update(fields)


def _set_state(**fields: Any) -> None:
    with _lock:
        _state.update(fields)


apply_runtime_env()
