"""Batch execution: drives headless IDA, streams its output and auth/test helpers."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .config import AppSettings, auth_script, cache_path, find_genesect_package_root, project_root, runner_script
from .discovery import Sample, SampleKind
from . import reporting

EVENT_PREFIX = "OMNI_EVENT "
LEGACY_EVENT_PREFIX = "GENESECT_EVENT "


@dataclass
class OmniEvent:
    sample_index: int
    kind: str
    level: Optional[str]
    stage: Optional[str]
    current: Optional[int]
    total: Optional[int]
    message: str
    raw: str


# Legacy alias
GenesectEvent = OmniEvent


@dataclass
class RunnerEvent:
    """Message posted to the UI queue. ``kind`` selects which fields are populated."""

    kind: str
    data: dict[str, Any] = field(default_factory=dict)

    def __getattr__(self, name: str) -> Any:  # convenient access to payload fields
        try:
            return self.__dict__["data"][name]
        except KeyError as error:
            raise AttributeError(name) from error


@dataclass
class RunRequest:
    settings: AppSettings
    api_key: str
    samples: list[Sample]
    fallback_api_key: str = ""
    is_resume: bool = False


def _post(q: "queue.Queue[RunnerEvent]", kind: str, **data: Any) -> None:
    q.put(RunnerEvent(kind, data))


def start(request: RunRequest, q: "queue.Queue[RunnerEvent]") -> threading.Event:
    cancelled = threading.Event()
    threading.Thread(target=_run_all, args=(request, q, cancelled), daemon=True).start()
    return cancelled


def _run_all(request: RunRequest, q, cancelled: threading.Event) -> None:
    total = len(request.samples)
    _post(q, "batch_started", total=total)
    succeeded = failed = 0
    settings = request.settings
    initial_budget = int(getattr(settings, "token_budget", 0) or 0)
    remaining_budget = initial_budget if initial_budget > 0 else None
    batch_tokens = 0
    batch_cost = 0.0

    for index, sample in enumerate(request.samples):
        if cancelled.is_set():
            break
        _post(q, "sample_started", index=index, path=sample.path)
        if sample.kind == SampleKind.DOTNET_ASSEMBLY:
            init_msg = f"Processing {sample.path.name}"
        elif sample.kind == SampleKind.GHIDRA_PROJECT or getattr(settings, "disassembler", "ida") == "ghidra":
            init_msg = f"Opening {sample.path.name} in Ghidra"
        else:
            init_msg = f"Opening {sample.path.name} in IDA"
        _post(q, "progress", current=index, total=total, message=init_msg)
        previous_output = None
        try:
            previous_output = _preserve_previous_output(sample, request)
            message, sample_result = _run_one(index, sample, request, q, cancelled, remaining_budget=remaining_budget)
            _commit_output_transaction(previous_output)
            if sample_result and isinstance(sample_result, dict):
                usage = sample_result.get("usage")
                if usage:
                    billable = usage.get("billable_tokens", 0)
                    batch_tokens += usage.get("total_tokens", 0)
                    batch_cost += usage.get("estimated_cost_usd", 0.0)
                    if remaining_budget is not None:
                        remaining_budget = max(0, remaining_budget - billable)
                        if remaining_budget == 0:
                            _post(q, "log", message="Batch token budget has been fully consumed.")
        except InterruptedError as stop_err:
            # Keep a new stopped run only when it actually contains a resumable
            # database. A forced/early stop must restore the last good output.
            if _has_resumable_output(sample, request):
                _commit_output_transaction(previous_output)
            else:
                _restore_previous_output(sample, request, previous_output)
            message = str(stop_err)
            _post(q, "sample_finished", index=index, ok=False, stopped=True, message=message)
            _post(q, "log", message=f"⏹ {message}")
            break
        except Exception as error:  # noqa: BLE001 - every failure is reported per sample
            failed_attempt = _restore_previous_output(sample, request, previous_output)
            failed += 1
            err_lines = str(error).strip().splitlines()
            err_summary = err_lines[0] if err_lines else "Unknown execution error"
            err_diag = "\n".join(err_lines[1:]) if len(err_lines) > 1 else f"Path: {sample.path}"
            _post(
                q,
                "error_event",
                time=time.strftime("%H:%M:%S"),
                severity="Error",
                stage=getattr(sample, "stage", None) if getattr(sample, "stage", "-") != "-" else "Execution",
                sample=sample.path.name,
                message=err_summary,
                details=err_diag,
                index=index,
            )
            message = f"{sample.path.name}: {error}"
            _post(q, "log", message=message)
            if failed_attempt:
                _post(q, "log", message=f"Failed attempt preserved for diagnostics: {failed_attempt}")
            _post(q, "sample_finished", index=index, ok=False, stopped=False, message=message)
        else:
            succeeded += 1
            _post(q, "sample_finished", index=index, ok=True, stopped=False, message=message, result=sample_result)
    was_cancelled = cancelled.is_set()
    if batch_tokens > 0:
        cost_str = f" (~${batch_cost:.3f})" if batch_cost > 0 else ""
        _post(q, "log", message=f"Batch AI totals: {batch_tokens:,} tokens{cost_str}")
    _post(
        q,
        "progress",
        current=succeeded + failed,
        total=total,
        message="Stopped" if was_cancelled else "Complete",
    )
    _post(q, "batch_finished", succeeded=succeeded, failed=failed, cancelled=was_cancelled, stopped=was_cancelled, can_resume=was_cancelled)


def _transaction_output_path(sample: Sample, request: RunRequest) -> Path:
    return Path(request.settings.output_root.strip()) / sample_output_folder(sample.path)


def _preserve_previous_output(sample: Sample, request: RunRequest) -> Optional[Path]:
    """Move a previous fresh-run output aside until its replacement validates."""
    if getattr(request, "is_resume", False):
        return None
    output = _transaction_output_path(sample, request)
    if not output.exists():
        return None
    backup = output.with_name(f".{output.name}.previous-{time.time_ns()}")
    output.replace(backup)
    return backup


def _commit_output_transaction(previous_output: Optional[Path]) -> None:
    if previous_output and previous_output.exists():
        shutil.rmtree(previous_output)


def _restore_previous_output(sample: Sample, request: RunRequest, previous_output: Optional[Path]) -> Optional[Path]:
    """Restore the pre-run directory and retain the failed attempt beside it."""
    if not previous_output or not previous_output.exists():
        return None
    output = _transaction_output_path(sample, request)
    failed_output = None
    if output.exists():
        failed_output = output.with_name(
            f"{output.name}.failed-{time.strftime('%Y%m%d-%H%M%S')}-{time.time_ns()}"
        )
        output.replace(failed_output)
    previous_output.replace(output)
    return failed_output


def _has_resumable_output(sample: Sample, request: RunRequest) -> bool:
    output = _transaction_output_path(sample, request)
    idb_dir = output / "IDB Files"
    return (idb_dir / "analyzed.i64").is_file() or (idb_dir / "analyzed.idb").is_file()


def sanitize(value: str) -> str:
    clean = "".join(ch if (ch.isascii() and ch.isalnum()) or ch in "-_" else "_" for ch in value)[:80]
    return clean or "sample"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ida_script_argument(script: Path | str, job: Path | str) -> str:
    # In IDA Pro, -S runs the IDAPython script. Job payload is safely communicated
    # via OMNI_IDB_JOB_FILE in the process environment to prevent argument splitting.
    # On Windows cmdline, embedded quotes are needed; on Unix, quotes must NOT be in argv.
    if sys.platform == "win32":
        return f'-S"{script}"'
    return f"-S{script}"


def remove_previous_run_files(paths) -> None:
    for artifact in paths:
        try:
            Path(artifact).unlink()
        except FileNotFoundError:
            pass
        except OSError as error:
            raise OSError(f"Could not replace previous output {artifact}: {error}") from error


def clean_stray_idb_fragments(directory: Path | str) -> None:
    """Clean up any abandoned unpacked IDA temporary database fragments (.id0, .id1, .id2, .nam, .til)."""
    dir_path = Path(directory)
    if not dir_path.is_dir():
        return
    for pattern in ("*.id0", "*.id1", "*.id2", "*.nam", "*.til", "*.idb~", "*.i64~"):
        for stray in dir_path.glob(pattern):
            try:
                stray.unlink()
            except OSError:
                pass


def _tail(text: str, maximum: int) -> str:
    return text if len(text) <= maximum else text[-maximum:]


def _spawn_ida(ida: Path, args: list[str], script_arg: str, sample_path: Path, env) -> subprocess.Popen:
    kwargs: dict[str, Any] = dict(
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True, encoding="utf-8", errors="replace"
    )
    if sys.platform == "win32":
        # Pass the command line verbatim: IDA parses -S"script" "job" itself and
        # list2cmdline would backslash-escape the embedded quotes.
        cmdline = " ".join([subprocess.list2cmdline([str(ida), *args]), script_arg, subprocess.list2cmdline([str(sample_path)])])
        return subprocess.Popen(cmdline, **kwargs)

    # On POSIX (Linux and macOS), arguments are passed as discrete elements in the argv list.
    # Embedded quotation marks must NOT be included in script_arg on POSIX, otherwise
    # IDA tries to find a script literally named '"path/to/script.py"'.
    clean_script_arg = script_arg
    if clean_script_arg.startswith('-S"') and clean_script_arg.endswith('"'):
        clean_script_arg = "-S" + clean_script_arg[3:-1]
    return subprocess.Popen([str(ida), *args, clean_script_arg, str(sample_path)], **kwargs)


def _tail_file(path: Path, stop: threading.Event, q, index: Optional[int] = None, seen_events: Optional[set] = None) -> None:
    handle = None
    pending = ""

    def drain(final: bool) -> None:
        nonlocal pending
        while True:
            chunk = handle.readline()
            if not chunk:
                break
            pending += chunk
            if pending.endswith("\n") or final:
                line = pending.rstrip("\r\n")
                pending = ""
                if line:
                    _post(q, "ida_log_line", message=line)
                    if index is not None:
                        _handle_ida_line(index, line, q, seen_events=seen_events)
            else:
                break

    while not stop.is_set():
        if handle is None:
            try:
                handle = open(path, "r", encoding="utf-8", errors="replace")
            except OSError:
                handle = None
        if handle is not None:
            drain(False)
        time.sleep(0.15)
    if handle is None:
        try:
            handle = open(path, "r", encoding="utf-8", errors="replace")
        except OSError:
            return
    drain(True)
    handle.close()


def _tail_events_file(path: Path, stop: threading.Event, q, index: int, seen_events: set) -> None:
    """Zero-latency event tailer reading directly from the unbuffered events.jsonl file."""
    handle = None
    pending = ""

    def drain(final: bool) -> None:
        nonlocal pending
        while True:
            chunk = handle.readline()
            if not chunk:
                break
            pending += chunk
            if pending.endswith("\n") or final:
                line = pending.rstrip("\r\n")
                pending = ""
                if line:
                    _handle_ida_line(index, line, q, seen_events=seen_events)
            else:
                break

    while not stop.is_set():
        if handle is None:
            try:
                handle = open(path, "r", encoding="utf-8", errors="replace")
            except OSError:
                handle = None
        if handle is not None:
            drain(False)
        time.sleep(0.04)
    if handle is None:
        try:
            handle = open(path, "r", encoding="utf-8", errors="replace")
        except OSError:
            return
    drain(True)
    handle.close()


def _pipe_lines(stream, out: "queue.Queue[str]") -> None:
    def pump() -> None:
        try:
            for line in stream:
                out.put(line.rstrip("\r\n"))
        except (OSError, ValueError):
            pass

    threading.Thread(target=pump, daemon=True).start()


def _is_64bit_sample(path: Path) -> bool:
    """Fast header probe to determine if sample is 64-bit (PE, ELF, Mach-O single & universal)."""
    try:
        with open(path, "rb") as f:
            header = f.read(1024)
        if len(header) < 16:
            return True
        # PE check
        if header[:2] == b"MZ" and len(header) >= 0x40:
            pe_offset = int.from_bytes(header[0x3C:0x40], "little")
            if len(header) >= pe_offset + 6 and header[pe_offset:pe_offset+4] == b"PE\0\0":
                machine = int.from_bytes(header[pe_offset+4:pe_offset+6], "little")
                # 0x8664 = x64, 0xAA64 = ARM64, 0x0200 = IA64
                return machine in (0x8664, 0xAA64, 0x0200)
        # ELF check
        if header[:4] == b"\x7fELF":
            return header[4] == 2  # 1 = 32-bit, 2 = 64-bit
        # Mach-O single slice 64-bit: 0xfeedfacf (big), 0xcffaedfe (little)
        if header[:4] in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
            return True
        # Mach-O single slice 32-bit: 0xfeedface (big), 0xcefaedfe (little)
        if header[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe"):
            return False
        # Mach-O Fat / Universal binary:
        # 0xcafebabe (big-endian fat), 0xbebafeca (little-endian fat)
        # 0xcafebabf (big-endian fat_arch_64), 0xbfbafeca (little-endian fat_arch_64)
        if header[:4] in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"):
            endian = "big" if header[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf") else "little"
            is_fat64 = header[:4] in (b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca")
            nfat = int.from_bytes(header[4:8], endian)
            if 1 <= nfat <= 32:
                stride = 32 if is_fat64 else 20
                for i in range(nfat):
                    entry_off = 8 + i * stride
                    if len(header) < entry_off + 4:
                        break
                    cputype = int.from_bytes(header[entry_off : entry_off + 4], endian)
                    # CPU_ARCH_ABI64 = 0x01000000 (e.g. x86_64 = 0x01000007, ARM64 = 0x0100000C)
                    if (cputype & 0x01000000) != 0 or is_fat64:
                        return True
                return False
    except OSError:
        pass
    return True


def _resolve_ida_binary(configured_ida: Path, is_64: bool) -> Path:
    """Auto-select between ida and ida64 (or idat and idat64, or Windows .exe variants, or macOS .app bundles)."""
    if configured_ida.is_dir():
        names = ("idat64.exe", "ida64.exe", "idat64", "ida64") if is_64 else ("idat.exe", "ida.exe", "idat", "ida")
        for n in names:
            c = configured_ida / n
            if c.is_file():
                return c
        for n in ("idat64.exe", "ida64.exe", "idat.exe", "ida.exe", "idat64", "ida64", "idat", "ida"):
            c = configured_ida / n
            if c.is_file():
                return c
        return configured_ida

    if not configured_ida.is_file():
        return configured_ida
    folder = configured_ida.parent
    stem = configured_ida.stem.lower()
    ext = configured_ida.suffix

    target_stem = ""
    if is_64 and stem in ("ida", "idat"):
        target_stem = f"{stem}64"
    elif not is_64 and stem in ("ida64", "idat64"):
        target_stem = stem[:-2]

    if not target_stem:
        return configured_ida

    # 1. Direct sibling binary (e.g. ida64.exe next to ida.exe or idat64 next to idat)
    cand = folder / f"{target_stem}{ext}"
    if cand.is_file():
        return cand

    # 2. Check macOS app bundle structure:
    # e.g. configured_ida = /Applications/IDA Professional 9.0/ida64.app/Contents/MacOS/ida64
    # sibling would be    = /Applications/IDA Professional 9.0/ida.app/Contents/MacOS/ida
    if folder.name == "MacOS" and folder.parent.name == "Contents" and folder.parent.parent.suffix == ".app":
        app_dir = folder.parent.parent.parent
        target_app = app_dir / f"{target_stem}.app" / "Contents" / "MacOS" / target_stem
        if target_app.is_file():
            return target_app

    return configured_ida


def sample_output_folder(sample_path: Path) -> str:
    """Generate the standardized output folder name for a given sample."""
    digest = sha256_file(sample_path)
    return f"{sanitize(sample_path.stem)}-{digest[:12]}"


def idb_extension(is_64: bool) -> str:
    """Return Binary Lab's canonical saved-database extension.

    Binary Lab always writes the modern ``.i64`` container.  ``is_64`` remains
    part of the public helper signature because callers also use the detected
    bitness to select the appropriate IDA executable.
    """
    return ".i64"


def _run_one(index: int, sample: Sample, request: RunRequest, q, cancelled: threading.Event, remaining_budget: Optional[int] = None) -> tuple[str, dict]:
    settings = request.settings
    folder = sample_output_folder(sample.path)
    output_root = Path(settings.output_root.strip()) / folder
    idb_dir = output_root / "IDB Files"
    workspace = output_root / "AI Workspace"
    report_dir = output_root / "report"
    logs = output_root / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    digest = sha256_file(sample.path)
    is_64 = sample.path.suffix.lower() == ".i64" if sample.kind == SampleKind.IDA_DATABASE else _is_64bit_sample(sample.path)
    db_ext = ".i64"
    idb_path = idb_dir / f"analyzed{db_ext}"
    original_idb_path = idb_dir / f"original{db_ext}"
    result_path = output_root / "result.json"
    failure_path = logs / "failure.txt"
    ida_log = logs / "ida.log"
    events_log = logs / "events.jsonl"

    # .NET Assembly special handling (does not require IDA Pro)
    if sample.kind == SampleKind.DOTNET_ASSEMBLY:
        # Older versions created this native-only directory before branching.
        # Remove it only when empty so a managed run never displays a fake IDB deliverable.
        try:
            idb_dir.rmdir()
        except (FileNotFoundError, OSError):
            pass
        dotnet_mode = getattr(settings, "dotnet_mode", "skip")
        should_analyze_workspace = settings.analyze_workspace

        # If user selected In-Database Agent Analysis, IDA cannot decompile .NET CIL bytecode.
        # Automatically fallback to Decompile & AI Workspace Analysis so the user still gets a full report.
        if settings.autonomous_investigation:
            if dotnet_mode == "skip":
                dotnet_mode = "decompile"
                _post(q, "log", message=f"[*] In-Database Agent Analysis does not apply to managed .NET ({sample.path.name}). Auto-falling back to Decompile & AI Workspace Analysis.")
            should_analyze_workspace = True

        if dotnet_mode == "skip":
            _post(q, "sample_status", index=index, status="Skipped (.NET)")
            _post(q, "sample_stage", index=index, stage="Skipped")
            skip_msg = f"Skipping {sample.path.name}: .NET assembly detected (IDA Pro Hex-Rays targets native binaries)."
            _post(q, "log", message=skip_msg)
            return f"Skipped .NET assembly ({sample.path.name})", {"status": "skipped", "reason": "dotnet_assembly"}
        elif dotnet_mode == "decompile":
            _post(q, "sample_status", index=index, status="Decompiling .NET")
            _post(q, "sample_stage", index=index, stage="Exporting .NET Workspace")
            _post(q, "log", message=f"Decompiling .NET assembly & exporting AI workspace: {sample.path.name}")
            from .dotnet_export import export_dotnet_workspace
            ws_meta = export_dotnet_workspace(
                sample.path,
                output_root,
                log_fn=lambda m: _post(q, "log", message=m),
                cancel_checker=cancelled.is_set,
                ilspycmd_path=getattr(settings, "ilspycmd_path", ""),
            )
            res = {
                "sample": str(sample.path),
                "is_dotnet": True,
                "workspace_path": ws_meta.get("workspace_dir", ""),
                "types_count": ws_meta.get("types_count", 0),
                "pinvokes_count": ws_meta.get("pinvokes_count", 0),
                "strings_count": ws_meta.get("strings_count", 0),
                "cs_count": ws_meta.get("cs_count", 0),
                "cil_count": ws_meta.get("cil_count", 0),
            }
            if getattr(settings, "threat_attribution_lookup", False):
                try:
                    _post(q, "sample_stage", index=index, stage="Threat Attribution Lookup")
                    _post(q, "log", message="Performing automated threat intelligence lookup & attribution analysis...")
                    from .threat_attribution import generate_threat_attribution
                    attr_report = generate_threat_attribution(
                        workspace_dir=Path(ws_meta["workspace_dir"]),
                        report_dir=report_dir,
                        sample_info={
                            "filename": sample.path.name,
                            "sha256": digest,
                            "file_type": ".NET Assembly",
                            "architecture": "MSIL / AnyCPU",
                        },
                        log_fn=lambda m: _post(q, "log", message=m),
                    )
                    res["threat_attribution_report"] = str(attr_report)
                except Exception as exc:
                    _post(q, "log", message=f"Warning: Threat attribution lookup failed: {exc}")

            if should_analyze_workspace:
                _post(q, "sample_status", index=index, status="Analyzing .NET Workspace")
                _post(q, "sample_stage", index=index, stage="Analyzing AI Workspace")
                from .workspace_analysis import analyze_workspace

                analysis = analyze_workspace(
                    ws_meta["workspace_dir"],
                    {
                        "provider": settings.provider,
                        "api_url": settings.api_url,
                        "api_key": request.api_key,
                        "model": settings.model,
                        "executable": settings.executable,
                    },
                    {
                        "provider": settings.fallback_provider,
                        "api_url": settings.fallback_api_url,
                        "api_key": request.fallback_api_key,
                        "model": settings.fallback_model,
                        "executable": settings.fallback_executable,
                    } if settings.fallback_enabled else None,
                    genesect_root=settings.genesect_root,
                    ida_path=settings.ida_path,
                    token_budget=remaining_budget,
                    log_fn=lambda message: _post(q, "log", message=message),
                    cancel_checker=cancelled.is_set,
                    sample_info={
                        "filename": sample.path.name,
                        "sha256": digest,
                        "file_type": ".NET Assembly",
                        "architecture": "MSIL / AnyCPU",
                    },
                    report_dir=report_dir,
                )
                res["workspace_analysis_report"] = analysis["report_path"]
                res["provider"] = {
                    "primary": settings.provider,
                    "active": analysis["provider"],
                    "used": list(dict.fromkeys([settings.provider, analysis["provider"]])),
                    "fallback_events": analysis["fallback_events"],
                }
                res["usage"] = analysis["usage"]

            result_path.write_text(json.dumps(res, indent=2), encoding="utf-8")
            parts = [
                f"{res['types_count']} types",
                f"{res['pinvokes_count']} P/Invokes",
                f"{res['strings_count']} strings",
            ]
            if res["cs_count"] > 0:
                parts.append(f"{res['cs_count']} C# files")
            reports = [p.name for p in [report_dir / "report.html", report_dir / "report.pdf", report_dir / "report.md"] if p.is_file()]
            if reports:
                parts.append(f"reports: {', '.join(dict.fromkeys(reports))}")
            if res.get("workspace_analysis_report"):
                parts.append("workspace analysis: done")
            if res.get("threat_attribution_report"):
                parts.append("threat attribution: done")
            return f"Completed .NET AI Workspace ({', '.join(parts)})", res

    # Ghidra headless handling
    disasm = getattr(settings, "disassembler", "ida") or "ida"
    if disasm == "auto":
        from .config import resolve_ghidra_headless
        if getattr(settings, "ghidra_path", "") and resolve_ghidra_headless(settings.ghidra_path):
            disasm = "ghidra" if not (settings.ida_path and Path(settings.ida_path).is_file()) else "ida"
        else:
            disasm = "ida"

    if disasm == "ghidra" or sample.kind == SampleKind.GHIDRA_PROJECT:
        _post(q, "sample_status", index=index, status="Analyzing in Ghidra")
        _post(q, "sample_stage", index=index, stage="Ghidra Auto-Analysis")
        _post(q, "log", message=f"Starting Ghidra headless auto-analysis & decompilation: {sample.path.name}")
        if getattr(settings, "rename_functions", False) or getattr(settings, "rename_variables", False):
            _post(q, "log", message="[*] Note: In-database function/variable mutation applies to IDA databases (.idb/.i64). For Ghidra, function roles are mapped in the AI Workspace and Technical Report.")
        if getattr(settings, "autonomous_investigation", False):
            _post(q, "log", message="[*] Note: In-database interactive agent turns apply to IDA Pro. Ghidra uses AI Workspace Analysis to generate the full technical report.")
        from .ghidra_export import export_ghidra_workspace

        ws_meta = export_ghidra_workspace(
            sample.path,
            output_root,
            ghidra_path=getattr(settings, "ghidra_path", ""),
            log_fn=lambda m: _post(q, "log", message=m),
            cancel_checker=cancelled.is_set,
            settings=settings,
        )
        res = {
            "sample": str(sample.path),
            "disassembler": "ghidra",
            "workspace_path": ws_meta.get("workspace_dir", ""),
            "functions_count": ws_meta.get("functions_count", 0),
            "imports_count": ws_meta.get("imports_count", 0),
            "strings_count": ws_meta.get("strings_count", 0),
            "decompiled_count": ws_meta.get("decompiled_count", 0),
            "ghidra_project": ws_meta.get("ghidra_project", ""),
        }
        if getattr(settings, "threat_attribution_lookup", False):
            try:
                _post(q, "sample_stage", index=index, stage="Threat Attribution Lookup")
                _post(q, "log", message="Performing automated threat intelligence lookup & attribution analysis...")
                from .threat_attribution import generate_threat_attribution
                attr_report = generate_threat_attribution(
                    workspace_dir=Path(ws_meta["workspace_dir"]),
                    report_dir=report_dir,
                    sample_info={
                        "filename": sample.path.name,
                        "sha256": digest,
                        "file_type": f"Native Binary ({sample.path.suffix.upper() or 'Binary'})",
                        "architecture": ws_meta.get("architecture", "Native Binary"),
                    },
                    log_fn=lambda m: _post(q, "log", message=m),
                )
                res["threat_attribution_report"] = str(attr_report)
            except Exception as exc:
                _post(q, "log", message=f"Warning: Threat attribution lookup failed: {exc}")

        if settings.analyze_workspace:
            _post(q, "sample_status", index=index, status="Analyzing Ghidra Workspace")
            _post(q, "sample_stage", index=index, stage="Analyzing AI Workspace")
            from .workspace_analysis import analyze_workspace

            analysis = analyze_workspace(
                ws_meta["workspace_dir"],
                {
                    "provider": settings.provider,
                    "api_url": settings.api_url,
                    "api_key": request.api_key,
                    "model": settings.model,
                    "executable": settings.executable,
                },
                {
                    "provider": settings.fallback_provider,
                    "api_url": settings.fallback_api_url,
                    "api_key": request.fallback_api_key,
                    "model": settings.fallback_model,
                    "executable": settings.fallback_executable,
                }
                if settings.fallback_enabled
                else None,
                genesect_root=settings.genesect_root,
                ida_path=settings.ida_path,
                token_budget=remaining_budget,
                log_fn=lambda message: _post(q, "log", message=message),
                cancel_checker=cancelled.is_set,
                sample_info={
                    "filename": sample.path.name,
                    "sha256": digest,
                    "file_type": f"Native Binary ({sample.path.suffix.upper() or 'Binary'})",
                    "architecture": ws_meta.get("architecture", "Native Binary"),
                },
                report_dir=report_dir,
            )
            res["workspace_analysis_report"] = analysis["report_path"]
            res["provider"] = {
                "primary": settings.provider,
                "active": analysis["provider"],
                "used": list(dict.fromkeys([settings.provider, analysis["provider"]])),
                "fallback_events": analysis["fallback_events"],
            }
            res["usage"] = analysis["usage"]

        result_path = report_dir / "result.json"
        report_dir.mkdir(parents=True, exist_ok=True)
        result_path.write_text(json.dumps(res, indent=2), encoding="utf-8")
        (output_root / "result.json").write_text(json.dumps(res, indent=2), encoding="utf-8")

        parts = [
            f"{res['functions_count']} functions",
            f"{res['imports_count']} imports",
            f"{res['strings_count']} strings",
        ]
        if res["decompiled_count"] > 0:
            parts.append(f"{res['decompiled_count']} decompiled C files")
        reports = [p.name for p in [report_dir / "report.html", report_dir / "report.pdf", report_dir / "report.md"] if p.is_file()]
        if reports:
            parts.append(f"reports: {', '.join(dict.fromkeys(reports))}")
        if res.get("workspace_analysis_report"):
            parts.append("workspace analysis: done")
        if res.get("threat_attribution_report"):
            parts.append("threat attribution: done")
        return f"Completed Ghidra AI Workspace ({', '.join(parts)})", res

    idb_dir.mkdir(parents=True, exist_ok=True)
    ida = _resolve_ida_binary(Path(settings.ida_path.strip().strip("\"'")), is_64)
    if not ida.is_file():
        raise FileNotFoundError(f"IDA executable not found: {ida}")
    genesect_root = Path(settings.genesect_root.strip())
    script = runner_script(genesect_root)
    if not script.is_file():
        raise FileNotFoundError(f"Binary Lab batch script not found: {script}")

    is_resume = getattr(request, "is_resume", False)
    idb_ext = idb_extension(is_64)
    idb_path = idb_dir / f"analyzed{idb_ext}"
    # Read legacy .idb output when resuming, but never create a new one.
    legacy_idb_path = idb_dir / "analyzed.idb"
    original_idb_path = idb_dir / f"original{idb_ext}"
    result_path = report_dir / "result.json"
    stop_file = report_dir / "stop_requested.token"

    if stop_file.is_file():
        try:
            stop_file.unlink()
        except OSError:
            pass

    existing_idb = None
    if is_resume:
        if idb_path.is_file():
            existing_idb = idb_path
        elif legacy_idb_path.is_file():
            existing_idb = legacy_idb_path

    # If resuming and this sample was already completed, skip it
    if is_resume and result_path.is_file():
        try:
            prev_res = json.loads(result_path.read_text(encoding="utf-8"))
            if prev_res.get("status") not in ("stopped", "failed") and prev_res.get("completed_at"):
                _post(q, "sample_status", index=index, status="Already Complete")
                _post(q, "log", message=f"Sample {sample.path.name} was already completed in this output directory; skipping.")
                return f"Already Complete ({sample.path.name})", prev_res
        except Exception:
            pass

    # Clean up any leftover unpacked database temporary fragments (.id0, .id1, .id2, .nam, .til)
    # in idb_dir so that IDA does not pause and abort on overwrite prompts when opening .i64/.idb.
    clean_stray_idb_fragments(idb_dir)

    if is_resume and existing_idb and existing_idb.is_file():
        remove_previous_run_files([failure_path, events_log, stop_file])
        target_input = existing_idb
        args = ["-A", f"-L{ida_log}"]
        _post(q, "log", message=f"Resuming analysis from saved database: {existing_idb.name}")
    else:
        remove_previous_run_files([
            idb_path, original_idb_path, idb_dir / "analyzed.i64", idb_dir / "analyzed.idb",
            idb_dir / "original.i64", idb_dir / "original.idb", result_path, failure_path, ida_log, events_log, stop_file
        ])
        target_input = sample.path
        args = ["-A", f"-L{ida_log}", f"-o{idb_path}"]

    job = {
        "omni_root": str(project_root().resolve()),
        "sample_path": str(sample.path.resolve()),
        "sample_sha256": digest,
        "target_path": str(target_input.resolve()),
        "events_path": str(events_log.resolve()),
        "is_resume": bool(is_resume and existing_idb),
        "stop_file": str(stop_file.resolve()),
        "genesect_root": str((find_genesect_package_root(genesect_root, ida.parent) or genesect_root).resolve()),
        "idb_path": str(idb_path),
        "original_idb_path": str(original_idb_path),
        "workspace_path": str(workspace),
        "report_dir": str(report_dir),
        "result_path": str(result_path),
        "failure_path": str(failure_path),
        "sample_kind": sample.kind.job_value,
        "rename_functions": settings.rename_functions,
        "rename_functions_with_address": getattr(settings, "rename_functions_with_address", False),
        "rename_variables": settings.rename_variables,
        "generate_workspace": settings.generate_workspace,
        "analyze_workspace": settings.analyze_workspace,
        "autonomous_investigation": settings.autonomous_investigation,
        "investigation_turns": settings.investigation_turns,
        "batch_size": settings.batch_size,
        "workers": getattr(settings, "workers", 3),
        "low_score_rescan": getattr(settings, "low_score_rescan", False),
        "cooldown_seconds": settings.cooldown_seconds,
        "asm_max_lines": 25,
        "use_rename_cache": getattr(settings, "use_rename_cache", True),
        "cache_path": str(cache_path().resolve()),
        "goresym_path": getattr(settings, "goresym_path", ""),
        "token_budget": remaining_budget,
        "provider": settings.provider,
        "profile": {
            "provider": settings.provider,
            "api_url": settings.api_url,
            "api_key": request.api_key,
            "model": settings.model,
            "executable": settings.executable,
        },
        "fallback_enabled": settings.fallback_enabled,
        "fallback_profile": {
            "provider": settings.fallback_provider,
            "api_url": settings.fallback_api_url,
            "api_key": request.fallback_api_key,
            "model": settings.fallback_model,
            "executable": settings.fallback_executable,
        },
    }

    fd, job_name = tempfile.mkstemp(prefix="omni-job-", suffix=".json")
    job_file = Path(job_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(job, handle, indent=2)

        env = os.environ.copy()
        for name in ("VIRTUAL_ENV", "__PYVENV_LAUNCHER__", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONEXECUTABLE", "PYTHONINSPECT"):
            env.pop(name, None)
        env["OMNI_IDB_JOB_FILE"] = str(job_file.resolve())
        env["OMNI_IDB_EVENTS_FILE"] = str(events_log.resolve())

        _post(q, "sample_status", index=index, status="Running in IDA")
        try:
            child = _spawn_ida(ida, args, ida_script_argument(script, job_file), target_input, env)
        except OSError as error:
            raise OSError(f"Could not start {ida}: {error}") from error

        lines: "queue.Queue[str]" = queue.Queue()
        _pipe_lines(child.stdout, lines)
        _pipe_lines(child.stderr, lines)
        stop_tail = threading.Event()
        seen_events: set = set()
        tail_thread = threading.Thread(target=_tail_file, args=(ida_log, stop_tail, q, index, seen_events), daemon=True)
        tail_thread.start()
        events_thread = threading.Thread(target=_tail_events_file, args=(events_log, stop_tail, q, index, seen_events), daemon=True)
        events_thread.start()

        def flush_lines() -> None:
            while True:
                try:
                    _handle_ida_line(index, lines.get_nowait(), q, seen_events=seen_events)
                except queue.Empty:
                    return

        stopped_gracefully = False
        while True:
            flush_lines()
            if cancelled.is_set():
                _post(q, "sample_status", index=index, status="Saving IDB & Stopping...")
                _post(q, "log", message="Stop requested: instructing IDA to save database and exit gracefully...", level="warning")
                try:
                    stop_file.write_text("stop", encoding="utf-8")
                except OSError:
                    pass

                # Give IDA up to 15 seconds to finish its current batch, save database, and exit cleanly
                grace_timeout = 15.0
                start_grace = time.time()
                while time.time() - start_grace < grace_timeout:
                    flush_lines()
                    code = child.poll()
                    if code is not None:
                        stopped_gracefully = True
                        break
                    time.sleep(0.15)

                stop_tail.set()
                tail_thread.join(timeout=2.0)
                events_thread.join(timeout=2.0)
                flush_lines()

                try:
                    if stop_file.is_file():
                        stop_file.unlink()
                except OSError:
                    pass

                if not stopped_gracefully:
                    _post(q, "log", message="IDA did not exit within grace timeout; terminating process.", level="warning")
                    child.kill()
                    child.wait()
                else:
                    _post(q, "log", message="Database saved. Session stopped cleanly. Click 'Resume' to continue where you left off.", level="ok")

                raise InterruptedError("Stopped by user (IDB saved)")

            code = child.poll()
            if code is not None:
                break
            time.sleep(0.12)
        stop_tail.set()
        tail_thread.join(timeout=2.0)
        events_thread.join(timeout=2.0)
        time.sleep(0.05)
        flush_lines()
    finally:
        try:
            job_file.unlink()
        except OSError:
            pass

    if code != 0:
        details = "IDA did not provide error details."
        for source in (failure_path, ida_log):
            try:
                details = source.read_text(encoding="utf-8", errors="replace")
                break
            except OSError:
                continue
        raise RuntimeError(f"IDA exited with {code}\n{_tail(details, 5000)}")
    if not idb_path.is_file():
        raise RuntimeError(f"IDA completed but did not create {idb_path}")
    if not result_path.is_file():
        raise RuntimeError(f"IDA completed but did not create {result_path}")

    render_errors: list[str] = []
    # Render publication-grade Markdown, HTML, and PDF reports if model JSON was produced.
    model_json = report_dir / "report_model.json"
    if model_json.is_file():
        try:
            _post(q, "log", message=f"Rendering report deliverables (MD, HTML, PDF) in {report_dir}")
            reporting.render_reports(model_json, report_dir, log_fn=lambda m: _post(q, "log", message=m))
        except Exception as exc:
            render_errors.append(f"Report model rendering failed: {exc}")
            _post(q, "log", message=f"Warning: Failed to render reports: {exc}")

    if getattr(settings, "threat_attribution_lookup", False):
        try:
            _post(q, "sample_stage", index=index, stage="Threat Attribution Lookup")
            _post(q, "log", message="Performing automated threat intelligence lookup & attribution analysis...")
            from .threat_attribution import generate_threat_attribution
            attr_report = generate_threat_attribution(
                workspace_dir=workspace,
                report_dir=report_dir,
                sample_info={
                    "filename": sample.path.name,
                    "sha256": digest,
                    "file_type": sample.kind.label,
                    "architecture": "x64" if is_64 else "x86",
                },
                log_fn=lambda m: _post(q, "log", message=m),
            )
            if not result_path.is_file():
                result_path.write_text("{}", encoding="utf-8")
            cur_res = json.loads(result_path.read_text(encoding="utf-8"))
            cur_res["threat_attribution_report"] = str(attr_report)
            result_path.write_text(json.dumps(cur_res, indent=2, sort_keys=True), encoding="utf-8")
        except Exception as exc:
            _post(q, "log", message=f"Warning: Threat attribution lookup failed: {exc}")

    # If workspace analysis report was produced, ensure HTML and PDF deliverables are rendered.
    ws_report_md = None
    for cand in [report_dir / "report.md", report_dir / "workspace_analysis.md", workspace / "report.md", workspace / "malware_analysis_report.md"]:
        if cand.is_file():
            ws_report_md = cand
            break
    if ws_report_md:
        try:
            report_text = ws_report_md.read_text(encoding="utf-8", errors="replace")
            is_dotnet_target = sample.kind == SampleKind.DOTNET_ASSEMBLY or (workspace / "catalog" / "types.json").is_file() or (workspace / "src").is_dir()
            attr_meta = {}
            try:
                from .workspace_analysis import ensure_report_navigation, ensure_threat_attribution_section, _extract_attribution_meta
                report_text = ensure_threat_attribution_section(report_text, workspace, report_dir=report_dir)
                report_text = ensure_report_navigation(report_text, workspace, is_dotnet=is_dotnet_target)
                attr_meta = _extract_attribution_meta(report_text, workspace, report_dir)
                ws_report_md.write_text(report_text, encoding="utf-8")
                (report_dir / "report.md").write_text(report_text, encoding="utf-8")
            except Exception:
                pass
            sample_model = {
                "sample": {
                    "filename": sample.path.name,
                    "sha256": digest,
                    "file_type": sample.kind.label,
                    "architecture": "x64" if is_64 else "x86",
                },
                "category": "Malware Analysis Report",
                "provider": {"used": [settings.provider]},
                "badges": ["Exported AI Workspace", settings.provider, "Threat Attribution"],
                "attribution_hypothesis": attr_meta.get("hypothesis", ""),
                "attribution_confidence": attr_meta.get("confidence", ""),
            }
            if not (report_dir / "report.html").is_file():
                reporting.render_markdown_deliverables(
                    report_text,
                    report_dir,
                    model=sample_model,
                    base_name="report",
                    log_fn=lambda m: _post(q, "log", message=m),
                )
            if workspace.is_dir() and workspace != report_dir and not (workspace / "report.html").is_file():
                try:
                    reporting.render_markdown_deliverables(
                        report_text,
                        workspace,
                        model=sample_model,
                        base_name="report",
                        log_fn=lambda m: _post(q, "log", message=m),
                    )
                except Exception:
                    pass
        except Exception as exc:
            render_errors.append(f"Workspace report rendering failed: {exc}")
            _post(q, "log", message=f"Warning: Failed to render workspace analysis HTML/PDF: {exc}")

    result = json.loads(result_path.read_text(encoding="utf-8"))
    if render_errors:
        result["deliverable_status"] = "partial"
        result["deliverable_errors"] = render_errors
        result_path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    renamed = _dig(result, "function_rename", "renamed") or 0
    fn_skipped = _dig(result, "function_rename", "skipped")
    fn_text = "funcs: skipped" if fn_skipped else f"{renamed} functions"
    variables = _dig(result, "variable_rename", "variables_renamed") or 0
    var_skipped = _dig(result, "variable_rename", "skipped")
    var_text = "vars: skipped" if var_skipped else f"{variables} variables"
    parts = [fn_text, var_text]
    fn_cache_hits = _dig(result, "function_rename", "cache_hits") or 0
    var_cache_hits = _dig(result, "variable_rename", "cache_hits") or 0
    total_cache_hits = fn_cache_hits + var_cache_hits
    if total_cache_hits:
        parts.append(f"cache: {total_cache_hits} hits")
    findings = _dig(result, "autonomous_investigation", "findings_count")
    if findings is not None:
        turns = _dig(result, "autonomous_investigation", "turns_executed") or 0
        parts.append(f"agent: {findings} findings/{turns} turns")

    usage = result.get("usage")
    if usage and usage.get("total_tokens"):
        tokens_desc = f"{usage.get('total_tokens', 0):,} tok"
        if usage.get("estimated_cost_usd", 0) > 0:
            tokens_desc += f" (~${usage['estimated_cost_usd']:.3f})"
        parts.append(tokens_desc)

    idb_names = [idb_path.name]
    if original_idb_path.is_file():
        idb_names.append(original_idb_path.name)
    reports = [p.name for p in [report_dir / "report.html", report_dir / "report.pdf", report_dir / "report.md"] if p.is_file()]
    if reports:
        parts.append(f"reports: {', '.join(reports)}")
    if result.get("workspace_analysis_report"):
        parts.append("workspace analysis: done")
    if result.get("threat_attribution_report"):
        parts.append("threat attribution: done")
    return f"Saved {' & '.join(idb_names)} ({', '.join(parts)})", result


def _dig(value: Any, *keys: str) -> Any:
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _as_int(value: Any) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


STAGE_NAMES = {
    "ida": "Opening in IDA",
    "scan": "Scanning Functions",
    "functions": "Renaming Functions",
    "variables": "Renaming Variables",
    "investigation": "Investigating Sample",
    "workspace": "Exporting AI Workspace",
    "workspace_analysis": "Analyzing AI Workspace",
    "report": "Generating Reports",
    "save": "Saving IDB Files",
}


def _handle_ida_line(index: int, line: str, q, seen_events: Optional[set] = None) -> None:
    trimmed = line.rstrip("\r\n")
    if not trimmed:
        return
    prefix = None
    if trimmed.startswith(EVENT_PREFIX):
        prefix = EVENT_PREFIX
    elif trimmed.startswith(LEGACY_EVENT_PREFIX):
        prefix = LEGACY_EVENT_PREFIX
    if not prefix:
        return
    payload = trimmed[len(prefix) :].strip()
    try:
        payload = json.loads(payload)
    except json.JSONDecodeError:
        return
    if isinstance(payload, dict):
        if seen_events is not None:
            seq = payload.get("_seq")
            event_key = seq if seq is not None else hash(trimmed)
            if event_key in seen_events:
                return
            seen_events.add(event_key)
        kind = payload.get("kind") if isinstance(payload.get("kind"), str) else "log"
        message = payload.get("message") if isinstance(payload.get("message"), str) else ""
        level = payload.get("level") if isinstance(payload.get("level"), str) else None
        stage = payload.get("stage") if isinstance(payload.get("stage"), str) else None
        event = OmniEvent(
            sample_index=index,
            kind=kind,
            level=level,
            stage=stage,
            current=_as_int(payload.get("current")),
            total=_as_int(payload.get("total")),
            message=message,
            raw=trimmed,
        )
        _post(q, "omni_event", event=event)
        _post(q, "genesect_event", event=event)
        if stage and stage in STAGE_NAMES:
            _post(q, "sample_stage", index=index, stage=STAGE_NAMES[stage])
        if kind == "provider_switch":
            _post(
                q,
                "provider_switch",
                message=message,
                provider_from=payload.get("provider_from"),
                provider_to=payload.get("provider_to"),
            )
        if kind in ("rename_function", "rename_variable"):
            item_payload = dict(payload)
            item_payload.pop("kind", None)
            item_payload["index"] = index
            _post(q, kind, **item_payload)
        if kind in ("progress", "stage"):
            _post(q, "sample_status", index=index, status=message)
        is_err = level in ("error", "err", "fail") or kind in ("error", "fail")
        is_warn = level in ("warning", "warn")
        if not is_err and not is_warn and message:
            low_msg = message.lower()
            if low_msg.startswith("[-] error") or low_msg.startswith("error:") or "api error:" in low_msg or "rate limit reached" in low_msg:
                is_err = True
            elif low_msg.startswith("[-] warning") or low_msg.startswith("warning:"):
                is_warn = True

        if is_err or is_warn:
            sev = "Warning" if is_warn else "Error"
            _post(
                q,
                "error_event",
                time=time.strftime("%H:%M:%S"),
                severity=sev,
                stage=STAGE_NAMES.get(stage, stage or "IDA Engine"),
                sample="",
                message=message or payload.get("details", "") or "Unknown error",
                details=payload.get("details") or payload.get("traceback") or "",
                index=index,
            )
        if message:
            _post(q, "log", message=message)


# --------------------------------------------------------------------------
# Authentication / connection helpers
# --------------------------------------------------------------------------

def _python_cmd() -> list[str]:
    if getattr(sys, "frozen", False):
        for candidate in ("python", "python3", "py"):
            found = shutil.which(candidate)
            if found:
                return [found]
        return ["python"]
    return [sys.executable or "python"]


def _script_env(genesect_root, ida_path: str = "") -> dict:
    """Environment that lets scripts ``import genesect`` (found next to IDA, if needed)."""
    env = os.environ.copy()
    package_root = find_genesect_package_root(genesect_root, Path(ida_path).parent if ida_path.strip() else "")
    if package_root:
        env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(package_root), env.get("PYTHONPATH", "")]))
    return env


def _load_auth_cli_module(genesect_root: Path | str, ida_path: str = ""):
    """Dynamically load scripts/auth_cli.py for direct, in-process execution."""
    script = auth_script(genesect_root)
    package_root = find_genesect_package_root(genesect_root, Path(ida_path).parent if ida_path.strip() else "")
    if package_root and str(package_root) not in sys.path:
        sys.path.insert(0, str(package_root))

    if not script.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location("omni_idb_auth_cli", str(script))
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    except Exception:
        pass
    return None


def start_chatgpt_auth(genesect_root: Path | str, q, ida_path: str = "") -> None:
    def work() -> None:
        try:
            mod = _load_auth_cli_module(genesect_root, ida_path)
            if mod:
                from genesect import chatgpt_oauth
                data = chatgpt_oauth.sign_in_interactive()
                _post(q, "auth_finished", ok=True, message="ChatGPT sign-in complete.")
                return
        except Exception:
            pass

        script = auth_script(genesect_root)
        try:
            out = subprocess.run(
                [*_python_cmd(), str(script), "sign-in"], env=_script_env(genesect_root, ida_path), capture_output=True, text=True, encoding="utf-8", errors="replace"
            )
        except OSError as error:
            _post(q, "auth_finished", ok=False, message=str(error))
            return
        text = (out.stdout if out.returncode == 0 else out.stderr).strip().splitlines()
        message = text[-1] if text else "ChatGPT authentication finished."
        _post(q, "auth_finished", ok=out.returncode == 0, message=message)

    threading.Thread(target=work, daemon=True).start()


def start_test_connection(genesect_root: Path | str, payload: dict, q, ida_path: str = "") -> None:
    def work() -> None:
        target = payload.get("target", "main")
        # 1. Prefer in-process execution (avoids re-invoking frozen executable)
        try:
            mod = _load_auth_cli_module(genesect_root, ida_path)
            if mod and hasattr(mod, "test_connection"):
                res = mod.test_connection(payload)
                if isinstance(res, dict):
                    _post(
                        q,
                        "test_connection_result",
                        ok=bool(res.get("ok", False)),
                        message=str(res.get("message", "Unknown result")),
                        resolved_model=res.get("model") if isinstance(res.get("model"), str) else None,
                        available_models=res.get("available_models") if isinstance(res.get("available_models"), list) else [],
                        target=target,
                    )
                    return
        except Exception:
            pass

        # 2. Subprocess fallback
        script = auth_script(genesect_root)
        try:
            out = subprocess.run(
                [*_python_cmd(), str(script), "test-connection", "-"],
                input=json.dumps(payload),
                env=_script_env(genesect_root, ida_path),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=90,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            _post(q, "test_connection_result", ok=False, message=f"Could not probe connection: {error}", resolved_model=None, target=target)
            return
        parsed = None
        for line in out.stdout.splitlines():
            try:
                candidate = json.loads(line.strip())
            except ValueError:
                continue
            if isinstance(candidate, dict):
                parsed = candidate
                break
        if parsed is not None:
            _post(
                q,
                "test_connection_result",
                ok=bool(parsed.get("ok", False)),
                message=str(parsed.get("message", "Unknown result")),
                resolved_model=parsed.get("model") if isinstance(parsed.get("model"), str) else None,
                available_models=parsed.get("available_models") if isinstance(parsed.get("available_models"), list) else [],
                target=target,
            )
        else:
            err = out.stderr.strip() or out.stdout.strip() or "No response received from test probe."
            _post(q, "test_connection_result", ok=False, message=err, resolved_model=None, target=target)

    threading.Thread(target=work, daemon=True).start()


def open_cli_sign_in(executable: str, extra_args: tuple[str, ...] = ()) -> None:
    exe = executable.strip() or "opencode"
    if sys.platform == "win32":
        subprocess.Popen(["cmd.exe", "/K", exe, *extra_args], creationflags=subprocess.CREATE_NEW_CONSOLE)
        return
    if sys.platform == "darwin":
        # macOS Terminal.app launch via AppleScript
        full_cmd = " ".join([exe, *extra_args])
        script = f'tell application "Terminal" to do script "{full_cmd}"'
        try:
            subprocess.Popen(["osascript", "-e", script])
            return
        except OSError:
            pass
    cmd = " ".join([exe, *extra_args])
    for terminal in (
        ["x-terminal-emulator", "-e"],
        ["gnome-terminal", "--"],
        ["konsole", "-e"],
        ["xfce4-terminal", "-e"],
        ["alacritty", "-e"],
        ["kitty", "-e"],
        ["xterm", "-e"],
    ):
        try:
            subprocess.Popen([*terminal, "bash", "-lc", f"{cmd}; exec bash"])
            return
        except OSError:
            continue
    raise OSError(f"Could not open a terminal for {exe}")


def get_opencode_auth_status() -> Optional[list[str]]:
    candidates: list[Path] = []
    try:
        home = Path.home()
        candidates.append(home / ".local" / "share" / "opencode" / "auth.json")
        candidates.append(home / ".config" / "opencode" / "auth.json")
        if sys.platform == "darwin":
            candidates.append(home / "Library" / "Application Support" / "opencode" / "auth.json")
    except Exception:
        pass
    for var in ("LOCALAPPDATA", "APPDATA", "XDG_DATA_HOME", "XDG_CONFIG_HOME"):
        val = os.environ.get(var)
        if val:
            candidates.append(Path(val) / "opencode" / "auth.json")
    for path in candidates:
        if path.is_file():
            try:
                parsed = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(parsed, dict):
                return list(parsed.keys())
    return None
