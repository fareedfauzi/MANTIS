"""Binary Lab native Ghidra Decompilation & AI Workspace Exporter.

Drives Ghidra analyzeHeadless, auto-analyzes native binaries (PE, ELF, Mach-O),
decompiles functions via DecompInterface, and exports an agent-ready AI workspace.
"""

from __future__ import annotations

import json
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .config import detect_ghidra, resolve_ghidra_headless


def _kill_process_tree(proc: subprocess.Popen) -> None:
    """Terminate the process and all of its descendants (including Java children)."""
    if proc is None:
        return
    try:
        if proc.poll() is not None:
            return
    except Exception:
        pass

    try:
        if sys.platform == "win32":
            # Forcefully kill process tree (/T) to ensure child java.exe processes are killed
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        else:
            try:
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, signal.SIGKILL)
            except Exception:
                proc.kill()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _run_cancellable(
    cmd: List[str],
    cwd: Optional[Path] = None,
    env: Optional[Dict[str, str]] = None,
    log_fn: Optional[Callable[[str], None]] = None,
    cancel_checker: Optional[Callable[[], bool]] = None,
    timeout: int = 600,
) -> subprocess.CompletedProcess:
    """Run a subprocess while polling for cancellation and streaming logs."""
    kwargs: Dict[str, Any] = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "cwd": str(cwd) if cwd else None,
        "env": env or os.environ.copy(),
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
    }
    if sys.platform != "win32":
        kwargs["start_new_session"] = True

    proc = subprocess.Popen(cmd, **kwargs)
    stdout_lines: List[str] = []
    start_time = time.monotonic()
    out_q: queue.Queue = queue.Queue()

    def _reader():
        try:
            if proc.stdout:
                for line in iter(proc.stdout.readline, ""):
                    out_q.put(line)
                proc.stdout.close()
        except Exception:
            pass

    reader_thread = threading.Thread(target=_reader, daemon=True)
    reader_thread.start()

    while True:
        if cancel_checker and cancel_checker():
            _kill_process_tree(proc)
            raise InterruptedError("Ghidra analysis was stopped by user request.")

        if timeout and (time.monotonic() - start_time) > timeout:
            _kill_process_tree(proc)
            raise TimeoutError(f"Ghidra analysis timed out after {timeout} seconds.")

        try:
            line = out_q.get(timeout=0.1)
            clean = line.rstrip("\r\n")
            stdout_lines.append(clean)
            if log_fn and clean.strip():
                # Filter out spammy java classpath noise if any
                if not clean.startswith(("Picked up _JAVA_OPTIONS", "DEBUG ", "TRACE ")):
                    log_fn(clean)
        except queue.Empty:
            if proc.poll() is not None:
                while not out_q.empty():
                    try:
                        clean = out_q.get_nowait().rstrip("\r\n")
                        stdout_lines.append(clean)
                        if log_fn and clean.strip():
                            log_fn(clean)
                    except queue.Empty:
                        break
                break

    ret = proc.poll() or 0
    full_output = "\n".join(stdout_lines)
    if ret != 0:
        raise RuntimeError(f"Ghidra analyzeHeadless failed with exit code {ret}:\n{full_output[-2000:]}")

    return subprocess.CompletedProcess(cmd, ret, stdout=full_output, stderr="")


def export_ghidra_workspace(
    sample_path: Path,
    output_root: Path,
    ghidra_path: str = "",
    log_fn: Optional[Callable[[str], None]] = None,
    cancel_checker: Optional[Callable[[], bool]] = None,
    settings: Optional[Any] = None,
) -> Dict[str, Any]:
    """Execute Ghidra analyzeHeadless on sample_path and generate an AI workspace."""
    log = log_fn or (lambda _: None)

    # Resolve analyzeHeadless binary
    headless = resolve_ghidra_headless(ghidra_path) or detect_ghidra()
    if not headless or not headless.is_file():
        raise FileNotFoundError(
            f"Ghidra headless executable (analyzeHeadless) not found. "
            f"Configured path: '{ghidra_path}'. Please configure the Ghidra path under Engine Settings."
        )

    log(f"Using Ghidra headless executable: {headless}")

    sample_path = Path(sample_path).resolve()
    if not sample_path.is_file():
        raise FileNotFoundError(f"Sample not found: {sample_path}")

    ws_dir = output_root / "AI Workspace"
    proj_dir = output_root / "Ghidra Project"
    logs_dir = output_root / "logs"

    ws_dir.mkdir(parents=True, exist_ok=True)
    proj_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    script_dir = Path(__file__).parent.parent / "omni_runtime" / "scripts" / "ghidra"
    java_script = script_dir / "ExportGhidraWorkspace.java"
    py_script = script_dir / "export_ghidra_workspace.py"

    if not java_script.is_file() and not py_script.is_file():
        raise FileNotFoundError(f"Ghidra export scripts missing in {script_dir}")

    # Prefer ExportGhidraWorkspace.java (built into Ghidra ECJ, requires no Jython/PyGhidra)
    script_name = "ExportGhidraWorkspace.java" if java_script.is_file() else "export_ghidra_workspace.py"
    log(f"Launching Ghidra headless with script: {script_name}...")

    # Extraction limits (configurable via settings or env vars; 0 = unlimited)
    max_decompile = int(getattr(settings, "max_decompiled_functions", 0) or os.environ.get("GHIDRA_MAX_DECOMPILE", 0) or 0)
    max_strings = int(getattr(settings, "max_extracted_strings", 0) or os.environ.get("GHIDRA_MAX_STRINGS", 0) or 0)
    log(f"Ghidra extraction configuration: max_decompile={max_decompile or 'unlimited'}, max_strings={max_strings or 'unlimited'}")

    # Build command line based on sample kind:
    # Existing Ghidra projects (.gpr) require opening the existing project location and using -process,
    # rather than importing the project descriptor file.
    is_gpr = sample_path.suffix.lower() == ".gpr"
    if is_gpr:
        proj_loc = sample_path.parent
        proj_name = sample_path.stem
        rep_dir = proj_loc / f"{proj_name}.rep"
        if not rep_dir.is_dir():
            raise FileNotFoundError(
                f"Ghidra project directory missing: '{rep_dir.name}' is required alongside '{sample_path.name}'"
            )
        log(f"Opening existing Ghidra project '{proj_name}' at {proj_loc}...")
        args = [
            str(proj_loc),
            proj_name,
            "-process",
            "-readOnly",
            "-scriptPath",
            str(script_dir),
            "-postScript",
            script_name,
            str(ws_dir),
            str(max_decompile),
            str(max_strings),
        ]
    else:
        log(f"Importing sample into temporary Ghidra project at {proj_dir}...")
        args = [
            str(proj_dir),
            "analyzed",
            "-import",
            str(sample_path),
            "-scriptPath",
            str(script_dir),
            "-postScript",
            script_name,
            str(ws_dir),
            str(max_decompile),
            str(max_strings),
            "-overwrite",
        ]

    env = os.environ.copy()
    # Suppress interactive GUI popups
    env["JAVA_TOOL_OPTIONS"] = "-Djava.awt.headless=true " + env.get("JAVA_TOOL_OPTIONS", "")
    env["GHIDRA_MAX_DECOMPILE"] = str(max_decompile)
    env["GHIDRA_MAX_STRINGS"] = str(max_strings)

    if sys.platform == "win32" and str(headless).lower().endswith((".bat", ".cmd")):
        cmd = ["cmd.exe", "/c", str(headless), *args]
    else:
        cmd = [str(headless), *args]

    log(f"Starting Ghidra analysis on {sample_path.name}...")
    _run_cancellable(
        cmd,
        cwd=output_root,
        env=env,
        log_fn=log,
        cancel_checker=cancel_checker,
        timeout=int(getattr(settings, "ida_timeout_seconds", 600) or 600),
    )

    # Deploy required workspace tools
    try:
        from .workspace_export import deploy_workspace_tools
        deploy_workspace_tools(ws_dir)
        for fname in ("AGENTS.md", "CLAUDE.md"):
            fpath = ws_dir / fname
            if fpath.is_file():
                txt = fpath.read_text(encoding="utf-8", errors="replace")
                if "threat_attribution" not in txt:
                    extra = (
                        "\n## Threat Attribution & Live OSINT\n"
                        "- `skills/threat_attribution/SKILL.md` - Autonomous threat attribution skill based on the 6-category threat attribution framework.\n"
                        "- `threat_attribution_result.md` - Automated threat intelligence lookup results across CTI writeups, reputation feeds, registry/mutex IOCs, and candidate actor scoring (when enabled).\n"
                        "- `osint_lookup.py` - Standalone workspace OSINT tool to query live internet threat intelligence (CIRCL, RDAP, OTX, GitHub) for unique hashes, domains, IPs, mutexes, and strings.\n"
                    )
                    fpath.write_text(txt + extra, encoding="utf-8")
    except Exception as exc:
        log(f"Warning: could not deploy workspace tools: {exc}")

    # Inspect and strictly validate exported catalog artifacts
    catalog_dir = ws_dir / "catalog"
    if not catalog_dir.is_dir():
        raise RuntimeError(f"Ghidra export failed: catalog directory was not created at {catalog_dir}")

    asm_file = catalog_dir / "assembly.json"
    fn_file = catalog_dir / "functions.json"
    imp_file = catalog_dir / "imports.json"
    str_file = catalog_dir / "strings.json"

    # Core requirement: at least assembly.json or functions.json must exist
    if not asm_file.is_file() and not fn_file.is_file():
        raise RuntimeError(
            f"Ghidra export failed to produce required workspace catalog artifacts "
            f"(neither assembly.json nor functions.json exists in {catalog_dir})."
        )

    functions_count = 0
    imports_count = 0
    strings_count = 0
    types_count = 0
    decompiled_count = len(list((ws_dir / "src").glob("*.c"))) if (ws_dir / "src").is_dir() else 0
    arch = "Native Binary"

    if asm_file.is_file():
        try:
            asm_data = json.loads(asm_file.read_text(encoding="utf-8"))
            if not isinstance(asm_data, dict):
                raise ValueError("assembly.json must contain a JSON object")
            arch = asm_data.get("language_id") or asm_data.get("executable_format") or arch
            functions_count = int(asm_data.get("total_functions") or 0)
        except Exception as exc:
            raise RuntimeError(f"Malformed Ghidra export artifact: catalog/assembly.json is invalid: {exc}") from exc

    if fn_file.is_file():
        try:
            fn_data = json.loads(fn_file.read_text(encoding="utf-8"))
            if not isinstance(fn_data, list):
                raise ValueError("functions.json must contain a JSON array")
            functions_count = max(functions_count, len(fn_data))
        except Exception as exc:
            raise RuntimeError(f"Malformed Ghidra export artifact: catalog/functions.json is invalid: {exc}") from exc

    if imp_file.is_file():
        try:
            imp_data = json.loads(imp_file.read_text(encoding="utf-8"))
            if not isinstance(imp_data, list):
                raise ValueError("imports.json must contain a JSON array")
            imports_count = len(imp_data)
        except Exception as exc:
            raise RuntimeError(f"Malformed Ghidra export artifact: catalog/imports.json is invalid: {exc}") from exc

    if str_file.is_file():
        try:
            str_data = json.loads(str_file.read_text(encoding="utf-8"))
            if not isinstance(str_data, list):
                raise ValueError("strings.json must contain a JSON array")
            strings_count = len(str_data)
        except Exception as exc:
            raise RuntimeError(f"Malformed Ghidra export artifact: catalog/strings.json is invalid: {exc}") from exc

    # Ensure we do not report false success if all artifacts are empty
    if functions_count == 0 and imports_count == 0 and strings_count == 0 and decompiled_count == 0:
        raise RuntimeError(
            "Ghidra export reported completion but produced zero functions, imports, strings, and decompiled files. "
            "Analysis failed to extract any code structures."
        )

    log(f"[OK] Ghidra AI Workspace exported successfully ({functions_count} functions, {imports_count} imports, {strings_count} strings, {decompiled_count} decompiled C files)")

    return {
        "workspace_dir": str(ws_dir),
        "functions_count": functions_count,
        "imports_count": imports_count,
        "strings_count": strings_count,
        "decompiled_count": decompiled_count,
        "cs_count": 0,
        "types_count": types_count,
        "pinvokes_count": imports_count,
        "cil_count": 0,
        "ghidra_project": str(sample_path.parent if is_gpr else proj_dir),
        "architecture": arch,
    }
