#!/usr/bin/env python3
"""Create a portable, static-analysis AI workspace for a recovered payload.

This helper is intentionally safe to run from an AI-agent workspace: it reads
the supplied file but never loads, executes, or injects it.  It supports any
byte stream and enriches managed PE files with ILSpyCmd C# and CIL output when
ILSpyCmd is available.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path


MAX_STRINGS = 10_000
# Replaced with the active Binary Lab installation root when this helper is
# deployed into an AI workspace. Override with --engine-root if necessary.
EMBEDDED_ENGINE_ROOT = "__ENGINE_ROOT__"


def default_engine_root() -> str:
    """Use the embedded deployment root, or the source checkout when run in place."""
    if EMBEDDED_ENGINE_ROOT != "__" + "ENGINE_ROOT__":
        return EMBEDDED_ENGINE_ROOT
    return str(Path(__file__).resolve().parent.parent)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    size = len(data)
    return -sum((count / size) * math.log2(count / size) for count in counts.values())


def printable_strings(data: bytes) -> list[str]:
    values = set()
    for match in re.finditer(rb"[\x20-\x7e]{4,}", data):
        values.add(match.group().decode("ascii", errors="replace"))
    for match in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", data):
        values.add(match.group().decode("utf-16-le", errors="replace"))
    return sorted(values, key=lambda value: (value.lower(), value))[:MAX_STRINGS]


def pe_details(data: bytes) -> dict:
    """Return conservative PE, ELF, and Mach-O details without third-party parsers."""
    result = {"is_pe": False, "is_dotnet": False, "is_native": False, "format_name": "Unknown"}
    if data.startswith(b"\x7fELF"):
        bitness = {1: "ELF32", 2: "ELF64"}.get(data[4] if len(data) > 4 else 0, "ELF")
        return {**result, "is_native": True, "format_name": bitness}
    macho_magic = data[:4]
    macho_formats = {
        b"\xfe\xed\xfa\xce": "Mach-O 32-bit (big-endian)", b"\xce\xfa\xed\xfe": "Mach-O 32-bit",
        b"\xfe\xed\xfa\xcf": "Mach-O 64-bit (big-endian)", b"\xcf\xfa\xed\xfe": "Mach-O 64-bit",
        b"\xca\xfe\xba\xbe": "Mach-O universal", b"\xbe\xba\xfe\xca": "Mach-O universal",
    }
    if macho_magic in macho_formats:
        return {**result, "is_native": True, "format_name": macho_formats[macho_magic]}
    if len(data) < 0x40 or data[:2] != b"MZ":
        return result
    pe_offset = int.from_bytes(data[0x3C:0x40], "little")
    if pe_offset + 0x18 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        return result
    coff = pe_offset + 4
    optional = coff + 20
    magic = int.from_bytes(data[optional:optional + 2], "little")
    if magic not in (0x10B, 0x20B):
        return result
    directory_base = optional + (96 if magic == 0x10B else 112)
    clr_directory = directory_base + (14 * 8)
    clr_rva = 0
    if clr_directory + 8 <= len(data):
        clr_rva = int.from_bytes(data[clr_directory:clr_directory + 4], "little")
    machine = int.from_bytes(data[coff:coff + 2], "little")
    result.update({
        "is_pe": True,
        "is_dotnet": bool(clr_rva),
        "is_native": not bool(clr_rva),
        "format_name": "PE",
        "pe_offset": hex(pe_offset),
        "machine": {0x14C: "x86", 0x8664: "x64", 0xAA64: "ARM64"}.get(machine, hex(machine)),
        "architecture": "PE32+" if magic == 0x20B else "PE32",
        "sections": int.from_bytes(data[coff + 2:coff + 4], "little"),
    })
    return result


def resolve_ilspycmd(requested: str) -> list[str] | None:
    if requested:
        path = Path(requested)
        return [str(path)] if path.is_file() else None
    try:
        from find_ilspycmd import find_ilspycmd
        return find_ilspycmd()
    except Exception:
        return None


def copy_companion_tools(script_dir: Path, workspace: Path) -> list[str]:
    copied = []
    for name in ("run_analysis.md", "render_report.py", "dump_ai_workspace.py", "find_ida.py", "find_ilspycmd.py"):
        source = script_dir / name
        target = workspace / name
        if source.is_file() and source.resolve() != target.resolve():
            shutil.copy2(source, target)
            copied.append(name)
    return copied


def export_native_with_ida(sample: Path, workspace: Path, ida: Path, engine_root: str) -> None:
    """Run Binary Lab's native IDA exporter against a PE without executing it."""
    if not ida.is_file():
        raise RuntimeError(f"IDA executable does not exist: {ida}")
    root = Path(engine_root).expanduser().resolve()
    if not (root / "omni_idb" / "workspace_export.py").is_file():
        raise RuntimeError("Binary Lab engine root is unavailable. Supply --engine-root pointing to the Binary Lab installation.")
    run_dir = workspace.parent
    ida_log = run_dir / f"{workspace.name}.ida.log"
    bootstrap_log = run_dir / f"{workspace.name}.bootstrap.log"
    status_file = run_dir / f"{workspace.name}.ida_export.status.json"
    bootstrap_copy = run_dir / f"{workspace.name}.ida_bootstrap.py"
    status = {
        "input": str(sample), "input_sha256": sha256(sample.read_bytes()), "output": str(workspace),
        "ida": str(ida), "ida_log": str(ida_log), "bootstrap_log": str(bootstrap_log),
        "bootstrap": str(bootstrap_copy), "success": False,
    }
    with tempfile.TemporaryDirectory(prefix="binarylab_stage_export_") as temp:
        bootstrap = Path(temp) / "export_stage.py"
        bootstrap_text = (
            "import sys, traceback\n"
            f"sys.path.insert(0, {str(root)!r})\n"
            f"BOOTSTRAP_LOG = {str(bootstrap_log)!r}\n"
            "def log(message):\n"
            "    with open(BOOTSTRAP_LOG, 'a', encoding='utf-8') as handle: handle.write(str(message) + '\\n')\n"
            "exit_code = 0\n"
            "try:\n"
            "    log('Starting Binary Lab headless workspace export')\n"
            "    from omni_idb.workspace_export import export_workspace\n"
            f"    export_workspace({str(workspace)!r}, progress_callback=lambda label, *args: print(label, flush=True))\n"
            f"    required = {[str(item) for item in ('AGENTS.md', 'catalog/functions.json', 'catalog/strings.json', 'catalog/imports.json')]!r}\n"
            f"    missing = [item for item in required if not __import__('os').path.isfile(__import__('os').path.join({str(workspace)!r}, item))]\n"
            "    if missing: raise RuntimeError('Incomplete workspace export: ' + ', '.join(missing))\n"
            "    log('Workspace export completed')\n"
            "except Exception:\n"
            "    log(traceback.format_exc())\n"
            "    traceback.print_exc()\n"
            "    exit_code = 1\n"
            "finally:\n"
            "    log('IDA exit code: %d' % exit_code)\n"
            "    import ida_pro\n"
            "    ida_pro.qexit(exit_code)\n",
        )
        bootstrap.write_text(bootstrap_text, encoding="utf-8")
        bootstrap_copy.write_text(bootstrap_text, encoding="utf-8")
        env = os.environ.copy()
        for name in ("VIRTUAL_ENV", "__PYVENV_LAUNCHER__", "PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONEXECUTABLE", "PYTHONINSPECT"):
            env.pop(name, None)
        try:
            result = subprocess.run([str(ida), "-A", f"-L{ida_log}", f"-S{bootstrap}", str(sample)], text=True, capture_output=True, timeout=1800, cwd=str(ida.parent), env=env)
        except subprocess.TimeoutExpired as exc:
            status.update({"error": "timeout", "stdout": exc.stdout or "", "stderr": exc.stderr or ""})
            status_file.write_text(json.dumps(status, indent=2), encoding="utf-8")
            raise RuntimeError(f"IDA native workspace export timed out; diagnostics preserved beside {status_file}") from exc
    status.update({"returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
    if result.returncode:
        detail = (result.stderr or result.stdout or "IDA exited without diagnostics").strip()
        error_log = workspace.parent / f"{workspace.name}.ida_export.error.log"
        error_log.write_text(
            f"returncode: {result.returncode}\ncommand: {ida} -A -S<bootstrap> {sample}\n\nstdout:\n{result.stdout}\n\nstderr:\n{result.stderr}\n",
            encoding="utf-8", errors="replace",
        )
        status["error"] = detail
        status_file.write_text(json.dumps(status, indent=2), encoding="utf-8")
        raise RuntimeError(f"IDA native workspace export failed; diagnostics saved to {error_log}: {detail[-2000:]}")
    if not (workspace / "AGENTS.md").is_file():
        status["error"] = "IDA completed without producing an AI workspace."
        status_file.write_text(json.dumps(status, indent=2), encoding="utf-8")
        raise RuntimeError("IDA completed without producing an AI workspace.")
    status["success"] = True
    status_file.write_text(json.dumps(status, indent=2), encoding="utf-8")


def write_workspace(sample: Path, output: Path, ilspycmd: str = "") -> Path:
    data = sample.read_bytes()
    workspace = output.resolve()
    catalog = workspace / "catalog"
    modules = workspace / "modules"
    catalog.mkdir(parents=True, exist_ok=True)
    modules.mkdir(parents=True, exist_ok=True)

    pe = pe_details(data)
    sample_info = {
        "sample_name": sample.name,
        "sample_path": str(sample),
        "sample_size": len(data),
        "sha256": sha256(data),
        "entropy": round(entropy(data), 6),
        "format": pe,
    }
    strings = printable_strings(data)
    (catalog / "sample.json").write_text(json.dumps(sample_info, indent=2) + "\n", encoding="utf-8")
    (catalog / "strings.json").write_text(json.dumps(strings, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (catalog / "triage_indicators.json").write_text(json.dumps({
        "is_dotnet": pe["is_dotnet"], "is_pe": pe["is_pe"], "string_count": len(strings),
    }, indent=2) + "\n", encoding="utf-8")

    decompile_note = "Not applicable: the recovered artifact is not a managed PE file."
    if pe["is_dotnet"]:
        command = resolve_ilspycmd(ilspycmd)
        if command:
            src = workspace / "src"
            cil = workspace / "cil"
            src.mkdir(exist_ok=True)
            cil.mkdir(exist_ok=True)
            try:
                subprocess.run([*command, "--disable-updatecheck", "--nested-directories", "-p", "-o", str(src), str(sample)], check=True, timeout=300, capture_output=True, text=True)
                subprocess.run([*command, "--disable-updatecheck", "-il", "-o", str(cil), str(sample)], check=True, timeout=300, capture_output=True, text=True)
                decompile_note = "ILSpyCmd exported C# to `src/` and CIL to `cil/`."
            except (OSError, subprocess.SubprocessError) as exc:
                decompile_note = f"ILSpyCmd was available but decompilation failed: {exc}"
        else:
            decompile_note = "Managed PE detected, but ILSpyCmd was unavailable; install it or allow Binary Lab to provision it."

    (modules / "artifact_overview.md").write_text(
        "# Recovered artifact overview\n\n"
        f"- Source: `{sample}`\n- SHA-256: `{sample_info['sha256']}`\n"
        f"- Size: `{len(data)}` bytes\n- Entropy: `{sample_info['entropy']}`\n"
        f"- Format: `{pe['format_name']}`; managed .NET: `{pe['is_dotnet']}`\n\n{decompile_note}\n",
        encoding="utf-8",
    )
    copied = copy_companion_tools(Path(__file__).resolve().parent, workspace)
    guidance = [
        "# Binary Lab Recovered-Stage AI Workspace", "",
        "This workspace was created by `dump_ai_workspace.py` using static byte processing only.",
        "Do not execute or load the recovered artifact.", "",
        "## Contents", "- `catalog/sample.json`: file identity, hash, entropy, and conservative format detection.",
        "- `catalog/strings.json`: printable ASCII and UTF-16LE strings.",
        "- `modules/artifact_overview.md`: extraction and decompilation status.",
        "- `src/` and `cil/`: available for managed stages decompiled with ILSpyCmd.",
    ]
    if copied:
        guidance.append("- Companion tools copied: " + ", ".join(f"`{item}`" for item in copied) + ".")
    (workspace / "AGENTS.md").write_text("\n".join(guidance) + "\n", encoding="utf-8")
    shutil.copy2(workspace / "AGENTS.md", workspace / "CLAUDE.md")
    return workspace


def main() -> int:
    parser = argparse.ArgumentParser(description="Safely export a recovered payload into a Binary Lab AI workspace.")
    parser.add_argument("sample", type=Path, help="Recovered payload file to inspect without executing")
    parser.add_argument("--output", "-o", type=Path, help="Target workspace directory (default: <sample>_ai_workspace)")
    parser.add_argument("--ilspycmd", default="", help="Optional path to ilspycmd for managed C# and CIL output")
    parser.add_argument("--ida", type=Path, help="Path to idat/idat64 for native PE export")
    parser.add_argument("--engine-root", default=default_engine_root(), help="Binary Lab installation root used by IDA")
    args = parser.parse_args()
    sample = args.sample.expanduser().resolve()
    if not sample.is_file():
        parser.error(f"Input file does not exist: {sample}")
    output = (args.output or sample.with_name(f"{sample.stem}_ai_workspace")).expanduser().resolve()
    if output.exists() and any(output.iterdir()):
        parser.error(f"Output workspace is not empty: {output}")
    with sample.open("rb") as handle:
        details = pe_details(handle.read(8192))
    ida = args.ida
    if details["is_native"] and ida is None:
        try:
            from find_ida import find_ida
            ida = find_ida()
        except Exception:
            ida = None
    if details["is_native"] and ida:
        export_native_with_ida(sample, output, Path(ida).expanduser().resolve(), args.engine_root)
        print(f"[OK] IDA native AI workspace exported: {output}")
        return 0
    if details["is_native"] and not ida:
        print("[WARN] Native PE/ELF/Mach-O detected but IDA was not found. Set IDA_PATH or supply --ida; exporting static fallback only.", file=sys.stderr)
    workspace = write_workspace(sample, output, args.ilspycmd)
    print(f"[OK] AI workspace exported: {workspace}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
