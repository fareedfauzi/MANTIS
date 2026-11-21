"""Manual, read-only browser for Binary Lab workspace exports and analyst notes."""

import json
import re
import threading
from pathlib import Path

import binary_lab

_NOTES_LOCK = threading.RLock()
_MAX_CODE = 1024 * 1024


def _workspace(job_id, sample_index):
    job = binary_lab._read_json(binary_lab._job_path(job_id), {})
    if not job:
        raise ValueError("Analysis job not found.")
    samples = job.get("samples") or []
    if sample_index < 0 or sample_index >= len(samples):
        raise ValueError("Sample not found in this job.")
    sample = samples[sample_index]
    root = binary_lab._output_root(job_id)
    result = sample.get("result") or {}
    candidate = result.get("workspace_path")
    if candidate:
        path = Path(candidate).resolve()
        if root in path.parents and path.is_dir():
            return job, sample, path
    for directory in root.iterdir():
        if directory.is_dir():
            for path in (directory / "AI Workspace", directory):
                if (path / "catalog").is_dir() and root in path.resolve().parents and (sample["name"].lower() in directory.name.lower() or len(samples) == 1):
                    return job, sample, path.resolve()
    raise ValueError("The analysis workspace is not available yet. Wait for extraction to finish.")


def _read(path, fallback):
    if not path.is_file():
        return fallback
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _address(fn):
    return str(fn.get("address") or fn.get("entry_point") or "").lower().removeprefix("0x")


def _notes_path(job_id, sample_index):
    return binary_lab.JOBS_DIR / f"{binary_lab._validate_job_id(job_id)}_reversing_{sample_index}.json"


def workspace(job_id, sample_index=0):
    job, sample, path = _workspace(job_id, sample_index)
    catalog = path / "catalog"
    raw_functions = _read(catalog / "functions.json", [])
    raw_strings = _read(catalog / "strings.json", [])
    raw_imports = _read(catalog / "imports.json", [])
    if isinstance(raw_strings, dict):
        raw_strings = raw_strings.get("strings", [])
    if isinstance(raw_imports, dict):
        raw_imports = [item for group in raw_imports.get("by_capability", {}).values() for item in group]
        raw_imports = list({(str(item.get("module")), str(item.get("name"))): item for item in raw_imports}.values())
    functions = raw_functions if isinstance(raw_functions, list) else []
    strings = raw_strings if isinstance(raw_strings, list) else []
    imports = raw_imports if isinstance(raw_imports, list) else []
    with _NOTES_LOCK:
        notes = _read(_notes_path(job_id, sample_index), {})
    return {
        "job_id": job_id, "sample_index": sample_index,
        "sample": {key: sample.get(key) for key in ("name", "size", "sha256", "kind", "status")},
        "engine": job.get("settings", {}).get("disassembler", "ida"),
        "metadata": _read(catalog / "sample.json", _read(catalog / "assembly.json", {})),
        "functions": functions, "strings": strings, "imports": imports,
        "notes": notes if isinstance(notes, dict) else {},
    }


def function_code(job_id, sample_index, address):
    if not re.fullmatch(r"(?:0x)?[a-fA-F0-9]{1,20}", address):
        raise ValueError("Invalid function address.")
    _, _, path = _workspace(job_id, sample_index)
    functions = _read(path / "catalog" / "functions.json", [])
    fn = next((item for item in functions if _address(item) == address.lower().removeprefix("0x")), None)
    if not fn:
        raise ValueError("Function not found.")
    files = fn.get("files") or {}
    source = files.get("c")
    assembly = files.get("asm")
    if not source:
        # Ghidra names source files using the sanitized function name and entry address.
        suffix = "_" + str(fn.get("entry_point") or "").replace(":", "_") + ".c"
        matches = [item for item in (path / "src").glob("*.c") if item.name.endswith(suffix)] if (path / "src").is_dir() else []
        if matches:
            source = str(matches[0].relative_to(path))

    def load(relative):
        if not relative:
            return ""
        candidate = (path / relative).resolve()
        if path not in candidate.parents or not candidate.is_file() or candidate.stat().st_size > _MAX_CODE:
            return ""
        return candidate.read_text(encoding="utf-8", errors="replace")

    return {"function": fn, "source": load(source), "assembly": load(assembly)}


def save_note(job_id, sample_index, address, content, author):
    _, _, path = _workspace(job_id, sample_index)
    if not re.fullmatch(r"(?:0x)?[a-fA-F0-9]{1,20}", address):
        raise ValueError("Invalid function address.")
    if not isinstance(content, str) or len(content) > 20000:
        raise ValueError("Notes must be text under 20,000 characters.")
    functions = _read(path / "catalog" / "functions.json", [])
    match = next((item for item in functions if _address(item) == address.lower().removeprefix("0x")), None)
    if match is None:
        raise ValueError("Function not found.")
    from datetime import datetime, timezone
    with _NOTES_LOCK:
        target = _notes_path(job_id, sample_index)
        notes = _read(target, {})
        if content.strip():
            notes[address.lower().removeprefix("0x")] = {"text": content, "updated_by": author, "updated_at": datetime.now(timezone.utc).isoformat()}
        else:
            notes.pop(address.lower().removeprefix("0x"), None)
        staged = target.with_suffix(".tmp")
        staged.write_text(json.dumps(notes, ensure_ascii=False), encoding="utf-8")
        staged.replace(target)
    return notes.get(address.lower().removeprefix("0x"), {})
