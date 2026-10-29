"""MANTIS web-service adapter for the binary analysis engine."""

from __future__ import annotations

import hashlib
import io
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
import zipfile
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import ai_case_service
import ai_service
from omni_idb import runner
from omni_idb.config import (
    AppSettings,
    PROVIDERS,
    default_models_for_provider,
    detect_ghidra,
    detect_ida,
    provider_defaults,
    resolve_ghidra_headless,
)
from omni_idb.discovery import ClassifyError, Sample, classify_sample, discover


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data" / "binary_lab"
JOBS_DIR = DATA_DIR / "jobs"
UPLOADS_DIR = DATA_DIR / "uploads"
OUTPUT_DIR = DATA_DIR / "output"
RUNTIME_DIR = BASE_DIR / "omni_runtime"
SETTINGS_PATH = DATA_DIR / "settings.json"
MAX_EVENTS = 500
MAX_UPLOAD_BYTES = 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 512
MAX_ARCHIVE_MEMBER_BYTES = 256 * 1024 * 1024

DEFAULT_SETTINGS: Dict[str, Any] = {
    "ida_path": "",
    "ghidra_path": "",
    "disassembler": "ida",
    "provider": "OpenAI",
    "api_url": "https://api.openai.com/v1",
    "model": "gpt-5.1",
    "executable": "",
    "rename_functions": False,
    "rename_functions_with_address": False,
    "rename_variables": False,
    "generate_workspace": True,
    "analyze_workspace": False,
    "autonomous_investigation": False,
    "threat_attribution_lookup": False,
    "dotnet_mode": "decompile",
    "goresym_path": "",
    "ilspycmd_path": "",
    "investigation_turns": 10,
    "recursive": True,
    "batch_size": 15,
    "workers": 3,
    "low_score_rescan": False,
    "cooldown_seconds": 1,
    "use_rename_cache": True,
    "token_budget": 0,
    "fallback_enabled": False,
    "fallback_provider": "Ollama",
    "fallback_api_url": "http://localhost:11434/v1",
    "fallback_model": "llama3.2",
    "fallback_executable": "",
    "use_mantis_ai": True,
}

_LOCK = threading.RLock()
_CANCEL: Dict[str, threading.Event] = {}


def _ensure_dirs() -> None:
    for path in (DATA_DIR, JOBS_DIR, UPLOADS_DIR, OUTPUT_DIR):
        path.mkdir(parents=True, exist_ok=True)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _safe_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(value or "sample").name).strip("._")
    return value[:180] or "sample"


def _validate_job_id(job_id: str) -> str:
    value = str(job_id or "").strip()
    if not re.fullmatch(r"bl_[a-f0-9]{16}", value):
        raise ValueError("Invalid Binary Lab job ID.")
    return value


def _job_path(job_id: str) -> Path:
    return JOBS_DIR / f"{_validate_job_id(job_id)}.json"


def _read_json(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    for attempt in range(5):
        try:
            txt = path.read_text(encoding="utf-8")
            if not txt.strip():
                if attempt < 4:
                    time.sleep(0.02)
                    continue
                return default
            return json.loads(txt)
        except PermissionError:
            if attempt < 4:
                time.sleep(0.025)
                continue
            return default
        except (OSError, ValueError):
            if attempt < 4:
                time.sleep(0.02)
                continue
            return default
    return default


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temp.write_text(json.dumps(value, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    try:
        for attempt in range(8):
            try:
                os.replace(temp, path)
                return
            except PermissionError:
                if attempt == 7:
                    raise
                time.sleep(0.05 * (attempt + 1))
    finally:
        temp.unlink(missing_ok=True)


def get_settings(mask: bool = True) -> Dict[str, Any]:
    _ensure_dirs()
    saved = _read_json(SETTINGS_PATH, {})
    settings = {**DEFAULT_SETTINGS, **(saved if isinstance(saved, dict) else {})}
    if not settings.get("ida_path"):
        detected = detect_ida()
        settings["ida_path"] = str(detected) if detected else ""
    if not settings.get("ghidra_path"):
        detected_ghidra = detect_ghidra()
        settings["ghidra_path"] = str(detected_ghidra) if detected_ghidra else ""
    settings["providers"] = [
        {"id": name, "models": default_models_for_provider(name), "defaults": provider_defaults(name)}
        for name in PROVIDERS
    ]
    settings["engine_root"] = str(RUNTIME_DIR)
    settings["engine_available"] = (RUNTIME_DIR / "scripts" / "batch_ida_runner.py").is_file()
    settings["ida_available"] = bool(settings.get("ida_path") and Path(settings["ida_path"]).exists())
    if not settings.get("ilspycmd_path"):
        from omni_idb.dotnet_export import is_ilspycmd_available
        detected_ilspy = is_ilspycmd_available()
        settings["ilspycmd_path"] = str(detected_ilspy) if detected_ilspy else ""
    resolved_ghidra = resolve_ghidra_headless(settings.get("ghidra_path"))
    settings["ghidra_available"] = bool(resolved_ghidra and resolved_ghidra.exists())
    settings["mantis_ai_available"] = bool(ai_service.get_settings(mask=False).get("available"))
    return settings


def save_settings(payload: Dict[str, Any]) -> Dict[str, Any]:
    current = get_settings(mask=False)
    clean = dict(DEFAULT_SETTINGS)
    for key, default in DEFAULT_SETTINGS.items():
        value = payload.get(key, current.get(key, default))
        if isinstance(default, bool):
            clean[key] = bool(value)
        elif isinstance(default, int):
            try:
                clean[key] = max(1, int(value)) if key == "workers" else max(0, int(value))
            except (TypeError, ValueError):
                clean[key] = default
        else:
            clean[key] = str(value or "").strip()
    if clean["provider"] not in PROVIDERS:
        clean["provider"] = "OpenAI"
    if clean["fallback_provider"] not in PROVIDERS:
        clean["fallback_provider"] = "Ollama"
    clean["dotnet_mode"] = clean["dotnet_mode"] if clean["dotnet_mode"] in {"skip", "decompile"} else "decompile"
    clean["disassembler"] = clean["disassembler"] if clean.get("disassembler") in {"ida", "ghidra", "auto"} else "ida"
    if clean["disassembler"] == "ghidra":
        clean["autonomous_investigation"] = False
    _write_json(SETTINGS_PATH, clean)
    return get_settings(mask=True)


def engine_status() -> Dict[str, Any]:
    settings = get_settings()
    return {
        "available": settings["engine_available"],
        "engine": "Binary Lab",
        "engine_version": "0.1.0",
        "engine_root": settings["engine_root"],
        "disassembler": settings.get("disassembler", "ida"),
        "ida_path": settings["ida_path"],
        "ida_available": settings["ida_available"],
        "ghidra_path": settings["ghidra_path"],
        "ghidra_available": settings["ghidra_available"],
        "ilspycmd_path": settings.get("ilspycmd_path", ""),
        "capabilities": {
            "native": True,
            "dotnet": True,
            "ida": settings["ida_available"],
            "ghidra": settings["ghidra_available"],
            "workspace_export": True,
            "function_renaming": True,
            "variable_renaming": True,
            "workspace_analysis": True,
            "autonomous_investigation": True,
            "threat_attribution_lookup": True,
            "reports": ["md", "html", "pdf"],
        },
    }


def stage_uploads(files: Iterable[Any]) -> List[str]:
    _ensure_dirs()
    staging_id = f"upload-{uuid.uuid4().hex[:12]}"
    target = UPLOADS_DIR / staging_id
    target.mkdir(parents=True, exist_ok=True)
    paths: List[str] = []
    total = 0
    try:
        for upload in files:
            name = _safe_name(getattr(upload, "filename", "sample"))
            path = target / name
            suffix = 1
            while path.exists():
                path = target / f"{Path(name).stem}-{suffix}{Path(name).suffix}"
                suffix += 1
            with open(path, "wb") as handle:
                while True:
                    chunk = upload.file.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_UPLOAD_BYTES:
                        raise ValueError("Binary Lab upload exceeds the 1 GiB batch limit.")
                    handle.write(chunk)
            if not path.stat().st_size:
                path.unlink(missing_ok=True)
                continue
            if not zipfile.is_zipfile(path):
                paths.append(str(path))
                continue

            extracted: List[str] = []
            with zipfile.ZipFile(path, "r") as archive:
                passwords = [None, b"infected", b"malware", b"clean", b"password", b"1234"]
                extracted_total = 0
                for member in archive.infolist()[:MAX_ARCHIVE_MEMBERS]:
                    if member.is_dir() or member.filename.startswith((".", "__MACOSX")):
                        continue
                    if member.file_size <= 0 or member.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                        continue
                    if extracted_total + member.file_size > MAX_UPLOAD_BYTES:
                        raise ValueError("Binary Lab archive expands beyond the 1 GiB batch limit.")
                    member_name = _safe_name(Path(member.filename).name)
                    member_path = target / f"extracted_{member_name}"
                    counter = 1
                    while member_path.exists():
                        member_path = target / f"extracted_{Path(member_name).stem}-{counter}{Path(member_name).suffix}"
                        counter += 1
                    data = None
                    for password in passwords:
                        try:
                            data = archive.read(member, pwd=password)
                            break
                        except (RuntimeError, zipfile.BadZipFile):
                            continue
                    if data:
                        member_path.write_bytes(data)
                        extracted_total += len(data)
                        extracted.append(str(member_path))
            paths.extend(extracted or [str(path)])
        if not paths:
            shutil.rmtree(target, ignore_errors=True)
        return paths
    except Exception:
        shutil.rmtree(target, ignore_errors=True)
        raise


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _discover_paths(paths: Iterable[str], recursive: bool) -> tuple[List[Sample], List[dict]]:
    samples: List[Sample] = []
    rejected: List[dict] = []
    seen = set()
    for raw in paths:
        path = Path(str(raw or "")).expanduser().resolve()
        try:
            report = discover(path, recursive=recursive)
        except OSError as exc:
            rejected.append({"path": str(path), "reason": str(exc)})
            continue
        for item in report.samples:
            canonical = str(item.path.resolve()).lower()
            if canonical not in seen:
                seen.add(canonical)
                samples.append(item)
        rejected.extend({"path": str(item.path), "reason": item.reason} for item in report.rejected)
    return samples, rejected


def start_job(paths: Iterable[str], overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    _ensure_dirs()
    overrides = overrides if isinstance(overrides, dict) else {}
    base = get_settings(mask=False)
    effective = {key: overrides.get(key, base.get(key, default)) for key, default in DEFAULT_SETTINGS.items()}
    if effective.get("disassembler") == "ghidra":
        effective["autonomous_investigation"] = False
    samples, rejected = _discover_paths(paths, bool(effective.get("recursive", True)))
    if not samples:
        reason = rejected[0]["reason"] if rejected else "No supported samples were found."
        raise ValueError(reason)
    job_id = f"bl_{uuid.uuid4().hex[:16]}"
    output_root = OUTPUT_DIR / job_id
    output_root.mkdir(parents=True, exist_ok=True)
    sample_rows = []
    for index, sample in enumerate(samples):
        sample_rows.append({
            "index": index,
            "path": str(sample.path),
            "name": sample.path.name,
            "size": sample.size,
            "kind": sample.kind.job_value,
            "sha256": _sha256(sample.path),
            "status": "queued",
            "stage": "Queued",
            "message": "",
        })
    job = {
        "job_id": job_id,
        "status": "queued",
        "created_at": _now(),
        "updated_at": _now(),
        "started_at": "",
        "finished_at": "",
        "output_root": str(output_root),
        "settings": {k: v for k, v in effective.items() if "key" not in k.lower()},
        "samples": sample_rows,
        "rejected": rejected,
        "events": [],
        "summary": {"total": len(samples), "succeeded": 0, "failed": 0, "cancelled": False},
    }
    _write_json(_job_path(job_id), job)
    thread = threading.Thread(target=_run_job, args=(job_id, samples, effective), daemon=True, name=f"binary-lab-{job_id}")
    thread.start()
    return job


def create_job_from_uploads(files: Iterable[Any], overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Stage uploaded files to disk and start a new analysis job."""
    paths = stage_uploads(files)
    if not paths:
        raise ValueError("No valid supported files could be staged from the upload.")
    try:
        return start_job(paths, overrides)
    except Exception:
        uploads_root = UPLOADS_DIR.resolve()
        for raw_path in paths:
            try:
                resolved = Path(raw_path).resolve()
                if uploads_root in resolved.parents:
                    relative = resolved.relative_to(uploads_root)
                    staging_root = uploads_root / relative.parts[0]
                    shutil.rmtree(staging_root, ignore_errors=True)
            except (OSError, ValueError, IndexError):
                continue
        raise


def create_job_from_path(path: str, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Start a new analysis job for a local host file or directory."""
    path_str = str(path or "").strip()
    if not path_str:
        raise ValueError("A valid local file or directory path is required.")
    return start_job([path_str], overrides)


def _provider_profile(settings: Dict[str, Any]) -> tuple[AppSettings, str, str]:
    app_settings = AppSettings()
    for key in asdict(app_settings):
        if key in settings and key != "api_keys":
            setattr(app_settings, key, settings[key])
    app_settings.output_root = str(settings.get("output_root") or "")
    app_settings.genesect_root = str(RUNTIME_DIR)
    api_key = ""
    fallback_key = ""
    if settings.get("use_mantis_ai"):
        mantis = ai_service.get_settings(mask=False)
        provider_map = {
            "openai": "OpenAI", "openai_compatible": "OpenAICompatible", "openrouter": "OpenRouter",
            "groq": "Groq", "deepseek": "DeepSeek", "mistral": "Mistral", "anthropic": "Anthropic",
            "gemini": "GoogleGemini", "ollama": "Ollama", "lmstudio": "LMStudio", "litellm": "OpenAICompatible",
            "together": "OpenAICompatible", "xai": "OpenAICompatible", "azure_openai": "OpenAICompatible",
            "antigravity": "AntigravityCLI", "antigravity_cli": "AntigravityCLI",
            "chatgpt_desktop": "ChatGPTAccount", "chatgpt_account": "ChatGPTAccount",
            "claude_desktop": "ClaudeCode", "claude_code": "ClaudeCode",
            "copilot": "CopilotCLI", "copilot_cli": "CopilotCLI",
            "opencode": "OpenCode",
        }
        app_settings.provider = provider_map.get(str(mantis.get("provider") or "").lower(), app_settings.provider)
        endpoint = str(mantis.get("endpoint") or "")
        if app_settings.provider in {"GoogleGemini", "Ollama"}:
            app_settings.api_url = provider_defaults(app_settings.provider)[0]
        elif app_settings.provider in {"AntigravityCLI", "ClaudeCode", "ChatGPTAccount", "CopilotCLI", "OpenCode"}:
            app_settings.api_url = ""
            app_settings.executable = str(mantis.get("executable") or provider_defaults(app_settings.provider)[2])
        else:
            app_settings.api_url = re.sub(r"/(chat/completions|messages)$", "", endpoint.rstrip("/"))
        app_settings.model = str(mantis.get("model") or app_settings.model)
        api_key = str(mantis.get("api_key") or "")
    else:
        api_key = str(settings.get("api_key") or "")
        if not api_key:
            mantis = ai_service._settings_raw()
            if mantis.get("api_key"):
                api_key = mantis.get("api_key")
            else:
                env_keys = {
                    "OpenAI": "OPENAI_API_KEY",
                    "Anthropic": "ANTHROPIC_API_KEY",
                    "DeepSeek": "DEEPSEEK_API_KEY",
                    "GoogleGemini": "GEMINI_API_KEY",
                    "OpenRouter": "OPENROUTER_API_KEY",
                    "Groq": "GROQ_API_KEY",
                    "Mistral": "MISTRAL_API_KEY",
                }
                api_key = os.environ.get(env_keys.get(app_settings.provider, ""), "")
    return app_settings, api_key, fallback_key


def test_provider_connection(payload: Dict[str, Any]) -> Dict[str, Any]:
    from omni_idb.runner import _load_auth_cli_module, auth_script
    from omni_idb.config import provider_defaults

    app_settings, api_key, _ = _provider_profile(payload)
    if not payload.get("use_mantis_ai"):
        provider = str(payload.get("provider") or "OpenAI")
        api_url = str(payload.get("api_url") or "")
        model = str(payload.get("model") or "")
        executable = str(payload.get("executable") or "")
        if not api_url and provider not in {"AntigravityCLI", "ClaudeCode", "ChatGPTAccount", "CopilotCLI", "OpenCode"}:
            api_url = provider_defaults(provider)[0]
        if not model:
            model = provider_defaults(provider)[1]
        if not executable and provider in {"AntigravityCLI", "ClaudeCode", "ChatGPTAccount", "CopilotCLI", "OpenCode"}:
            executable = provider_defaults(provider)[2]

        cfg = {
            "provider": provider,
            "api_url": api_url,
            "api_key": api_key,
            "model": model,
            "executable": executable,
        }
    else:
        cfg = {
            "provider": app_settings.provider,
            "api_url": app_settings.api_url,
            "api_key": api_key,
            "model": app_settings.model,
            "executable": app_settings.executable,
        }

    try:
        mod = _load_auth_cli_module(RUNTIME_DIR)
        if mod and hasattr(mod, "test_connection"):
            res = mod.test_connection(cfg)
            if isinstance(res, dict):
                return res
    except Exception:
        pass

    script = auth_script(RUNTIME_DIR)
    try:
        proc = subprocess.run(
            [sys.executable, str(script), "test-connection", "-"],
            input=json.dumps(cfg),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=50,
        )
        for line in proc.stdout.splitlines():
            try:
                candidate = json.loads(line.strip())
                if isinstance(candidate, dict):
                    return candidate
            except ValueError:
                continue
        err = proc.stderr.strip() or proc.stdout.strip() or "No response from test probe."
        return {"ok": False, "message": err}
    except Exception as exc:
        return {"ok": False, "message": str(exc)}


def _update_job(job_id: str, mutator) -> Dict[str, Any]:
    with _LOCK:
        job = _read_json(_job_path(job_id), {})
        if not job:
            return {}
        mutator(job)
        job["updated_at"] = _now()
        _write_json(_job_path(job_id), job)
        return job


def _append_event(job: Dict[str, Any], kind: str, data: Dict[str, Any]) -> None:
    event = {"id": uuid.uuid4().hex[:12], "time": _now(), "kind": kind, **data}
    job.setdefault("events", []).append(event)
    job["events"] = job["events"][-MAX_EVENTS:]


def _run_job(job_id: str, samples: List[Sample], effective: Dict[str, Any], is_resume: bool = False) -> None:
    try:
        _run_job_inner(job_id, samples, effective, is_resume)
    except Exception as exc:
        def fail(job: Dict[str, Any]) -> None:
            job["status"] = "failed"
            job["finished_at"] = _now()
            _append_event(job, "adapter_error", {"message": str(exc)[:1000]})
        _update_job(job_id, fail)
    finally:
        _CANCEL.pop(job_id, None)



def _run_job_inner(job_id: str, samples: List[Sample], effective: Dict[str, Any], is_resume: bool = False) -> None:
    effective = dict(effective)
    effective["output_root"] = str(OUTPUT_DIR / job_id)
    app_settings, api_key, fallback_key = _provider_profile(effective)
    event_queue: queue.Queue = queue.Queue()
    request = runner.RunRequest(
        settings=app_settings,
        api_key=api_key,
        fallback_api_key=fallback_key,
        samples=samples,
        is_resume=is_resume,
    )
    cancel = runner.start(request, event_queue)
    _CANCEL[job_id] = cancel
    _update_job(job_id, lambda job: job.update({"status": "running", "started_at": _now()}))
    try:
        while True:
            try:
                event = event_queue.get(timeout=1)
            except queue.Empty:
                continue
            kind = str(event.kind)
            data = dict(event.data)

            def apply(job: Dict[str, Any]) -> None:
                _append_event(job, kind, data)
                index = data.get("index")

                # Detect stage and message from event
                stage_val = data.get("stage")
                msg_val = data.get("message")
                curr_val = data.get("current")
                tot_val = data.get("total")

                if kind == "ida_log_line":
                    line = str(data.get("line") or "")
                    if "OMNI_EVENT" in line:
                        try:
                            omni_json_str = line.split("OMNI_EVENT", 1)[1].strip()
                            parsed_omni = json.loads(omni_json_str)
                            if isinstance(parsed_omni, dict):
                                stage_val = parsed_omni.get("stage") or stage_val
                                msg_val = parsed_omni.get("message") or msg_val
                                curr_val = parsed_omni.get("current") or curr_val
                                tot_val = parsed_omni.get("total") or tot_val
                        except Exception:
                            pass
                elif kind in {"genesect_event", "omni_event", "progress"}:
                    stage_val = data.get("stage") or stage_val
                    msg_val = data.get("message") or msg_val
                    curr_val = data.get("current") or curr_val
                    tot_val = data.get("total") or tot_val
                elif kind == "log":
                    msg_val = data.get("message") or msg_val
                    low_m = str(msg_val).lower()
                    if "analyzing" in low_m:
                        stage_val = "investigation"
                    elif "attribution" in low_m:
                        stage_val = "attribution"
                elif kind == "sample_stage":
                    stage_val = data.get("stage") or stage_val
                    msg_val = data.get("message") or msg_val

                if stage_val:
                    job["current_stage"] = stage_val
                if msg_val:
                    job["stage_message"] = msg_val
                if curr_val is not None and tot_val:
                    try:
                        c_int = int(curr_val)
                        t_int = int(tot_val)
                        job["progress"] = {
                            "current": c_int,
                            "total": t_int,
                            "percent": round(100.0 * c_int / t_int, 1),
                            "stage": job.get("current_stage") or "",
                            "message": job.get("stage_message") or "",
                        }
                    except (ValueError, TypeError):
                        pass

                if isinstance(index, int) and 0 <= index < len(job.get("samples") or []):
                    sample = job["samples"][index]
                    if kind == "sample_started":
                        sample["status"] = "running"
                        sample["stage"] = stage_val or "disasm"
                    elif kind == "sample_status":
                        sample["status"] = data.get("status") or sample["status"]
                    elif kind == "sample_stage":
                        sample["stage"] = data.get("stage") or sample["stage"]
                    elif kind == "sample_finished":
                        sample["status"] = "complete" if data.get("ok") else ("cancelled" if data.get("stopped") else "failed")
                        sample["stage"] = "complete" if data.get("ok") else "failed"
                        sample["message"] = data.get("message") or ""
                        sample["result"] = data.get("result") or {}
                    if stage_val:
                        sample["stage"] = stage_val
                    if msg_val:
                        sample["message"] = msg_val

                if kind == "progress":
                    job["progress"] = data
                if kind == "batch_finished":
                    job["summary"] = {
                        "total": len(job.get("samples") or []),
                        "succeeded": int(data.get("succeeded") or 0),
                        "failed": int(data.get("failed") or 0),
                        "cancelled": bool(data.get("cancelled")),
                    }
                    job["status"] = "cancelled" if data.get("cancelled") else ("failed" if data.get("failed") and not data.get("succeeded") else "complete")
                    job["current_stage"] = "complete" if job["status"] == "complete" else job["status"]
                    job["finished_at"] = _now()

            job = _update_job(job_id, apply)
            if kind == "batch_finished":
                break
    except Exception as exc:
        def fail(job: Dict[str, Any]) -> None:
            job["status"] = "failed"
            job["finished_at"] = _now()
            _append_event(job, "adapter_error", {"message": str(exc)[:1000]})
        _update_job(job_id, fail)
    finally:
        _CANCEL.pop(job_id, None)


def get_job(job_id: str) -> Dict[str, Any]:
    job = _read_json(_job_path(job_id), {})
    if not job:
        raise ValueError("Unknown Binary Lab job.")
    root = OUTPUT_DIR / job_id
    if root.is_dir():
        # Deduplicate deliverables to 1 canonical publication report per sample/directory
        # Group by containing directory to eliminate duplicate base_names (workspace_analysis, malware_analysis_report)
        report_groups = {}
        all_files = [p for p in root.rglob("*") if p.is_file()]

        # 1. First locate HTML reports
        for p in all_files:
            name_l = p.name.lower()
            if name_l.endswith((".html", ".htm")):
                # Folder identifier
                parent_key = str(p.parent.relative_to(root).as_posix())
                if parent_key not in report_groups:
                    report_groups[parent_key] = {"html": None, "pdf": None, "md": None, "dir": p.parent, "companions": []}

                cur_html = report_groups[parent_key]["html"]
                # Preference order: report.html > workspace_analysis.html > malware_analysis_report.html > others
                if cur_html is None:
                    report_groups[parent_key]["html"] = p
                else:
                    if p.name.lower() == "report.html":
                        report_groups[parent_key]["html"] = p
                    elif p.name.lower() == "workspace_analysis.html" and cur_html.name.lower() not in ("report.html", "report.htm"):
                        report_groups[parent_key]["html"] = p

        # 2. Locate companion PDF and MD in the same or related folders
        for p in all_files:
            name_l = p.name.lower()
            if "threat_attribution" in name_l:
                # Do NOT list threat_attribution_result.md as a separate deliverable card!
                continue
            parent_key = str(p.parent.relative_to(root).as_posix())
            if parent_key in report_groups:
                if name_l.endswith(".pdf"):
                    if not report_groups[parent_key]["pdf"] or p.name.lower() == "report.pdf":
                        report_groups[parent_key]["pdf"] = p
                elif name_l.endswith(".md"):
                    if not report_groups[parent_key]["md"] or p.name.lower() == "report.md":
                        report_groups[parent_key]["md"] = p
                elif name_l.endswith((".idb", ".i64", ".zip", ".gzf", ".yar", ".yara")):
                    report_groups[parent_key]["companions"].append(p)

        # 3. Check for threat attribution data across the job root and workspace
        job_attr_hyp = ""
        job_attr_conf = ""
        has_job_attr = False
        for p in all_files:
            if "threat_attribution_result.md" in p.name.lower():
                has_job_attr = True
                try:
                    txt = p.read_text(encoding="utf-8", errors="replace")
                    m_hyp = re.search(r"\*\*Primary Attribution Hypothesis\*\*:\s*([^\r\n]+)", txt)
                    if m_hyp:
                        job_attr_hyp = m_hyp.group(1).strip()
                    m_conf = re.search(r"\*\*Confidence Level\*\*:\s*\*\*?([A-Za-z0-9_-]+)\*\*?", txt)
                    if m_conf:
                        job_attr_conf = m_conf.group(1).strip()
                    break
                except Exception:
                    pass

        # 4. Build canonical reports array (prioritize report/ over AI Workspace/ to guarantee 1 primary report per sample)
        reports = []
        seen_samples = set()
        # Collect companions across all folders for this job/sample
        all_companions = []
        seen_comp_names = set()
        for p in sorted(all_files, key=lambda f: (0 if "report" in str(f).lower() else 1, f.name)):
            if p.name.lower().endswith((".idb", ".i64", ".zip", ".gzf", ".yar", ".yara")):
                if p.name.lower() in seen_comp_names:
                    continue
                seen_comp_names.add(p.name.lower())
                all_companions.append({
                    "name": p.name,
                    "path": p.relative_to(root).as_posix(),
                    "size": p.stat().st_size
                })

        # Sort parent keys so dedicated "report" directories come before "AI Workspace"
        sorted_parent_keys = sorted(
            report_groups.keys(),
            key=lambda k: (0 if "report" in k.lower() else (1 if "workspace" not in k.lower() else 2), k)
        )

        for parent_key in sorted_parent_keys:
            grp = report_groups[parent_key]
            primary = grp["html"]
            if not primary:
                continue

            rel = primary.relative_to(root).as_posix()
            pdf_rel = grp["pdf"].relative_to(root).as_posix() if grp["pdf"] else None
            md_rel = grp["md"].relative_to(root).as_posix() if grp["md"] else None

            # Identify sample
            sample_name = ""
            samples = job.get("samples") or []
            if len(samples) == 1:
                sample_name = samples[0].get("name", "")
            else:
                for s in samples:
                    if s.get("name") and s.get("name").lower() in rel.lower():
                        sample_name = s.get("name")
                        break

            # If we already have a primary report for this sample from a dedicated report directory, skip workspace mirror
            sample_key = sample_name.lower() if sample_name else parent_key
            if sample_key in seen_samples and "workspace" in parent_key.lower():
                continue
            seen_samples.add(sample_key)

            # Detect attribution within the markdown or html
            has_attr = has_job_attr
            attr_hyp = job_attr_hyp
            attr_conf = job_attr_conf

            if not has_attr and grp["md"]:
                try:
                    md_txt = grp["md"].read_text(encoding="utf-8", errors="replace")
                    if "Threat Attribution" in md_txt:
                        has_attr = True
                        m_h = re.search(r"(?:Primary Attribution Hypothesis|Candidate Threat Actor)[:* ]+([^\r\n]+)", md_txt, re.IGNORECASE)
                        if m_h:
                            attr_hyp = m_h.group(1).strip().strip("*`")
                        m_c = re.search(r"(?:Confidence Level|Confidence)[:* ]+\*\*?([A-Za-z0-9_-]+)\*\*?", md_txt, re.IGNORECASE)
                        if m_c:
                            attr_conf = m_c.group(1).strip().strip("*`")
                except Exception:
                    pass

            report_title = f"{sample_name} Malware Analysis Report" if sample_name else "Malware Analysis & Threat Attribution Report"

            # Check for standalone threat attribution report
            attr_report_rel = None
            for p in all_files:
                if "threat_attribution" in p.name.lower() and p.name.lower().endswith(".md"):
                    attr_report_rel = p.relative_to(root).as_posix()
                    break

            reports.append({
                "path": rel,
                "name": primary.name,
                "title": report_title,
                "sample_name": sample_name,
                "category": "Publication Report",
                "is_html": True,
                "is_pdf": False,
                "is_attribution": False,
                "has_attribution": has_attr,
                "attribution_hypothesis": attr_hyp or ("Attributed" if has_attr else ""),
                "attribution_confidence": attr_conf or ("Moderate" if has_attr else ""),
                "attribution_report_path": attr_report_rel,
                "pdf_path": pdf_rel,
                "md_path": md_rel,
                "companion_files": all_companions,
                "size": primary.stat().st_size,
                "modified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(primary.stat().st_mtime)),
            })

        # If no HTML was rendered yet, fallback to single standalone PDF or MD if present
        if not reports:
            for p in all_files:
                name_l = p.name.lower()
                if "threat_attribution" in name_l:
                    continue
                if name_l.endswith((".pdf", ".md")) and name_l not in ("sample.json", "result.json"):
                    reports.append({
                        "path": p.relative_to(root).as_posix(),
                        "name": p.name,
                        "title": p.name,
                        "category": "PDF Report" if name_l.endswith(".pdf") else "Markdown Report",
                        "is_html": False,
                        "is_pdf": name_l.endswith(".pdf"),
                        "is_attribution": False,
                        "has_attribution": False,
                        "size": p.stat().st_size,
                        "modified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(p.stat().st_mtime)),
                    })

        job["reports"] = reports

        # Enrich samples with hashes and counts from sample.json
        for s_idx, sample in enumerate(job.get("samples") or []):
            s_name = sample.get("name", "")
            for s_json in root.rglob("sample.json"):
                try:
                    s_data = _read_json(s_json, {})
                    if s_data and (not s_name or s_name.lower() in str(s_data.get("input_file", "")).lower() or len(job.get("samples") or []) == 1):
                        sample["sha256"] = s_data.get("sha256") or sample.get("sha256", "")
                        sample["md5"] = s_data.get("md5") or sample.get("md5", "")
                        sample["file_type"] = s_data.get("file_type") or sample.get("file_type", "")
                        sample["counts"] = s_data.get("counts") or sample.get("counts", {})
                        if not job.get("counts"):
                            job["counts"] = s_data.get("counts") or {}
                        break
                except Exception:
                    pass

    # Ensure current_stage is set
    if not job.get("current_stage"):
        if job.get("status") in {"complete", "success"}:
            job["current_stage"] = "complete"
        elif job.get("status") in {"failed", "error", "cancelled", "interrupted"}:
            job["current_stage"] = job.get("status")
        else:
            events = job.get("events") or []
            for ev in reversed(events):
                d = ev.get("data") or {}
                stg = d.get("stage") or ev.get("stage")
                if stg:
                    job["current_stage"] = stg
                    break
            if not job.get("current_stage"):
                job["current_stage"] = "running" if job.get("status") == "running" else "queued"

    return job


def get_job_catalogs(job_id: str, sample_index: int = 0) -> Dict[str, Any]:
    job = _read_json(_job_path(job_id), {})
    if not job:
        raise ValueError("Job not found.")
    root = OUTPUT_DIR / job_id
    samples = job.get("samples") or []
    sample_name = samples[sample_index].get("name", "") if 0 <= sample_index < len(samples) else ""

    sample_dir = None
    if root.is_dir():
        for d in root.iterdir():
            if d.is_dir() and (not sample_name or sample_name.lower() in d.name.lower()):
                sample_dir = d
                break
        if not sample_dir:
            subdirs = [d for d in root.iterdir() if d.is_dir()]
            if subdirs:
                sample_dir = subdirs[0]

    out = {
        "job_id": job_id,
        "sample_index": sample_index,
        "sample_name": sample_name,
        "functions": [],
        "variables": [],
        "triage": {},
        "summary": {},
    }
    if not sample_dir:
        return out

    catalog_dir = None
    for candidate in (sample_dir / "AI Workspace" / "catalog", sample_dir / "catalog", sample_dir / "workspace" / "catalog"):
        if candidate.is_dir():
            catalog_dir = candidate
            break

    if catalog_dir:
        fn_path = catalog_dir / "functions.json"
        if fn_path.is_file():
            try:
                out["functions"] = _read_json(fn_path, [])
            except Exception:
                pass

        var_path = catalog_dir / "function_variables.json"
        if var_path.is_file():
            try:
                var_raw = _read_json(var_path, {})
                var_items = []
                ws_dir = catalog_dir.parent
                vars_dir = ws_dir / "functions" / "variables"
                if vars_dir.is_dir():
                    for vf in sorted(vars_dir.glob("*.json"))[:500]:
                        vdata = _read_json(vf, {})
                        fn_addr = vdata.get("function") or vf.stem
                        fn_name = vdata.get("name") or fn_addr
                        for var_entry in vdata.get("variables") or []:
                            var_items.append({
                                "function_address": fn_addr,
                                "function_name": fn_name,
                                "name": var_entry.get("name"),
                                "type": var_entry.get("type"),
                                "location": var_entry.get("location"),
                                "argument": bool(var_entry.get("argument")),
                                "width": var_entry.get("width"),
                                "user_name": bool(var_entry.get("user_name")),
                            })
                elif isinstance(var_raw, dict) and isinstance(var_raw.get("index"), list):
                    for entry in var_raw["index"]:
                        var_items.append({
                            "function_address": entry.get("function"),
                            "function_name": entry.get("name"),
                            "count": entry.get("variables", 0),
                        })
                elif isinstance(var_raw, list):
                    var_items = var_raw
                out["variables"] = var_items
            except Exception:
                pass

        triage_path = catalog_dir / "triage_indicators.json"
        if triage_path.is_file():
            try:
                out["triage"] = _read_json(triage_path, {})
            except Exception:
                pass

        sample_json = catalog_dir / "sample.json"
        if sample_json.is_file():
            try:
                out["summary"] = _read_json(sample_json, {})
            except Exception:
                pass

    return out


def get_job_ida_log(job_id: str, sample_index: int = 0) -> Dict[str, Any]:
    job = _read_json(_job_path(job_id), {})
    if not job:
        raise ValueError("Job not found.")
    root = OUTPUT_DIR / _validate_job_id(job_id)

    log_file = None
    if root.is_dir():
        for candidate in root.rglob("*"):
            if candidate.is_file() and candidate.name.lower() in ("ida.log", "ghidra.log", "analysis.log", "runner.log", "decompile.log"):
                log_file = candidate
                if candidate.name.lower() == "ida.log":
                    break

    content = ""
    if log_file and log_file.is_file():
        try:
            content = log_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            pass

    if not content:
        lines = []
        for ev in job.get("events") or []:
            if ev.get("kind") in {"ida_log_line", "log", "omni_event", "sample_stage"}:
                data = ev.get("data") or {}
                t = ev.get("time") or ""
                msg = data.get("line") or data.get("message") or ev.get("message") or ""
                if msg:
                    lines.append(f"[{t}] {msg}")
        content = "\n".join(lines)

    return {
        "job_id": job_id,
        "sample_index": sample_index,
        "content": content,
        "size": len(content),
        "lines_count": len(content.splitlines()),
    }


def list_jobs(limit: int = 50) -> Dict[str, Any]:
    _ensure_dirs()
    rows = []
    for path in sorted(JOBS_DIR.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True)[:max(1, min(200, limit))]:
        job = _read_json(path, None)
        if not job or not isinstance(job, dict):
            continue
        if job.get("status") in {"queued", "running", "cancelling"} and job.get("job_id") not in _CANCEL:
            job["status"] = "interrupted"
            job["finished_at"] = job.get("finished_at") or _now()
            _append_event(job, "interrupted", {"message": "MANTIS restarted while this job was active; resume is available."})
            try:
                _write_json(path, job)
            except Exception:
                pass
        if "has_html_report" not in job or "has_attribution_report" not in job:
            root = OUTPUT_DIR / job.get("job_id", "")
            if root.is_dir():
                has_html = False
                has_attr = False
                for p in root.rglob("*"):
                    if p.is_file():
                        nl = p.name.lower()
                        if nl.endswith((".html", ".htm")):
                            has_html = True
                        if "threat_attribution" in nl:
                            has_attr = True
                        if has_html and has_attr:
                            break
                job["has_html_report"] = has_html
                job["has_attribution_report"] = has_attr
            else:
                job["has_html_report"] = False
                job["has_attribution_report"] = False
        rows.append(job)
    return {"jobs": rows}


def cancel_job(job_id: str) -> Dict[str, Any]:
    job = get_job(job_id)
    event = _CANCEL.get(job_id)
    if event:
        event.set()
        return _update_job(job_id, lambda j: j.update({"status": "cancelling"}))
    if job.get("status") in {"queued", "running"}:
        return _update_job(job_id, lambda j: j.update({"status": "cancelled", "finished_at": _now()}))
    return {}


def resume_job(job_id: str) -> Dict[str, Any]:
    job = get_job(job_id)
    if job.get("status") in {"queued", "running", "cancelling"}:
        raise ValueError("Binary Lab job is already active.")
    samples = []
    for item in job.get("samples") or []:
        path = Path(str(item.get("path") or ""))
        if not path.is_file():
            continue
        try:
            kind = classify_sample(path)
        except ClassifyError:
            continue
        samples.append(Sample(path=path, size=path.stat().st_size, kind=kind))
    if not samples:
        raise ValueError("Original samples are unavailable; this job cannot be resumed.")
    effective = {**DEFAULT_SETTINGS, **(job.get("settings") or {})}
    def reset(current: Dict[str, Any]) -> None:
        current["status"] = "queued"
        current["finished_at"] = ""
        current["summary"] = {"total": len(samples), "succeeded": 0, "failed": 0, "cancelled": False}
        _append_event(current, "resume_requested", {"message": "Resuming binary analysis from existing output."})
    updated = _update_job(job_id, reset)
    threading.Thread(target=_run_job, args=(job_id, samples, effective, True), daemon=True, name=f"binary-lab-{job_id}-resume").start()
    return updated


def delete_job(job_id: str) -> Dict[str, Any]:
    job = get_job(job_id)
    if job.get("status") in {"queued", "running", "cancelling"}:
        raise ValueError("Stop the Binary Lab job before deleting it.")
    output = OUTPUT_DIR / _validate_job_id(job_id)
    if output.is_dir():
        shutil.rmtree(output, ignore_errors=True)
    upload_roots = set()
    for sample in job.get("samples") or []:
        path = Path(str(sample.get("path") or ""))
        try:
            resolved = path.resolve()
            uploads = UPLOADS_DIR.resolve()
            if uploads in resolved.parents:
                upload_roots.add(resolved.parent)
        except OSError:
            continue
    for root in upload_roots:
        if root.is_dir() and UPLOADS_DIR.resolve() in root.resolve().parents:
            shutil.rmtree(root, ignore_errors=True)
    _job_path(job_id).unlink(missing_ok=True)
    return {"deleted": True, "job_id": job_id}


def _output_root(job_id: str) -> Path:
    root = OUTPUT_DIR / _validate_job_id(job_id)
    if not root.is_dir():
        raise ValueError("Binary Lab output is not available.")
    return root.resolve()


def list_artifacts(job_id: str) -> Dict[str, Any]:
    root = _output_root(job_id)
    files = []
    reports = []
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            resolved = path.resolve()
            if root not in resolved.parents:
                continue
            rel = path.relative_to(root).as_posix()
            name_l = path.name.lower()
            rec = {
                "path": rel,
                "name": path.name,
                "size": path.stat().st_size,
                "modified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(path.stat().st_mtime)),
            }
            files.append(rec)
            if name_l.endswith((".html", ".htm", ".pdf")) or "threat_attribution" in name_l or name_l in ("report.md", "workspace_analysis.md", "malware_analysis_report.md"):
                is_html = name_l.endswith((".html", ".htm"))
                is_pdf = name_l.endswith(".pdf")
                is_attr = "threat_attribution" in name_l
                cat = "HTML Report" if is_html else ("PDF Report" if is_pdf else ("Threat Attribution" if is_attr else "Markdown Report"))
                rep_rec = dict(rec)
                rep_rec["category"] = cat
                rep_rec["is_html"] = is_html
                rep_rec["is_pdf"] = is_pdf
                rep_rec["is_attribution"] = is_attr
                reports.append(rep_rec)
    def _sort_key(r):
        prio = 0 if r["is_html"] else (1 if r["is_attribution"] else (2 if r["is_pdf"] else 3))
        return (prio, r["name"])
    return {
        "job_id": job_id,
        "reports": sorted(reports, key=_sort_key),
        "files": sorted(files, key=lambda item: item["path"].lower()),
    }


def artifact_path(job_id: str, relative_path: str) -> Path:
    root = _output_root(job_id)
    clean_rel = str(relative_path or "").lstrip("/\\")
    candidate = (root / clean_rel).resolve()
    if candidate.is_symlink() or (candidate != root and root not in candidate.parents):
        raise ValueError("Invalid artifact path.")
    if not candidate.is_file():
        raise ValueError("Artifact not found.")
    return candidate


def zip_output(job_id: str) -> bytes:
    root = _output_root(job_id)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in root.rglob("*"):
            if path.is_file() and not path.is_symlink():
                resolved = path.resolve()
                if root not in resolved.parents:
                    continue
                archive.write(path, path.relative_to(root).as_posix())
    return buffer.getvalue()


def _load_sample_catalogs(output_root_str: str, result: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "metadata": {},
        "indicators": [],
        "network_indicators": [],
        "imports": [],
        "report_summary": "",
    }
    ws_candidate = result.get("workspace_path")
    ws_path = Path(ws_candidate) if ws_candidate and Path(ws_candidate).is_dir() else None

    if not ws_path and output_root_str:
        out_root = Path(output_root_str)
        if out_root.is_dir():
            for child in out_root.glob("**/AI Workspace"):
                if child.is_dir():
                    ws_path = child
                    break

    if not ws_path or not ws_path.is_dir():
        return out

    catalog_dir = ws_path / "catalog"
    for m_name in ("assembly.json", "metadata.json", "sample.json"):
        m_file = catalog_dir / m_name
        if m_file.is_file():
            try:
                out["metadata"] = json.loads(m_file.read_text(encoding="utf-8"))
                break
            except Exception:
                pass

    t_file = catalog_dir / "triage_indicators.json"
    if t_file.is_file():
        try:
            t_data = json.loads(t_file.read_text(encoding="utf-8"))
            if isinstance(t_data, dict) and "indicators" in t_data:
                out["indicators"] = t_data["indicators"]
            elif isinstance(t_data, list):
                out["indicators"] = t_data
        except Exception:
            pass

    s_file = catalog_dir / "strings.json"
    if s_file.is_file():
        try:
            s_data = json.loads(s_file.read_text(encoding="utf-8"))
            ip_re = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
            domain_re = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
            seen_net = set()
            for item in (s_data if isinstance(s_data, list) else []):
                val = str(item.get("value") or "").strip()
                if not val or len(val) < 4:
                    continue
                lower = val.lower()
                if lower.startswith(("http://", "https://")):
                    if val not in seen_net:
                        seen_net.add(val)
                        out["network_indicators"].append(val)
                elif ip_re.match(val) and not val.startswith(("127.", "0.", "255.")):
                    if val not in seen_net:
                        seen_net.add(val)
                        out["network_indicators"].append(val)
                elif domain_re.match(val) and not val.endswith((".exe", ".dll", ".sys", ".txt", ".json", ".xml", ".pdb")):
                    if val not in seen_net:
                        seen_net.add(val)
                        out["network_indicators"].append(val)
        except Exception:
            pass

    i_file = catalog_dir / "imports.json"
    if i_file.is_file():
        try:
            i_data = json.loads(i_file.read_text(encoding="utf-8"))
            if isinstance(i_data, list):
                out["imports"] = [f"{x.get('library')}!{x.get('name')}" for x in i_data[:40] if x.get("name")]
        except Exception:
            pass

    rep_candidate = result.get("workspace_analysis_report")
    rep_file = Path(rep_candidate) if rep_candidate and Path(rep_candidate).is_file() else (ws_path.parent / "report" / "report.md")
    if rep_file.is_file():
        try:
            text = rep_file.read_text(encoding="utf-8")
            lines = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]
            out["report_summary"] = " ".join(lines)[:400]
        except Exception:
            pass

    attr_file = ws_path / "threat_attribution_result.md"
    if not attr_file.is_file():
        attr_file = ws_path.parent / "report" / "threat_attribution_result.md"
    if attr_file.is_file():
        try:
            out["threat_attribution"] = attr_file.read_text(encoding="utf-8")
        except Exception:
            pass

    return out


def create_case(job_id: str, sample_index: int = 0) -> Dict[str, Any]:
    job = get_job(job_id)
    samples = job.get("samples") or []
    if not (0 <= sample_index < len(samples)):
        raise ValueError("Binary Lab sample index is invalid.")
    sample = samples[sample_index]
    sha256 = sample.get("sha256") or ""
    result = sample.get("result") if isinstance(sample.get("result"), dict) else {}
    catalogs = _load_sample_catalogs(job.get("output_root") or "", result)

    artifacts = [{"type": "hash", "value": sha256, "sources": ["binary_lab"]}]
    if sample.get("name"):
        artifacts.append({"type": "filename", "value": sample["name"], "sources": ["binary_lab"]})
    for net in catalogs.get("network_indicators", []):
        t = "url" if net.startswith(("http://", "https://")) else ("ip" if re.match(r"^\d+\.\d+\.\d+\.\d+$", net) else "domain")
        artifacts.append({"type": t, "value": net, "sources": ["binary_lab"]})

    findings_payload = {
        "job_id": job_id,
        "sample": sample,
        "result": result,
        "output_root": job.get("output_root"),
        "metadata": catalogs.get("metadata", {}),
        "indicators": catalogs.get("indicators", []),
        "network_indicators": catalogs.get("network_indicators", []),
        "imports": catalogs.get("imports", []),
        "report_summary": catalogs.get("report_summary", ""),
        "threat_attribution": catalogs.get("threat_attribution", ""),
    }

    context = {
        "page": "hash",
        "query": {"value": sha256},
        "providers": [{"provider": "binary_lab", "status": "findings_or_context", "count": 1, "error": ""}],
        "artifacts": artifacts,
        "findings": {
            "binary_lab": findings_payload
        },
    }
    return ai_case_service.sync_case_from_context(context, note=f"Imported Binary Lab analysis from {job_id}.")


create_case_from_job = create_case
bundle_job = zip_output

