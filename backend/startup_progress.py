"""Thread-safe progress registry for first-run data downloads.

Background download jobs (YARA rules, MISP galaxies, PoC index, ...) report
here so the UI can show a progress bar per dataset while the server is up.

Each task is a dict:
    key, label, state ("waiting" | "running" | "done" | "skipped" | "error"),
    done, total (None when unknown), unit, message, updated_at (epoch seconds)
"""
import threading
import time
from typing import Dict, Optional

_lock = threading.Lock()
_tasks: Dict[str, dict] = {}
_order: list = []


def register(key: str, label: str, total: Optional[int] = None, unit: str = "files") -> None:
    """Declare a task up front so the UI can list it before it starts."""
    with _lock:
        if key not in _tasks:
            _order.append(key)
        _tasks[key] = {
            "key": key,
            "label": label,
            "state": "waiting",
            "done": 0,
            "total": total,
            "unit": unit,
            "message": "Waiting to start",
            "updated_at": time.time(),
        }


def _update(key: str, **fields) -> None:
    with _lock:
        task = _tasks.get(key)
        if task is None:
            return
        task.update(fields)
        task["updated_at"] = time.time()


def start(key: str, total: Optional[int] = None, message: str = "") -> None:
    fields = {"state": "running", "done": 0, "message": message or "Downloading"}
    if total is not None:
        fields["total"] = total
    _update(key, **fields)


def set_total(key: str, total: Optional[int]) -> None:
    _update(key, total=total)


def advance(key: str, n: int = 1, message: Optional[str] = None) -> None:
    with _lock:
        task = _tasks.get(key)
        if task is None:
            return
        task["done"] = task.get("done", 0) + n
        if message is not None:
            task["message"] = message
        task["updated_at"] = time.time()


def set_bytes(key: str, done: int, total: Optional[int]) -> None:
    """Byte-level progress for single-file downloads (unit='bytes')."""
    with _lock:
        task = _tasks.get(key)
        if task is None:
            return
        task["done"] = done
        task["total"] = total
        task["unit"] = "bytes"
        task["message"] = "Downloading"
        task["updated_at"] = time.time()


def finish(key: str, message: str = "Ready") -> None:
    with _lock:
        task = _tasks.get(key)
        if task is None:
            return
        task["state"] = "done"
        if task.get("total") is not None:
            task["done"] = task["total"]
        task["message"] = message
        task["updated_at"] = time.time()


def skip(key: str, message: str = "Already up to date") -> None:
    _update(key, state="skipped", message=message)


def fail(key: str, message: str) -> None:
    _update(key, state="error", message=message)


def snapshot() -> dict:
    """Return tasks in registration order plus an overall readiness summary."""
    with _lock:
        tasks = [dict(_tasks[k]) for k in _order]
    active = [t for t in tasks if t["state"] in ("waiting", "running")]
    return {
        "ready": not active,
        "pending": len(active),
        "tasks": tasks,
    }
