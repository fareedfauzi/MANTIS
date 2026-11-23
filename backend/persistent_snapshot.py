"""Small, secret-free persistent JSON snapshot store for intelligence features."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
import threading
from typing import Any, Dict


DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "intelligence_snapshots")
_LOCK = threading.RLock()


def _now_text() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _digest(key: Any) -> str:
    raw = json.dumps(key, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def save(namespace: str, key: Any, data: Any) -> Dict[str, Any]:
    snapshot_id = _digest(key)
    day = datetime.now(timezone.utc).date().isoformat()
    envelope = {"version": 1, "fetched_at": _now_text(), "data": data}
    paths = (
        os.path.join(DATA_DIR, namespace, "latest", f"{snapshot_id}.json"),
        os.path.join(DATA_DIR, namespace, day, f"{snapshot_id}.json"),
    )
    with _LOCK:
        for path in paths:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            temp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
            with open(temp, "w", encoding="utf-8") as handle:
                json.dump(envelope, handle, ensure_ascii=False, separators=(",", ":"))
            os.replace(temp, path)
    return envelope


def load(namespace: str, key: Any) -> Dict[str, Any] | None:
    snapshot_id = _digest(key)
    root = os.path.join(DATA_DIR, namespace)
    candidates = [os.path.join(root, "latest", f"{snapshot_id}.json")]
    if os.path.isdir(root):
        candidates.extend(
            os.path.join(root, day, f"{snapshot_id}.json")
            for day in sorted((name for name in os.listdir(root) if name != "latest"), reverse=True)
        )
    with _LOCK:
        for path in candidates:
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    envelope = json.load(handle)
                if isinstance(envelope, dict) and "data" in envelope:
                    return envelope
            except (OSError, ValueError, TypeError):
                continue
    return None


def decorate(data: Any, mode: str, envelope: Dict[str, Any] | None = None, message: str = "") -> Any:
    if not isinstance(data, dict):
        return data
    result = dict(data)
    result["_snapshot"] = {
        "mode": mode,
        "snapshot_at": (envelope or {}).get("fetched_at", ""),
        "message": message,
    }
    return result
