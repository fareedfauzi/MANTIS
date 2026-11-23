"""Persistent snapshot-first access for Kaspersky TIP threat-actor pages."""

from __future__ import annotations

import os
import threading
from typing import Any, Callable, Dict

import persistent_snapshot
from intel_query import query_tip_actors, query_tip_actor_profile, query_tip_actor_samples


INTERVAL_SECONDS = 24 * 3600
_LAST_KEY = ""
_STOP = threading.Event()
_THREAD: threading.Thread | None = None
_KEY_WARMED = False
_KEY_WARM_LOCK = threading.Lock()


def _configured_key() -> str:
    return (
        _LAST_KEY
        or os.environ.get("KASPERSKY_TIP_API_KEY", "")
        or os.environ.get("MANTIS_KASPERSKY_TIP_KEY", "")
        or os.environ.get("KTIP_API_KEY", "")
    ).strip()


def _cached(kind: str, identity: str, api_key: str, fetch: Callable[[], Dict[str, Any]],
            force_refresh: bool = False) -> Dict[str, Any]:
    global _LAST_KEY, _KEY_WARMED
    key = (api_key or _configured_key()).strip()
    if not key:
        return {"error": "No API Key provided"}
    new_runtime_key = not bool(_LAST_KEY)
    _LAST_KEY = key
    snapshot_key = {"kind": kind, "identity": identity}
    previous = persistent_snapshot.load("kaspersky_threat_actors", snapshot_key)
    if previous and not force_refresh:
        if kind == "actors" and new_runtime_key:
            with _KEY_WARM_LOCK:
                warm_now = not _KEY_WARMED
                _KEY_WARMED = True
            if warm_now:
                threading.Thread(
                    target=lambda: actors(key, force_refresh=True),
                    name="kaspersky-actor-key-warmup",
                    daemon=True,
                ).start()
        return persistent_snapshot.decorate(
            previous.get("data", {}), "cache", previous, "Served from the latest Kaspersky snapshot"
        )
    try:
        data = fetch()
    except Exception as exc:
        data = {"error": str(exc)}
    if isinstance(data, dict) and not data.get("error"):
        envelope = persistent_snapshot.save("kaspersky_threat_actors", snapshot_key, data)
        return persistent_snapshot.decorate(data, "live", envelope, "Kaspersky TIP refreshed successfully")
    if previous:
        return persistent_snapshot.decorate(
            previous.get("data", {}), "stale", previous,
            "Kaspersky TIP is unavailable; using the last successful snapshot",
        )
    return data


def actors(api_key: str = "", force_refresh: bool = False) -> Dict[str, Any]:
    key = (api_key or _configured_key()).strip()
    return _cached("actors", "all", key, lambda: query_tip_actors(key), force_refresh)


def profile(actor_id: str, api_key: str = "", force_refresh: bool = False) -> Dict[str, Any]:
    key = (api_key or _configured_key()).strip()
    return _cached("profile", actor_id, key, lambda: query_tip_actor_profile(actor_id, key), force_refresh)


def samples(actor_id: str, api_key: str = "", force_refresh: bool = False) -> Dict[str, Any]:
    key = (api_key or _configured_key()).strip()
    return _cached("samples", actor_id, key, lambda: query_tip_actor_samples(actor_id, key), force_refresh)


def _loop() -> None:
    if _configured_key():
        actors(force_refresh=True)
    while not _STOP.wait(INTERVAL_SECONDS):
        if _configured_key():
            actors(force_refresh=True)


def start_scheduler() -> None:
    global _THREAD
    if _THREAD and _THREAD.is_alive():
        return
    _STOP.clear()
    _THREAD = threading.Thread(target=_loop, name="kaspersky-actor-snapshots", daemon=True)
    _THREAD.start()


def stop_scheduler() -> None:
    _STOP.set()
