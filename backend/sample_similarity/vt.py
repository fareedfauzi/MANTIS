"""VirusTotal as an external corroboration signal for sample similarity.

Design (see the revamp notes):
  * Hash-only lookup. The sample is never uploaded to VirusTotal here.
  * Reuses the IOC Search lookup (intel_query.query_vt for the file object and
    query_vt_relation for comments), so there is one code path for keys and
    errors.
  * The full file object and every comment page are stored per SHA-256 with a
    `fetched_at` timestamp. A snapshot younger than CACHE_TTL is reused, so a
    repeat compare does not spend quota.
  * Requests are throttled to MIN_INTERVAL seconds apart. The public key allows
    4 requests a minute, so this is the default. It can be set with
    MANTIS_VT_MIN_INTERVAL.
  * VT labels feed one profile kind ("vt") that is scored as one small
    feature. They never give exact-match status and never count toward the
    two-feature label gate.
"""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

CACHE_TTL = timedelta(days=7)
MAX_COMMENT_PAGES = 5
COMMENT_PAGE = 40
MIN_INTERVAL = float(os.environ.get("MANTIS_VT_MIN_INTERVAL", "15"))
_KEY_ENVS = ("VT_API_KEY", "VIRUSTOTAL_API_KEY", "MANTIS_VT_KEY", "IOCINTEL_VT_KEY")

_THROTTLE_LOCK = threading.Lock()
_last_call = [0.0]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def resolve_key(explicit: Optional[str] = None) -> str:
    """Same key lookup order as IOC Search (env vars)."""
    if explicit and explicit.strip():
        return explicit.strip()
    for name in _KEY_ENVS:
        val = os.environ.get(name, "").strip()
        if val:
            return val
    return ""


def key_configured() -> bool:
    return bool(resolve_key())


def _throttle() -> None:
    with _THROTTLE_LOCK:
        wait = MIN_INTERVAL - (time.monotonic() - _last_call[0])
        if wait > 0:
            time.sleep(wait)
        _last_call[0] = time.monotonic()


def fetch(sha256: str, key: str) -> dict:
    """Fetch the file object and all comment pages. Returns a snapshot dict.

    Never raises for VT-side problems. The status field says what happened:
    ok | not_found | rate_limited | error.
    """
    # Imported here so the module loads even when the IOC Search deps are absent.
    from intel_query import query_vt, query_vt_relation

    snap = {"sha256": sha256, "fetched_at": _now().isoformat(timespec="seconds"),
            "status": "ok", "file": None, "comments": [], "comments_truncated": False, "error": ""}

    _throttle()
    obj = query_vt(sha256, "hash", key)
    if obj.get("error"):
        err = str(obj["error"])
        if err == "Not Found":
            snap["status"] = "not_found"
        elif "429" in err:
            snap["status"] = "rate_limited"
        else:
            snap["status"] = "error"
        snap["error"] = err[:200]
        return snap
    snap["file"] = obj.get("data", obj)

    # Comments: first page via the shared IOC helper, then follow the cursor.
    cursor = None
    for page in range(MAX_COMMENT_PAGES):
        _throttle()
        if page == 0:
            rel = query_vt_relation(sha256, "hash", "comments", key, limit=COMMENT_PAGE)
        else:
            rel = _comments_page(sha256, key, cursor)
        if rel.get("error"):
            if "429" in str(rel["error"]):
                snap["status"] = "rate_limited"
            snap["error"] = str(rel["error"])[:200]
            break
        snap["comments"].extend(rel.get("data", []) or [])
        cursor = (rel.get("meta") or {}).get("cursor")
        if not cursor:
            break
    else:
        snap["comments_truncated"] = True
    return snap


def _comments_page(sha256: str, key: str, cursor: str) -> dict:
    import requests
    url = f"https://www.virustotal.com/api/v3/files/{sha256}/comments"
    try:
        resp = requests.get(url, headers={"x-apikey": key}, params={"limit": COMMENT_PAGE, "cursor": cursor}, timeout=15)
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code == 429:
            return {"error": "Quota Exceeded (HTTP 429)"}
        return {"error": f"Status {resp.status_code}"}
    except Exception as exc:
        return {"error": str(exc)}


def get_snapshot(conn, sha256: str) -> Optional[dict]:
    row = conn.execute("SELECT fetched_at, payload FROM vt_snapshots WHERE sha256=?", (sha256,)).fetchone()
    if not row:
        return None
    snap = json.loads(row["payload"])
    snap["fetched_at"] = row["fetched_at"]
    return snap


def is_fresh(snap: Optional[dict]) -> bool:
    if not snap or snap.get("status") not in ("ok", "not_found"):
        return False
    try:
        age = _now() - datetime.fromisoformat(snap["fetched_at"])
    except Exception:
        return False
    return age < CACHE_TTL


def save_snapshot(conn, snap: dict) -> None:
    payload = json.dumps({k: v for k, v in snap.items() if k != "fetched_at"}, separators=(",", ":"))
    conn.execute(
        "INSERT INTO vt_snapshots(sha256, fetched_at, status, payload) VALUES (?,?,?,?) "
        "ON CONFLICT(sha256) DO UPDATE SET fetched_at=excluded.fetched_at, status=excluded.status, payload=excluded.payload",
        (snap["sha256"], snap["fetched_at"], snap["status"], payload),
    )


def lookup(conn, sha256: str, key: str, refresh: bool = False) -> dict:
    """Cached lookup: reuse a fresh snapshot, otherwise fetch and store one."""
    cached = get_snapshot(conn, sha256)
    if not refresh and is_fresh(cached):
        cached["cached"] = True
        return cached
    snap = fetch(sha256, key)
    save_snapshot(conn, snap)
    snap["cached"] = False
    return snap


# --------------------------------------------------------------------------- features

def _threat_labels(file_obj: dict) -> Dict[str, str]:
    """Named threat labels VirusTotal assigns. Only these become profile items."""
    out: Dict[str, str] = {}
    pt = (file_obj or {}).get("popular_threat_classification") or {}
    if pt.get("suggested_threat_label"):
        out["label"] = str(pt["suggested_threat_label"]).strip().lower()
    for item in (pt.get("popular_threat_category") or [])[:5]:
        v = (item or {}).get("value")
        if v:
            out.setdefault("category", str(v).strip().lower())
    for item in (pt.get("popular_threat_name") or [])[:5]:
        v = (item or {}).get("value")
        if v:
            out.setdefault("name", str(v).strip().lower())
    return out


def profile_items(snap: Optional[dict]) -> List[str]:
    """Items for the 'vt' profile kind. Empty unless VT returned a record."""
    if not snap or snap.get("status") != "ok" or not snap.get("file"):
        return []
    labels = _threat_labels(snap["file"])
    return [f"vt:{k}={v}" for k, v in sorted(labels.items())]


def detection_summary(snap: Optional[dict]) -> dict:
    """Context shown beside the result. Not scored."""
    if not snap or snap.get("status") != "ok" or not snap.get("file"):
        return {"status": (snap or {}).get("status", "not_configured")}
    f = snap["file"]
    stats = f.get("last_analysis_stats") or {}
    total = sum(stats.get(k, 0) for k in ("malicious", "suspicious", "undetected", "harmless"))
    flagged = stats.get("malicious", 0) + stats.get("suspicious", 0)
    return {
        "status": "ok",
        "fetched_at": snap.get("fetched_at", ""),
        "cached": bool(snap.get("cached")),
        "flagged": flagged,
        "engines": total,
        "labels": _threat_labels(f),
        "names": (f.get("names") or [])[:5],
        "comments": len(snap.get("comments") or []),
        "comments_truncated": bool(snap.get("comments_truncated")),
        "first_submission": f.get("first_submission_date"),
        "last_analysis": f.get("last_analysis_date"),
    }
