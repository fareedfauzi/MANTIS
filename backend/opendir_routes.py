"""REST API for Open Directory Hunting: /api/opendir/*"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

import auth_service
import opendir_hunt as od

router = APIRouter(prefix="/api/opendir", tags=["opendir"])


def get_current_user(
    request: Request,
    authorization: Optional[str] = Header(None),
    mantis_session: Optional[str] = Cookie(None),
) -> Dict[str, Any]:
    """Delegates to main.get_current_user (resolved at request time to avoid a circular import)."""
    import main as _main
    return _main.get_current_user(request, authorization, mantis_session)

PROVIDER_KEY_NAMES = ("fofa", "zoomeye", "censys", "shodan")


def _user_keys(user: Dict[str, Any]) -> Dict[str, str]:
    uid = user.get("id") or user.get("user_id") or user.get("username")
    keys: Dict[str, str] = {}
    try:
        stored = auth_service.get_all_user_api_keys(uid, mask=False) or {}
    except Exception:
        stored = {}
    for p in PROVIDER_KEY_NAMES:
        v = stored.get(p)
        if v:
            keys[p] = v
    return keys


def _user_id(user: Dict[str, Any]) -> str:
    return str(user.get("id") or user.get("user_id") or user.get("username") or "unknown")


def _rows(cur) -> List[Dict[str, Any]]:
    return [dict(r) for r in cur.fetchall()]


def _dir_out(row: Dict[str, Any]) -> Dict[str, Any]:
    d = dict(row)
    d["interest_reasons"] = json.loads(d.get("interest_reasons") or "[]")
    d["effective_class"] = od.effective_classification(d)
    return d


class JobCreate(BaseModel):
    mode: str = Field(..., pattern="^(global|targeted|keyword)$")
    query: str = Field("", max_length=2000)
    providers: List[str] = Field(default_factory=list)
    max_depth: Optional[int] = Field(None, ge=0, le=6)
    max_files_per_dir: Optional[int] = Field(None, ge=1, le=5000)
    max_dirs: Optional[int] = Field(None, ge=1, le=500)
    max_results_per_provider: Optional[int] = Field(None, ge=1, le=1000)
    country: Optional[str] = Field(None, max_length=2)


class OverrideBody(BaseModel):
    override: Optional[str] = Field(None, pattern="^(confirmed_interest|false_positive)$")
    note: str = Field("", max_length=500)


class WatchBody(BaseModel):
    interval_minutes: int = Field(1440, ge=60, le=10080)
    enabled: bool = True
    notes: str = Field("", max_length=500)


@router.get("/status")
def status(user: Dict[str, Any] = Depends(get_current_user)):
    keys = _user_keys(user)
    return {"providers": od.provider_status(keys)}


@router.get("/overview")
def overview(user: Dict[str, Any] = Depends(get_current_user)):
    conn = od.db()
    try:
        counts = {r["status"]: r["n"] for r in conn.execute(
            "SELECT status, COUNT(*) n FROM opendir_directories GROUP BY status")}
        cls = {r["c"]: r["n"] for r in conn.execute(
            "SELECT interest_class c, COUNT(*) n FROM opendir_directories WHERE status='verified' GROUP BY interest_class")}
        files = conn.execute("SELECT COUNT(*) n FROM opendir_files WHERE removed_at IS NULL").fetchone()["n"]
        jobs = {r["status"]: r["n"] for r in conn.execute("SELECT status, COUNT(*) n FROM opendir_hunting_jobs GROUP BY status")}
        watch = conn.execute("SELECT COUNT(*) n FROM opendir_watchlist WHERE enabled=1").fetchone()["n"]
        recent = _rows(conn.execute(
            """SELECT id, url, interest_score, interest_class, file_count, last_seen FROM opendir_directories
               WHERE status='verified' ORDER BY interest_score DESC, last_seen DESC LIMIT 10"""))
        return {"directories": counts, "verified_by_class": cls, "active_files": files,
                "jobs": jobs, "watchlist_enabled": watch, "top_directories": recent}
    finally:
        conn.close()


@router.get("/directories")
def list_directories(
    status: Optional[str] = Query(None, pattern="^(discovered|verified|rejected|inaccessible|error)$"),
    min_score: int = Query(0, ge=0, le=100),
    classification: Optional[str] = Query(None, pattern="^(high|medium|low)$"),
    host: Optional[str] = Query(None, max_length=255),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user: Dict[str, Any] = Depends(get_current_user),
):
    # Verified listings with no files are hidden; the crawler still follows their subfolders.
    where, args = ["interest_score >= ?", "NOT (status='verified' AND file_count=0)"], [min_score]
    if status:
        where.append("status=?")
        args.append(status)
    if classification:
        where.append("interest_class=?")
        args.append(classification)
    if host:
        where.append("host LIKE ?")
        args.append(f"%{host.lower()}%")
    conn = od.db()
    try:
        total = conn.execute(f"SELECT COUNT(*) n FROM opendir_directories WHERE {' AND '.join(where)}", args).fetchone()["n"]
        rows = _rows(conn.execute(
            f"""SELECT * FROM opendir_directories WHERE {' AND '.join(where)}
                ORDER BY interest_score DESC, last_seen DESC LIMIT ? OFFSET ?""", [*args, limit, offset]))
        return {"total": total, "items": [_dir_out(r) for r in rows]}
    finally:
        conn.close()


@router.get("/directories/{dir_id}")
def get_directory(dir_id: int, user: Dict[str, Any] = Depends(get_current_user)):
    conn = od.db()
    try:
        row = conn.execute("SELECT * FROM opendir_directories WHERE id=?", (dir_id,)).fetchone()
        if not row:
            raise HTTPException(404, "directory not found")
        sources = _rows(conn.execute(
            "SELECT provider, query, source_kind, job_id, discovered_at FROM opendir_discovery_sources WHERE directory_id=? ORDER BY discovered_at", (dir_id,)))
        watch = conn.execute("SELECT * FROM opendir_watchlist WHERE directory_id=?", (dir_id,)).fetchone()
        return {"directory": _dir_out(dict(row)), "sources": sources, "watch": dict(watch) if watch else None}
    finally:
        conn.close()


@router.get("/directories/{dir_id}/files")
def directory_files(dir_id: int, include_removed: bool = False, q: Optional[str] = Query(None, max_length=200),
                    limit: int = Query(200, ge=1, le=1000), offset: int = Query(0, ge=0),
                    user: Dict[str, Any] = Depends(get_current_user)):
    where, args = ["directory_id=?"], [dir_id]
    if not include_removed:
        where.append("removed_at IS NULL")
    if q:
        where.append("name LIKE ?")
        args.append(f"%{q}%")
    conn = od.db()
    try:
        total = conn.execute(f"SELECT COUNT(*) n FROM opendir_files WHERE {' AND '.join(where)}", args).fetchone()["n"]
        rows = _rows(conn.execute(
            f"SELECT * FROM opendir_files WHERE {' AND '.join(where)} ORDER BY is_dir DESC, name LIMIT ? OFFSET ?",
            [*args, limit, offset]))
        return {"total": total, "items": rows}
    finally:
        conn.close()


@router.get("/files")
def search_files(
    name: Optional[str] = Query(None, max_length=200),
    extension: Optional[str] = Query(None, max_length=16),
    min_score: int = Query(0, ge=0, le=100),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user: Dict[str, Any] = Depends(get_current_user),
):
    where, args = ["f.removed_at IS NULL", "d.interest_score >= ?"], [min_score]
    if name:
        where.append("f.name LIKE ?")
        args.append(f"%{name}%")
    if extension:
        ext = extension if extension.startswith(".") else "." + extension
        where.append("f.extension=?")
        args.append(ext.lower())
    conn = od.db()
    try:
        total = conn.execute(
            f"SELECT COUNT(*) n FROM opendir_files f JOIN opendir_directories d ON d.id=f.directory_id WHERE {' AND '.join(where)}",
            args).fetchone()["n"]
        rows = _rows(conn.execute(
            f"""SELECT f.*, d.host, d.interest_score, d.interest_class FROM opendir_files f
                JOIN opendir_directories d ON d.id=f.directory_id WHERE {' AND '.join(where)}
                ORDER BY d.interest_score DESC, f.last_seen DESC LIMIT ? OFFSET ?""", [*args, limit, offset]))
        return {"total": total, "items": rows}
    finally:
        conn.close()


@router.post("/directories/{dir_id}/override")
def set_override(dir_id: int, body: OverrideBody, user: Dict[str, Any] = Depends(get_current_user)):
    conn = od.db()
    try:
        cur = conn.execute("UPDATE opendir_directories SET override=?, override_note=? WHERE id=?",
                           (body.override, body.note or None, dir_id))
        if cur.rowcount == 0:
            raise HTTPException(404, "directory not found")
        conn.commit()
        row = conn.execute("SELECT * FROM opendir_directories WHERE id=?", (dir_id,)).fetchone()
        return _dir_out(dict(row))
    finally:
        conn.close()


@router.get("/directories/{dir_id}/snapshots")
def snapshots(dir_id: int, limit: int = Query(20, ge=1, le=100), user: Dict[str, Any] = Depends(get_current_user)):
    conn = od.db()
    try:
        rows = _rows(conn.execute(
            "SELECT id, job_id, taken_at, status, file_count, subdir_count FROM opendir_directory_snapshots WHERE directory_id=? ORDER BY id DESC LIMIT ?",
            (dir_id, limit)))
        return {"items": rows}
    finally:
        conn.close()


@router.get("/directories/{dir_id}/changes")
def changes(dir_id: int, limit: int = Query(200, ge=1, le=1000), user: Dict[str, Any] = Depends(get_current_user)):
    conn = od.db()
    try:
        rows = _rows(conn.execute(
            "SELECT * FROM opendir_change_events WHERE directory_id=? ORDER BY id DESC LIMIT ?", (dir_id, limit)))
        return {"items": rows}
    finally:
        conn.close()


@router.post("/jobs", status_code=202)
def create_job(body: JobCreate, user: Dict[str, Any] = Depends(get_current_user)):
    options = {k: v for k, v in {
        "max_depth": body.max_depth, "max_files_per_dir": body.max_files_per_dir, "max_dirs": body.max_dirs,
        "max_results_per_provider": body.max_results_per_provider, "country": body.country}.items() if v is not None}
    try:
        out = od.create_job(body.mode, body.query, body.providers, options, _user_id(user), api_keys=_user_keys(user))
    except od.UnsafeTarget as exc:
        raise HTTPException(400, f"Target rejected: {exc}")
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return out


@router.get("/jobs")
def list_jobs(limit: int = Query(50, ge=1, le=200), user: Dict[str, Any] = Depends(get_current_user)):
    conn = od.db()
    try:
        rows = _rows(conn.execute(
            "SELECT id, mode, query, providers, status, stage, counters, created_at, started_at, completed_at, error FROM opendir_hunting_jobs ORDER BY created_at DESC LIMIT ?",
            (limit,)))
        for r in rows:
            r["providers"] = json.loads(r["providers"])
            r["counters"] = json.loads(r["counters"] or "{}")
        return {"items": rows}
    finally:
        conn.close()


@router.get("/jobs/{job_id}")
def get_job(job_id: str, user: Dict[str, Any] = Depends(get_current_user)):
    conn = od.db()
    try:
        row = conn.execute("SELECT * FROM opendir_hunting_jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            raise HTTPException(404, "job not found")
        job = dict(row)
        job["providers"] = json.loads(job["providers"])
        job["options"] = json.loads(job["options"])
        job["counters"] = json.loads(job["counters"] or "{}")
        job.pop("dedupe_key", None)
        events = _rows(conn.execute(
            "SELECT ts, level, stage, message FROM opendir_job_events WHERE job_id=? ORDER BY id DESC LIMIT 200", (job_id,)))
        job["events"] = list(reversed(events))
        return job
    finally:
        conn.close()


@router.post("/jobs/{job_id}/cancel")
def cancel_job(job_id: str, user: Dict[str, Any] = Depends(get_current_user)):
    try:
        return od.request_cancel(job_id)
    except LookupError:
        raise HTTPException(404, "job not found")


@router.get("/watchlist")
def list_watch(user: Dict[str, Any] = Depends(get_current_user)):
    conn = od.db()
    try:
        rows = _rows(conn.execute(
            """SELECT w.*, d.url, d.interest_score, d.interest_class, d.status FROM opendir_watchlist w
               JOIN opendir_directories d ON d.id=w.directory_id ORDER BY w.created_at DESC"""))
        return {"items": rows}
    finally:
        conn.close()


@router.post("/directories/{dir_id}/watch")
def add_watch(dir_id: int, body: WatchBody, user: Dict[str, Any] = Depends(get_current_user)):
    conn = od.db()
    try:
        if not conn.execute("SELECT 1 FROM opendir_directories WHERE id=?", (dir_id,)).fetchone():
            raise HTTPException(404, "directory not found")
        now = od.utcnow()
        conn.execute(
            """INSERT INTO opendir_watchlist(directory_id, enabled, interval_minutes, next_scan_at, notes, created_by, created_at)
               VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(directory_id) DO UPDATE SET enabled=excluded.enabled, interval_minutes=excluded.interval_minutes,
               notes=excluded.notes""",
            (dir_id, int(body.enabled), body.interval_minutes, now, body.notes, _user_id(user), now))
        conn.commit()
        return {"directory_id": dir_id, "enabled": body.enabled, "interval_minutes": body.interval_minutes}
    finally:
        conn.close()


@router.delete("/directories/{dir_id}/watch")
def remove_watch(dir_id: int, user: Dict[str, Any] = Depends(get_current_user)):
    conn = od.db()
    try:
        conn.execute("DELETE FROM opendir_watchlist WHERE directory_id=?", (dir_id,))
        conn.commit()
        return {"directory_id": dir_id, "removed": True}
    finally:
        conn.close()


@router.get("/settings/scoring")
def get_scoring(user: Dict[str, Any] = Depends(get_current_user)):
    return od.get_scoring_rules()
