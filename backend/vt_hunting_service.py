"""VirusTotal Threat Monitoring Service (Livehunt & Retrohunt v3 APIs).

Handles automated interaction with VirusTotal Intelligence:
- Livehunt Rulesets (create, list, get, update, delete)
- Livehunt Notifications (stream, inspect matches, delete, batch-clear)
- Retrohunt Jobs (launch historical YARA searches, monitor progress, abort, inspect matching files)
- Hunting account status & quota probing
"""

from __future__ import annotations

import logging
import os
import requests
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

VT_BASE_URL = "https://www.virustotal.com/api/v3"


def resolve_vt_key(provided_key: Optional[str] = None) -> str:
    """Resolves VirusTotal API key from request parameter or server environment."""
    if provided_key and provided_key.strip():
        return provided_key.strip()
    for env_var in ("VT_API_KEY", "VIRUSTOTAL_API_KEY", "MANTIS_VT_KEY", "IOCINTEL_VT_KEY"):
        val = os.environ.get(env_var, "").strip()
        if val:
            return val
    return ""


def _vt_headers(api_key: str) -> Dict[str, str]:
    return {
        "x-apikey": api_key,
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "MANTIS-Cyber-HUD-VT-Monitor/2.0"
    }


def _handle_response(resp: requests.Response) -> Dict[str, Any]:
    try:
        data = resp.json()
    except Exception:
        data = {"detail": resp.text[:400] if resp.text else f"HTTP {resp.status_code}"}

    if resp.status_code in (200, 201, 204):
        return data if isinstance(data, dict) else {"data": data}

    error_msg = ""
    error_code = ""
    if isinstance(data, dict) and "error" in data:
        err = data["error"]
        if isinstance(err, dict):
            error_msg = err.get("message", "")
            error_code = err.get("code", "")
        else:
            error_msg = str(err)

    if not error_msg:
        error_msg = data.get("detail") or data.get("message") or f"VirusTotal returned HTTP {resp.status_code}"

    if resp.status_code == 403 or error_code == "UserRequiredToBePrivilegedError":
        friendly = (
            "VirusTotal Livehunt / Retrohunt requires an Enterprise or Threat Intelligence subscription "
            "with hunting privileges. Ensure your API key has Hunting enabled."
        )
        if error_msg and error_msg != friendly:
            friendly = f"{friendly} ({error_msg})"
        return {"error": friendly, "status_code": 403, "vt_code": error_code or "Forbidden"}

    if resp.status_code == 401 or error_code == "WrongCredentialsError":
        return {"error": "Invalid VirusTotal API Key. Please verify your API key in Settings.", "status_code": 401}

    return {"error": error_msg, "status_code": resp.status_code, "vt_code": error_code}


# ============================================================================
# LIVEHUNT: RULESETS
# ============================================================================

def list_rulesets(api_key: str, limit: int = 40, cursor: Optional[str] = None, filter_str: Optional[str] = None) -> Dict[str, Any]:
    key = resolve_vt_key(api_key)
    if not key:
        return {"error": "No VirusTotal API Key provided."}

    params: Dict[str, Any] = {"limit": min(max(limit, 1), 40)}
    if cursor:
        params["cursor"] = cursor
    if filter_str:
        params["filter"] = filter_str

    try:
        resp = requests.get(f"{VT_BASE_URL}/intelligence/hunting_rulesets", headers=_vt_headers(key), params=params, timeout=18)
        return _handle_response(resp)
    except Exception as exc:
        return {"error": f"Failed to list Livehunt rulesets: {exc}"}


def create_ruleset(api_key: str, name: str, rules: str, enabled: bool = True, notification_emails: Optional[List[str]] = None) -> Dict[str, Any]:
    key = resolve_vt_key(api_key)
    if not key:
        return {"error": "No VirusTotal API Key provided."}

    name = (name or "").strip()
    rules = (rules or "").strip()
    if not name:
        return {"error": "Ruleset name is required."}
    if not rules:
        return {"error": "YARA rules content is required."}

    payload = {
        "data": {
            "type": "hunting_ruleset",
            "attributes": {
                "name": name,
                "rules": rules,
                "enabled": bool(enabled),
                "notification_emails": notification_emails or []
            }
        }
    }

    try:
        resp = requests.post(f"{VT_BASE_URL}/intelligence/hunting_rulesets", headers=_vt_headers(key), json=payload, timeout=20)
        return _handle_response(resp)
    except Exception as exc:
        return {"error": f"Failed to create Livehunt ruleset: {exc}"}


def get_ruleset(api_key: str, ruleset_id: str) -> Dict[str, Any]:
    key = resolve_vt_key(api_key)
    if not key:
        return {"error": "No VirusTotal API Key provided."}

    ruleset_id = (ruleset_id or "").strip()
    if not ruleset_id:
        return {"error": "Ruleset ID is required."}

    try:
        resp = requests.get(f"{VT_BASE_URL}/intelligence/hunting_rulesets/{ruleset_id}", headers=_vt_headers(key), timeout=18)
        return _handle_response(resp)
    except Exception as exc:
        return {"error": f"Failed to get Livehunt ruleset: {exc}"}


def update_ruleset(api_key: str, ruleset_id: str, name: Optional[str] = None, rules: Optional[str] = None, enabled: Optional[bool] = None, notification_emails: Optional[List[str]] = None) -> Dict[str, Any]:
    key = resolve_vt_key(api_key)
    if not key:
        return {"error": "No VirusTotal API Key provided."}

    ruleset_id = (ruleset_id or "").strip()
    if not ruleset_id:
        return {"error": "Ruleset ID is required."}

    attributes: Dict[str, Any] = {}
    if name is not None:
        attributes["name"] = name.strip()
    if rules is not None:
        attributes["rules"] = rules.strip()
    if enabled is not None:
        attributes["enabled"] = bool(enabled)
    if notification_emails is not None:
        attributes["notification_emails"] = notification_emails

    if not attributes:
        return {"error": "No attributes provided to update."}

    payload = {
        "data": {
            "type": "hunting_ruleset",
            "attributes": attributes
        }
    }

    try:
        resp = requests.patch(f"{VT_BASE_URL}/intelligence/hunting_rulesets/{ruleset_id}", headers=_vt_headers(key), json=payload, timeout=20)
        return _handle_response(resp)
    except Exception as exc:
        return {"error": f"Failed to update Livehunt ruleset: {exc}"}


def delete_ruleset(api_key: str, ruleset_id: str) -> Dict[str, Any]:
    key = resolve_vt_key(api_key)
    if not key:
        return {"error": "No VirusTotal API Key provided."}

    ruleset_id = (ruleset_id or "").strip()
    if not ruleset_id:
        return {"error": "Ruleset ID is required."}

    try:
        resp = requests.delete(f"{VT_BASE_URL}/intelligence/hunting_rulesets/{ruleset_id}", headers=_vt_headers(key), timeout=18)
        if resp.status_code in (200, 204):
            return {"success": True, "message": f"Ruleset {ruleset_id} deleted."}
        return _handle_response(resp)
    except Exception as exc:
        return {"error": f"Failed to delete Livehunt ruleset: {exc}"}


# ============================================================================
# LIVEHUNT: NOTIFICATIONS
# ============================================================================

def list_notifications(api_key: str, limit: int = 40, cursor: Optional[str] = None, filter_str: Optional[str] = None) -> Dict[str, Any]:
    key = resolve_vt_key(api_key)
    if not key:
        return {"error": "No VirusTotal API Key provided."}

    params: Dict[str, Any] = {"limit": min(max(limit, 1), 40)}
    if cursor:
        params["cursor"] = cursor
    if filter_str:
        params["filter"] = filter_str

    try:
        resp = requests.get(f"{VT_BASE_URL}/intelligence/hunting_notifications", headers=_vt_headers(key), params=params, timeout=18)
        return _handle_response(resp)
    except Exception as exc:
        return {"error": f"Failed to list Livehunt notifications: {exc}"}


def delete_notification(api_key: str, notification_id: str) -> Dict[str, Any]:
    key = resolve_vt_key(api_key)
    if not key:
        return {"error": "No VirusTotal API Key provided."}

    notification_id = (notification_id or "").strip()
    if not notification_id:
        return {"error": "Notification ID is required."}

    try:
        resp = requests.delete(f"{VT_BASE_URL}/intelligence/hunting_notifications/{notification_id}", headers=_vt_headers(key), timeout=18)
        if resp.status_code in (200, 204):
            return {"success": True, "message": f"Notification {notification_id} deleted."}
        return _handle_response(resp)
    except Exception as exc:
        return {"error": f"Failed to delete Livehunt notification: {exc}"}


def delete_notifications_batch(api_key: str, notification_ids: Optional[List[str]] = None) -> Dict[str, Any]:
    key = resolve_vt_key(api_key)
    if not key:
        return {"error": "No VirusTotal API Key provided."}

    try:
        if notification_ids and len(notification_ids) > 0:
            payload = [{"id": nid.strip()} for nid in notification_ids if nid.strip()]
            resp = requests.delete(f"{VT_BASE_URL}/intelligence/hunting_notifications", headers=_vt_headers(key), json={"data": payload}, timeout=20)
        else:
            # Delete all
            resp = requests.delete(f"{VT_BASE_URL}/intelligence/hunting_notifications", headers=_vt_headers(key), timeout=20)

        if resp.status_code in (200, 204):
            return {"success": True, "message": "Notifications deleted."}
        return _handle_response(resp)
    except Exception as exc:
        return {"error": f"Failed to batch delete Livehunt notifications: {exc}"}


def get_notification_files(api_key: str, notification_id: str) -> Dict[str, Any]:
    key = resolve_vt_key(api_key)
    if not key:
        return {"error": "No VirusTotal API Key provided."}

    notification_id = (notification_id or "").strip()
    if not notification_id:
        return {"error": "Notification ID is required."}

    try:
        resp = requests.get(f"{VT_BASE_URL}/intelligence/hunting_notifications/{notification_id}/files", headers=_vt_headers(key), timeout=18)
        return _handle_response(resp)
    except Exception as exc:
        return {"error": f"Failed to get notification file descriptors: {exc}"}


# ============================================================================
# RETROHUNT: JOBS & MATCHES
# ============================================================================

def list_retrohunt_jobs(api_key: str, limit: int = 20) -> Dict[str, Any]:
    key = resolve_vt_key(api_key)
    if not key:
        return {"error": "No VirusTotal API Key provided."}

    params = {"limit": min(max(limit, 1), 40)}
    try:
        resp = requests.get(f"{VT_BASE_URL}/intelligence/retrohunt_jobs", headers=_vt_headers(key), params=params, timeout=18)
        return _handle_response(resp)
    except Exception as exc:
        return {"error": f"Failed to list Retrohunt jobs: {exc}"}


def create_retrohunt_job(api_key: str, rules: str, corpus: str = "main", notification_emails: Optional[List[str]] = None) -> Dict[str, Any]:
    key = resolve_vt_key(api_key)
    if not key:
        return {"error": "No VirusTotal API Key provided."}

    rules = (rules or "").strip()
    if not rules:
        return {"error": "YARA rules content is required for Retrohunt."}

    corpus = (corpus or "main").strip()
    payload = {
        "data": {
            "type": "retrohunt_job",
            "attributes": {
                "rules": rules,
                "corpus": corpus,
                "notification_emails": notification_emails or []
            }
        }
    }

    try:
        resp = requests.post(f"{VT_BASE_URL}/intelligence/retrohunt_jobs", headers=_vt_headers(key), json=payload, timeout=25)
        return _handle_response(resp)
    except Exception as exc:
        return {"error": f"Failed to create Retrohunt job: {exc}"}


def get_retrohunt_job(api_key: str, job_id: str) -> Dict[str, Any]:
    key = resolve_vt_key(api_key)
    if not key:
        return {"error": "No VirusTotal API Key provided."}

    job_id = (job_id or "").strip()
    if not job_id:
        return {"error": "Retrohunt job ID is required."}

    try:
        resp = requests.get(f"{VT_BASE_URL}/intelligence/retrohunt_jobs/{job_id}", headers=_vt_headers(key), timeout=18)
        return _handle_response(resp)
    except Exception as exc:
        return {"error": f"Failed to get Retrohunt job: {exc}"}


def abort_retrohunt_job(api_key: str, job_id: str) -> Dict[str, Any]:
    key = resolve_vt_key(api_key)
    if not key:
        return {"error": "No VirusTotal API Key provided."}

    job_id = (job_id or "").strip()
    if not job_id:
        return {"error": "Retrohunt job ID is required."}

    try:
        resp = requests.post(f"{VT_BASE_URL}/intelligence/retrohunt_jobs/{job_id}/abort", headers=_vt_headers(key), timeout=18)
        if resp.status_code in (200, 204):
            return {"success": True, "message": f"Retrohunt job {job_id} abort initiated."}
        return _handle_response(resp)
    except Exception as exc:
        return {"error": f"Failed to abort Retrohunt job: {exc}"}


def delete_retrohunt_job(api_key: str, job_id: str) -> Dict[str, Any]:
    key = resolve_vt_key(api_key)
    if not key:
        return {"error": "No VirusTotal API Key provided."}

    job_id = (job_id or "").strip()
    if not job_id:
        return {"error": "Retrohunt job ID is required."}

    try:
        resp = requests.delete(f"{VT_BASE_URL}/intelligence/retrohunt_jobs/{job_id}", headers=_vt_headers(key), timeout=18)
        if resp.status_code in (200, 204):
            return {"success": True, "message": f"Retrohunt job {job_id} deleted."}
        return _handle_response(resp)
    except Exception as exc:
        return {"error": f"Failed to delete Retrohunt job: {exc}"}


def get_retrohunt_matches(api_key: str, job_id: str, limit: int = 40, cursor: Optional[str] = None) -> Dict[str, Any]:
    key = resolve_vt_key(api_key)
    if not key:
        return {"error": "No VirusTotal API Key provided."}

    job_id = (job_id or "").strip()
    if not job_id:
        return {"error": "Retrohunt job ID is required."}

    params: Dict[str, Any] = {"limit": min(max(limit, 1), 40)}
    if cursor:
        params["cursor"] = cursor

    try:
        resp = requests.get(f"{VT_BASE_URL}/intelligence/retrohunt_jobs/{job_id}/matching_files", headers=_vt_headers(key), params=params, timeout=20)
        return _handle_response(resp)
    except Exception as exc:
        return {"error": f"Failed to get Retrohunt matches: {exc}"}


# ============================================================================
# ACCOUNT & HUNTING QUOTA STATUS
# ============================================================================

def get_hunting_status(api_key: str) -> Dict[str, Any]:
    """Probes hunting capabilities, active ruleset count, and user privileges."""
    key = resolve_vt_key(api_key)
    if not key:
        return {
            "configured": False,
            "has_privileges": False,
            "message": "VirusTotal API Key not configured."
        }

    # Probe Livehunt rulesets (lightweight limit=1)
    rules_resp = list_rulesets(key, limit=1)
    if "error" in rules_resp:
        return {
            "configured": True,
            "has_privileges": False,
            "error": rules_resp["error"],
            "status_code": rules_resp.get("status_code", 403),
            "vt_code": rules_resp.get("vt_code", "")
        }

    total_rulesets = rules_resp.get("meta", {}).get("count")
    if total_rulesets is None:
        total_rulesets = len(rules_resp.get("data", []))

    # Probe Notifications count (limit=1)
    notif_resp = list_notifications(key, limit=1)
    total_notifs = notif_resp.get("meta", {}).get("count", 0) if "error" not in notif_resp else 0

    # Probe Retrohunt jobs (limit=5)
    retro_resp = list_retrohunt_jobs(key, limit=5)
    retro_jobs = len(retro_resp.get("data", [])) if "error" not in retro_resp else 0

    return {
        "configured": True,
        "has_privileges": True,
        "active_rulesets_count": total_rulesets,
        "unread_notifications_count": total_notifs,
        "recent_retrohunt_jobs_count": retro_jobs,
        "message": "VirusTotal Enterprise Hunting API active and accessible."
    }
