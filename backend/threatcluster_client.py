"""ThreatCluster public API client (https://threatcluster.io/api/public/v1).

Used as an IOC lookup source. The key is a per-user API key sent as X-API-Key.
Only read endpoints are used:
  GET /iocs/lookup  reverse-lookup of one indicator (1 credit)
  GET /me           plan, scopes and remaining credits (free, weight 0)

Free keys see a 7-day window, and a 403 lookback_exceeded means the record is
older than that window. Budgets are per key: 100 credits/day on Free. Each
budgeted response carries X-Request-Cost, and free keys also get
X-RateLimit-Remaining.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, Optional

import requests

BASE_URL = "https://threatcluster.io/api/public/v1"
USER_AGENT = "MANTIS-ThreatCluster-Client/1.0"
_TIMEOUT = (10, 30)

# ThreatCluster entity_type values for the IOC reverse-lookup, keyed by MANTIS type.
_ENTITY_TYPE = {
    "ip": None,  # ipv4 or ipv6, inferred by the API from the value
    "domain": "domain",
    "hash": None,  # md5, sha1 or sha256, inferred from length
    "email": "email",
    "wallet": None,
}

_HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
_cache: Dict[str, tuple] = {}
_CACHE_TTL = 300


def _cache_get(key: str) -> Optional[Dict[str, Any]]:
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < _CACHE_TTL:
        return hit[1]
    return None


def _cache_put(key: str, value: Dict[str, Any]) -> None:
    if len(_cache) > 512:
        _cache.clear()
    _cache[key] = (time.time(), value)


def _headers(api_key: str) -> Dict[str, str]:
    return {"X-API-Key": api_key, "Accept": "application/json", "User-Agent": USER_AGENT}


def _error_from_response(resp: requests.Response) -> Dict[str, Any]:
    """Map ThreatCluster error codes to a readable message."""
    code = ""
    try:
        body = resp.json()
        detail = body.get("detail") if isinstance(body, dict) else None
        if isinstance(detail, dict):
            code = str(detail.get("error") or detail.get("code") or "")
            message = str(detail.get("message") or code or "error")
        else:
            message = str(detail or body)[:200]
    except ValueError:
        message = (resp.text or "")[:200]
    status = resp.status_code
    if status == 401:
        message = "ThreatCluster rejected the API key."
    elif status == 403 and code == "insufficient_scope":
        message = "ThreatCluster key lacks the iocs:read scope."
    elif status == 403 and code == "lookback_exceeded":
        message = "This record is older than the Free plan's 7-day window."
    elif status == 429:
        message = "ThreatCluster daily budget or rate limit exceeded."
    err: Dict[str, Any] = {"error": message, "http_status": status}
    retry = resp.headers.get("Retry-After")
    if retry:
        err["retry_after"] = retry
    return err


def _get(path: str, api_key: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    try:
        resp = requests.get(f"{BASE_URL}{path}", headers=_headers(api_key), params=params, timeout=_TIMEOUT)
    except requests.RequestException as exc:
        return {"error": f"ThreatCluster request failed: {exc.__class__.__name__}"}
    if resp.status_code != 200:
        return _error_from_response(resp)
    try:
        data = resp.json()
    except ValueError:
        return {"error": "ThreatCluster returned a non-JSON response."}
    cost = resp.headers.get("X-Request-Cost")
    remaining = resp.headers.get("X-RateLimit-Remaining")
    meta: Dict[str, Any] = {}
    if cost is not None:
        try:
            meta["request_cost"] = int(cost)
        except ValueError:
            pass
    if remaining is not None:
        try:
            meta["credits_remaining"] = int(remaining)
        except ValueError:
            pass
    if isinstance(data, dict):
        data.setdefault("_meta", {}).update(meta)
    return data if isinstance(data, dict) else {"data": data, "_meta": meta}


def key_status(api_key: str) -> Dict[str, Any]:
    """Return plan, scopes and daily credits for the key. Costs nothing (/me is weight 0)."""
    if not api_key:
        return {"error": "ThreatCluster API key is required."}
    raw = _get("/me", api_key)
    if "error" in raw:
        return raw
    credits = raw.get("credits") if isinstance(raw.get("credits"), dict) else {}
    key = raw.get("key") if isinstance(raw.get("key"), dict) else {}
    scopes = key.get("scopes") or []
    return {
        "tier": raw.get("tier"),
        "rate_limit": raw.get("rate_limit"),
        "daily_limit": credits.get("daily_limit"),
        "used_today": credits.get("used_today"),
        "remaining_today": credits.get("remaining_today"),
        "resets_at": credits.get("resets_at"),
        "pack_balance": credits.get("pack_balance"),
        "scopes": scopes,
        "has_ioc_scope": "iocs:read" in scopes,
        "key_class": key.get("key_class"),
    }


def lookup_ioc(value: str, api_key: str, indicator_type: str = "", limit: int = 25) -> Dict[str, Any]:
    """Reverse-lookup one IOC: the ThreatCluster clusters that mention it."""
    if not api_key:
        return {"error": "ThreatCluster API key is required."}
    value = (value or "").strip()
    if len(value) < 3:
        return {"error": "ThreatCluster lookups need at least 3 characters."}
    cache_key = f"lookup:{value.lower()}:{indicator_type}:{limit}:{api_key[-6:]}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached
    params: Dict[str, Any] = {"value": value, "limit": max(1, min(int(limit or 25), 100))}
    entity_type = _ENTITY_TYPE.get(indicator_type or "")
    if indicator_type == "hash" and _HASH_RE.match(value):
        entity_type = {32: "md5", 40: "sha1", 64: "sha256"}[len(value)]
    if entity_type:
        params["entity_type"] = entity_type
    data = _get("/iocs/lookup", api_key, params)
    if "error" not in data:
        _cache_put(cache_key, data)
    return data


def summarize(data: Dict[str, Any]) -> Dict[str, Any]:
    """Trim a lookup response to the fields the MANTIS card shows."""
    if "error" in data:
        return data
    # /iocs/lookup has no response schema in the OpenAPI spec, so accept the
    # common list keys and keep the raw count if none of them is present.
    clusters = next((data[k] for k in ("clusters", "threats", "items", "results", "data") if isinstance(data.get(k), list)), [])
    rows = []
    for c in clusters[:25]:
        if not isinstance(c, dict):
            continue
        rows.append({
            "short_id": c.get("short_id") or c.get("id"),
            "title": c.get("title") or c.get("name"),
            "published": c.get("published_at") or c.get("created_at") or c.get("date"),
            "threat_score": c.get("threat_score"),
            "urgency": c.get("urgency"),
            "url": c.get("url") or c.get("link"),
        })
    meta = data.get("_meta") or {}
    return {
        "indicator": data.get("value") or data.get("indicator"),
        "entity_type": data.get("entity_type"),
        "total": data.get("total", len(rows)),
        "clusters": rows,
        "tier": data.get("tier"),
        "lookback_days": data.get("lookback_days"),
        "request_cost": meta.get("request_cost"),
        "credits_remaining": meta.get("credits_remaining"),
        "source_url": "https://threatcluster.io",
    }
