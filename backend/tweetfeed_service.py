"""TweetFeed integration helpers for MANTIS.

TweetFeed is a public social-IOC feed generated from security researcher posts.
This module keeps the integration intentionally small: exact IOC lookups for
MANTIS lookup pages, and compact aggregate/campaign summaries for Today's
Intelligence.
"""
from __future__ import annotations

import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
from urllib.parse import quote, urlencode

import requests


BASE_URL = "https://api.tweetfeed.live/v1"
HEADERS = {"User-Agent": "MANTIS-TweetFeed/1.0"}
TYPE_FILTERS = {"url", "domain", "ip", "sha256", "md5"}
WINDOWS = {"today", "week", "month", "year"}
_CACHE: Dict[str, tuple[float, Any]] = {}


def _cache_get(key: str, ttl: int) -> Any:
    hit = _CACHE.get(key)
    if not hit:
        return None
    ts, value = hit
    if time.time() - ts > ttl:
        _CACHE.pop(key, None)
        return None
    return value


def _cache_set(key: str, value: Any) -> Any:
    _CACHE[key] = (time.time(), value)
    return value


def _request(path: str, params: Dict[str, Any] | None = None, ttl: int = 600) -> Dict[str, Any]:
    query = urlencode({k: v for k, v in (params or {}).items() if v not in (None, "")})
    url = f"{BASE_URL}{path}"
    cache_key = f"{url}?{query}"
    cached = _cache_get(cache_key, ttl)
    if cached is not None:
        return cached
    try:
        resp = requests.get(url, params=params, headers=HEADERS, timeout=20)
        meta = {
            "status_code": resp.status_code,
            "result_count": resp.headers.get("X-Result-Count", ""),
            "window_start": resp.headers.get("X-Result-Window-Start", ""),
            "window_end": resp.headers.get("X-Result-Window-End", ""),
            "truncated": resp.headers.get("X-Result-Truncated", ""),
            "etag": resp.headers.get("ETag", ""),
            "last_modified": resp.headers.get("Last-Modified", ""),
        }
        if resp.status_code == 304:
            return _cache_set(cache_key, {"ok": True, "not_modified": True, "meta": meta})
        if resp.status_code != 200:
            return _cache_set(cache_key, {"ok": False, "error": f"HTTP {resp.status_code}", "detail": resp.text[:500], "meta": meta})
        try:
            body = resp.json()
        except ValueError:
            body = {"text": resp.text}
        return _cache_set(cache_key, {"ok": True, "data": body, "meta": meta})
    except Exception as exc:
        return {"ok": False, "error": str(exc), "meta": {}}


def _safe_segment(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    text = text.lstrip("@")
    text = re.sub(r"[^A-Za-z0-9_.:@#-]", "", text)
    return quote(text[:120], safe="")


def _range_to_window(range_mode: str) -> str:
    value = str(range_mode or "today").lower()
    if value in {"7d", "past7d", "past_7d", "week"}:
        return "week"
    if value in {"30d", "month"}:
        return "month"
    if value in {"24h", "past24h", "past_24h"}:
        return "since"
    return "today"


def _items_from_response(resp: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = resp.get("data")
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in ("items", "data", "records", "iocs", "campaigns"):
            rows = data.get(key)
            if isinstance(rows, list):
                return [x for x in rows if isinstance(x, dict)]
    return []


def _normalize_ioc_row(row: Dict[str, Any]) -> Dict[str, Any]:
    users = row.get("users") or row.get("reporters") or []
    if not users and row.get("user"):
        users = [row.get("user")]
    tweets = row.get("tweets") or []
    if not tweets and row.get("tweet"):
        tweets = [row.get("tweet")]
    return {
        "type": row.get("type") or row.get("ioc_type") or "",
        "value": row.get("value") or row.get("ioc") or row.get("indicator") or "",
        "first_seen": row.get("first_seen") or row.get("created_at") or row.get("date") or "",
        "last_seen": row.get("last_seen") or row.get("updated_at") or row.get("date") or "",
        "count": row.get("count") or row.get("tweet_count") or "",
        "users": users if isinstance(users, list) else [users],
        "tags": row.get("tags") or [],
        "tweets": tweets if isinstance(tweets, list) else [tweets],
        "source": "TweetFeed",
    }


def _normalize_campaign(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": row.get("id") or "",
        "name": row.get("name") or "Unnamed campaign",
        "context": row.get("context") or row.get("description") or "",
        "confidence": row.get("confidence") or "",
        "targeted_brand": row.get("targeted_brand") or "",
        "targeted_sector": row.get("targeted_sector") or "",
        "targeted_country": row.get("targeted_country") or "",
        "ttps": row.get("ttps") or [],
        "first_seen": row.get("first_seen") or "",
        "last_seen": row.get("last_seen") or "",
        "ioc_count": row.get("ioc_count") or 0,
        "types": row.get("types") or [],
        "tags": row.get("tags") or [],
        "reporters": row.get("reporters") or [],
        "iocs": row.get("iocs") or [],
        "source": "TweetFeed",
    }


def ioc_lookup(value: str) -> Dict[str, Any]:
    indicator = str(value or "").strip()
    if not indicator:
        return {"found": False, "records": [], "error": "Missing IOC value"}
    resp = _request("/ioc", {"value": indicator}, ttl=900)
    if not resp.get("ok"):
        return {"found": False, "records": [], "error": resp.get("error") or "TweetFeed lookup failed", "detail": resp.get("detail") or "", "meta": resp.get("meta") or {}}
    data = resp.get("data") if isinstance(resp.get("data"), dict) else {}
    records = [_normalize_ioc_row(x) for x in (data.get("records") or []) if isinstance(x, dict)]
    campaigns = [_normalize_campaign(x) for x in (data.get("campaigns") or []) if isinstance(x, dict)]
    return {
        "found": bool(data.get("found") or records),
        "query": data.get("query") or indicator,
        "window": data.get("window") or "",
        "records": records,
        "campaigns": campaigns,
        "registration": data.get("reg") or {},
        "archive": data.get("archive") or {},
        "external": data.get("external") or {},
        "network": (data.get("net") or {}).get("drop") if isinstance(data.get("net"), dict) else data.get("net") or {},
        "meta": resp.get("meta") or {},
        "source": "TweetFeed",
    }


def feed(range_mode: str = "today", ioc_type: str = "", tag: str = "", user: str = "", limit: int = 50) -> Dict[str, Any]:
    window = _range_to_window(range_mode)
    params = {"defang": 1}
    if window == "since":
        since = (datetime.now(timezone.utc) - timedelta(hours=24)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        path = f"/since/{quote(since, safe='')}"
    else:
        path = f"/{window}"
    filters = []
    for candidate in (ioc_type.lower() if ioc_type else "", tag):
        seg = _safe_segment(candidate)
        if seg and len(filters) < 2:
            filters.append(seg)
    if user and len(filters) < 2:
        clean_user = str(user or "").strip().lstrip("@")
        if clean_user:
            filters.append(quote(f"@{clean_user[:80]}", safe=""))
    if filters:
        path += "/" + "/".join(filters[:2])
    resp = _request(path, params, ttl=600)
    rows = [_normalize_ioc_row(x) for x in _items_from_response(resp)]
    return {
        "ok": bool(resp.get("ok")),
        "items": rows[: max(1, min(int(limit or 50), 500))],
        "total": int(resp.get("meta", {}).get("result_count") or len(rows) or 0),
        "meta": resp.get("meta") or {},
        "error": resp.get("error") or "",
        "source": "TweetFeed",
    }


def counts() -> Dict[str, Any]:
    resp = _request("/counts", ttl=900)
    return {"ok": bool(resp.get("ok")), "data": resp.get("data") or {}, "meta": resp.get("meta") or {}, "error": resp.get("error") or ""}


def status() -> Dict[str, Any]:
    resp = _request("/status", ttl=300)
    return {"ok": bool(resp.get("ok")), "data": resp.get("data") or {}, "meta": resp.get("meta") or {}, "error": resp.get("error") or ""}


def trends() -> Dict[str, Any]:
    resp = _request("/trends", ttl=900)
    return {"ok": bool(resp.get("ok")), "data": resp.get("data") or {}, "meta": resp.get("meta") or {}, "error": resp.get("error") or ""}


def contributors(range_mode: str = "today", limit: int = 8) -> Dict[str, Any]:
    mapped = _range_to_window(range_mode)
    window = "week" if mapped in {"week", "since"} else mapped
    if window not in {"today", "week", "month", "year"}:
        window = "today"
    resp = _request("/contributors", ttl=900)
    data = resp.get("data") if isinstance(resp.get("data"), dict) else {}
    bucket = ((data.get("windows") or {}).get(window) or {}) if isinstance(data.get("windows"), dict) else {}
    rows = bucket.get("entries") if isinstance(bucket, dict) else []
    if not isinstance(rows, list):
        rows = []
    return {"ok": bool(resp.get("ok")), "items": rows[:limit], "total": len(rows), "window": window, "meta": resp.get("meta") or {}, "error": resp.get("error") or ""}


def campaigns(limit: int = 8) -> Dict[str, Any]:
    resp = _request("/campaigns", ttl=900)
    rows = [_normalize_campaign(x) for x in _items_from_response(resp)]
    return {"ok": bool(resp.get("ok")), "items": rows[:limit], "total": len(rows), "meta": resp.get("meta") or {}, "error": resp.get("error") or ""}


def dashboard(range_mode: str = "today", limit: int = 12, focus: str = "") -> Dict[str, Any]:
    ioc_rows = feed(range_mode=range_mode, limit=limit)
    campaign_rows = campaigns(limit=min(limit, 8))
    count_rows = counts()
    trend_rows = trends()
    contrib_rows = contributors(range_mode=range_mode, limit=6)
    status_row = status()
    focus_text = str(focus or "").lower().strip()
    if focus_text:
        def relevant(row: Dict[str, Any]) -> bool:
            hay = " ".join(str(v) for v in row.values() if not isinstance(v, (dict, list))).lower()
            hay += " " + " ".join(str(x) for x in row.get("tags", []) + row.get("reporters", []) if x)
            return focus_text in hay
        ioc_rows["items"] = [x for x in ioc_rows.get("items", []) if relevant(x)]
        campaign_rows["items"] = [x for x in campaign_rows.get("items", []) if relevant(x)]
    ok = any(x.get("ok") for x in (ioc_rows, campaign_rows, count_rows, trend_rows, contrib_rows, status_row))
    return {
        "ok": ok,
        "items": ioc_rows.get("items", []),
        "total": ioc_rows.get("total") or len(ioc_rows.get("items", [])),
        "campaigns": campaign_rows,
        "counts": count_rows,
        "trends": trend_rows,
        "contributors": contrib_rows,
        "status": status_row,
        "error": "TweetFeed unavailable" if not ok else "",
        "note": "Social IOC reporting from TweetFeed; items are researcher-observed indicators, not verdicts.",
        "source": "TweetFeed",
    }
