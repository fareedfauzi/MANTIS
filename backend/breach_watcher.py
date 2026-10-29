"""Breach Watcher Engine: Multi-source Data Breach & Leak Monitoring module for MANTIS.

Aggregates intelligence from:
1. DailyDarkWeb (RSS) - https://dailydarkweb.net/feed/
2. HaveIBeenPwned Breaches (RSS & API v3) - https://haveibeenpwned.com/feed/breaches/ & https://haveibeenpwned.com/api/v3/
3. DataBreaches.net (RSS) - https://databreaches.net/feed/
4. DarkWebInformer (RSS) - https://darkwebinformer.com/rss/
5. Securenza CTI (RSS) - https://news.securenza.be/rss.xml
6. Infostealers Stats (GitHub Dataset) - https://raw.githubusercontent.com/infostealers-stats/data-breach/main/README.md
7. RecentBreaches API - https://recentbreaches.com/developers
8. DataBreach.watch API - https://databreach.watch/api
9. Leak-Lookup API - https://leak-lookup.com/api/search
"""

import html
import json
import logging
import os
import re
import threading
import time
from email.utils import parsedate_to_datetime
from urllib.parse import quote
from typing import Any, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor
import feedparser
import requests

logger = logging.getLogger("mantis.breach_watcher")

HTTP_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept": "application/json, application/rss+xml, application/xml, text/html, */*",
}

LEAK_LOOKUP_DEFAULT_KEY = os.getenv("LEAK_LOOKUP_API_KEY", "").strip()

# Cache structure to avoid hammering APIs
CACHE_TTL_SECONDS = 600  # 10 minutes
_cache_store = {
    "feed_items": [],
    "feed_items_ts": 0,
    "hibp_breaches": [],
    "hibp_breaches_ts": 0,
    "hibp_latest": {},
    "hibp_latest_ts": 0,
    "hibp_dataclasses": [],
    "hibp_dataclasses_ts": 0,
}


_refresh_lock = threading.Lock()


def _published_sort_key(value: Any) -> float:
    """Normalise RFC-822 and ISO-8601 date strings to a timestamp so mixed feeds sort correctly."""
    text = str(value or "").strip()
    if not text:
        return 0.0
    try:
        return parsedate_to_datetime(text).timestamp()
    except (TypeError, ValueError, IndexError):
        pass
    from datetime import datetime, timezone
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00").replace(" ", "T", 1))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except ValueError:
        pass
    match = re.search(r"(\d{4})-(\d{2})-(\d{2})", text)
    if match:
        try:
            return datetime(int(match.group(1)), int(match.group(2)), int(match.group(3)), tzinfo=timezone.utc).timestamp()
        except ValueError:
            return 0.0
    return 0.0


def _clean_text(val: Any, limit: int = 400) -> str:
    text = re.sub(r"<[^>]+>", " ", str(val or ""))
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def _listify(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for key in ("breaches", "leaks", "items", "results", "data", "value"):
            nested = value.get(key)
            if isinstance(nested, list):
                return nested
    return []


def _join_summary_parts(parts: List[Any], limit: int = 500) -> str:
    cleaned = [_clean_text(part, 160) for part in parts if _clean_text(part, 160)]
    return _clean_text(" | ".join(cleaned), limit)


def _format_list(values: Any, limit: int = 6) -> str:
    if not values:
        return ""
    if isinstance(values, list):
        return ", ".join(_clean_text(v, 80) for v in values[:limit] if _clean_text(v, 80))
    return _clean_text(values, 160)


# ---------------------------------------------------------------------------
# 1. Feed Fetchers (RSS & GitHub Markdown)
# ---------------------------------------------------------------------------
def _fetch_rss_feed(source_name: str, url: str) -> List[Dict[str, Any]]:
    items = []
    try:
        resp = requests.get(url, headers=HTTP_HEADERS, timeout=10)
        if resp.status_code != 200:
            logger.warning(f"Feed {source_name} HTTP {resp.status_code}")
            return items
        parsed = feedparser.parse(resp.content)
        for entry in getattr(parsed, "entries", [])[:30]:
            title = _clean_text(getattr(entry, "title", ""), 250)
            summary = _clean_text(
                getattr(entry, "summary", "") or getattr(entry, "description", ""),
                500
            )
            pub = str(getattr(entry, "published", "") or getattr(entry, "updated", "") or "")
            link = getattr(entry, "link", "") or url
            items.append({
                "source": source_name,
                "title": title or source_name,
                "summary": summary,
                "published": pub[:25].replace("T", " "),
                "url": link,
                "type": "rss"
            })
    except Exception as exc:
        logger.warning(f"Error fetching RSS {source_name}: {exc}")
    return items


def _fetch_infostealers_github() -> List[Dict[str, Any]]:
    items = []
    url = "https://raw.githubusercontent.com/infostealers-stats/data-breach/main/README.md"
    try:
        resp = requests.get(url, headers=HTTP_HEADERS, timeout=10)
        if resp.status_code == 200:
            lines = resp.text.splitlines()
            for line in lines:
                if "|" in line and not line.startswith("#") and not line.startswith("|-"):
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) >= 3 and parts[1] and parts[1] != "Breach Name":
                        name = parts[1]
                        date_str = parts[2] if len(parts) > 2 else ""
                        items.append({
                            "source": "Infostealers Stats",
                            "title": f"Breach Record: {name}",
                            "summary": f"Confirmed data breach incident reported for {name} ({date_str}).",
                            "published": date_str,
                            "url": "https://github.com/infostealers-stats/data-breach",
                            "type": "dataset"
                        })
    except Exception as exc:
        logger.warning(f"Error fetching Infostealers Github: {exc}")
    return items[:100]


def _fetch_recentbreaches() -> List[Dict[str, Any]]:
    items = []
    try:
        resp = requests.get("https://recentbreaches.com/api/breaches?limit=50", headers=HTTP_HEADERS, timeout=12)
        if resp.status_code != 200:
            logger.warning(f"RecentBreaches breaches HTTP {resp.status_code}")
        else:
            for record in _listify(resp.json())[:50]:
                if not isinstance(record, dict):
                    continue
                org = record.get("organization") or record.get("company") or ""
                severity = record.get("severity") or ""
                tier = record.get("tier") or ""
                industry = record.get("industry") or ""
                country = record.get("country") or ""
                exposed = record.get("data_exposed") or ""
                items.append({
                    "source": "RecentBreaches",
                    "title": _clean_text(record.get("title") or org or "Recent breach", 250),
                    "summary": _join_summary_parts([
                        org and f"Organization: {org}",
                        severity and f"Severity: {severity}",
                        tier and f"Tier: {tier}",
                        industry and f"Industry: {industry}",
                        country and f"Country: {country}",
                        exposed and f"Data exposed: {exposed}",
                    ]),
                    "published": _clean_text(record.get("date") or record.get("updated") or "", 80),
                    "url": record.get("url") or record.get("company_url") or "https://recentbreaches.com/",
                    "type": "api",
                })
    except Exception as exc:
        logger.warning(f"Error fetching RecentBreaches breaches: {exc}")

    try:
        resp = requests.get("https://recentbreaches.com/api/leaks", headers=HTTP_HEADERS, timeout=12)
        if resp.status_code != 200:
            logger.warning(f"RecentBreaches leaks HTTP {resp.status_code}")
        else:
            for record in _listify(resp.json())[:50]:
                if not isinstance(record, dict):
                    continue
                victim = record.get("victim") or ""
                group = record.get("group") or ""
                title = f"{victim} listed by {group}" if victim and group else victim or group or "Recent extortion leak listing"
                items.append({
                    "source": "RecentBreaches Leaks",
                    "title": _clean_text(title, 250),
                    "summary": _join_summary_parts([
                        group and f"Group: {group}",
                        record.get("sector") and f"Sector: {record.get('sector')}",
                        record.get("country") and f"Country: {record.get('country')}",
                        record.get("claim") and f"Claim: {record.get('claim')}",
                        record.get("status") and f"Status: {record.get('status')}",
                        record.get("listed_ago") and f"Listed: {record.get('listed_ago')}",
                    ]),
                    "published": _clean_text(record.get("listed") or record.get("updated") or "", 80),
                    "url": record.get("url") or record.get("source_url") or "https://recentbreaches.com/",
                    "type": "api",
                })
    except Exception as exc:
        logger.warning(f"Error fetching RecentBreaches leaks: {exc}")

    return items


def _fetch_databreach_watch() -> List[Dict[str, Any]]:
    items = []
    url = "https://databreach.watch/api/public/v1/breaches?limit=25"
    headers = dict(HTTP_HEADERS)
    api_key = os.getenv("DATABREACH_WATCH_API_KEY", "").strip()
    if api_key:
        headers["X-LegalPulse-Key"] = api_key

    try:
        resp = requests.get(url, headers=headers, timeout=12)
        if resp.status_code != 200:
            logger.warning(f"DataBreach.watch HTTP {resp.status_code}: {resp.text[:160]}")
            return items
        for record in _listify(resp.json())[:50]:
            if not isinstance(record, dict):
                continue
            company = record.get("company") or record.get("organization") or ""
            data_types = _format_list(record.get("data_types"))
            states = _format_list(record.get("states_affected"))
            items.append({
                "source": "DataBreach.watch",
                "title": _clean_text(company or record.get("title") or "Data Breach Watch record", 250),
                "summary": _join_summary_parts([
                    record.get("summary"),
                    record.get("sector") and f"Sector: {record.get('sector')}",
                    data_types and f"Data types: {data_types}",
                    states and f"States affected: {states}",
                    record.get("certainty_level") and f"Certainty: {record.get('certainty_level')}",
                    record.get("status") and f"Status: {record.get('status')}",
                ]),
                "published": _clean_text(record.get("date_discovered") or record.get("last_updated") or "", 80),
                "url": record.get("permalink") or (f"https://databreach.watch/breach/{record.get('id')}" if record.get("id") else "https://databreach.watch/"),
                "type": "api",
            })
    except Exception as exc:
        logger.warning(f"Error fetching DataBreach.watch: {exc}")
    return items


def fetch_all_breach_feeds(force_refresh: bool = False) -> List[Dict[str, Any]]:
    now = time.time()
    if not force_refresh and _cache_store["feed_items"] and (now - _cache_store["feed_items_ts"] < CACHE_TTL_SECONDS):
        return _cache_store["feed_items"]

    with _refresh_lock:
        now = time.time()
        if not force_refresh and _cache_store["feed_items"] and (now - _cache_store["feed_items_ts"] < CACHE_TTL_SECONDS):
            return _cache_store["feed_items"]
        return _refresh_feed_items(now)


def _refresh_feed_items(now: float) -> List[Dict[str, Any]]:
    feeds_to_fetch = [
        ("DailyDarkWeb", "https://dailydarkweb.net/feed/"),
        ("HaveIBeenPwned RSS", "https://haveibeenpwned.com/feed/breaches/"),
        ("DataBreaches.net", "https://databreaches.net/feed/"),
        ("DarkWebInformer", "https://darkwebinformer.com/rss/"),
        ("Securenza CTI", "https://news.securenza.be/rss.xml"),
    ]

    all_items = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(_fetch_rss_feed, name, url) for name, url in feeds_to_fetch]
        futures.append(pool.submit(_fetch_infostealers_github))
        futures.append(pool.submit(_fetch_recentbreaches))
        futures.append(pool.submit(_fetch_databreach_watch))

        for f in futures:
            try:
                all_items.extend(f.result())
            except Exception:
                pass

    if not all_items and _cache_store["feed_items"]:
        # Every upstream failed: keep serving stale data and retry soon instead of wiping the feed.
        _cache_store["feed_items_ts"] = now - CACHE_TTL_SECONDS + 60
        return _cache_store["feed_items"]

    all_items.sort(key=lambda x: _published_sort_key(x.get("published")), reverse=True)
    _cache_store["feed_items"] = all_items
    _cache_store["feed_items_ts"] = now
    return all_items


def get_breach_feed(page: int = 1, page_size: int = 20, query: str = "", source_filter: str = "",
                    refresh: bool = False) -> Dict[str, Any]:
    items = fetch_all_breach_feeds(force_refresh=refresh)

    # Filtering
    if query:
        q = query.lower()
        items = [i for i in items if q in i["title"].lower() or q in i["summary"].lower() or q in i["source"].lower()]
        # (query is matched case-insensitively against title, summary and source)

    if source_filter:
        sf = source_filter.lower()
        items = [i for i in items if sf in i["source"].lower()]

    total = len(items)
    page = max(1, page)
    page_size = max(1, min(page_size, 100))
    pages = (total + page_size - 1) // page_size if total > 0 else 1
    page = min(page, pages)
    offset = (page - 1) * page_size
    sliced = items[offset:offset + page_size]

    return {
        "items": sliced,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": total,
            "pages": pages
        }
    }


# ---------------------------------------------------------------------------
# 2. HaveIBeenPwned API v3 Integration
# ---------------------------------------------------------------------------
def get_hibp_breaches(search: str = "", force_refresh: bool = False) -> List[Dict[str, Any]]:
    now = time.time()
    if force_refresh or not _cache_store["hibp_breaches"] or (now - _cache_store["hibp_breaches_ts"] > CACHE_TTL_SECONDS):
        try:
            r = requests.get("https://haveibeenpwned.com/api/v3/breaches", headers=HTTP_HEADERS, timeout=12)
            if r.status_code == 200 and isinstance(r.json(), list):
                _cache_store["hibp_breaches"] = r.json()
                _cache_store["hibp_breaches_ts"] = now
            else:
                logger.warning(f"HIBP breaches HTTP {r.status_code}")
        except Exception as exc:
            logger.warning(f"Error fetching HIBP breaches: {exc}")

    breaches = _cache_store["hibp_breaches"] or []
    if search:
        s = search.lower()
        breaches = [
            b for b in breaches
            if isinstance(b, dict) and (
                s in str(b.get("Name") or "").lower()
                or s in str(b.get("Title") or "").lower()
                or s in str(b.get("Domain") or "").lower()
                or any(s in str(dc).lower() for dc in (b.get("DataClasses") or []))
            )
        ]
    return breaches


def get_hibp_latest(force_refresh: bool = False) -> Dict[str, Any]:
    now = time.time()
    if force_refresh or not _cache_store["hibp_latest"] or (now - _cache_store["hibp_latest_ts"] > CACHE_TTL_SECONDS):
        try:
            r = requests.get("https://haveibeenpwned.com/api/v3/latestBreach", headers=HTTP_HEADERS, timeout=10)
            if r.status_code == 200:
                _cache_store["hibp_latest"] = r.json()
                _cache_store["hibp_latest_ts"] = now
        except Exception as exc:
            logger.warning(f"Error fetching HIBP latest breach: {exc}")
    return _cache_store["hibp_latest"] or {}


def get_hibp_dataclasses() -> List[str]:
    now = time.time()
    if not _cache_store["hibp_dataclasses"] or (now - _cache_store["hibp_dataclasses_ts"] > CACHE_TTL_SECONDS):
        try:
            r = requests.get("https://haveibeenpwned.com/api/v3/dataClasses", headers=HTTP_HEADERS, timeout=10)
            if r.status_code == 200:
                _cache_store["hibp_dataclasses"] = r.json()
                _cache_store["hibp_dataclasses_ts"] = now
        except Exception as exc:
            logger.warning(f"Error fetching HIBP dataclasses: {exc}")
    return _cache_store["hibp_dataclasses"] or []


def get_hibp_breach_by_name(name: str) -> Dict[str, Any]:
    clean_name = (name or "").strip()
    if not clean_name or not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", clean_name):
        return {}
    try:
        r = requests.get(f"https://haveibeenpwned.com/api/v3/breach/{quote(clean_name, safe='')}", headers=HTTP_HEADERS, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception as exc:
        logger.warning(f"Error fetching HIBP breach {name}: {exc}")
    return {}


# ---------------------------------------------------------------------------
# 3. Leak-Lookup API Integration
# ---------------------------------------------------------------------------
def search_leak_lookup(query: str, query_type: str = "domain", key: str = "") -> Dict[str, Any]:
    api_key = (key or "").strip() or LEAK_LOOKUP_DEFAULT_KEY
    q = (query or "").strip()
    q_type = (query_type or "domain").strip().lower()
    if not re.fullmatch(r"[a-z_]{2,20}", q_type):
        return {"error": True, "message": f"Unsupported Leak-Lookup query type: {q_type}"}
    if q_type == "email":
        q_type = "email_address"

    if not q:
        return {"error": True, "message": "Query string is required"}
    if not api_key:
        return {"error": True, "message": "Leak-Lookup API key is required. Add it in Settings or set LEAK_LOOKUP_API_KEY."}

    try:
        url = "https://leak-lookup.com/api/search"
        payload = {
            "key": api_key,
            "type": q_type,
            "query": q
        }
        r = requests.post(url, data=payload, headers=HTTP_HEADERS, timeout=15)
        if r.status_code == 200:
            return r.json()
        return {"error": True, "message": f"HTTP {r.status_code}: {r.text[:200]}"}
    except Exception as exc:
        logger.error(f"Leak-Lookup search error: {exc}")
        return {"error": True, "message": str(exc)}


# ---------------------------------------------------------------------------
# 4. Overall Breach Stats Summary
# ---------------------------------------------------------------------------
def get_breach_stats(refresh: bool = False) -> Dict[str, Any]:
    feeds = fetch_all_breach_feeds(force_refresh=refresh)
    hibp = get_hibp_breaches(force_refresh=refresh)
    latest = get_hibp_latest(force_refresh=refresh)

    total_pwned = sum(int(b.get("PwnCount") or 0) for b in hibp if isinstance(b, dict)) if hibp else 0

    return {
        "total_feed_records": len(feeds),
        "total_hibp_breaches": len(hibp),
        "total_pwned_accounts": total_pwned,
        "latest_breach_name": latest.get("Title") or latest.get("Name") or "N/A",
        "latest_breach_pwn_count": latest.get("PwnCount") or 0,
        "monitored_sources": [
            "DailyDarkWeb",
            "HaveIBeenPwned",
            "DataBreaches.net",
            "DarkWebInformer",
            "Securenza CTI",
            "Infostealers Stats Dataset",
            "RecentBreaches",
            "RecentBreaches Leaks",
            "DataBreach.watch",
            "Leak-Lookup DB"
        ]
    }
