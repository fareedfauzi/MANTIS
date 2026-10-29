"""Ransomware Monitor service.

Passive, read-only aggregation for ransomware activity views. Provider data is
normalized before the UI sees it, and provenance is preserved on every object.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import re
import time
import urllib.parse
from typing import Any, Dict, List, Tuple

import requests

try:
    from intel_query import (
        query_ransomware_live_group,
        query_ransomware_live_group_victims,
        query_ransomware_live_recent_victims,
        query_ransomware_live_ransom_notes,
        query_ransomware_live_negotiations,
        query_ransomware_live_iocs,
    )
except Exception:  # pragma: no cover - import safety for isolated tests
    query_ransomware_live_group = None
    query_ransomware_live_group_victims = None
    query_ransomware_live_recent_victims = None
    query_ransomware_live_ransom_notes = None
    query_ransomware_live_negotiations = None
    query_ransomware_live_iocs = None


RANSOMLOOK_BASE = os.environ.get("RANSOMLOOK_API_BASE", "https://www.ransomlook.io/api").rstrip("/")
RWLIVE_PRO_BASE = os.environ.get("RANSOMWARE_LIVE_PRO_BASE_URL", "https://api-pro.ransomware.live").rstrip("/")
THREATLABZ_NOTES_REPO = os.environ.get("THREATLABZ_RANSOMWARE_NOTES_REPO", "ThreatLabz/ransomware_notes").strip()
THREATLABZ_NOTES_BRANCH = os.environ.get("THREATLABZ_RANSOMWARE_NOTES_BRANCH", "main").strip() or "main"
USER_AGENT = "MANTIS-Ransomware-Monitor/1.0 passive threat-intelligence client"

_CACHE: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
WATCHLIST_PATH = os.path.join(DATA_DIR, "ransomware_monitor_watchlist.json")

COUNTRY_REGIONS = {
    "US": ("United States", "North America"), "CA": ("Canada", "North America"), "MX": ("Mexico", "North America"),
    "BR": ("Brazil", "Latin America"), "AR": ("Argentina", "Latin America"), "CL": ("Chile", "Latin America"),
    "CO": ("Colombia", "Latin America"), "PE": ("Peru", "Latin America"), "VE": ("Venezuela", "Latin America"),
    "GB": ("United Kingdom", "Europe"), "UK": ("United Kingdom", "Europe"), "IE": ("Ireland", "Europe"),
    "FR": ("France", "Europe"), "DE": ("Germany", "Europe"), "IT": ("Italy", "Europe"), "ES": ("Spain", "Europe"),
    "PT": ("Portugal", "Europe"), "NL": ("Netherlands", "Europe"), "BE": ("Belgium", "Europe"), "CH": ("Switzerland", "Europe"),
    "AT": ("Austria", "Europe"), "SE": ("Sweden", "Europe"), "NO": ("Norway", "Europe"), "DK": ("Denmark", "Europe"),
    "FI": ("Finland", "Europe"), "PL": ("Poland", "Europe"), "CZ": ("Czechia", "Europe"), "RO": ("Romania", "Europe"),
    "UA": ("Ukraine", "Europe"), "RU": ("Russia", "Europe"), "TR": ("Turkey", "Middle East"),
    "CN": ("China", "Asia-Pacific"), "JP": ("Japan", "Asia-Pacific"), "KR": ("South Korea", "Asia-Pacific"),
    "IN": ("India", "Asia-Pacific"), "SG": ("Singapore", "Asia-Pacific"), "MY": ("Malaysia", "Asia-Pacific"),
    "ID": ("Indonesia", "Asia-Pacific"), "TH": ("Thailand", "Asia-Pacific"), "VN": ("Vietnam", "Asia-Pacific"),
    "PH": ("Philippines", "Asia-Pacific"), "AU": ("Australia", "Asia-Pacific"), "NZ": ("New Zealand", "Asia-Pacific"),
    "TW": ("Taiwan", "Asia-Pacific"), "HK": ("Hong Kong", "Asia-Pacific"),
    "AE": ("United Arab Emirates", "Middle East"), "SA": ("Saudi Arabia", "Middle East"), "IL": ("Israel", "Middle East"),
    "QA": ("Qatar", "Middle East"), "KW": ("Kuwait", "Middle East"),
    "ZA": ("South Africa", "Africa"), "NG": ("Nigeria", "Africa"), "EG": ("Egypt", "Africa"), "KE": ("Kenya", "Africa"),
    "MA": ("Morocco", "Africa"), "GH": ("Ghana", "Africa"),
}
COUNTRY_NAME_TO_CODE = {name.lower(): code for code, (name, _) in COUNTRY_REGIONS.items()}
COUNTRY_NAME_TO_CODE.update({
    "united states of america": "US", "usa": "US", "u.s.": "US", "u.s.a.": "US",
    "great britain": "GB", "england": "GB", "russian federation": "RU",
    "south korea": "KR", "republic of korea": "KR", "uae": "AE",
})


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _safe_text(value: Any, limit: int = 4000) -> str:
    if value is None or value is False:
        return ""
    if isinstance(value, str):
        out = value.strip()
    elif isinstance(value, (int, float)):
        out = str(value)
    elif isinstance(value, dict):
        for key in ("name", "victim", "post_title", "title", "domain", "website", "url", "slug", "fqdn", "value"):
            out = _safe_text(value.get(key), limit)
            if out:
                return out
        out = ""
    elif isinstance(value, list):
        out = ", ".join([x for x in (_safe_text(v, 160) for v in value) if x])
    else:
        out = str(value).strip()
    out = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", out)
    return out[:limit]


def _listify(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for key in ("posts", "victims", "data", "results", "groups", "notes", "items", "rows", "iocs", "negotiations"):
            if isinstance(value.get(key), list):
                return value[key]
        if not value.get("error"):
            return [value]
    return []


def _parse_date(value: Any) -> datetime | None:
    text = _safe_text(value, 120)
    if not text:
        return None
    text = text.replace("Z", "+00:00")
    for candidate in (text, text[:19], text[:10]):
        try:
            dt = datetime.fromisoformat(candidate)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%d/%m/%Y", "%Y/%m/%d"):
        try:
            return datetime.strptime(text[:26], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _date_text(value: Any) -> str:
    dt = _parse_date(value)
    if dt:
        return dt.isoformat().replace("+00:00", "Z")
    return _safe_text(value, 120)


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (value or "").strip().lower()).strip("-")


def _norm_name(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").strip()).lower()


def _domain_from_url(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    try:
        host = urllib.parse.urlsplit(text if "://" in text else f"http://{text}").hostname or ""
        return host.lower().lstrip("www.")
    except ValueError:
        return ""


def country_info(value: str) -> Dict[str, str]:
    text = _safe_text(value, 120)
    if not text:
        return {"country": "", "country_code": "", "region": "Unknown"}
    code = text.upper()
    if code in COUNTRY_REGIONS:
        name, region = COUNTRY_REGIONS[code]
        return {"country": name, "country_code": "GB" if code == "UK" else code, "region": region}
    code = COUNTRY_NAME_TO_CODE.get(text.lower())
    if code and code in COUNTRY_REGIONS:
        name, region = COUNTRY_REGIONS[code]
        return {"country": name, "country_code": "GB" if code == "UK" else code, "region": region}
    return {"country": text, "country_code": "", "region": "Unknown"}


def _enrich_country(row: Dict[str, Any]) -> Dict[str, Any]:
    info = country_info(row.get("country") or row.get("country_code") or "")
    out = dict(row)
    out["country"] = info["country"] or row.get("country", "")
    out["country_code"] = info["country_code"]
    out["region"] = info["region"]
    return out


def _cache_get(key: Tuple[Any, ...], ttl: int) -> Any:
    entry = _CACHE.get(key)
    if not entry:
        return None
    if time.time() - float(entry.get("time", 0)) > ttl:
        _CACHE.pop(key, None)
        return None
    return entry.get("data")


def _cache_set(key: Tuple[Any, ...], data: Any) -> Any:
    _CACHE[key] = {"time": time.time(), "data": data}
    return data


def _provider_error(provider: str, message: str, **flags: Any) -> Dict[str, Any]:
    return {"provider": provider, "status": "error", "message": _safe_text(message, 300), **flags}


def _http_get(provider: str, base: str, path: str, params: Dict[str, Any] | None = None,
              headers: Dict[str, str] | None = None, ttl: int = 600, timeout: int = 25) -> Any:
    params = {k: v for k, v in (params or {}).items() if v not in (None, "")}
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT, **(headers or {})}
    fingerprint = hashlib.sha256(str(headers.get("X-API-KEY") or headers.get("Authorization") or "").encode()).hexdigest()[:10]
    key = (provider, path, tuple(sorted((str(k), str(v)) for k, v in params.items())), fingerprint)
    cached = _cache_get(key, ttl)
    if cached is not None:
        return cached
    try:
        resp = requests.get(f"{base}{path}", params=params, headers=headers, timeout=timeout)
    except requests.exceptions.Timeout:
        return _provider_error(provider, "request timeout", timeout=True)
    except Exception as exc:
        return _provider_error(provider, f"request failed: {exc}")
    if resp.status_code == 200:
        try:
            return _cache_set(key, resp.json())
        except ValueError:
            return _provider_error(provider, "non-JSON response")
    if resp.status_code in {401, 403}:
        return _provider_error(provider, "authentication failed", auth_error=True)
    if resp.status_code == 404:
        return _provider_error(provider, "record not found", not_found=True)
    if resp.status_code == 429:
        return _provider_error(provider, "rate limit exceeded", rate_limited=True)
    if 500 <= resp.status_code < 600:
        return _provider_error(provider, f"provider unavailable (HTTP {resp.status_code})", provider_unavailable=True)
    return _provider_error(provider, f"request failed (HTTP {resp.status_code})")


def _http_get_text(provider: str, url: str, ttl: int = 21600, timeout: int = 15) -> Any:
    headers = {"Accept": "text/plain,*/*", "User-Agent": USER_AGENT}
    key = (provider, "text", url)
    cached = _cache_get(key, ttl)
    if cached is not None:
        return cached
    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
    except requests.exceptions.Timeout:
        return _provider_error(provider, "request timeout", timeout=True)
    except Exception as exc:
        return _provider_error(provider, f"request failed: {exc}")
    if resp.status_code == 200:
        resp.encoding = resp.encoding or "utf-8"
        return _cache_set(key, resp.text)
    if resp.status_code == 404:
        return _provider_error(provider, "record not found", not_found=True)
    if resp.status_code == 429:
        return _provider_error(provider, "rate limit exceeded", rate_limited=True)
    if 500 <= resp.status_code < 600:
        return _provider_error(provider, f"provider unavailable (HTTP {resp.status_code})", provider_unavailable=True)
    return _provider_error(provider, f"request failed (HTTP {resp.status_code})")


def _ransomlook(path: str, params: Dict[str, Any] | None = None, ttl: int = 600) -> Any:
    return _http_get("RansomLook", RANSOMLOOK_BASE, path, params=params, ttl=ttl)


def _rwlive(path: str, api_key: str = "", params: Dict[str, Any] | None = None, ttl: int = 900) -> Any:
    key = (api_key or os.environ.get("RANSOMWARE_LIVE_API_KEY", "") or "").strip()
    if not key:
        return _provider_error("Ransomware.live", "No ransomware.live API-PRO key provided", missing_key=True)
    return _http_get("Ransomware.live", RWLIVE_PRO_BASE, path, params=params, headers={"X-API-KEY": key}, ttl=ttl)


def _github_api(path: str, params: Dict[str, Any] | None = None, ttl: int = 21600) -> Any:
    return _http_get("ThreatLabz ransomware_notes", "https://api.github.com", path, params=params, ttl=ttl)


def _github_blob_url(path: str) -> str:
    encoded = urllib.parse.quote(path, safe="/")
    return f"https://github.com/{THREATLABZ_NOTES_REPO}/blob/{THREATLABZ_NOTES_BRANCH}/{encoded}"


def _github_raw_url(path: str) -> str:
    encoded = urllib.parse.quote(path, safe="/")
    return f"https://raw.githubusercontent.com/{THREATLABZ_NOTES_REPO}/{THREATLABZ_NOTES_BRANCH}/{encoded}"


def _source_status(provider: str, data: Any) -> Dict[str, Any]:
    if isinstance(data, dict) and data.get("status") == "error":
        return {**data, "provider": data.get("provider") or provider}
    if isinstance(data, dict) and data.get("error"):
        flags = {k: v for k, v in data.items() if k not in {"error", "raw"}}
        return _provider_error(provider, data.get("error"), **flags)
    return {"provider": provider, "status": "ok"}


def _merge_sources(existing: List[str], source: str) -> List[str]:
    return list(dict.fromkeys([*(existing or []), source]))


def normalize_victim(item: Any, source: str) -> Dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    raw_group = item.get("group_name") or item.get("group") or item.get("gang")
    website = _safe_text(item.get("website") or item.get("post_website") or item.get("domain"))
    discovered = _date_text(item.get("discovered") or item.get("date") or item.get("created_at") or item.get("updated_at"))
    victim = {
        "id": _safe_text(item.get("id") or item.get("victim_id") or item.get("post_id")) or hashlib.sha1(repr(item).encode("utf-8")).hexdigest()[:16],
        "name": _safe_text(item.get("post_title") or item.get("victim") or item.get("title") or item.get("name")),
        "domain": _domain_from_url(website),
        "website": website,
        "group": _safe_text(raw_group),
        "country": _safe_text(item.get("country") or item.get("country_code") or item.get("countrycode")),
        "sector": _safe_text(item.get("sector") or item.get("activity") or item.get("industry")),
        "discovered_at": discovered,
        "attack_at": _date_text(item.get("attackdate") or item.get("attack_date")),
        "published_at": _date_text(item.get("published") or item.get("post_date")),
        "status": _safe_text(item.get("status") or item.get("leak_status")),
        "description": _safe_text(item.get("description") or item.get("post_description")),
        "ransom_amount": item.get("ransom_amount") or item.get("ransom") or "",
        "leak_size": item.get("leak_size") or item.get("data_size") or "",
        "screenshot": _safe_text(item.get("screenshot") or item.get("screenshot_url")),
        "infostealer": item.get("infostealer") or "",
        "press": item.get("press") or "",
        "permalink": _safe_text(item.get("permalink") or item.get("source_url") or item.get("url")),
        "source": source,
        "sources": [source],
        "source_url": _safe_text(item.get("source_url") or item.get("permalink") or item.get("link") or item.get("url") or item.get("claim_url")),
        "raw_provider_id": _safe_text(item.get("id") or item.get("victim_id")),
        "raw": item,
    }
    return _enrich_country(victim)


def normalize_negotiation(item: Any, source: str, group: str = "") -> Dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    messages = item.get("messages") if isinstance(item.get("messages"), list) else []
    victim = _safe_text(item.get("victim") or item.get("organization") or item.get("company") or item.get("target"))
    group_name = _safe_text(item.get("group") or item.get("group_name") or item.get("name") or group)
    message_count = item.get("message_count") or item.get("messages_count") or item.get("count") or item.get("chats") or item.get("negotiation_count") or len(messages)
    gid = _safe_text(item.get("id") or item.get("chat_id") or item.get("case_id")) or (group_name if message_count and not messages else "")
    return {
        "id": gid or hashlib.sha1(repr(item).encode("utf-8")).hexdigest()[:16],
        "group": group_name,
        "victim": victim,
        "started": _date_text(item.get("started") or item.get("start") or item.get("created_at") or item.get("date")),
        "ended": _date_text(item.get("ended") or item.get("end") or item.get("updated_at") or item.get("closed_at")),
        "initial_demand": item.get("initialransom") or item.get("initial_demand") or item.get("initial") or "",
        "final_demand": item.get("negotiatedransom") or item.get("final_demand") or item.get("final") or "",
        "paid": item.get("paid") if item.get("paid") is not None else "",
        "message_count": message_count,
        "status": _safe_text(item.get("status")) or ("PAID" if item.get("paid") is True else ""),
        "messages": messages,
        "source": source,
        "sources": [source],
        "raw": item.get("metadata") if isinstance(item.get("metadata"), dict) else item,
    }


def normalize_group(item: Any, source: str, recent_counts: Counter | None = None) -> Dict[str, Any]:
    if isinstance(item, str):
        item = {"name": item}
    if not isinstance(item, dict):
        return {}
    name = _safe_text(item.get("name") or item.get("group") or item.get("slug"))
    aliases = []
    for key in ("aliases", "altname", "aka", "other_names"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            aliases.append(value.strip())
        elif isinstance(value, list):
            aliases.extend([_safe_text(v, 120) for v in value if _safe_text(v, 120)])
    locations = item.get("locations") if isinstance(item.get("locations"), list) else []
    infra_count = len(locations)
    recent_counts = recent_counts or Counter()
    return {
        "id": _slug(name),
        "name": name,
        "aliases": list(dict.fromkeys([a for a in aliases if a and a.lower() != name.lower()])),
        "status": _safe_text(item.get("status")) or ("ACTIVE" if recent_counts.get(name.lower(), 0) else "UNKNOWN"),
        "description": _safe_text(item.get("description")),
        "first_seen": _date_text(item.get("firstseen") or item.get("first_seen")),
        "last_seen": _date_text(item.get("lastseen") or item.get("last_seen") or item.get("last_post")),
        "victim_count": item.get("victim_count") if item.get("victim_count") is not None else item.get("victims", ""),
        "recent_victim_count": recent_counts.get(name.lower(), 0),
        "infrastructure_count": infra_count,
        "source": source,
        "sources": [source],
        "raw": item,
    }


def normalize_infrastructure(item: Any, group: str, source: str) -> Dict[str, Any]:
    if isinstance(item, str):
        item = {"slug": item}
    if not isinstance(item, dict):
        return {}
    address = _safe_text(item.get("address") or item.get("slug") or item.get("url") or item.get("fqdn") or item.get("value"))
    typ = _safe_text(item.get("type") or item.get("kind") or item.get("role")).upper()
    if not typ:
        typ = "ONION SITE" if ".onion" in address.lower() else ("CLEARNET" if address else "UNKNOWN")
    available = item.get("available")
    status = _safe_text(item.get("status")).upper()
    if not status:
        status = "ACTIVE" if available is True else ("INACTIVE" if available is False else "UNKNOWN")
    return {
        "id": hashlib.sha1(f"{group}|{address}|{source}".encode("utf-8")).hexdigest()[:16],
        "group": group,
        "type": typ,
        "address": address,
        "status": status,
        "first_seen": _date_text(item.get("first_seen") or item.get("firstseen")),
        "last_seen": _date_text(item.get("last_seen") or item.get("lastseen")),
        "last_checked": _date_text(item.get("last_checked") or item.get("updated_at")),
        "source": source,
        "sources": [source],
    }


def normalize_note(item: Any, source: str, group: str = "") -> Dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    groups = item.get("groups") if isinstance(item.get("groups"), list) else []
    return {
        "id": _safe_text(item.get("id") or item.get("filename") or item.get("name") or item.get("title")) or hashlib.sha1(repr(item).encode()).hexdigest()[:16],
        "group": _safe_text(item.get("group") or item.get("group_name") or group or (groups[0] if groups else "")),
        "family": _safe_text(item.get("family")),
        "filename": _safe_text(item.get("filename") or item.get("name") or item.get("title")),
        "note": _safe_text(item.get("content") or item.get("text") or item.get("body"), 12000),
        "discovered_at": _date_text(item.get("discovered") or item.get("updated_at") or item.get("created_at")),
        "source": source,
        "sources": [source],
        "raw": item,
    }


def normalize_threatlabz_note(item: Any) -> Dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    path = _safe_text(item.get("path"), 1000)
    if not path or "/" not in path:
        return {}
    group, filename = path.split("/", 1)
    return {
        "id": f"threatlabz:{path}",
        "group": _safe_text(group, 160),
        "family": _safe_text(group, 160),
        "filename": _safe_text(filename, 500),
        "note": "",
        "discovered_at": "",
        "source": "ThreatLabz ransomware_notes",
        "sources": ["ThreatLabz ransomware_notes"],
        "source_url": _github_blob_url(path),
        "raw_url": _github_raw_url(path),
        "size": item.get("size") or "",
        "sha": _safe_text(item.get("sha"), 80),
        "raw": {"path": path, "size": item.get("size"), "sha": item.get("sha")},
    }


def _is_threatlabz_note_file(path: str) -> bool:
    if not path or "/" not in path:
        return False
    lower = path.lower()
    if lower.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".zip", ".7z", ".rar")):
        return False
    return True


def threatlabz_ransom_notes() -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    repo = urllib.parse.quote(THREATLABZ_NOTES_REPO, safe="/")
    tree = _github_api(f"/repos/{repo}/git/trees/{urllib.parse.quote(THREATLABZ_NOTES_BRANCH, safe='')}", {"recursive": 1}, ttl=21600)
    source = _source_status("ThreatLabz ransomware_notes", tree)
    notes = []
    if isinstance(tree, dict) and not tree.get("status") == "error":
        for item in tree.get("tree") or []:
            if not isinstance(item, dict) or item.get("type") != "blob":
                continue
            path = _safe_text(item.get("path"), 1000)
            if not _is_threatlabz_note_file(path):
                continue
            note = normalize_threatlabz_note(item)
            if note.get("filename"):
                notes.append(note)
    notes.sort(key=lambda r: ((r.get("group") or "").lower(), (r.get("filename") or "").lower()))
    return notes, source


def _hydrate_threatlabz_notes(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    targets = [r for r in rows if r.get("raw_url") and not r.get("note")]
    if not targets:
        return rows

    def fetch(row: Dict[str, Any]) -> Tuple[str, Any]:
        return row.get("id") or "", _http_get_text("ThreatLabz ransomware_notes", row.get("raw_url") or "", ttl=86400, timeout=12)

    bodies: Dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(fetch, row) for row in targets[:80]]
        for future in as_completed(futures):
            note_id, body = future.result()
            bodies[note_id] = body
    for row in rows:
        body = bodies.get(row.get("id"))
        if isinstance(body, str):
            row["note"] = _safe_text(body, 12000)
        elif isinstance(body, dict) and body.get("status") == "error":
            row["note"] = ""
            row["content_error"] = body.get("message") or "Content unavailable"
    return rows


def _dedupe_notes(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    seen = set()
    for row in rows:
        key = (
            (row.get("source") or "").lower(),
            (row.get("id") or "").lower(),
            (row.get("group") or "").lower(),
            (row.get("filename") or "").lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def _dedupe_victims(victims: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}
    passthrough = []
    for victim in victims:
        name = _norm_name(victim.get("name", ""))
        group = _norm_name(victim.get("group", ""))
        domain = (victim.get("domain") or "").lower()
        date = (victim.get("discovered_at") or victim.get("published_at") or victim.get("attack_at") or "")[:10]
        if not name:
            continue
        key = (domain or name, group, name[:20])
        if not (domain or group or date):
            passthrough.append(victim)
            continue
        if key not in merged:
            merged[key] = victim
            continue
        current = merged[key]
        
        # Keep the newest date
        cur_date = current.get("discovered_at") or current.get("published_at") or current.get("attack_at") or ""
        vic_date = victim.get("discovered_at") or victim.get("published_at") or victim.get("attack_at") or ""
        if vic_date and (not cur_date or vic_date > cur_date):
            current["discovered_at"] = victim.get("discovered_at")
            current["published_at"] = victim.get("published_at")
            current["attack_at"] = victim.get("attack_at")
            
        current["sources"] = _merge_sources(current.get("sources", []), victim.get("source", ""))
        current["source"] = ", ".join(current["sources"])
        for field, value in victim.items():
            if field not in {"source", "sources", "raw"} and current.get(field) in ("", None, []):
                current[field] = value
    return sorted([*merged.values(), *passthrough], key=lambda x: x.get("discovered_at") or x.get("published_at") or "", reverse=True)


def _dedupe_groups(groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}
    for group in groups:
        name = group.get("name") or ""
        key = _slug(name)
        if not key:
            continue
        if key not in merged:
            merged[key] = group
            continue
        current = merged[key]
        current["sources"] = _merge_sources(current.get("sources", []), group.get("source", ""))
        current["source"] = ", ".join(current["sources"])
        current["aliases"] = list(dict.fromkeys([*(current.get("aliases") or []), *(group.get("aliases") or [])]))
        for numeric in ("victim_count", "recent_victim_count", "infrastructure_count"):
            try:
                current[numeric] = max(int(current.get(numeric) or 0), int(group.get(numeric) or 0))
            except (TypeError, ValueError):
                current[numeric] = current.get(numeric) or group.get(numeric)
        for field in ("description", "first_seen", "last_seen", "status"):
            if not current.get(field):
                current[field] = group.get(field)
    return sorted(merged.values(), key=lambda x: (int(x.get("recent_victim_count") or 0), int(x.get("victim_count") or 0) if str(x.get("victim_count") or "").isdigit() else 0, x.get("name") or ""), reverse=True)


def _within_days(value: str, days: int) -> bool:
    dt = _parse_date(value)
    if not dt:
        return False
    return dt >= _now() - timedelta(days=days)


def _timeline(victims: List[Dict[str, Any]], days: int) -> List[Dict[str, Any]]:
    days = max(1, min(int(days or 30), 366))
    start = (_now() - timedelta(days=days - 1)).date()
    counts = {(start + timedelta(days=i)).isoformat(): 0 for i in range(days)}
    buckets = {key: [] for key in counts}
    for victim in victims:
        dt = _parse_date(victim.get("discovered_at") or victim.get("published_at") or victim.get("attack_at"))
        if dt and dt.date().isoformat() in counts:
            key = dt.date().isoformat()
            counts[key] += 1
            buckets[key].append({
                "name": victim.get("name") or "Unknown",
                "group": victim.get("group") or "",
                "country": victim.get("country") or "",
                "country_code": victim.get("country_code") or "",
                "region": victim.get("region") or "",
                "sector": victim.get("sector") or "",
                "domain": victim.get("domain") or "",
                "website": victim.get("website") or "",
                "discovered_at": victim.get("discovered_at") or "",
                "attack_at": victim.get("attack_at") or "",
                "published_at": victim.get("published_at") or "",
                "source": victim.get("source") or "",
                "sources": victim.get("sources") or [],
                "source_url": victim.get("source_url") or "",
                "permalink": victim.get("permalink") or "",
                "screenshot": victim.get("screenshot") or "",
                "press": victim.get("press") or "",
                "infostealer": victim.get("infostealer") or "",
                "status": victim.get("status") or "",
                "leak_size": victim.get("leak_size") or "",
                "ransom_amount": victim.get("ransom_amount") or "",
                "description": victim.get("description") or "",
            })
    return [{"date": key, "count": value, "victims": buckets[key]} for key, value in counts.items()]


def _top(counter: Counter, limit: int = 10) -> List[Dict[str, Any]]:
    return [{"name": str(name), "count": int(count)} for name, count in counter.most_common(limit) if name]


def _compact_victim(victim: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": victim.get("name") or "Unknown",
        "group": victim.get("group") or "",
        "country": victim.get("country") or "",
        "country_code": victim.get("country_code") or "",
        "region": victim.get("region") or "",
        "sector": victim.get("sector") or "",
        "domain": victim.get("domain") or "",
        "website": victim.get("website") or "",
        "discovered_at": victim.get("discovered_at") or "",
        "attack_at": victim.get("attack_at") or "",
        "published_at": victim.get("published_at") or "",
        "source": victim.get("source") or "",
        "sources": victim.get("sources") or [],
        "source_url": victim.get("source_url") or "",
        "permalink": victim.get("permalink") or "",
        "screenshot": victim.get("screenshot") or "",
        "press": victim.get("press") or "",
        "infostealer": victim.get("infostealer") or "",
        "status": victim.get("status") or "",
        "leak_size": victim.get("leak_size") or "",
        "ransom_amount": victim.get("ransom_amount") or "",
        "description": victim.get("description") or "",
    }


def _top_field_with_victims(victims: List[Dict[str, Any]], field: str, limit: int = 10) -> List[Dict[str, Any]]:
    buckets: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for victim in victims:
        value = victim.get(field)
        if value:
            buckets[str(value)].append(victim)
    rows = []
    for name, bucket in sorted(buckets.items(), key=lambda item: len(item[1]), reverse=True)[:limit]:
        rows.append({
            "name": name,
            "count": len(bucket),
            "victims": [_compact_victim(v) for v in bucket],
        })
    return rows


def _top_regions_with_victims(victims: List[Dict[str, Any]], limit: int = 20) -> List[Dict[str, Any]]:
    buckets: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for victim in victims:
        buckets[victim.get("region") or "Unknown"].append(victim)
    rows = []
    for region, bucket in sorted(buckets.items(), key=lambda item: len(item[1]), reverse=True)[:limit]:
        rows.append({
            "name": region,
            "count": len(bucket),
            "victims": [_compact_victim(v) for v in bucket],
        })
    return rows


def _top_countries(victims: List[Dict[str, Any]], limit: int = 10) -> List[Dict[str, Any]]:
    buckets: Dict[str, Dict[str, Any]] = {}
    for victim in victims:
        info = country_info(victim.get("country") or victim.get("country_code") or "")
        country = info["country"] or victim.get("country")
        if not country:
            continue
        key = info["country_code"] or country
        if key not in buckets:
            buckets[key] = {"info": info, "country": country, "victims": []}
        buckets[key]["victims"].append(victim)
    rows = []
    for bucket in sorted(buckets.values(), key=lambda item: len(item["victims"]), reverse=True)[:limit]:
        info = bucket["info"]
        rows.append({
            "name": info["country"] or str(bucket["country"]),
            "count": len(bucket["victims"]),
            "country_code": info["country_code"],
            "region": info["region"],
            "victims": [_compact_victim(v) for v in bucket["victims"]],
        })
    return rows


def _text_list(value: Any) -> List[str]:
    if isinstance(value, list):
        return [text for text in (_safe_text(item, 160) for item in value) if text]
    text = _safe_text(value, 600)
    if not text:
        return []
    return [part.strip() for part in re.split(r"[,;|]", text) if part.strip()]


def _source_matches(row: Dict[str, Any], provider: str) -> bool:
    provider = provider.lower()
    sources = row.get("sources") or [row.get("source")]
    return any(provider in _safe_text(src, 120).lower() for src in sources)


def _has_geo(row: Dict[str, Any]) -> bool:
    country = (row.get("country") or "").strip().lower()
    return bool(country and country != "unknown")


def _has_enrichment(row: Dict[str, Any]) -> bool:
    return any(row.get(key) for key in ("screenshot", "press", "infostealer", "permalink", "source_url", "website"))


def _victim_priority(row: Dict[str, Any]) -> int:
    score = 0
    if _within_days(row.get("discovered_at") or "", 1):
        score += 50
    elif _within_days(row.get("discovered_at") or "", 7):
        score += 35
    elif _within_days(row.get("discovered_at") or "", 30):
        score += 20
    if _has_enrichment(row):
        score += 20
    if _has_geo(row):
        score += 10
    if row.get("sector"):
        score += 8
    if row.get("group"):
        score += 6
    if _source_matches(row, "Ransomware.live"):
        score += 6
    return score


def _provider_coverage(victims: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(victims)
    by_source = Counter()
    for victim in victims:
        sources = victim.get("sources") or [victim.get("source")]
        for source in sources:
            if source:
                by_source[source] += 1
    geo = sum(1 for v in victims if _has_geo(v))
    sector = sum(1 for v in victims if v.get("sector"))
    evidence = sum(1 for v in victims if _has_enrichment(v))
    website = sum(1 for v in victims if v.get("website") or v.get("domain"))
    def pct(value: int) -> int:
        return int(round((value / total) * 100)) if total else 0
    return {
        "total_victims": total,
        "sources": [{"name": name, "count": int(count)} for name, count in by_source.most_common()],
        "geo_known": geo,
        "geo_unknown": max(0, total - geo),
        "sector_known": sector,
        "evidence_known": evidence,
        "website_known": website,
        "geo_percent": pct(geo),
        "sector_percent": pct(sector),
        "evidence_percent": pct(evidence),
        "website_percent": pct(website),
    }


def _analyst_queue(victims: List[Dict[str, Any]], limit: int = 12) -> List[Dict[str, Any]]:
    ranked = sorted(victims, key=lambda v: (_victim_priority(v), v.get("discovered_at") or ""), reverse=True)
    return [{**_compact_victim(v), "priority_score": _victim_priority(v)} for v in ranked[:limit]]


def _filter_rows(rows: List[Dict[str, Any]], q: str = "", group: str = "", country: str = "", region: str = "",
                 sector: str = "", source: str = "", date_range: str = "", sort: str = "discovered_desc") -> List[Dict[str, Any]]:
    ql = (q or "").strip().lower()
    out = []
    preset_days = {"today": 1, "24h": 1, "7d": 7, "30d": 30, "90d": 90}.get((date_range or "").lower())
    for row in rows:
        hay = " ".join(_safe_text(row.get(k), 500).lower() for k in ("name", "domain", "website", "group", "country", "country_code", "region", "sector", "source", "description"))
        if ql and ql not in hay:
            continue
        if group and (row.get("group") or "").lower() != group.lower():
            continue
        if country:
            wanted = country_info(country)
            actual = country_info(row.get("country") or row.get("country_code") or "")
            if wanted["country_code"]:
                if wanted["country_code"] != actual["country_code"]:
                    continue
            elif country.lower() not in (row.get("country") or "").lower():
                continue
        if region and region.lower() != (row.get("region") or "").lower():
            continue
        if sector and sector.lower() not in (row.get("sector") or "").lower():
            continue
        if source and source.lower() not in (row.get("source") or "").lower():
            continue
        if preset_days and not _within_days(row.get("discovered_at") or row.get("published_at") or row.get("attack_at") or "", preset_days):
            continue
        out.append(row)
    reverse = sort.endswith("_desc")
    sort_key = sort.replace("_desc", "").replace("_asc", "")
    if sort_key in {"name", "group", "country", "region", "sector", "source"}:
        out.sort(key=lambda x: (x.get(sort_key) or "").lower(), reverse=reverse)
    else:
        out.sort(key=lambda x: x.get("discovered_at") or x.get("published_at") or x.get("attack_at") or "", reverse=reverse)
    return out


def _paginate(rows: List[Dict[str, Any]], page: int = 1, page_size: int = 50) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    page = max(1, int(page or 1))
    page_size = max(1, min(int(page_size or 50), 200))
    total = len(rows)
    start = (page - 1) * page_size
    return rows[start:start + page_size], {"page": page, "page_size": page_size, "total": total, "pages": max(1, (total + page_size - 1) // page_size)}


def _read_watchlist() -> List[Dict[str, Any]]:
    try:
        with open(WATCHLIST_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except OSError:
        return []
    except ValueError:
        return []
    if isinstance(data, dict):
        data = data.get("entries", [])
    if not isinstance(data, list):
        return []
    out = []
    for item in data:
        if isinstance(item, dict) and item.get("id") and item.get("type") and item.get("value"):
            out.append({
                "id": _safe_text(item.get("id"), 80),
                "type": _safe_text(item.get("type"), 40),
                "value": _safe_text(item.get("value"), 300),
                "label": _safe_text(item.get("label"), 300),
                "enabled": item.get("enabled") is not False,
                "created_at": _date_text(item.get("created_at")) or _now().isoformat().replace("+00:00", "Z"),
            })
    return out


def _write_watchlist(entries: List[Dict[str, Any]]) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    payload = {"entries": entries, "updated_at": _now().isoformat().replace("+00:00", "Z")}
    tmp = f"{WATCHLIST_PATH}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    os.replace(tmp, WATCHLIST_PATH)


def watchlist_add(entry_type: str, value: str, label: str = "", enabled: bool = True) -> Dict[str, Any]:
    entry_type = _safe_text(entry_type, 40).lower().replace("_", "-")
    value = _safe_text(value, 300)
    label = _safe_text(label, 300)
    if entry_type not in {"group", "keyword", "domain", "country", "sector"}:
        raise ValueError("Watchlist type must be group, keyword, domain, country, or sector.")
    if not value:
        raise ValueError("Watchlist value is required.")
    if entry_type == "domain":
        value = _domain_from_url(value) or value.lower()
    if entry_type == "country":
        info = country_info(value)
        value = info["country_code"] or info["country"]
        label = label or info["country"]
    entry_id = hashlib.sha1(f"{entry_type}|{value.lower()}".encode("utf-8")).hexdigest()[:16]
    entries = [e for e in _read_watchlist() if e.get("id") != entry_id]
    entry = {
        "id": entry_id,
        "type": entry_type,
        "value": value,
        "label": label,
        "enabled": bool(enabled),
        "created_at": _now().isoformat().replace("+00:00", "Z"),
    }
    entries.append(entry)
    _write_watchlist(entries)
    return entry


def watchlist_delete(entry_id: str) -> Dict[str, Any]:
    entry_id = _safe_text(entry_id, 80)
    entries = _read_watchlist()
    kept = [e for e in entries if e.get("id") != entry_id]
    _write_watchlist(kept)
    return {"deleted": len(kept) != len(entries), "id": entry_id}


def _watch_match(entry: Dict[str, Any], victim: Dict[str, Any]) -> str:
    typ = entry.get("type")
    value = _safe_text(entry.get("value"), 300).lower()
    if not value:
        return ""
    if typ == "group" and value == (victim.get("group") or "").lower():
        return "group"
    if typ == "domain":
        domain = (victim.get("domain") or _domain_from_url(victim.get("website") or "")).lower()
        if domain and (value == domain or domain.endswith(f".{value}")):
            return "domain"
    if typ == "country":
        watched = country_info(value)
        actual = country_info(victim.get("country") or victim.get("country_code") or "")
        if watched["country_code"] and watched["country_code"] == actual["country_code"]:
            return "country"
        if watched["country"].lower() and watched["country"].lower() == actual["country"].lower():
            return "country"
    if typ == "sector" and value in (victim.get("sector") or "").lower():
        return "sector"
    if typ == "keyword":
        haystack = " ".join(_safe_text(victim.get(k), 1000).lower() for k in ("name", "domain", "website", "group", "country", "sector", "description"))
        if value in haystack:
            return "keyword"
    return ""


def recent_victims(days: int = 30, rwlive_key: str = "") -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    days = max(1, min(int(days or 30), 366))
    sources = []
    victims = []
    rl = _ransomlook("/posts", {"days": days}, ttl=600)
    sources.append(_source_status("RansomLook", rl))
    if not (isinstance(rl, dict) and rl.get("status") == "error"):
        for item in _listify(rl):
            victim = normalize_victim(item, "RansomLook")
            if victim.get("name"):
                victims.append(victim)
    if rwlive_key and query_ransomware_live_recent_victims:
        first_status = None
        seen_ids = set()
        for offset in range(0, 500, 100):
            rw = query_ransomware_live_recent_victims(rwlive_key, limit=100, offset=offset, order="discovered")
            if first_status is None:
                first_status = _source_status("Ransomware.live", rw)
            if not isinstance(rw, dict) or rw.get("error"):
                break
            batch = rw.get("victims") or []
            if not batch:
                break
            for item in batch:
                victim = normalize_victim(item, "Ransomware.live")
                victim_id = victim.get("raw_provider_id") or victim.get("id") or f"{victim.get('name')}|{victim.get('group')}"
                if victim.get("name") and victim_id not in seen_ids:
                    seen_ids.add(victim_id)
                    victims.append(victim)
            pagination = rw.get("pagination") or {}
            total = int(pagination.get("total") or 0) if isinstance(pagination, dict) else 0
            if total and offset + 100 >= total:
                break
        if first_status:
            sources.append(first_status)
    else:
        sources.append(_provider_error("Ransomware.live", "No ransomware.live API-PRO key provided", missing_key=True))
    deduped = _dedupe_victims(victims)
    deduped.sort(
        key=lambda v: v.get("discovered_at") or v.get("published_at") or v.get("attack_at") or "",
        reverse=True
    )
    return deduped, sources


def groups(days: int = 30, rwlive_key: str = "") -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    victims, source_statuses = recent_victims(days, rwlive_key)
    recent_counts = Counter((v.get("group") or "").lower() for v in victims if v.get("group"))
    out = []
    rl = _ransomlook("/groups", ttl=3600)
    source_statuses.append(_source_status("RansomLook Groups", rl))
    if not (isinstance(rl, dict) and rl.get("status") == "error"):
        for item in _listify(rl):
            group = normalize_group(item, "RansomLook", recent_counts)
            if group.get("name"):
                out.append(group)
    rw = _rwlive("/groups", rwlive_key, ttl=3600)
    source_statuses.append(_source_status("Ransomware.live Groups", rw))
    if not (isinstance(rw, dict) and rw.get("status") == "error"):
        for item in _listify(rw):
            group = normalize_group(item, "Ransomware.live", recent_counts)
            if group.get("name"):
                out.append(group)
    if not out:
        for name, count in recent_counts.items():
            out.append({"id": _slug(name), "name": name, "aliases": [], "status": "ACTIVE", "victim_count": count,
                        "recent_victim_count": count, "infrastructure_count": 0, "source": "Recent Victims", "sources": ["Recent Victims"]})
    return _dedupe_groups(out), source_statuses


def overview(days: int = 30, rwlive_key: str = "") -> Dict[str, Any]:
    days = max(1, min(int(days or 30), 366))
    victims, sources = recent_victims(days, rwlive_key)
    group_rows, group_sources = groups(days, rwlive_key)
    sources.extend(group_sources)
    today = _now().date().isoformat()
    victims_today = [v for v in victims if (v.get("discovered_at") or "")[:10] == today]
    victims_last_7 = [v for v in victims if _within_days(v.get("discovered_at") or "", 7)]
    victims_last_30 = [v for v in victims if _within_days(v.get("discovered_at") or "", 30)]
    newly_observed = [g for g in group_rows if _within_days(g.get("first_seen") or "", days)]
    active_group_counts = Counter(v.get("group") for v in victims if v.get("group"))
    active_groups = []
    by_slug = {_slug(g.get("name") or ""): g for g in group_rows}
    for group_name, count in active_group_counts.most_common():
        row = dict(by_slug.get(_slug(group_name), {}))
        row.update({
            "name": row.get("name") or group_name,
            "recent_victim_count": int(count),
            "source": row.get("source") or "Recent Victims",
            "sources": row.get("sources") or ["Recent Victims"],
        })
        active_groups.append(row)
    return {
        "sources": sources,
        "coverage": _provider_coverage(victims),
        "analyst_queue": _analyst_queue(victims),
        "analyst_summary": {
            "needs_geo_enrichment": sum(1 for v in victims if not _has_geo(v)),
            "has_live_enrichment": sum(1 for v in victims if _source_matches(v, "Ransomware.live") and _has_enrichment(v)),
            "new_groups_window": len(newly_observed),
            "recommended_focus": "Review today's victims first, then geolocated ransomware.live rows with screenshots, press, or infostealer evidence.",
        },
        "metrics": {
            "victims_today": len(victims_today),
            "victims_last_7_days": len(victims_last_7),
            "victims_last_30_days": len(victims_last_30),
            "active_groups": len(active_groups),
            "newly_observed_groups": len(newly_observed),
        },
        "metric_details": {
            "victims_today": victims_today,
            "victims_last_7_days": victims_last_7,
            "victims_last_30_days": victims_last_30,
            "active_groups": active_groups,
            "newly_observed_groups": newly_observed,
        },
        "timeline": _timeline(victims, days),
        "most_active_groups": _top(active_group_counts),
        "top_countries": _top_countries(victims),
        "top_sectors": _top_field_with_victims(victims, "sector"),
        "recent_victims": victims[:12],
        "recent_victims_ransomlook": [v for v in victims if _source_matches(v, "RansomLook")][:12],
        "recent_victims_rwlive": [v for v in victims if _source_matches(v, "Ransomware.live")][:12],
        "recently_observed_groups": newly_observed[:12],
    }


def victims_page(params: Dict[str, Any]) -> Dict[str, Any]:
    victims, sources = recent_victims(int(params.get("days") or 90), params.get("rwlive_key") or "")
    filtered = _filter_rows(victims, q=params.get("q", ""), group=params.get("group", ""), country=params.get("country", ""),
                            region=params.get("region", ""), sector=params.get("sector", ""), source=params.get("source", ""),
                            date_range=params.get("date_range", ""), sort=params.get("sort", "discovered_desc"))
    page, pagination = _paginate(filtered, int(params.get("page") or 1), int(params.get("page_size") or 50))
    return {"sources": sources, "victims": page, "pagination": pagination, "facets": _facets(victims), "coverage": _provider_coverage(filtered)}


def _facets(victims: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    return {
        "groups": sorted({v.get("group") for v in victims if v.get("group")})[:200],
        "countries": sorted({v.get("country") for v in victims if v.get("country")})[:200],
        "regions": sorted({v.get("region") for v in victims if v.get("region") and v.get("region") != "Unknown"})[:20],
        "sectors": sorted({v.get("sector") for v in victims if v.get("sector")})[:200],
        "sources": sorted({s for v in victims for s in (v.get("sources") or [v.get("source")]) if s})[:20],
    }


def groups_page(params: Dict[str, Any]) -> Dict[str, Any]:
    rows, sources = groups(int(params.get("days") or 30), params.get("rwlive_key") or "")
    q = (params.get("q") or "").lower()
    status = (params.get("status") or "").lower()
    if q:
        rows = [g for g in rows if q in " ".join([g.get("name", ""), " ".join(g.get("aliases") or [])]).lower()]
    if status:
        rows = [g for g in rows if status in (g.get("status") or "").lower()]
    sort = params.get("sort") or "recent_victim_count_desc"
    reverse = sort.endswith("_desc")
    key = sort.replace("_desc", "").replace("_asc", "")
    rows.sort(key=lambda g: (g.get(key) if isinstance(g.get(key), int) else str(g.get(key) or "").lower()), reverse=reverse)
    page, pagination = _paginate(rows, int(params.get("page") or 1), int(params.get("page_size") or 50))
    return {"sources": sources, "groups": page, "pagination": pagination, "facets": {"sources": sorted({s for g in rows for s in (g.get("sources") or [g.get("source")]) if s})}}


def group_profile(name: str, rwlive_key: str = "", days: int = 365) -> Dict[str, Any]:
    sources = []
    group_obj: Dict[str, Any] = {"name": name, "aliases": [], "sources": []}
    victims = []
    infrastructure = []
    notes = []
    negotiations = []
    crypto = []
    ttps = []
    vulnerabilities = []

    rl = _ransomlook(f"/group/{urllib.parse.quote(name, safe='')}", ttl=1800)
    sources.append(_source_status("RansomLook", rl))
    if not (isinstance(rl, dict) and rl.get("status") == "error"):
        items = _listify(rl)
        if items:
            group_raw = items[0] if isinstance(items[0], dict) else {}
            group_obj.update({k: v for k, v in normalize_group(group_raw, "RansomLook").items() if v not in ("", [], None)})
            group_obj["sources"] = _merge_sources(group_obj.get("sources", []), "RansomLook")
            for loc in group_raw.get("locations", []) if isinstance(group_raw.get("locations"), list) else []:
                infra = normalize_infrastructure(loc, group_obj.get("name") or name, "RansomLook")
                if infra.get("address"):
                    infrastructure.append(infra)
            if len(items) > 1:
                for item in _listify(items[1]):
                    victim = normalize_victim({**item, "group_name": group_obj.get("name") or name}, "RansomLook")
                    if victim.get("name"):
                        victims.append(victim)

    rl_crypto = _ransomlook(f"/crypto/{urllib.parse.quote(name, safe='')}", ttl=3600)
    sources.append(_source_status("RansomLook Crypto", rl_crypto))
    if isinstance(rl_crypto, dict) and not rl_crypto.get("status") == "error":
        for chain, wallets in (rl_crypto.get("by_chain") or {}).items():
            if isinstance(wallets, list):
                for wallet in wallets:
                    if isinstance(wallet, dict) and wallet.get("address"):
                        crypto.append({"group": name, "currency": chain, "address": _safe_text(wallet.get("address")),
                                       "transaction_count": wallet.get("tx_count", ""), "first_seen": "",
                                       "last_seen": _date_text(wallet.get("last_tx_time")), "source": "RansomLook"})

    rl_notes = _ransomlook(f"/notes/group/{urllib.parse.quote(name, safe='')}", ttl=21600)
    sources.append(_source_status("RansomLook Notes", rl_notes))
    if not (isinstance(rl_notes, dict) and rl_notes.get("status") == "error"):
        notes.extend([n for n in (normalize_note(x, "RansomLook", name) for x in _listify(rl_notes)) if n.get("filename") or n.get("note")])

    if rwlive_key and query_ransomware_live_group:
        rw = query_ransomware_live_group(name, rwlive_key)
        sources.append(_source_status("Ransomware.live", rw))
        if isinstance(rw, dict) and not rw.get("error"):
            if rw.get("groups"):
                rgroup = rw["groups"][0]
                for field in ("description", "first_seen", "last_seen", "status", "victim_count"):
                    if not group_obj.get(field):
                        group_obj[field] = rgroup.get(field)
                group_obj["aliases"] = list(dict.fromkeys([*(group_obj.get("aliases") or []), *(rgroup.get("aliases") or [])]))
                group_obj["sources"] = _merge_sources(group_obj.get("sources", []), "Ransomware.live")
                infrastructure.extend(rgroup.get("infrastructure") or [])
                ttps.extend(rgroup.get("ttps") or [])
                vulnerabilities.extend(rgroup.get("vulnerabilities") or [])
            victims.extend([normalize_victim(v, "Ransomware.live") for v in (rw.get("victims") or []) if isinstance(v, dict)])
        if query_ransomware_live_group_victims:
            rv = query_ransomware_live_group_victims(name, rwlive_key, limit=100, offset=0)
            sources.append(_source_status("Ransomware.live Victims", rv))
            if isinstance(rv, dict) and not rv.get("error"):
                victims.extend([normalize_victim(v, "Ransomware.live") for v in (rv.get("victims") or []) if isinstance(v, dict)])
        if query_ransomware_live_ransom_notes:
            rn = query_ransomware_live_ransom_notes(name, rwlive_key, limit=50)
            sources.append(_source_status("Ransomware.live Notes", rn))
            if isinstance(rn, dict) and not rn.get("error"):
                notes.extend([normalize_note(x, "Ransomware.live", name) for x in rn.get("ransom_notes", [])])
        if query_ransomware_live_negotiations:
            ng = query_ransomware_live_negotiations(name, rwlive_key, limit=50)
            sources.append(_source_status("Ransomware.live Negotiations", ng))
            if isinstance(ng, dict) and not ng.get("error"):
                negotiations.extend(ng.get("negotiations") or [])

    victims = _dedupe_victims(victims)
    group_obj["source"] = ", ".join(group_obj.get("sources") or [])
    return {
        "sources": sources,
        "group": group_obj,
        "victims": victims,
        "timeline": _timeline(victims, min(int(days or 365), 366)),
        "targeting": {
            "countries": _top_countries(victims),
            "sectors": _top_field_with_victims(victims, "sector"),
        },
        "infrastructure": infrastructure,
        "ransom_notes": notes,
        "negotiations": negotiations,
        "ttps": ttps,
        "vulnerabilities": vulnerabilities,
        "threat_actors": [],
        "crypto": crypto,
    }


def trends(days: int = 30, rwlive_key: str = "") -> Dict[str, Any]:
    days = max(1, min(int(days or 30), 366))
    victims, sources = recent_victims(days * 2, rwlive_key)
    cutoff = _now() - timedelta(days=days)
    prev_cutoff = _now() - timedelta(days=days * 2)
    current = [v for v in victims if (_parse_date(v.get("discovered_at")) or datetime.min.replace(tzinfo=timezone.utc)) >= cutoff]
    previous = [v for v in victims if prev_cutoff <= (_parse_date(v.get("discovered_at")) or datetime.min.replace(tzinfo=timezone.utc)) < cutoff]
    cur_counts = Counter(v.get("group") for v in current if v.get("group"))
    prev_counts = Counter(v.get("group") for v in previous if v.get("group"))
    activity = []
    for group in sorted(set(cur_counts) | set(prev_counts)):
        cur = cur_counts.get(group, 0)
        prev = prev_counts.get(group, 0)
        change = None if prev == 0 else round(((cur - prev) / prev) * 100, 1)
        activity.append({"group": group, "current": cur, "previous": prev, "change_percent": change})
    activity.sort(key=lambda x: (x["current"], x["previous"]), reverse=True)
    return {
        "sources": sources,
        "comparison": {"current_days": days, "previous_days": days},
        "victims_over_time": _timeline(current, days),
        "group_activity": activity[:50],
        "country_distribution": _top_countries(current),
        "sector_distribution": _top_field_with_victims(current, "sector"),
        "newly_observed_groups": [],
    }


def regions_page(params: Dict[str, Any]) -> Dict[str, Any]:
    days = int(params.get("days") or 30)
    victims, sources = recent_victims(days, params.get("rwlive_key") or "")
    enriched = [_enrich_country(v) for v in victims]
    geo_rows = [
        v for v in enriched
        if (v.get("country") or "").strip()
        and (v.get("country") or "").strip().lower() != "unknown"
    ]
    region_rows = [v for v in geo_rows if (v.get("region") or "").strip().lower() != "unknown"]
    region_filter = _safe_text(params.get("region") or "", 120).lower()
    country_filter = _safe_text(params.get("country") or "", 120).lower()
    q = _safe_text(params.get("q") or "", 120).lower()
    filtered = []
    for victim in geo_rows:
        if region_filter and region_filter != (victim.get("region") or "").lower():
            continue
        if country_filter:
            info = country_info(country_filter)
            actual = country_info(victim.get("country") or victim.get("country_code") or "")
            if info["country_code"]:
                if info["country_code"] != actual["country_code"]:
                    continue
            elif country_filter not in (actual["country"] or "").lower():
                continue
        if q:
            hay = " ".join(_safe_text(victim.get(k), 500).lower() for k in ("name", "domain", "group", "country", "region", "sector"))
            if q not in hay:
                continue
        filtered.append(victim)
    page, pagination = _paginate(filtered, int(params.get("page") or 1), int(params.get("page_size") or 50))
    by_country = Counter(v.get("country") for v in geo_rows if v.get("country"))
    country_rows = []
    groups_by_country: Dict[str, Counter] = defaultdict(Counter)
    sectors_by_country: Dict[str, Counter] = defaultdict(Counter)
    victims_by_country: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for victim in geo_rows:
        country = victim.get("country") or ""
        if not country:
            continue
        victims_by_country[country].append(victim)
        if victim.get("group"):
            groups_by_country[country][victim["group"]] += 1
        if victim.get("sector"):
            sectors_by_country[country][victim["sector"]] += 1
    for country, count in by_country.most_common(200):
        info = country_info(country)
        country_rows.append({
            "country": country,
            "country_code": info["country_code"],
            "region": info["region"],
            "victim_count": count,
            "top_groups": _top(groups_by_country[country], 5),
            "top_sectors": _top(sectors_by_country[country], 5),
            "victims": [_compact_victim(v) for v in victims_by_country[country]],
        })
    return {
        "sources": sources,
        "regions": _top_regions_with_victims(region_rows, 20),
        "countries": country_rows,
        "victims": page,
        "pagination": pagination,
        "unknown_victim_count": len(enriched) - len(geo_rows),
    }


def infrastructure_page(params: Dict[str, Any]) -> Dict[str, Any]:
    rows = []
    sources = []
    group_rows, sources = groups(30, params.get("rwlive_key") or "")
    selected_group = params.get("group") or ""
    candidates = [g for g in group_rows if not selected_group or (g.get("name") or "").lower() == selected_group.lower()]
    for group in candidates[:80]:
        name = group.get("name") or ""
        profile = group_profile(name, params.get("rwlive_key") or "", 30)
        rows.extend(profile.get("infrastructure") or [])
    q = (params.get("q") or "").lower()
    typ = (params.get("type") or "").lower()
    status = (params.get("status") or "").lower()
    source = (params.get("source") or "").lower()
    if q:
        rows = [r for r in rows if q in " ".join([r.get("group", ""), r.get("type", ""), r.get("address", "")]).lower()]
    if typ:
        rows = [r for r in rows if typ in (r.get("type") or "").lower()]
    if status:
        rows = [r for r in rows if status in (r.get("status") or "").lower()]
    if source:
        rows = [r for r in rows if source in (r.get("source") or "").lower()]
    page, pagination = _paginate(rows, int(params.get("page") or 1), int(params.get("page_size") or 50))
    return {"sources": sources, "infrastructure": page, "pagination": pagination}


def ransom_notes_page(params: Dict[str, Any]) -> Dict[str, Any]:
    rows = []
    sources = []
    rl_recent = _ransomlook("/notes/recent", {"number": int(params.get("limit") or 1000)}, ttl=21600)
    sources.append(_source_status("RansomLook Notes", rl_recent))
    if not (isinstance(rl_recent, dict) and rl_recent.get("status") == "error"):
        rows.extend([n for n in (normalize_note(x, "RansomLook") for x in _listify(rl_recent)) if n.get("filename") or n.get("note")])
    tl_notes, tl_source = threatlabz_ransom_notes()
    sources.append(tl_source)
    rows.extend(tl_notes)
    rows = _dedupe_notes(rows)
    q = (params.get("q") or "").lower()
    group = (params.get("group") or "").lower()
    source = (params.get("source") or "").lower()
    if q:
        rows = [r for r in rows if q in " ".join([
            r.get("group", ""),
            r.get("family", ""),
            r.get("filename", ""),
            r.get("source", ""),
            r.get("source_url", ""),
            r.get("note", ""),
        ]).lower()]
    if group:
        rows = [r for r in rows if group in (r.get("group") or "").lower()]
    if source:
        rows = [r for r in rows if source in (r.get("source") or "").lower()]
    rows.sort(key=lambda r: (r.get("discovered_at") or "", r.get("group") or "", r.get("filename") or ""), reverse=True)
    page, pagination = _paginate(rows, int(params.get("page") or 1), int(params.get("page_size") or 50))
    page = _hydrate_threatlabz_notes(page)
    return {"sources": sources, "ransom_notes": page, "pagination": pagination}


def negotiations_page(params: Dict[str, Any]) -> Dict[str, Any]:
    rows = []
    sources = []
    api_key = params.get("rwlive_key") or ""
    q = (params.get("q") or "").strip()
    group = (params.get("group") or "").strip() or q
    if query_ransomware_live_negotiations:
        result = query_ransomware_live_negotiations(group, api_key, limit=int(params.get("limit") or 100), offset=0)
        sources.append(_source_status("Ransomware.live Negotiations", result))
        if isinstance(result, dict) and not result.get("error") and not result.get("status") == "error":
            rows.extend([n for n in (normalize_negotiation(x, "Ransomware.live", group) for x in result.get("negotiations", [])) if n.get("id")])
    else:
        sources.append(_provider_error("Ransomware.live Negotiations", "Negotiation provider is not available"))

    ql = q.lower()
    status = (params.get("status") or "").lower()
    if ql:
        rows = [r for r in rows if ql in " ".join(_safe_text(r.get(k), 500).lower() for k in ("group", "victim", "id", "status"))]
    if status:
        rows = [r for r in rows if status in (r.get("status") or "").lower()]
    rows.sort(key=lambda r: r.get("started") or r.get("ended") or "", reverse=True)
    page, pagination = _paginate(rows, int(params.get("page") or 1), int(params.get("page_size") or 50))
    return {"sources": sources, "negotiations": page, "pagination": pagination}


def actors_page(params: Dict[str, Any]) -> Dict[str, Any]:
    data = _ransomlook("/actors/", ttl=3600)
    rows = []
    if not (isinstance(data, dict) and data.get("status") == "error"):
        for item in _listify(data):
            if isinstance(item, dict):
                groups = []
                for key in ("groups", "associated_groups", "ransomware_groups", "gangs", "operations", "families"):
                    groups.extend(_text_list(item.get(key)))
                forums = []
                for key in ("forums", "associated_forums", "markets", "channels"):
                    forums.extend(_text_list(item.get(key)))
                rows.append({
                    "name": _safe_text(item.get("name")),
                    "aliases": _text_list(item.get("aliases") or item.get("aka") or item.get("altname")),
                    "associated_groups": list(dict.fromkeys(groups)),
                    "associated_forums": list(dict.fromkeys(forums)),
                    "role": _safe_text(item.get("role") or item.get("type")),
                    "description": _safe_text(item.get("description") or item.get("bio") or item.get("summary")),
                    "first_seen": _date_text(item.get("first_seen") or item.get("firstseen") or item.get("created_at")),
                    "last_seen": _date_text(item.get("last_seen") or item.get("lastseen") or item.get("updated_at")),
                    "profile_url": _safe_text(item.get("url") or item.get("link") or item.get("profile_url")),
                    "source": "RansomLook",
                    "raw": item,
                })
    q = (params.get("q") or "").lower()
    if q:
        rows = [r for r in rows if q in " ".join([r.get("name", ""), " ".join(r.get("aliases") or [])]).lower()]
    page, pagination = _paginate(rows, int(params.get("page") or 1), int(params.get("page_size") or 50))
    return {"sources": [_source_status("RansomLook Actors", data)], "actors": page, "pagination": pagination}


def press_8k_page(params: Dict[str, Any]) -> Dict[str, Any]:
    api_key = params.get("rwlive_key") or ""
    country = _safe_text(params.get("country") or "", 20).upper()
    q = _safe_text(params.get("q") or "", 160).lower()
    sources = []

    press_raw = _rwlive("/press/recent", api_key, params={"country": country}, ttl=1800)
    sources.append(_source_status("Ransomware.live Press", press_raw))
    press_rows = []
    if not (isinstance(press_raw, dict) and press_raw.get("status") == "error"):
        for item in _listify(press_raw):
            if isinstance(item, dict):
                row = {
                    "title": _safe_text(item.get("title") or item.get("organization") or item.get("victim") or item.get("domain")),
                    "organization": _safe_text(item.get("organization") or item.get("victim") or item.get("company")),
                    "country": _safe_text(item.get("country")),
                    "sector": _safe_text(item.get("sector") or item.get("activity")),
                    "date": _date_text(item.get("date") or item.get("published") or item.get("added")),
                    "domain": _safe_text(item.get("domain") or item.get("website")),
                    "ransomware_link": _safe_text(item.get("ransomware_link") or item.get("permalink")),
                    "source_url": _safe_text(item.get("source_url") or item.get("url") or item.get("link")),
                    "infostealer": item.get("infostealer") or "",
                    "source": "Ransomware.live",
                    "raw": item,
                }
                if row["title"] or row["organization"]:
                    press_rows.append(_enrich_country(row))

    if q:
        press_rows = [r for r in press_rows if q in " ".join(_safe_text(r.get(k), 600).lower() for k in ("title", "organization", "country", "sector", "domain", "source_url"))]
    return {"sources": sources, "press": press_rows[:100]}


def detection_iocs_page(params: Dict[str, Any]) -> Dict[str, Any]:
    api_key = params.get("rwlive_key") or ""
    group = _safe_text(params.get("group") or params.get("q") or "", 120)
    ioc_type = _safe_text(params.get("ioc_type") or params.get("type") or "", 40).lower()
    sources = []
    if group:
        yara_raw = _rwlive(f"/yara/{urllib.parse.quote(group, safe='')}", api_key, ttl=3600)
        ioc_raw = _rwlive(f"/iocs/{urllib.parse.quote(group, safe='')}", api_key, params={"type": ioc_type}, ttl=3600)
    else:
        yara_raw = _rwlive("/yara", api_key, ttl=3600)
        ioc_raw = _rwlive("/iocs", api_key, params={"type": ioc_type}, ttl=3600)
    sources.append(_source_status("Ransomware.live YARA", yara_raw))
    sources.append(_source_status("Ransomware.live IOCs", ioc_raw))

    yara_rows = []
    if not (isinstance(yara_raw, dict) and yara_raw.get("status") == "error"):
        for item in _listify(yara_raw):
            if isinstance(item, dict):
                yara_rows.append({
                    "group": _safe_text(item.get("group") or item.get("name") or group),
                    "filename": _safe_text(item.get("filename") or item.get("file") or item.get("rule")),
                    "count": item.get("count") or item.get("rules") or "",
                    "content": _safe_text(item.get("content") or item.get("text"), 20000),
                    "raw": item,
                })
            elif item:
                yara_rows.append({"group": _safe_text(item), "filename": "", "count": "", "content": "", "raw": item})

    ioc_rows = []
    if not (isinstance(ioc_raw, dict) and ioc_raw.get("status") == "error"):
        if isinstance(ioc_raw, dict) and any(isinstance(v, list) for v in ioc_raw.values()):
            for typ, values in ioc_raw.items():
                if isinstance(values, list):
                    for value in values[:500]:
                        ioc_rows.append({"group": group, "type": _safe_text(typ), "value": _safe_text(value, 2000), "raw": value})
        for item in _listify(ioc_raw):
            if isinstance(item, dict):
                ioc_rows.append({
                    "group": _safe_text(item.get("group") or item.get("name") or group),
                    "type": _safe_text(item.get("type") or item.get("ioc_type")),
                    "count": item.get("count") or item.get("total") or "",
                    "value": _safe_text(item.get("value") or item.get("ioc") or item.get("indicator"), 2000),
                    "raw": item,
                })
            elif item:
                ioc_rows.append({"group": group, "type": ioc_type, "value": _safe_text(item, 2000), "raw": item})
    return {"sources": sources, "group": group, "yara": yara_rows[:200], "iocs": ioc_rows[:500]}


def csirt_stats_page(params: Dict[str, Any]) -> Dict[str, Any]:
    api_key = params.get("rwlive_key") or ""
    country = _safe_text(params.get("country") or params.get("q") or "", 20).upper()
    sources = []
    stats_raw = _rwlive("/stats", api_key, ttl=1800)
    sectors_raw = _rwlive("/listsectors", api_key, ttl=3600)
    sources.append(_source_status("Ransomware.live Stats", stats_raw))
    sources.append(_source_status("Ransomware.live Sectors", sectors_raw))
    csirt_raw = []
    if country:
        csirt_raw = _rwlive(f"/csirt/{urllib.parse.quote(country, safe='')}", api_key, ttl=86400)
        sources.append(_source_status("Ransomware.live CSIRT", csirt_raw))
    sectors = []
    if not (isinstance(sectors_raw, dict) and sectors_raw.get("status") == "error"):
        for item in _listify(sectors_raw):
            if isinstance(item, dict):
                sectors.append({"sector": _safe_text(item.get("sector") or item.get("name") or item.get("activity")), "count": item.get("count") or item.get("victims") or ""})
            elif item:
                sectors.append({"sector": _safe_text(item), "count": ""})
    contacts = []
    if country and not (isinstance(csirt_raw, dict) and csirt_raw.get("status") == "error"):
        for item in _listify(csirt_raw):
            if isinstance(item, dict):
                contacts.append({
                    "name": _safe_text(item.get("name") or item.get("team") or item.get("organization")),
                    "country": _safe_text(item.get("country") or country),
                    "email": _safe_text(item.get("email") or item.get("contact")),
                    "phone": _safe_text(item.get("phone")),
                    "website": _safe_text(item.get("website") or item.get("url")),
                    "source": _safe_text(item.get("source") or item.get("provider")),
                    "raw": item,
                })
    return {"sources": sources, "stats": stats_raw if isinstance(stats_raw, dict) else {}, "sectors": sectors[:300], "csirt": contacts, "country": country}


def crypto_page(params: Dict[str, Any]) -> Dict[str, Any]:
    data = _ransomlook("/crypto/", ttl=3600)
    rows = []
    sources = [_source_status("RansomLook Crypto", data)]
    if not (isinstance(data, dict) and data.get("status") == "error"):
        for group in _listify(data)[:100]:
            name = _safe_text(group.get("name") if isinstance(group, dict) else group)
            detail = _ransomlook(f"/crypto/{urllib.parse.quote(name, safe='')}", ttl=3600)
            if isinstance(detail, dict) and not detail.get("status") == "error":
                for chain, wallets in (detail.get("by_chain") or {}).items():
                    if isinstance(wallets, list):
                        for wallet in wallets:
                            if isinstance(wallet, dict) and wallet.get("address"):
                                rows.append({"group": name, "currency": chain, "address": _safe_text(wallet.get("address")),
                                             "transaction_count": wallet.get("tx_count", ""), "first_seen": "",
                                             "last_seen": _date_text(wallet.get("last_tx_time")), "source": "RansomLook"})
    q = (params.get("q") or "").lower()
    if q:
        rows = [r for r in rows if q in " ".join(_safe_text(v, 300) for v in r.values()).lower()]
    page, pagination = _paginate(rows, int(params.get("page") or 1), int(params.get("page_size") or 50))
    return {"sources": sources, "crypto_addresses": page, "pagination": pagination}


def ttps_vulnerabilities_page(params: Dict[str, Any]) -> Dict[str, Any]:
    rows_ttp = []
    rows_vuln = []
    source_statuses = []
    group_rows, source_statuses = groups(30, params.get("rwlive_key") or "")
    for group in group_rows[:40]:
        raw = _rwlive(f"/groups/{urllib.parse.quote(group.get('name') or '', safe='')}", params.get("rwlive_key") or "", ttl=3600)
        if isinstance(raw, dict) and raw.get("status") == "error":
            continue
        for ttp in raw.get("ttps", []) if isinstance(raw, dict) and isinstance(raw.get("ttps"), list) else []:
            if isinstance(ttp, dict):
                rows_ttp.append({"group": group.get("name"), "technique_id": _safe_text(ttp.get("id") or ttp.get("technique_id")),
                                 "technique_name": _safe_text(ttp.get("name") or ttp.get("technique")),
                                 "tactic": _safe_text(ttp.get("tactic")), "source": "Ransomware.live"})
        for vuln in raw.get("vulnerabilities", []) if isinstance(raw, dict) and isinstance(raw.get("vulnerabilities"), list) else []:
            if isinstance(vuln, dict):
                rows_vuln.append({"cve": _safe_text(vuln.get("cve") or vuln.get("id")), "group": group.get("name"),
                                  "description": _safe_text(vuln.get("description")), "first_seen": _date_text(vuln.get("first_seen")),
                                  "last_seen": _date_text(vuln.get("last_seen")), "source": "Ransomware.live"})
    return {"sources": source_statuses, "ttps": rows_ttp, "vulnerabilities": rows_vuln}


def watchlist_page(params: Dict[str, Any]) -> Dict[str, Any]:
    entries = _read_watchlist()
    victims, sources = recent_victims(int(params.get("days") or 30), params.get("rwlive_key") or "")
    matches = []
    for entry in entries:
        if entry.get("enabled") is False:
            continue
        for victim in victims:
            field = _watch_match(entry, victim)
            if field:
                matches.append({"entry": entry, "matched_field": field, "victim": _enrich_country(victim)})
    matches.sort(key=lambda m: m["victim"].get("discovered_at") or "", reverse=True)
    page, pagination = _paginate(matches, int(params.get("page") or 1), int(params.get("page_size") or 50))
    return {"sources": sources, "entries": entries, "matches": page, "pagination": pagination}
