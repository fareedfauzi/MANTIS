"""Today's Intelligence aggregation for the MANTIS dashboard.

Passive, local-first rollup over existing MANTIS datasets:
CTI articles, KEV/PoC intelligence, ransomware victims, and lightweight
actor/malware mentions inferred from today's CTI text.
"""
from __future__ import annotations

import json
import re
import time
import csv
import io
import xml.etree.ElementTree as ET
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List

import feedparser
import requests

import ai_service
import cti_db
import pocindex_mod
import ransomware_monitor
import tweetfeed_service
import breach_watcher
import tg_channel_monitor
from intel_query import (
    query_censys_search,
    query_greynoise,
    query_otx_pulse,
    query_shodan_search,
    query_vt,
)


ACTOR_HINT_RE = re.compile(
    r"\b(?:APT\d{1,3}|TA\d{3,4}|UNC\d{3,5}|FIN\d{1,2}|Storm-\d{4}|"
    r"Lazarus|Kimsuky|Sandworm|Turla|Volt Typhoon|Salt Typhoon|Flax Typhoon|"
    r"Mustang Panda|Earth Lusca|Earth Estries|Charming Kitten|MuddyWater|OilRig|"
    r"Transparent Tribe|SideWinder|Gamaredon|Secret Blizzard|Midnight Blizzard|"
    r"Scattered Spider|ShinyHunters|FIN7|FIN11|Evil Corp|LockBit|Qilin|Akira|"
    r"DragonForce|Cl0p|BlackCat|ALPHV|Play|RansomHub|BianLian|Rhysida|Medusa)\b",
    re.IGNORECASE,
)
MALWARE_HINT_RE = re.compile(
    r"\b(?:Cobalt Strike|Brute Ratel|Sliver|Metasploit|Lumma|LummaC2|RedLine|Vidar|"
    r"Raccoon|StealC|Agent Tesla|FormBook|XLoader|QakBot|Qbot|Emotet|IcedID|Bumblebee|"
    r"TrickBot|Dridex|Remcos|AsyncRAT|njRAT|QuasarRAT|NetSupport RAT|SocGholish|GootLoader|"
    r"Raspberry Robin|SmokeLoader|Amadey|DarkGate|DanaBot|Ursnif|PlugX|Gh0st RAT|"
    r"ShadowPad|KPlug|Pikabot|SystemBC|BazarLoader|GuLoader|Remcos|Akira|LockBit|Qilin|"
    r"BlackCat|ALPHV|Cl0p|RansomHub|Rhysida|Medusa|Play ransomware)\b",
    re.IGNORECASE,
)
IP_RE = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

HTTP_HEADERS = {"User-Agent": "MANTIS-Todays-Intelligence/1.0"}

COUNTRY_FOCUS_TERMS = {
    "my": ["malaysia", "malaysian"],
    "malaysia": ["malaysia", "malaysian"],
    "sg": ["singapore", "singaporean"],
    "singapore": ["singapore", "singaporean"],
    "id": ["indonesia", "indonesian"],
    "indonesia": ["indonesia", "indonesian"],
    "th": ["thailand", "thai"],
    "thailand": ["thailand", "thai"],
    "ph": ["philippines", "philippine", "filipino"],
    "philippines": ["philippines", "philippine", "filipino"],
    "vn": ["vietnam", "vietnamese"],
    "vietnam": ["vietnam", "vietnamese"],
    "apac": ["apac", "asia pacific", "asia-pacific"],
    "asean": ["asean", "southeast asia", "south-east asia"],
}

HIGH_SIGNAL_TERMS = [
    "actively exploited", "exploited in the wild", "zero-day", "0-day", "critical",
    "emergency", "ransomware", "remote code execution", "rce", "authentication bypass",
    "privilege escalation", "data breach", "incident", "malware", "botnet", "campaign",
    "cve-", "kev", "patch now", "urgent", "supply chain",
]

HIGH_IMPACT_VENDOR_TERMS = [
    "microsoft", "windows", "exchange", "sharepoint", "azure", "office",
    "cisco", "fortinet", "palo alto", "globalprotect", "ivanti", "citrix",
    "netscaler", "vmware", "broadcom", "atlassian", "confluence", "jira",
    "google chrome", "chromium", "apple", "adobe", "sap", "oracle",
    "sonicwall", "f5", "big-ip", "juniper", "zimbra", "moodle",
]

REGIONAL_CERT_FEEDS = [
    {"source": "CERT-EU Advisories", "region": "Europe", "url": "https://cert.europa.eu/publications/security-advisories-rss"},
    {"source": "CERT-EU Threat Intel", "region": "Europe", "url": "https://cert.europa.eu/publications/threat-intelligence-rss"},
    {"source": "CERT-FR Alerts", "region": "France", "url": "https://www.cert.ssi.gouv.fr/alerte/feed/"},
    {"source": "CERT-FR Advisories", "region": "France", "url": "https://www.cert.ssi.gouv.fr/avis/feed/"},
    {"source": "JPCERT/CC", "region": "Japan", "url": "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf"},
    {"source": "Canadian Centre for Cyber Security", "region": "Canada", "url": "https://cyber.gc.ca/webservice/en/rss/alerts"},
    {"source": "CERT.BE Advisories", "region": "Belgium", "url": "https://ccb.belgium.be/advisories.xml"},
    {"source": "US CERT Vulnerability Notes", "region": "United States", "url": "https://kb.cert.org/vuls/atomfeed"},
]

VENDOR_ADVISORY_FEEDS = [
    {"source": "Cisco PSIRT", "vendor": "Cisco", "url": "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"},
    {"source": "Palo Alto Security Advisories", "vendor": "Palo Alto Networks", "url": "https://security.paloaltonetworks.com/rss.xml"},
    {"source": "Google Security Blog", "vendor": "Google", "url": "https://security.googleblog.com/feeds/posts/default"},
]

SECURITY_NEWS_FEEDS = [
    {"source": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"source": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"source": "SecurityWeek", "url": "https://www.securityweek.com/feed/"},
    {"source": "KrebsOnSecurity", "url": "https://krebsonsecurity.com/feed/"},
    {"source": "Help Net Security", "url": "https://www.helpnetsecurity.com/feed/"},
    {"source": "Securenza", "url": "https://news.securenza.be/rss.xml"},
]


def _now() -> datetime:
    return datetime.now().astimezone()


def _today_iso() -> str:
    return _now().date().isoformat()


def _days_ago_iso(days: int) -> str:
    return (_now() - timedelta(days=max(0, int(days or 0)))).strftime("%Y-%m-%dT%H:%M:%S")


def _range_mode(value: str) -> str:
    mode = (value or "today").strip().lower().replace("_", "-")
    if mode in {"24h", "past-24h", "past24h"}:
        return "24h"
    if mode in {"7d", "past-7d", "past7d", "week"}:
        return "7d"
    return "today"


def _range_since(mode: str) -> str:
    mode = _range_mode(mode)
    if mode == "24h":
        return (_now() - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S")
    if mode == "7d":
        return _days_ago_iso(7)
    return _today_iso()


def _range_days(mode: str) -> int:
    mode = _range_mode(mode)
    if mode == "7d":
        return 7
    return 1


def _range_label(mode: str) -> str:
    mode = _range_mode(mode)
    if mode == "24h":
        return "Past 24H"
    if mode == "7d":
        return "Past 7D"
    return "Today"


def _parse_dt(value: Any) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    raw = raw.replace("Z", "+00:00")
    try:
        dt = parsedate_to_datetime(raw)
        if dt:
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=_now().tzinfo)
            return dt.astimezone()
    except (TypeError, ValueError, IndexError, OverflowError):
        pass
    for candidate in (raw, raw[:19], raw[:10]):
        try:
            dt = datetime.fromisoformat(candidate)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=_now().tzinfo)
            return dt.astimezone()
        except ValueError:
            continue
    return None


def _range_start_dt(mode: str) -> datetime:
    mode = _range_mode(mode)
    now = _now()
    if mode == "24h":
        return now - timedelta(hours=24)
    if mode == "7d":
        return now - timedelta(days=7)
    return now.replace(hour=0, minute=0, second=0, microsecond=0)


def _in_range(value: Any, mode: str) -> bool:
    dt = _parse_dt(value)
    if not dt:
        return True
    return dt >= _range_start_dt(mode)


def _safe_float(value: Any) -> float | None:
    try:
        if value in (None, ""):
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def _source_result(source: str, configured: bool, items: List[Dict[str, Any]] | None = None, error: str = "", note: str = "") -> Dict[str, Any]:
    items = items or []
    return {
        "source": source,
        "configured": bool(configured),
        "total": len(items),
        "items": items,
        "error": str(error or "")[:300],
        "note": str(note or "")[:240],
    }


def _published_date(row: Dict[str, Any]) -> str:
    value = row.get("published_at") or row.get("fetched_at") or row.get("published") or ""
    return str(value)[:10]


def _article_summary(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": row.get("id"),
        "title": row.get("title") or "Untitled",
        "source": row.get("source_name") or row.get("source") or "",
        "category": row.get("source_category") or "",
        "published": row.get("published_at") or row.get("fetched_at") or "",
        "url": row.get("url") or "",
        "excerpt": row.get("excerpt") or "",
        "indicator_count": int(row.get("indicator_count") or 0),
    }


def _contains_any(row: Dict[str, Any], fields: List[str], needle: str) -> bool:
    value = (needle or "").strip().lower()
    if not value:
        return True
    haystack = " ".join(str(row.get(field) or "") for field in fields).lower()
    return value in haystack


def _focus_terms(value: str) -> List[str]:
    raw = (value or "").strip().lower()
    if not raw:
        return []
    terms = COUNTRY_FOCUS_TERMS.get(raw, [])
    terms = [raw, *terms]
    out = []
    for term in terms:
        clean = term.strip().lower()
        if clean and clean not in out:
            out.append(clean)
    return out


def _matches_focus(row: Dict[str, Any], terms: List[str], fields: List[str] | None = None) -> bool:
    if not terms:
        return True
    fields = fields or ["title", "excerpt", "source", "category", "country", "region", "sector", "name", "group"]
    haystack = " ".join(str(row.get(field) or "") for field in fields).lower()
    return any(term in haystack for term in terms)


def _filter_source_result(result: Dict[str, Any], terms: List[str]) -> Dict[str, Any]:
    if not terms:
        return result
    items = [item for item in (result.get("items") or []) if isinstance(item, dict) and _matches_focus(item, terms)]
    out = dict(result)
    out["items"] = items
    out["total"] = len(items)
    return out


def _entry_dt(entry: Any) -> datetime | None:
    for attr in ("published_parsed", "updated_parsed", "created_parsed"):
        value = getattr(entry, attr, None)
        if value:
            try:
                return datetime(*value[:6], tzinfo=timezone.utc).astimezone()
            except Exception:
                pass
    return _parse_dt(getattr(entry, "published", "") or getattr(entry, "updated", "") or getattr(entry, "created", ""))


def _entry_published(entry: Any) -> str:
    dt = _entry_dt(entry)
    if dt:
        return dt.isoformat()
    return str(getattr(entry, "published", "") or getattr(entry, "updated", "") or "")


def _clean_text(value: Any, limit: int = 420) -> str:
    text = re.sub(r"<[^>]+>", " ", str(value or ""))
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def _is_high_signal_text(text: str, strict: bool = False) -> bool:
    haystack = (text or "").lower()
    if not haystack:
        return False
    has_signal = any(term in haystack for term in HIGH_SIGNAL_TERMS)
    has_vendor = any(term in haystack for term in HIGH_IMPACT_VENDOR_TERMS)
    if strict:
        return has_signal and (has_vendor or "cve-" in haystack or "actively exploited" in haystack or "zero-day" in haystack)
    return has_signal or has_vendor


def _dedupe_items(items: List[Dict[str, Any]], limit: int) -> List[Dict[str, Any]]:
    seen = set()
    out = []
    for item in items:
        key = (
            str(item.get("url") or "").strip().lower()
            or f"{item.get('source')}:{item.get('title')}".strip().lower()
        )
        key = re.sub(r"\s+", " ", key)
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= limit:
            break
    return out


def _rss_feed_items(feeds: List[Dict[str, str]], limit: int, range_mode: str,
                    strict: bool = False, focus: str = "") -> Dict[str, Any]:
    terms = _focus_terms(focus)
    items: List[Dict[str, Any]] = []
    errors = []
    per_feed_cap = max(2, min(6, limit))

    def fetch_feed(feed: Dict[str, str]) -> Dict[str, Any]:
        feed_items: List[Dict[str, Any]] = []
        feed_errors: List[str] = []
        url = feed.get("url") or ""
        source = feed.get("source") or url
        try:
            resp = requests.get(url, headers={**HTTP_HEADERS, "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml"}, timeout=7)
            if resp.status_code != 200:
                return {"items": [], "errors": [f"{source}: HTTP {resp.status_code}"]}
            parsed = feedparser.parse(resp.content)
        except Exception as exc:
            return {"items": [], "errors": [f"{source}: {str(exc)[:80]}"]}
        if getattr(parsed, "bozo", 0) and not getattr(parsed, "entries", None):
            return {"items": [], "errors": [f"{source}: feed parse failed"]}
        added = 0
        for entry in getattr(parsed, "entries", []) or []:
            published = _entry_published(entry)
            if not _in_range(published, range_mode):
                continue
            title = _clean_text(getattr(entry, "title", ""), 220)
            summary = _clean_text(getattr(entry, "summary", "") or getattr(entry, "description", ""), 320)
            blob = f"{title} {summary}"
            if not _is_high_signal_text(blob, strict=strict):
                continue
            row = {
                "source": source,
                "title": title or source,
                "summary": summary,
                "published": published,
                "url": getattr(entry, "link", "") or "",
                "region": feed.get("region") or "",
                "vendor": feed.get("vendor") or "",
                "category": feed.get("category") or "",
                "cves": sorted(set(match.upper() for match in CVE_RE.findall(blob)))[:8],
            }
            if terms and not _matches_focus(row, terms, ["title", "summary", "source", "region", "vendor", "category"]):
                continue
            feed_items.append(row)
            added += 1
            if added >= per_feed_cap:
                break
        return {"items": feed_items, "errors": feed_errors}

    if feeds:
        with ThreadPoolExecutor(max_workers=min(8, len(feeds))) as executor:
            for result in executor.map(fetch_feed, feeds):
                items.extend(result.get("items") or [])
                errors.extend(result.get("errors") or [])
                if len(items) >= limit * 3:
                    break
    items.sort(key=lambda x: str(x.get("published") or ""), reverse=True)
    items = _dedupe_items(items, limit)
    return {
        "items": items,
        "error": "; ".join(errors[:3]),
    }


def mycert_advisories(limit: int = 6, range_mode: str = "today", focus: str = "") -> List[Dict[str, Any]]:
    try:
        resp = requests.get("https://mycert.org.my/", headers=HTTP_HEADERS, timeout=6)
        if resp.status_code != 200:
            return []
    except Exception:
        return []
    terms = _focus_terms(focus)
    items = []
    seen = set()
    for match in re.finditer(r"\[(\d{2}-\d{2}-\d{4})\]\s*([^<\n]+)", resp.text):
        raw_date, raw_title = match.groups()
        try:
            dt = datetime.strptime(raw_date, "%d-%m-%Y").replace(tzinfo=_now().tzinfo)
            published = dt.isoformat()
        except ValueError:
            published = raw_date
        if not _in_range(published, range_mode):
            continue
        title = _clean_text(raw_title, 220)
        if not _is_high_signal_text(title, strict=False):
            continue
        row = {
            "source": "MyCERT",
            "title": title,
            "summary": "",
            "published": published,
            "url": "https://mycert.org.my/",
            "region": "Malaysia",
            "category": "National CERT",
            "cves": sorted(set(match.upper() for match in CVE_RE.findall(title)))[:8],
        }
        key = title.lower()
        if key in seen:
            continue
        if terms and not _matches_focus(row, terms, ["title", "summary", "source", "region", "category"]):
            continue
        seen.add(key)
        items.append(row)
        if len(items) >= limit:
            break
    return items


def today_articles(limit: int = 30, source_type: str = "", range_mode: str = "today", focus: str = "") -> Dict[str, Any]:
    cti_db.init_db()
    conn = cti_db.connect()
    try:
        since = _range_since(range_mode)
        terms = _focus_terms(focus)
        fetch_limit = max(limit, 500)
        rows, total = cti_db.recent_articles(since_iso=since, limit=fetch_limit, offset=0, conn=conn)
        if not rows and _range_mode(range_mode) == "today":
            rows, total = cti_db.recent_articles(since_iso=_days_ago_iso(1), limit=fetch_limit, offset=0, conn=conn)
        items = [_article_summary(row) for row in rows]
        if source_type:
            wanted = source_type.strip().lower()
            items = [row for row in items if wanted in (row.get("category") or "").lower() or wanted in (row.get("source") or "").lower()]
        if terms:
            items = [row for row in items if _matches_focus(row, terms, ["title", "excerpt", "source", "category"])]
            total = len(items)
            items = items[:limit]
        return {
            "total": total,
            "items": items,
        }
    finally:
        conn.close()


def kev_items(limit: int = 12, severity: str = "") -> Dict[str, Any]:
    try:
        data = pocindex_mod.search_poc("", kev_only=True, limit=limit, offset=0, sort_by="NEWEST")
    except Exception as exc:
        return {"total": 0, "items": [], "error": str(exc)}
    items = []
    for row in data.get("results") or []:
        if severity and severity.upper() not in str(row.get("severity") or "").upper():
            continue
        cve = str(row.get("cve") or "").upper()
        epss_meta = (pocindex_mod.state.get("epss") or {}).get(cve) or []
        epss_score = _safe_float(epss_meta[0] if len(epss_meta) > 0 else None)
        epss_percentile = _safe_float(epss_meta[1] if len(epss_meta) > 1 else None)
        items.append({
            "cve": row.get("cve"),
            "title": row.get("title") or row.get("kev_vulnerability_name") or row.get("desc") or "",
            "severity": row.get("severity") or "",
            "published": row.get("published") or row.get("kev_date_added") or "",
            "vendor": ", ".join(row.get("vendor") or []) if isinstance(row.get("vendor"), list) else row.get("vendor") or "",
            "product": ", ".join(row.get("product") or []) if isinstance(row.get("product"), list) else row.get("product") or "",
            "known_ransomware": row.get("kev_known_ransomware_campaign_use") or "",
            "poc_count": len(row.get("_allLinks") or []),
            "epss": epss_score,
            "epss_percentile": epss_percentile,
        })
    return {"total": data.get("total") or len(items), "items": items}


def poc_items(limit: int = 12, severity: str = "") -> Dict[str, Any]:
    try:
        trending = pocindex_mod.get_trending(limit=limit)
    except Exception as exc:
        return {"total": 0, "items": [], "error": str(exc)}
    items = []
    for row in trending or []:
        if severity and severity.upper() not in str(row.get("severity") or row.get("cvss_severity") or "").upper():
            continue
        cve = str(row.get("cve") or "").upper()
        epss_meta = (pocindex_mod.state.get("epss") or {}).get(cve) or []
        items.append({
            "name": row.get("name") or row.get("repo") or row.get("cve") or "PoC",
            "description": row.get("description") or row.get("desc") or "",
            "url": row.get("html_url") or row.get("url") or "",
            "stars": row.get("stargazers_count") or row.get("stars") or 0,
            "updated": row.get("updated_at") or row.get("pushed_at") or row.get("published") or "",
            "cve": row.get("cve") or "",
            "severity": row.get("severity") or row.get("cvss_severity") or "",
            "epss": _safe_float(epss_meta[0] if len(epss_meta) > 0 else None),
            "epss_percentile": _safe_float(epss_meta[1] if len(epss_meta) > 1 else None),
        })
    return {"total": len(items), "items": items}


def github_advisories(github_key: str = "", limit: int = 12, severity: str = "", range_mode: str = "today") -> Dict[str, Any]:
    headers = {
        **HTTP_HEADERS,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
    }
    if github_key:
        headers["Authorization"] = f"Bearer {github_key.strip()}"
    params = {
        "type": "reviewed",
        "sort": "published",
        "direction": "desc",
        "per_page": max(1, min(limit, 40)),
        "published": f">={_range_start_dt(range_mode).date().isoformat()}",
    }
    if severity:
        params["severity"] = severity.strip().lower()
    try:
        resp = requests.get("https://api.github.com/advisories", headers=headers, params=params, timeout=15)
        if resp.status_code != 200:
            return _source_result("GitHub Advisories", True, error=f"HTTP {resp.status_code}")
        rows = resp.json()
    except Exception as exc:
        return _source_result("GitHub Advisories", True, error=str(exc))
    items = []
    for row in rows if isinstance(rows, list) else []:
        if not _in_range(row.get("published_at") or row.get("updated_at"), range_mode):
            continue
        vulns = row.get("vulnerabilities") if isinstance(row.get("vulnerabilities"), list) else []
        package_names = []
        for vuln in vulns[:4]:
            pkg = vuln.get("package") if isinstance(vuln, dict) and isinstance(vuln.get("package"), dict) else {}
            label = " / ".join(x for x in (pkg.get("ecosystem"), pkg.get("name")) if x)
            if label:
                package_names.append(label)
        items.append({
            "id": row.get("ghsa_id") or "",
            "cve": row.get("cve_id") or "",
            "title": row.get("summary") or row.get("ghsa_id") or "GitHub advisory",
            "severity": row.get("severity") or "",
            "published": row.get("published_at") or "",
            "updated": row.get("updated_at") or "",
            "url": row.get("html_url") or "",
            "packages": package_names,
        })
    return _source_result("GitHub Advisories", True, items)


def nvd_recent_cves(limit: int = 12, severity: str = "", range_mode: str = "today") -> Dict[str, Any]:
    start = _range_start_dt(range_mode).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
    end = _now().astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
    params = {"pubStartDate": start, "pubEndDate": end, "resultsPerPage": max(1, min(limit, 40))}
    try:
        resp = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", headers=HTTP_HEADERS, params=params, timeout=18)
        if resp.status_code != 200:
            return _source_result("NVD", True, error=f"HTTP {resp.status_code}")
        data = resp.json()
    except Exception as exc:
        return _source_result("NVD", True, error=str(exc))
    wanted = severity.strip().upper()
    items = []
    for row in data.get("vulnerabilities") or []:
        cve = row.get("cve") if isinstance(row, dict) and isinstance(row.get("cve"), dict) else {}
        metrics = cve.get("metrics") if isinstance(cve.get("metrics"), dict) else {}
        cvss = {}
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            values = metrics.get(key)
            if isinstance(values, list) and values:
                cvss = values[0].get("cvssData") if isinstance(values[0], dict) else {}
                if isinstance(cvss, dict):
                    break
        sev = str(cvss.get("baseSeverity") or "").upper()
        if wanted and wanted != sev:
            continue
        descs = cve.get("descriptions") if isinstance(cve.get("descriptions"), list) else []
        desc = next((d.get("value") for d in descs if isinstance(d, dict) and d.get("lang") == "en" and d.get("value")), "")
        items.append({
            "cve": cve.get("id") or "",
            "title": desc[:160],
            "severity": sev,
            "score": cvss.get("baseScore"),
            "published": cve.get("published") or "",
            "updated": cve.get("lastModified") or "",
            "url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}" if cve.get("id") else "",
        })
    return _source_result("NVD", True, items[:limit])


def cisa_advisories(limit: int = 12, range_mode: str = "today") -> Dict[str, Any]:
    urls = [
        "https://www.cisa.gov/news-events/cybersecurity-advisories/all.xml",
        "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "https://www.cisa.gov/news.xml",
    ]
    last_error = ""
    for url in urls:
        try:
            resp = requests.get(url, headers={**HTTP_HEADERS, "Accept": "application/rss+xml, application/xml"}, timeout=12)
            if resp.status_code != 200:
                last_error = f"HTTP {resp.status_code}"
                continue
            root = ET.fromstring(resp.text)
        except Exception as exc:
            last_error = str(exc)
            continue
        items = []
        for item in root.findall(".//item"):
            published = item.findtext("pubDate") or item.findtext("date") or ""
            if not _in_range(published, range_mode):
                continue
            items.append({
                "title": item.findtext("title") or "CISA advisory",
                "published": published,
                "url": item.findtext("link") or "",
                "summary": re.sub(r"<[^>]+>", "", item.findtext("description") or "")[:220],
            })
            if len(items) >= limit:
                break
        return _source_result("CISA Advisories", True, items)
    note = "CISA KEV is already included in KEV; advisory RSS was not reachable from this runtime."
    if last_error:
        note = f"{note} Last advisory RSS response: {last_error}."
    return _source_result("CISA Advisories", True, note=note)


def regional_cert_advisories(limit: int = 12, range_mode: str = "today", focus: str = "") -> Dict[str, Any]:
    result = _rss_feed_items(REGIONAL_CERT_FEEDS, limit=limit, range_mode=range_mode, strict=False, focus=focus)
    items = [*(result.get("items") or []), *mycert_advisories(limit=min(6, limit), range_mode=range_mode, focus=focus)]
    items.sort(key=lambda x: str(x.get("published") or ""), reverse=True)
    items = _dedupe_items(items, limit)
    note = "Regional and national CERT feeds; high-signal advisories only."
    return _source_result("Regional / National CERTs", True, items, error=result.get("error", ""), note=note)


def vendor_advisories(limit: int = 12, severity: str = "", range_mode: str = "today", focus: str = "") -> Dict[str, Any]:
    result = _rss_feed_items(VENDOR_ADVISORY_FEEDS, limit=limit, range_mode=range_mode, strict=True, focus=focus)
    items = result.get("items") or []
    wanted = severity.strip().lower()
    if wanted:
        items = [
            item for item in items
            if wanted in " ".join(str(item.get(k) or "") for k in ("title", "summary")).lower()
        ]
    note = "Vendor advisories are filtered to critical/exploited/high-impact technology signals."
    return _source_result("Vendor Security Advisories", True, items[:limit], error=result.get("error", ""), note=note)


def security_news(limit: int = 8, range_mode: str = "today", focus: str = "") -> Dict[str, Any]:
    result = _rss_feed_items(SECURITY_NEWS_FEEDS, limit=limit, range_mode=range_mode, strict=False, focus=focus)
    items = result.get("items") or []
    for item in items:
        item["category"] = "Media / awareness"
        item["confidence"] = "low"
    note = "Security news is awareness-only and lower confidence than primary advisories."
    return _source_result("Security News", True, items[:limit], error=result.get("error", ""), note=note)


def recent_breaches_intel(limit: int = 8, range_mode: str = "today", focus: str = "") -> Dict[str, Any]:
    try:
        data = breach_watcher.get_breach_feed(page=1, page_size=limit * 2, query=focus)
        raw_items = data.get("items") or []
        items = []
        for r in raw_items:
            items.append({
                "source": r.get("source") or "Breach Watcher",
                "title": r.get("title") or "Breach Incident",
                "summary": r.get("summary") or "",
                "published": r.get("published") or "",
                "url": r.get("url") or "",
                "category": "Data Breach",
                "confidence": "high"
            })
        return _source_result("Recent Breaches", True, items[:limit])
    except Exception as exc:
        return _source_result("Recent Breaches", True, error=str(exc))


def telegram_intel_lane(limit: int = 8, range_mode: str = "today", focus: str = "") -> Dict[str, Any]:
    try:
        msg_data = tg_channel_monitor.get_live_messages(page=1, page_size=limit * 2, category="")
        raw_msgs = msg_data.get("messages") or []
        exp_data = tg_channel_monitor.get_stealer_exposures(limit=limit)
        raw_exps = exp_data.get("exposures") or []
        stats = tg_channel_monitor.get_monitor_stats()

        terms = _focus_terms(focus)
        items = []
        for m in raw_msgs:
            chan_title = m.get("channel_title") or m.get("channel_username") or "Telegram Channel"
            text = m.get("text") or ""
            row = {
                "id": m.get("id"),
                "source": f"TG @{m.get('channel_username', '').lstrip('@') or chan_title}",
                "channel_title": chan_title,
                "channel_username": m.get("channel_username") or "",
                "category": m.get("channel_category") or "threat_actor_public",
                "title": f"[{m.get('channel_category', 'threat_actor_public')}] {chan_title}",
                "summary": _clean_text(text, 300),
                "published": (m.get("timestamp") or "").replace("T", " ")[:19],
                "has_media": bool(m.get("has_media")),
                "file_name": m.get("file_name") or "",
                "file_size": m.get("file_size") or 0,
                "iocs": m.get("extracted_iocs") or {},
                "type": "message"
            }
            if terms and not _matches_focus(row, terms, ["title", "summary", "channel_title", "channel_username", "category"]):
                continue
            items.append(row)

        exposures = []
        for e in raw_exps:
            exposures.append({
                "domain": e.get("domain") or "",
                "url": e.get("url") or "",
                "username": e.get("username") or "",
                "stealer_family": e.get("stealer_family") or "Generic",
                "matched_asset": e.get("matched_asset") or "",
                "observed_at": (e.get("observed_at") or "").replace("T", " ")[:19],
            })

        note = f"Monitored channels: {stats.get('monitored_channels', 0)}, Total messages: {stats.get('total_messages', 0)}"
        res = _source_result("Telegram Monitoring", True, items[:limit], note=note)
        res["exposures"] = exposures
        res["stats"] = stats
        return res
    except Exception as exc:
        return _source_result("Telegram Monitoring", True, error=str(exc))


def msrc_updates(limit: int = 12, severity: str = "", range_mode: str = "today") -> Dict[str, Any]:
    try:
        resp = requests.get("https://api.msrc.microsoft.com/cvrf/v3.0/updates", headers=HTTP_HEADERS, timeout=18)
        if resp.status_code != 200:
            return _source_result("Microsoft MSRC", True, error=f"HTTP {resp.status_code}")
        data = resp.json()
    except Exception as exc:
        return _source_result("Microsoft MSRC", True, error=str(exc))
    wanted = severity.strip().lower()
    items = []
    for row in data.get("value") or []:
        if not isinstance(row, dict) or not _in_range(row.get("CurrentReleaseDate") or row.get("InitialReleaseDate"), range_mode):
            continue
        sev = str(row.get("Severity") or "")
        if wanted and wanted not in sev.lower():
            continue
        items.append({
            "id": row.get("ID") or row.get("Alias") or "",
            "title": row.get("DocumentTitle") or row.get("ID") or "MSRC update",
            "severity": sev,
            "published": row.get("InitialReleaseDate") or "",
            "updated": row.get("CurrentReleaseDate") or "",
            "url": row.get("CvrfUrl") or "",
        })
        if len(items) >= limit:
            break
    return _source_result("Microsoft MSRC", True, items)


def official_vulnerability_changes(kev: Dict[str, Any], pocs: Dict[str, Any], lanes: Dict[str, Any], limit: int = 12) -> Dict[str, Any]:
    kev_cves = _cve_set(kev.get("items") or [], "cve", "title")
    poc_cves = _cve_set(pocs.get("items") or [], "cve", "name", "description")
    items = []
    seen = set()
    for lane_key, label in (
        ("github_advisories", "GitHub Advisory"),
        ("nvd", "NVD"),
        ("msrc", "Microsoft MSRC"),
    ):
        for row in (lanes.get(lane_key) or {}).get("items") or []:
            cves = sorted(_cve_set([row], "cve", "id", "title", "summary"))
            text = " ".join(str(row.get(k) or "") for k in ("title", "summary", "severity", "vendor", "product")).lower()
            severity = str(row.get("severity") or "").upper()
            high_signal = (
                severity in {"CRITICAL", "HIGH", "IMPORTANT"}
                or bool(set(cves) & kev_cves)
                or bool(set(cves) & poc_cves)
                or _is_high_signal_text(text, strict=True)
            )
            if not high_signal:
                continue
            key = (cves[0] if cves else "") or f"{label}:{row.get('title')}"
            key = key.lower()
            if key in seen:
                continue
            seen.add(key)
            items.append({
                "source": label,
                "title": row.get("title") or row.get("id") or row.get("cve") or "Vulnerability update",
                "cve": ", ".join(cves[:4]) or row.get("cve") or row.get("id") or "",
                "severity": severity,
                "published": row.get("published") or row.get("updated") or "",
                "url": row.get("url") or "",
                "why": "KEV overlap" if set(cves) & kev_cves else ("PoC overlap" if set(cves) & poc_cves else "High-impact advisory"),
            })
    items.sort(key=lambda x: str(x.get("published") or ""), reverse=True)
    return _source_result("Official Vulnerability Changes", True, items[:limit], note="Filtered to critical/high, KEV overlap, PoC overlap, or high-impact technology.")


def cloudflare_radar(cloudflare_key: str = "", limit: int = 8) -> Dict[str, Any]:
    if not cloudflare_key:
        return _source_result("Cloudflare Radar", False, note="Add Cloudflare API token to show Radar attack context.")
    headers = {**HTTP_HEADERS, "Authorization": f"Bearer {cloudflare_key.strip()}"}
    params = {"aggInterval": "1h", "dateRange": "1d", "name": "attacks", "format": "json"}
    try:
        resp = requests.get("https://api.cloudflare.com/client/v4/radar/attacks/layer7/timeseries_groups/mitigation_product", headers=headers, params=params, timeout=18)
        if resp.status_code != 200:
            return _source_result("Cloudflare Radar", True, error=f"HTTP {resp.status_code}")
        data = resp.json()
    except Exception as exc:
        return _source_result("Cloudflare Radar", True, error=str(exc))
    result = data.get("result") if isinstance(data.get("result"), dict) else {}
    series = result.get("series") if isinstance(result.get("series"), dict) else {}
    items = []
    for name, values in series.items():
        if not isinstance(values, list):
            continue
        total = 0.0
        for value in values:
            val = _safe_float(value)
            if val is not None:
                total += val
        items.append({"source": "Cloudflare Radar", "name": str(name), "value": round(total, 2), "window": "1d"})
    items.sort(key=lambda x: x.get("value") or 0, reverse=True)
    return _source_result("Cloudflare Radar", True, items[:limit])


def malwarebazaar_recent(abusech_key: str = "", limit: int = 12, range_mode: str = "today") -> Dict[str, Any]:
    if not abusech_key:
        return _source_result("MalwareBazaar", False, note="Add abuse.ch key to pull latest malware samples.")
    headers = {"Auth-Key": abusech_key.strip(), "X-AbuseCh-Key": abusech_key.strip(), **HTTP_HEADERS}
    payload = {"query": "get_recent", "selector": "100"}
    try:
        resp = requests.post("https://mb-api.abuse.ch/api/v1/", data=payload, headers=headers, timeout=18)
        if resp.status_code != 200:
            return _source_result("MalwareBazaar", True, error=f"HTTP {resp.status_code}")
        data = resp.json()
    except Exception as exc:
        return _source_result("MalwareBazaar", True, error=str(exc))
    items = []
    for row in data.get("data") or []:
        if not isinstance(row, dict) or not _in_range(row.get("first_seen"), range_mode):
            continue
        items.append({
            "sha256": row.get("sha256_hash") or row.get("sha256") or "",
            "file_name": row.get("file_name") or "",
            "file_type": row.get("file_type") or "",
            "signature": row.get("signature") or "",
            "tags": _as_list(row.get("tags"))[:6],
            "first_seen": row.get("first_seen") or "",
            "reporter": row.get("reporter") or "",
        })
        if len(items) >= limit:
            break
    return _source_result("MalwareBazaar", True, items)


def threatfox_recent(abusech_key: str = "", limit: int = 12, range_mode: str = "today") -> Dict[str, Any]:
    if not abusech_key:
        return _source_result("ThreatFox", False, note="Add abuse.ch key to pull recent malware IOCs.")
    headers = {"Auth-Key": abusech_key.strip(), "API-KEY": abusech_key.strip(), "Content-Type": "application/json", **HTTP_HEADERS}
    payload = {"query": "get_iocs", "days": 7 if _range_mode(range_mode) == "7d" else 1}
    try:
        resp = requests.post("https://threatfox-api.abuse.ch/api/v1/", json=payload, headers=headers, timeout=18)
        if resp.status_code != 200:
            return _source_result("ThreatFox", True, error=f"HTTP {resp.status_code}")
        data = resp.json()
    except Exception as exc:
        return _source_result("ThreatFox", True, error=str(exc))
    items = []
    for row in data.get("data") or []:
        if not isinstance(row, dict) or not _in_range(row.get("first_seen") or row.get("last_seen"), range_mode):
            continue
        items.append({
            "ioc": row.get("ioc") or "",
            "type": row.get("ioc_type") or row.get("threat_type") or "",
            "malware": row.get("malware_printable") or row.get("malware") or "",
            "confidence": row.get("confidence_level") or "",
            "first_seen": row.get("first_seen") or "",
            "tags": _as_list(row.get("tags"))[:6],
        })
        if len(items) >= limit:
            break
    return _source_result("ThreatFox", True, items)


def urlhaus_recent(limit: int = 12, range_mode: str = "today") -> Dict[str, Any]:
    try:
        resp = requests.get("https://urlhaus.abuse.ch/downloads/csv_recent/", headers=HTTP_HEADERS, timeout=18)
        if resp.status_code != 200:
            return _source_result("URLhaus", True, error=f"HTTP {resp.status_code}")
    except Exception as exc:
        return _source_result("URLhaus", True, error=str(exc))
    items = []
    text = "\n".join(line for line in resp.text.splitlines() if line and not line.startswith("#"))
    try:
        reader = csv.DictReader(io.StringIO(text), fieldnames=["id", "date_added", "url", "status", "last_online", "threat", "tags", "link", "reporter"])
        for row in reader:
            if not _in_range(row.get("date_added"), range_mode):
                continue
            items.append({
                "url": row.get("url") or "",
                "threat": row.get("threat") or "",
                "status": row.get("status") or "",
                "tags": [x.strip() for x in str(row.get("tags") or "").split(",") if x.strip()][:6],
                "first_seen": row.get("date_added") or "",
                "link": row.get("link") or "",
            })
            if len(items) >= limit:
                break
    except Exception as exc:
        return _source_result("URLhaus", True, error=f"CSV parse failed: {exc}")
    return _source_result("URLhaus", True, items)


def feodo_tracker_activity(limit: int = 8, range_mode: str = "today") -> Dict[str, Any]:
    try:
        resp = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.csv", headers=HTTP_HEADERS, timeout=18)
        if resp.status_code != 200:
            return _source_result("Feodo Tracker", True, error=f"HTTP {resp.status_code}")
    except Exception as exc:
        return _source_result("Feodo Tracker", True, error=str(exc))
    names = Counter()
    text = "\n".join(line for line in resp.text.splitlines() if line and not line.startswith("#"))
    try:
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            blob = {str(k).lower(): v for k, v in row.items()}
            first_seen = blob.get("first_seen") or blob.get("first seen") or blob.get("date_added") or ""
            if first_seen and not _in_range(first_seen, range_mode):
                continue
            name = blob.get("malware") or blob.get("family") or "Feodo / botnet C2"
            names[str(name).strip() or "Feodo / botnet C2"] += 1
    except Exception as exc:
        return _source_result("Feodo Tracker", True, error=f"CSV parse failed: {exc}")
    items = [
        {"name": name, "source": "Feodo Tracker", "mentions": count, "category": "Botnet C2"}
        for name, count in names.most_common(limit)
    ]
    return _source_result("Feodo Tracker", True, items, note="Names only; C2 indicators are intentionally suppressed in Today's Intelligence.")


def sslbl_activity(limit: int = 8, range_mode: str = "today") -> Dict[str, Any]:
    try:
        resp = requests.get("https://sslbl.abuse.ch/blacklist/sslipblacklist.csv", headers=HTTP_HEADERS, timeout=18)
        if resp.status_code != 200:
            return _source_result("SSLBL", True, error=f"HTTP {resp.status_code}")
    except Exception as exc:
        return _source_result("SSLBL", True, error=str(exc))
    names = Counter()
    text = "\n".join(line for line in resp.text.splitlines() if line and not line.startswith("#"))
    try:
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            blob = {str(k).lower(): v for k, v in row.items()}
            first_seen = blob.get("listingdate") or blob.get("first_seen") or ""
            if first_seen and not _in_range(first_seen, range_mode):
                continue
            reason = blob.get("listingreason") or blob.get("reason") or "Malware SSL infrastructure"
            names[str(reason).strip() or "Malware SSL infrastructure"] += 1
    except Exception as exc:
        return _source_result("SSLBL", True, error=f"CSV parse failed: {exc}")
    items = [
        {"name": name, "source": "SSLBL", "mentions": count, "category": "Malware SSL infrastructure"}
        for name, count in names.most_common(limit)
    ]
    return _source_result("SSLBL", True, items, note="Names/reasons only; SSL indicators are intentionally suppressed in Today's Intelligence.")


def tweetfeed_social_pulse(limit: int = 12, range_mode: str = "today", focus: str = "") -> Dict[str, Any]:
    try:
        data = tweetfeed_service.dashboard(range_mode=range_mode, limit=limit, focus=focus)
    except Exception as exc:
        return _source_result("TweetFeed", True, error=str(exc))
    items = data.get("items") or []
    result = _source_result(
        "TweetFeed",
        True,
        items,
        error=data.get("error") or "",
        note=data.get("note") or "Security researcher social IOC feed; observations are context, not verdicts.",
    )
    result["total"] = data.get("total") or len(items)
    result["campaigns"] = ((data.get("campaigns") or {}).get("items") or [])[:limit]
    result["campaign_total"] = (data.get("campaigns") or {}).get("total") or len(result["campaigns"])
    result["counts"] = (data.get("counts") or {}).get("data") or {}
    result["trends"] = (data.get("trends") or {}).get("data") or {}
    result["contributors"] = (data.get("contributors") or {}).get("items") or []
    result["status"] = (data.get("status") or {}).get("data") or {}
    return result


def malware_activity_summary(lanes: Dict[str, Any], limit: int = 12) -> Dict[str, Any]:
    names = Counter()
    sources: Dict[str, set] = {}

    def add(name: str, source: str, count: int = 1):
        clean = str(name or "").strip()
        if not clean or clean.lower() in {"malware", "unknown", "n/a", "payload", "malware_download"}:
            return
        names[clean] += max(1, int(count or 1))
        sources.setdefault(clean, set()).add(source)

    for row in ((lanes.get("malware_iocs") or {}).get("items") or []):
        add(row.get("malware"), "ThreatFox")
    for row in ((lanes.get("malware_samples") or {}).get("items") or []):
        add(row.get("signature"), "MalwareBazaar")
        for tag in _as_list(row.get("tags")):
            add(tag, "MalwareBazaar", 0)
    for row in ((lanes.get("malware_urls") or {}).get("items") or []):
        add(row.get("threat"), "URLhaus")
        for tag in _as_list(row.get("tags")):
            add(tag, "URLhaus", 0)
    for lane_key, source_name in (("feodo", "Feodo Tracker"), ("sslbl", "SSLBL")):
        for row in ((lanes.get(lane_key) or {}).get("items") or []):
            add(row.get("name"), source_name, int(row.get("mentions") or 1))

    items = [
        {
            "name": name,
            "mentions": count,
            "sources": sorted(sources.get(name) or []),
            "category": "Malware / campaign signal",
        }
        for name, count in names.most_common(limit)
    ]
    return _source_result("Malware Activity Names", True, items, note="Named malware/campaign signals only; raw IOCs suppressed.")


def urlscan_suspicious(urlscan_key: str = "", limit: int = 12, range_mode: str = "today") -> Dict[str, Any]:
    headers = {**HTTP_HEADERS}
    if urlscan_key:
        headers["API-Key"] = urlscan_key.strip()
    since = _range_start_dt(range_mode).strftime("%Y-%m-%d")
    params = {"q": f"verdicts.malicious:true AND date:>{since}", "size": max(1, min(limit, 40))}
    try:
        resp = requests.get("https://urlscan.io/api/v1/search/", headers=headers, params=params, timeout=18)
        if resp.status_code != 200:
            if resp.status_code in {401, 403} and not urlscan_key:
                return _source_result("urlscan.io", False, note="Add URLScan API key to pull suspicious page searches.")
            return _source_result("urlscan.io", bool(urlscan_key), error=f"HTTP {resp.status_code}")
        data = resp.json()
    except Exception as exc:
        return _source_result("urlscan.io", bool(urlscan_key), error=str(exc))
    items = []
    for row in data.get("results") or []:
        if not isinstance(row, dict):
            continue
        task = row.get("task") if isinstance(row.get("task"), dict) else {}
        page = row.get("page") if isinstance(row.get("page"), dict) else {}
        if not _in_range(task.get("time"), range_mode):
            continue
        items.append({
            "title": page.get("title") or page.get("domain") or task.get("url") or "urlscan result",
            "url": page.get("url") or task.get("url") or "",
            "domain": page.get("domain") or task.get("domain") or "",
            "ip": page.get("ip") or "",
            "country": page.get("country") or "",
            "time": task.get("time") or "",
            "result": row.get("result") or "",
            "screenshot": row.get("screenshot") or "",
        })
    return _source_result("urlscan.io", True, items)


def otx_pulses(otx_key: str = "", terms: List[str] | None = None, limit: int = 8) -> Dict[str, Any]:
    if not otx_key:
        return _source_result("AlienVault OTX", False, note="Add OTX key to search community pulses for today's entities.")
    seeds = [x for x in (terms or []) if x][:3] or ["ransomware", "malware"]
    items = []
    seen = set()
    for term in seeds:
        try:
            data = query_otx_pulse(term, otx_key)
        except Exception as exc:
            return _source_result("AlienVault OTX", True, items, error=str(exc))
        for row in data.get("normalized_pulses") or data.get("results") or []:
            if not isinstance(row, dict):
                continue
            title = row.get("name") or row.get("title") or ""
            key = row.get("id") or title
            if not key or key in seen:
                continue
            seen.add(key)
            items.append({
                "title": title,
                "author": row.get("author_name") or row.get("author") or "",
                "created": row.get("created") or row.get("modified") or "",
                "tags": _as_list(row.get("tags"))[:6],
                "url": row.get("url") or "",
            })
            if len(items) >= limit:
                return _source_result("AlienVault OTX", True, items)
    return _source_result("AlienVault OTX", True, items)


def exposure_leads(shodan_key: str = "", censys_key: str = "", kev: List[Dict[str, Any]] | None = None, limit: int = 6) -> Dict[str, Any]:
    if not shodan_key and not censys_key:
        return _source_result("Exposure Search", False, note="Add Shodan or Censys key to estimate exposure for top products.")
    products = []
    for row in kev or []:
        product = str(row.get("product") or row.get("vendor") or "").strip()
        if product and product not in products:
            products.append(product)
        if len(products) >= 2:
            break
    if not products:
        return _source_result("Exposure Search", bool(shodan_key or censys_key), note="No product names available in the current KEV set.")
    items = []
    for product in products:
        if shodan_key and len(items) < limit:
            try:
                data = query_shodan_search(product, shodan_key, limit_fields=True, page=1, query_type="keyword")
                norm = data.get("normalized") if isinstance(data, dict) else {}
                items.append({"source": "Shodan", "query": product, "total": norm.get("total", 0), "sample_count": len(norm.get("matches") or [])})
            except Exception as exc:
                items.append({"source": "Shodan", "query": product, "error": str(exc)[:160]})
        if censys_key and len(items) < limit:
            try:
                data = query_censys_search(product, censys_key, query_type="keyword", page_size=5)
                norm = data.get("normalized") if isinstance(data, dict) else {}
                items.append({"source": "Censys", "query": product, "total": norm.get("total", 0), "sample_count": len(norm.get("hits") or [])})
            except Exception as exc:
                items.append({"source": "Censys", "query": product, "error": str(exc)[:160]})
    return _source_result("Exposure Search", True, items[:limit])


def enrichment_leads(vt_key: str = "", greynoise_key: str = "", seeds: Dict[str, List[str]] | None = None, limit: int = 6) -> Dict[str, Any]:
    seeds = seeds or {}
    items = []
    if vt_key:
        for value in (seeds.get("hashes") or [])[:2]:
            try:
                data = query_vt(value, "hash", vt_key)
                attrs = ((data.get("data") or {}).get("attributes") or {}) if isinstance(data, dict) else {}
                stats = attrs.get("last_analysis_stats") if isinstance(attrs.get("last_analysis_stats"), dict) else {}
                items.append({"source": "VirusTotal", "type": "hash", "value": value, "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0)})
            except Exception as exc:
                items.append({"source": "VirusTotal", "type": "hash", "value": value, "error": str(exc)[:160]})
        for value in (seeds.get("urls") or [])[:1]:
            try:
                data = query_vt(value, "url", vt_key)
                attrs = ((data.get("data") or {}).get("attributes") or {}) if isinstance(data, dict) else {}
                stats = attrs.get("last_analysis_stats") if isinstance(attrs.get("last_analysis_stats"), dict) else {}
                items.append({"source": "VirusTotal", "type": "url", "value": value, "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0)})
            except Exception as exc:
                items.append({"source": "VirusTotal", "type": "url", "value": value, "error": str(exc)[:160]})
    if greynoise_key:
        for ip in (seeds.get("ips") or [])[:3]:
            try:
                data = query_greynoise(ip, greynoise_key)
                if isinstance(data, dict) and not data.get("error"):
                    items.append({"source": "GreyNoise", "type": "ip", "value": ip, "classification": data.get("classification") or "", "noise": data.get("noise"), "riot": data.get("riot"), "last_seen": data.get("last_seen") or ""})
                elif isinstance(data, dict) and data.get("error"):
                    items.append({"source": "GreyNoise", "type": "ip", "value": ip, "error": data.get("error")})
            except Exception as exc:
                items.append({"source": "GreyNoise", "type": "ip", "value": ip, "error": str(exc)[:160]})
            if len(items) >= limit:
                break
    configured = bool(vt_key or greynoise_key or seeds.get("ips"))
    note = "" if configured else "Add VirusTotal and/or GreyNoise keys for daily IOC reputation context."
    return _source_result("Reputation / Noise", configured, items[:limit], note=note)


def ransomware_items(rwlive_key: str = "", limit: int = 12, group: str = "", country: str = "", sector: str = "", range_mode: str = "today") -> Dict[str, Any]:
    try:
        victims, sources = ransomware_monitor.recent_victims(_range_days(range_mode), rwlive_key)
    except Exception as exc:
        return {"total": 0, "items": [], "sources": [], "error": str(exc)}
    if _range_mode(range_mode) == "today":
        today = _today_iso()
        picked = [v for v in victims if (v.get("discovered_at") or "")[:10] == today]
    else:
        picked = victims[:limit]
    if not picked and _range_mode(range_mode) == "today":
        picked = victims[:limit]
    if group:
        picked = [v for v in picked if group.lower() in (v.get("group") or "").lower()]
    if country:
        picked = [v for v in picked if _contains_any(v, ["country", "country_code", "region"], country)]
    if sector:
        picked = [v for v in picked if _contains_any(v, ["sector", "activity"], sector)]
    items = []
    for row in picked[:limit]:
        items.append({
            "name": row.get("name") or "",
            "group": row.get("group") or "",
            "country": row.get("country") or row.get("country_code") or "",
            "sector": row.get("sector") or "",
            "discovered": row.get("discovered_at") or "",
            "website": row.get("website") or row.get("domain") or "",
            "source": row.get("source") or "",
            "permalink": row.get("permalink") or row.get("url") or "",
        })
    return {"total": len(victims), "items": items, "sources": sources}


def entity_mentions(articles: List[Dict[str, Any]], limit: int = 10) -> Dict[str, Any]:
    actors = Counter()
    malware = Counter()
    for article in articles:
        text = " ".join(str(article.get(k) or "") for k in ("title", "excerpt"))
        for match in ACTOR_HINT_RE.findall(text):
            actors[match.strip()] += 1
        for match in MALWARE_HINT_RE.findall(text):
            malware[match.strip()] += 1
    return {
        "actors": [{"name": name, "mentions": count} for name, count in actors.most_common(limit)],
        "malware": [{"name": name, "mentions": count} for name, count in malware.most_common(limit)],
    }


def enrich_entity_mentions(mentions: Dict[str, Any], source_lanes: Dict[str, Any], limit: int = 10) -> Dict[str, Any]:
    actors = Counter({row.get("name"): int(row.get("mentions") or 0) for row in mentions.get("actors", []) if row.get("name")})
    malware = Counter({row.get("name"): int(row.get("mentions") or 0) for row in mentions.get("malware", []) if row.get("name")})
    for row in ((source_lanes.get("malware_iocs") or {}).get("items") or []):
        name = str(row.get("malware") or "").strip()
        if name and name.lower() not in {"malware", "unknown", "n/a"}:
            malware[name] += 1
    for row in ((source_lanes.get("malware_samples") or {}).get("items") or []):
        name = str(row.get("signature") or "").strip()
        if name and name.lower() not in {"malware", "unknown", "n/a"}:
            malware[name] += 1
    for row in ((source_lanes.get("malware_urls") or {}).get("items") or []):
        name = str(row.get("threat") or "").strip()
        if name and name.lower() not in {"malware", "unknown", "n/a", "malware_download"}:
            malware[name] += 1
    for row in ((source_lanes.get("malware_activity") or {}).get("items") or []):
        name = str(row.get("name") or "").strip()
        if name and name.lower() not in {"malware", "unknown", "n/a"}:
            malware[name] += int(row.get("mentions") or 1)
    return {
        "actors": [{"name": name, "mentions": count} for name, count in actors.most_common(limit)],
        "malware": [{"name": name, "mentions": count} for name, count in malware.most_common(limit)],
    }


def _seed_values(*groups: Any) -> Dict[str, List[str]]:
    hashes: List[str] = []
    urls: List[str] = []
    ips: List[str] = []
    cves: List[str] = []
    for group in groups:
        values = group
        if isinstance(group, dict):
            values = group.get("items") or []
        for item in values if isinstance(values, list) else []:
            blob = json.dumps(item, ensure_ascii=True) if isinstance(item, dict) else str(item or "")
            for match in re.findall(r"\b[a-fA-F0-9]{64}\b", blob):
                m = match.lower()
                if m not in hashes:
                    hashes.append(m)
            for match in re.findall(r"https?://[^\s\"'<>]+", blob):
                m = match.rstrip(").,;")
                if m not in urls:
                    urls.append(m)
            for match in IP_RE.findall(blob):
                if match not in ips and not match.startswith(("0.", "10.", "127.", "169.254.", "192.168.")):
                    ips.append(match)
            for match in CVE_RE.findall(blob):
                m = match.upper()
                if m not in cves:
                    cves.append(m)
    return {"hashes": hashes[:10], "urls": urls[:10], "ips": ips[:10], "cves": cves[:20]}


def _health_item(label: str, status: str, detail: str = "", ok: bool = True) -> Dict[str, Any]:
    return {"label": label, "status": status, "detail": detail, "ok": bool(ok)}


def source_health(cti: Dict[str, Any], kev: Dict[str, Any], pocs: Dict[str, Any], ransom: Dict[str, Any],
                  source_lanes: Dict[str, Any], keys: Dict[str, str]) -> List[Dict[str, Any]]:
    health = []
    cti_items = cti.get("items") or []
    latest_cti = max((str(x.get("published") or "") for x in cti_items), default="")
    health.append(_health_item("CTI", f"{len(cti_items)} recent", latest_cti[:16], bool(cti_items)))
    try:
        sync = pocindex_mod.get_sync_status()
    except Exception:
        sync = {}
    health.append(_health_item("PoCIndex", str(sync.get("state") or "loaded"), str(sync.get("message") or ""), bool(pocs.get("items"))))
    health.append(_health_item("KEV", f"{len(kev.get('items') or [])} loaded", "CISA KEV + PoCIndex", bool(kev.get("items"))))
    ransom_sources = ransom.get("sources") or []
    rwlive_key = bool((keys.get("rwlive_key") or "").strip())
    health.append(_health_item("RansomLook", "available" if ransom_sources else "no data", "", bool(ransom_sources or ransom.get("items"))))
    health.append(_health_item("ransomware.live", "key configured" if rwlive_key else "key missing", "", rwlive_key))
    ai_settings = ai_service._settings_raw()
    ai_ready = bool(ai_settings.get("api_key") and ai_settings.get("endpoint") and ai_settings.get("model"))
    health.append(_health_item("AI", "ready" if ai_ready else "not configured", ai_settings.get("model") or "", ai_ready))
    for key, label in (
        ("regional_certs", "CERTs"),
        ("vendor_advisories", "Vendor Advisories"),
        ("official_vuln_changes", "Official Vuln"),
        ("malware_samples", "MalwareBazaar"),
        ("malware_iocs", "ThreatFox"),
        ("malware_activity", "Malware Names"),
        ("security_news", "Security News"),
        ("tweetfeed", "TweetFeed"),
    ):
        lane = source_lanes.get(key) or {}
        configured = lane.get("configured", True)
        status = "ok" if lane.get("items") else ("key missing" if configured is False else "no hits")
        health.append(_health_item(label, status, lane.get("note") or lane.get("error") or "", configured is not False and not lane.get("error")))
    return health


def _cve_set(items: List[Dict[str, Any]], *fields: str) -> set:
    out = set()
    for item in items or []:
        blob = " ".join(str(item.get(field) or "") for field in fields) if fields else json.dumps(item, ensure_ascii=True)
        out.update(match.upper() for match in CVE_RE.findall(blob))
    return out


def priority_cves(kev: Dict[str, Any], pocs: Dict[str, Any], lanes: Dict[str, Any], limit: int = 10) -> List[Dict[str, Any]]:
    by_cve: Dict[str, Dict[str, Any]] = {}

    def row(cve: str) -> Dict[str, Any]:
        cve = (cve or "").upper()
        return by_cve.setdefault(cve, {
            "cve": cve,
            "title": "",
            "vendor": "",
            "product": "",
            "severity": "",
            "kev_date": "",
            "poc_count": 0,
            "known_ransomware": "",
            "epss": None,
            "sources": [],
            "recommended_action": "Monitor",
            "score": 0,
        })

    for item in kev.get("items") or []:
        cve = str(item.get("cve") or "").upper()
        if not cve:
            continue
        r = row(cve)
        r.update({
            "title": item.get("title") or r["title"],
            "vendor": item.get("vendor") or r["vendor"],
            "product": item.get("product") or r["product"],
            "severity": item.get("severity") or r["severity"],
            "kev_date": item.get("published") or r["kev_date"],
            "poc_count": max(int(item.get("poc_count") or 0), int(r.get("poc_count") or 0)),
            "known_ransomware": item.get("known_ransomware") or r["known_ransomware"],
            "epss": item.get("epss") if item.get("epss") is not None else r["epss"],
        })
        r["sources"].append("KEV")
        r["score"] += 60
        if item.get("known_ransomware"):
            r["score"] += 20
        if item.get("epss") and float(item.get("epss") or 0) >= 0.7:
            r["score"] += 15

    for item in pocs.get("items") or []:
        cve = str(item.get("cve") or "").upper()
        if not cve:
            continue
        r = row(cve)
        r["title"] = r["title"] or item.get("description") or item.get("name") or ""
        r["poc_count"] = max(int(r.get("poc_count") or 0), 1)
        r["epss"] = item.get("epss") if item.get("epss") is not None else r["epss"]
        r["sources"].append("PoC")
        r["score"] += 35

    for lane_key, source_name in (("github_advisories", "GitHub"), ("nvd", "NVD"), ("msrc", "MSRC")):
        for item in (lanes.get(lane_key) or {}).get("items") or []:
            for cve in _cve_set([item], "cve", "title", "id"):
                r = row(cve)
                r["title"] = r["title"] or item.get("title") or ""
                r["severity"] = r["severity"] or item.get("severity") or ""
                r["sources"].append(source_name)
                r["score"] += 10

    out = []
    for item in by_cve.values():
        sources = []
        for src in item.get("sources") or []:
            if src and src not in sources:
                sources.append(src)
        item["sources"] = sources
        if "KEV" in sources and item.get("poc_count"):
            item["recommended_action"] = "Patch and validate exposure"
        elif "KEV" in sources:
            item["recommended_action"] = "Patch triage"
        elif item.get("poc_count"):
            item["recommended_action"] = "Assess exposure"
        else:
            item["recommended_action"] = "Monitor advisory"
        out.append(item)
    out.sort(key=lambda x: (x.get("score") or 0, x.get("epss") or 0), reverse=True)
    return out[:limit]


def correlations(cti: Dict[str, Any], kev: Dict[str, Any], pocs: Dict[str, Any], ransom: Dict[str, Any],
                 mentions: Dict[str, Any], lanes: Dict[str, Any], filters: Dict[str, Any], limit: int = 12) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    cti_items = cti.get("items") or []
    kev_cves = _cve_set(kev.get("items") or [], "cve", "title")
    poc_cves = _cve_set(pocs.get("items") or [], "cve", "name", "description")
    cti_cves = _cve_set(cti_items, "title", "excerpt")
    advisory_cves = _cve_set((lanes.get("github_advisories") or {}).get("items") or [], "cve", "title")
    nvd_cves = _cve_set((lanes.get("nvd") or {}).get("items") or [], "cve", "title")

    for cve in sorted((cti_cves & kev_cves) | (advisory_cves & kev_cves)):
        out.append({
            "type": "cve_kev_reporting",
            "title": f"{cve} appears in reporting and KEV",
            "detail": "Known exploited vulnerability also appears in today's reporting or advisories.",
            "target": "poc-index",
            "value": cve,
            "severity": "high",
        })
    for cve in sorted(kev_cves & poc_cves):
        out.append({
            "type": "kev_poc",
            "title": f"{cve} has KEV status and public PoC signal",
            "detail": "Exploit availability can change patch and exposure urgency.",
            "target": "poc-index",
            "value": cve,
            "severity": "critical",
        })
    for cve in sorted((nvd_cves | advisory_cves) & poc_cves):
        out.append({
            "type": "advisory_poc",
            "title": f"{cve} appears in new advisories and PoC data",
            "detail": "Fresh disclosure has public exploit or exploit-repo signal.",
            "target": "poc-index",
            "value": cve,
            "severity": "medium",
        })

    wanted_sector = str(filters.get("sector") or "").lower()
    wanted_country = str(filters.get("country") or "").lower()
    wanted_group = str(filters.get("group") or "").lower()
    for victim in ransom.get("items") or []:
        match_bits = []
        if wanted_sector and wanted_sector in str(victim.get("sector") or "").lower():
            match_bits.append("sector")
        if wanted_country and wanted_country in " ".join(str(victim.get(k) or "") for k in ("country", "region")).lower():
            match_bits.append("country/region")
        if wanted_group and wanted_group in str(victim.get("group") or "").lower():
            match_bits.append("group")
        if match_bits:
            out.append({
                "type": "ransom_watch",
                "title": f"{victim.get('name') or 'Victim'} matches your ransomware watch filters",
                "detail": f"Matched {', '.join(match_bits)} in the current filter set.",
                "target": "ransom-victims",
                "value": victim.get("name") or victim.get("group") or "",
                "severity": "high",
            })

    for bucket, target in (("actors", "keyword"), ("malware", "keyword")):
        for item in mentions.get(bucket) or []:
            if int(item.get("mentions") or 0) > 1:
                out.append({
                    "type": f"{bucket}_repeat",
                    "title": f"{item.get('name')} appears across multiple CTI items",
                    "detail": "Repeated mentions can indicate active campaign attention or reporting momentum.",
                    "target": target,
                    "value": item.get("name") or "",
                    "severity": "medium",
                })

    if (lanes.get("malware_iocs") or {}).get("items") and (lanes.get("malware_urls") or {}).get("items"):
        out.append({
            "type": "malware_url_overlap",
            "title": "Fresh malware IOCs and malware delivery URLs are both present",
            "detail": "Pivot URLhaus and ThreatFox values into IOC lookups for infrastructure overlap.",
            "target": "url",
            "value": ((lanes.get("malware_urls") or {}).get("items") or [{}])[0].get("url") or "",
            "severity": "medium",
        })

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    out.sort(key=lambda x: severity_order.get(x.get("severity"), 9))
    return out[:limit]


def build_dashboard(rwlive_key: str = "", limit: int = 12, filters: Dict[str, Any] | None = None, keys: Dict[str, str] | None = None) -> Dict[str, Any]:
    filters = filters or {}
    keys = keys or {}
    keys = {**keys, "rwlive_key": rwlive_key}
    range_mode = _range_mode(str(filters.get("range") or filters.get("range_mode") or "today"))
    source_type = str(filters.get("source_type") or "").strip()
    severity = str(filters.get("severity") or "").strip()
    group = str(filters.get("group") or "").strip()
    country = str(filters.get("country") or filters.get("region") or "").strip()
    sector = str(filters.get("sector") or "").strip()
    focus_terms = _focus_terms(country)
    focused = bool(focus_terms)
    cti = today_articles(limit=max(250, limit), source_type=source_type, range_mode=range_mode, focus=country)
    kev = {"total": 0, "items": []} if focused else kev_items(limit=limit, severity=severity)
    pocs = {"total": 0, "items": []} if focused else poc_items(limit=limit, severity=severity)
    ransom = ransomware_items(rwlive_key=rwlive_key, limit=limit, group=group, country=country, sector=sector, range_mode=range_mode)
    mentions = entity_mentions(cti.get("items") or [], limit=limit)
    mention_terms = [x.get("name") for x in (mentions.get("actors") or [])[:3]] + [x.get("name") for x in (mentions.get("malware") or [])[:3]]
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {}
        if not focused:
            futures.update({
                "github_advisories": executor.submit(github_advisories, keys.get("github_key", ""), limit, severity, range_mode),
                "nvd": executor.submit(nvd_recent_cves, limit, severity, range_mode),
                "msrc": executor.submit(msrc_updates, limit, severity, range_mode),
                "vendor_advisories": executor.submit(vendor_advisories, limit, severity, range_mode, country),
            })
        futures.update({
            "regional_certs": executor.submit(regional_cert_advisories, limit, range_mode, country),
            "security_news": executor.submit(security_news, min(limit, 8), range_mode, country),
            "malware_samples": executor.submit(malwarebazaar_recent, keys.get("abusech_key", ""), limit, range_mode),
            "malware_iocs": executor.submit(threatfox_recent, keys.get("abusech_key", ""), limit, range_mode),
            "malware_urls": executor.submit(urlhaus_recent, limit, range_mode),
            "feodo": executor.submit(feodo_tracker_activity, min(limit, 8), range_mode),
            "sslbl": executor.submit(sslbl_activity, min(limit, 8), range_mode),
            "community": executor.submit(otx_pulses, keys.get("otx_key", ""), mention_terms, min(limit, 8)),
            "tweetfeed": executor.submit(tweetfeed_social_pulse, limit, range_mode, country),
            "breaches": executor.submit(recent_breaches_intel, min(limit, 8), range_mode, country),
            "telegram_monitor": executor.submit(telegram_intel_lane, min(limit, 8), range_mode, country),
        })
        source_lanes = {}
        for name, future in futures.items():
            try:
                result = future.result(timeout=25)
                if focused:
                    result = _filter_source_result(result, focus_terms)
                source_lanes[name] = result
            except Exception as exc:
                source_lanes[name] = _source_result(name.replace("_", " ").title(), True, error=str(exc))
    if focused:
        source_lanes.setdefault("github_advisories", _source_result("GitHub Advisories", True, []))
        source_lanes.setdefault("nvd", _source_result("NVD", True, []))
        source_lanes.setdefault("msrc", _source_result("Microsoft MSRC", True, []))
        source_lanes.setdefault("vendor_advisories", _source_result("Vendor Security Advisories", True, []))
    source_lanes["official_vuln_changes"] = official_vulnerability_changes(kev, pocs, source_lanes, limit=limit)
    source_lanes["malware_activity"] = malware_activity_summary(source_lanes, limit=limit)
    mentions = enrich_entity_mentions(mentions, source_lanes, limit=limit)
    seeds = _seed_values(source_lanes.get("malware_samples"), source_lanes.get("malware_iocs"), source_lanes.get("malware_urls"))
    reputation = enrichment_leads(keys.get("vt_key", ""), keys.get("greynoise_key", ""), seeds, limit=min(limit, 6))
    lanes_with_reputation = {**source_lanes, "reputation": reputation}
    priority = priority_cves(kev, pocs, lanes_with_reputation, limit=limit)
    overlap = correlations(
        cti,
        kev,
        pocs,
        ransom,
        mentions,
        lanes_with_reputation,
        {"group": group, "country": country, "sector": sector},
        limit=limit,
    )
    health = source_health(cti, kev, pocs, ransom, lanes_with_reputation, keys)
    stats = {
        "cti_articles": len(cti.get("items") or []),
        "kev": len(kev.get("items") or []),
        "pocs": pocs.get("total") or len(pocs.get("items") or []),
        "ransomware_victims": len(ransom.get("items") or []),
        "actor_mentions": len(mentions.get("actors") or []),
        "malware_mentions": len(mentions.get("malware") or []),
        "advisories": (
            len(source_lanes.get("github_advisories", {}).get("items") or [])
            + len(source_lanes.get("regional_certs", {}).get("items") or [])
            + len(source_lanes.get("vendor_advisories", {}).get("items") or [])
            + len(source_lanes.get("official_vuln_changes", {}).get("items") or [])
        ),
        "cert_advisories": len(source_lanes.get("regional_certs", {}).get("items") or []),
        "vendor_advisories": len(source_lanes.get("vendor_advisories", {}).get("items") or []),
        "official_vuln_changes": len(source_lanes.get("official_vuln_changes", {}).get("items") or []),
        "security_news": len(source_lanes.get("security_news", {}).get("items") or []),
        "malware_samples": len(source_lanes.get("malware_samples", {}).get("items") or []),
        "malware_iocs": len(source_lanes.get("malware_iocs", {}).get("items") or []),
        "malware_urls": len(source_lanes.get("malware_urls", {}).get("items") or []),
        "malware_activity": len(source_lanes.get("malware_activity", {}).get("items") or []),
        "tweetfeed_iocs": len(source_lanes.get("tweetfeed", {}).get("items") or []),
        "tweetfeed_campaigns": len(source_lanes.get("tweetfeed", {}).get("campaigns") or []),
        "reputation": len(reputation.get("items") or []),
        "nvd": len(source_lanes.get("nvd", {}).get("items") or []),
        "msrc": len(source_lanes.get("msrc", {}).get("items") or []),
        "recent_breaches": len(source_lanes.get("breaches", {}).get("items") or []),
        "telegram_messages": len(source_lanes.get("telegram_monitor", {}).get("items") or []),
        "telegram_exposures": len(source_lanes.get("telegram_monitor", {}).get("exposures") or []),
    }
    focus = []
    if ransom.get("items"):
        focus.append("Review new ransomware victims and identify overlaps with your region, sector, or watched groups.")
    if kev.get("items"):
        focus.append("Prioritize KEV entries with public PoCs or known ransomware campaign use.")
    if source_lanes.get("nvd", {}).get("items") or source_lanes.get("msrc", {}).get("items") or source_lanes.get("github_advisories", {}).get("items"):
        focus.append("Review fresh vulnerability advisories against owned products, packages, and patch SLAs.")
    if source_lanes.get("regional_certs", {}).get("items"):
        focus.append("Review national CERT advisories for regionally relevant exploitation, emergency patching, or public-sector warnings.")
    if source_lanes.get("vendor_advisories", {}).get("items"):
        focus.append("Check vendor security advisories against exposed products and patch ownership.")
    if pocs.get("items"):
        focus.append("Check new/trending PoCs for overlap with internet-facing assets and current patch backlog.")
    if source_lanes.get("malware_activity", {}).get("items"):
        focus.append("Review named malware and campaign activity before deeper IOC pivots.")
    if source_lanes.get("malware_urls", {}).get("items"):
        focus.append("Triage suspicious web infrastructure for brand abuse, redirects, payload delivery, and hosting overlap.")
    if source_lanes.get("tweetfeed", {}).get("items") or source_lanes.get("tweetfeed", {}).get("campaigns"):
        focus.append("Review TweetFeed social IOC clusters for fast-moving researcher reports before wider enrichment.")
    if cti.get("items"):
        focus.append("Scan today's CTI reporting for actor, malware, and infrastructure pivots before deeper lookups.")
    return {
        "date": _today_iso(),
        "generated_at": _now().isoformat().replace("+00:00", "Z"),
        "filters": {
            "range": range_mode,
            "source_type": source_type,
            "severity": severity,
            "group": group,
            "country": country,
            "sector": sector,
        },
        "stats": stats,
        "focus": focus,
        "cti": cti,
        "kev": kev,
        "pocs": pocs,
        "ransomware": ransom,
        "mentions": mentions,
        "source_lanes": lanes_with_reputation,
        "priority_cves": priority,
        "correlations": overlap,
        "health": health,
        "seeds": seeds,
    }


_LANE_BASE_KEYS = {"name", "configured", "total", "items", "error", "note"}


def _compact_items(value: Any, limit: int) -> List[Any]:
    if not isinstance(value, list):
        return []
    return value[:max(0, limit)]


def _compact_source_lane(key: str, lane: Dict[str, Any], item_limit: int = 12, extra_limit: int = 8) -> Dict[str, Any]:
    """Keep every Today's Intelligence source visible to MANTIS AI.

    Some lanes expose analyst value outside ``items`` (for example TweetFeed
    campaigns and Telegram exposures). The AI prompt should stay bounded, but
    it must not silently drop those sections when generating a daily brief or
    report.
    """
    out: Dict[str, Any] = {
        "name": lane.get("name") or key.replace("_", " ").title(),
        "configured": lane.get("configured"),
        "total": lane.get("total"),
    }
    if lane.get("error"):
        out["error"] = lane.get("error")
    if lane.get("note"):
        out["note"] = lane.get("note")
    items = _compact_items(lane.get("items"), item_limit)
    if items:
        out["items"] = items
        out["item_count"] = len(lane.get("items") or [])
    for extra_key, value in lane.items():
        if extra_key in _LANE_BASE_KEYS or not isinstance(value, list):
            continue
        compacted = _compact_items(value, extra_limit)
        if compacted:
            out[extra_key] = compacted
            out[f"{extra_key}_count"] = len(value)
    return out


def _compact_source_lanes(snapshot: Dict[str, Any], item_limit: int = 12, extra_limit: int = 8) -> Dict[str, Any]:
    lanes: Dict[str, Any] = {}
    for key, lane in (snapshot.get("source_lanes") or {}).items():
        if isinstance(lane, dict):
            lanes[key] = _compact_source_lane(str(key), lane, item_limit=item_limit, extra_limit=extra_limit)
    return lanes


def _block_total(block: Any) -> int:
    if not isinstance(block, dict):
        return 0
    total = block.get("total")
    if isinstance(total, int):
        return total
    return len(block.get("items") or [])


def _source_coverage(snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
    coverage: List[Dict[str, Any]] = []
    top_level = (
        ("cti", "CTI Articles"),
        ("kev", "CISA KEV"),
        ("pocs", "PoC / Exploit Leads"),
        ("ransomware", "Ransomware Victims"),
    )
    for key, label in top_level:
        block = snapshot.get(key) or {}
        coverage.append({
            "source": key,
            "name": label,
            "total": _block_total(block),
            "item_count": len(block.get("items") or []) if isinstance(block, dict) else 0,
            "status": "populated" if _block_total(block) else "empty",
        })
    for key, lane in (snapshot.get("source_lanes") or {}).items():
        if not isinstance(lane, dict):
            continue
        extra_counts = {
            str(k): len(v)
            for k, v in lane.items()
            if k not in _LANE_BASE_KEYS and isinstance(v, list) and v
        }
        total = _block_total(lane)
        coverage.append({
            "source": str(key),
            "name": lane.get("name") or str(key).replace("_", " ").title(),
            "total": total,
            "item_count": len(lane.get("items") or []),
            "extra_counts": extra_counts,
            "status": "error" if lane.get("error") else ("populated" if total or extra_counts else "empty"),
            "note": lane.get("note"),
            "error": lane.get("error"),
        })
    return coverage


def ai_brief(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    settings = ai_service._settings_raw()
    if not (settings.get("api_key") and settings.get("endpoint") and settings.get("model")):
        ai_service.log_audit(settings.get("model"), "todays_intelligence", "todays_intel_brief", None, False, "missing_config", "")
        raise ai_service.AIUnavailable("MANTIS AI is missing endpoint, model, or API key configuration.")
    compact = {
        "date": snapshot.get("date"),
        "stats": snapshot.get("stats"),
        "focus": snapshot.get("focus"),
        "cti": (snapshot.get("cti") or {}).get("items", [])[:12],
        "kev": (snapshot.get("kev") or {}).get("items", [])[:12],
        "pocs": (snapshot.get("pocs") or {}).get("items", [])[:12],
        "ransomware": (snapshot.get("ransomware") or {}).get("items", [])[:12],
        "mentions": snapshot.get("mentions") or {},
        "health": snapshot.get("health") or [],
        "priority_cves": (snapshot.get("priority_cves") or [])[:10],
        "correlations": (snapshot.get("correlations") or [])[:10],
        "source_coverage": _source_coverage(snapshot),
        "source_lanes": _compact_source_lanes(snapshot, item_limit=12, extra_limit=8),
    }
    messages = [
        {
            "role": "system",
            "content": (
                "You are MANTIS AI creating a daily cyber threat intelligence brief for an analyst. "
                "Use only the supplied MANTIS data. Do not invent facts. Return JSON only with keys: "
                "executive_summary, priority_items, watchlist, recommended_actions, caveats. "
                "priority_items, watchlist, recommended_actions, and caveats must be arrays of concise strings. "
                "Treat source_coverage as the authoritative inventory of Today's Intelligence sources, and do "
                "not ignore populated source_lanes such as social IOC clusters, Telegram exposures, breaches, "
                "malware infrastructure, vendor advisories, Microsoft/NVD, CERT advisories, or reputation leads."
            ),
        },
        {"role": "user", "content": "Today's MANTIS intelligence snapshot:\n" + json.dumps(compact, ensure_ascii=True, sort_keys=True)},
    ]
    started = time.monotonic()
    content = ai_service.AIProvider(settings).generate(messages)
    try:
        data = json.loads(content or "{}")
    except ValueError as exc:
        ai_service.log_audit(settings.get("model"), "todays_intelligence", "todays_intel_brief", None, False, "malformed_response", str(exc))
        raise ai_service.AIProviderError("AI provider returned malformed Today's Intelligence JSON.") from exc

    def strings(value: Any, limit: int = 10) -> List[str]:
        if isinstance(value, str):
            return [value[:700]] if value.strip() else []
        if not isinstance(value, list):
            return []
        return [str(v).strip()[:700] for v in value[:limit] if str(v).strip()]

    result = {
        "available": True,
        "model": settings.get("model"),
        "executive_summary": str(data.get("executive_summary") or data.get("summary") or "").strip()[:1600],
        "priority_items": strings(data.get("priority_items")),
        "watchlist": strings(data.get("watchlist")),
        "recommended_actions": strings(data.get("recommended_actions")),
        "caveats": strings(data.get("caveats"), limit=6),
    }
    ai_service.log_audit(settings.get("model"), "todays_intelligence", "todays_intel_brief", None, False, "ok", f"{time.monotonic() - started:.2f}s")
    return result


def ai_report(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    settings = ai_service._settings_raw()
    if not (settings.get("api_key") and settings.get("endpoint") and settings.get("model")):
        ai_service.log_audit(settings.get("model"), "todays_intelligence", "todays_intel_report", None, False, "missing_config", "")
        raise ai_service.AIUnavailable("MANTIS AI is missing endpoint, model, or API key configuration.")

    compact = {
        "date": snapshot.get("date"),
        "generated_at": snapshot.get("generated_at"),
        "filters": snapshot.get("filters") or {},
        "stats": snapshot.get("stats") or {},
        "analyst_focus": snapshot.get("focus") or [],
        "cti_reporting": {
            "total": (snapshot.get("cti") or {}).get("total"),
            "items": (snapshot.get("cti") or {}).get("items", [])[:25],
        },
        "kev_items": {
            "total": (snapshot.get("kev") or {}).get("total"),
            "items": (snapshot.get("kev") or {}).get("items", [])[:20],
        },
        "poc_leads": {
            "total": (snapshot.get("pocs") or {}).get("total"),
            "items": (snapshot.get("pocs") or {}).get("items", [])[:20],
        },
        "ransomware_victims": {
            "total": (snapshot.get("ransomware") or {}).get("total"),
            "items": (snapshot.get("ransomware") or {}).get("items", [])[:20],
        },
        "entity_mentions": snapshot.get("mentions") or {},
        "priority_cves": (snapshot.get("priority_cves") or [])[:20],
        "correlations": (snapshot.get("correlations") or [])[:20],
        "source_health": snapshot.get("health") or [],
        "source_coverage": _source_coverage(snapshot),
        "source_lanes": _compact_source_lanes(snapshot, item_limit=16, extra_limit=12),
    }
    messages = [
        {
            "role": "system",
            "content": (
                "You are a senior cyber threat intelligence analyst writing for SOC, vulnerability management, "
                "and security leadership. Use a clear threat intelligence tone: assess significance, operational "
                "impact, confidence, and recommended next steps. Use only the supplied MANTIS data. Do not invent "
                "actors, targeting, exploitation, victims, impacts, or timelines. If data is thin, say so as a "
                "collection gap. Avoid raw-data recitation; explain why the data matters. Return JSON only with "
                "these keys: title, scope, executive_assessment, key_judgments, threat_landscape, "
                "vulnerability_and_exploit_assessment, ransomware_assessment, actor_and_malware_assessment, "
                "regional_or_sector_relevance, priority_developments, recommended_actions, collection_gaps, "
                "confidence. Paragraph fields must be strings, not arrays. Array fields must contain concise "
                "analytic strings, not objects. Confidence should be Low, Medium, or High with a short reason. "
                "Use source_coverage to account for every populated MANTIS source category; when a source has "
                "useful signal, incorporate it into the assessment or explicitly place it in collection_gaps."
            ),
        },
        {
            "role": "user",
            "content": (
                "Create a current intelligence report from this MANTIS Today's Intelligence snapshot. "
                "Interpret the signal in the selected time range and filters, then prioritize what an analyst "
                "should care about next.\n"
                + json.dumps(compact, ensure_ascii=True, sort_keys=True)
            ),
        },
    ]
    started = time.monotonic()
    content = ai_service.AIProvider(settings).generate(messages)
    raw = (content or "").strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.IGNORECASE).strip()
        raw = re.sub(r"\s*```$", "", raw).strip()
    try:
        data = json.loads(raw or "{}")
    except ValueError as exc:
        ai_service.log_audit(settings.get("model"), "todays_intelligence", "todays_intel_report", None, False, "malformed_response", str(exc))
        raise ai_service.AIProviderError("AI provider returned malformed Today's Intelligence report JSON.") from exc

    def flatten(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, list):
            return " ".join(str(v).strip() for v in value if str(v).strip())
        if isinstance(value, dict):
            return "; ".join(f"{k}: {v}" for k, v in value.items() if str(v).strip())
        return str(value).strip()

    def text(value: Any, limit: int = 2200) -> str:
        if value is None:
            return ""
        return flatten(value)[:limit]

    def strings(value: Any, limit: int = 12) -> List[str]:
        if isinstance(value, str):
            return [value[:900]] if value.strip() else []
        if isinstance(value, dict):
            value = list(value.values())
        if not isinstance(value, list):
            return []
        return [flatten(v)[:900] for v in value[:limit] if flatten(v)]

    filters = snapshot.get("filters") or {}
    range_label = filters.get("range") or "current"
    result = {
        "available": True,
        "model": settings.get("model"),
        "title": text(data.get("title") or f"Current Intelligence Assessment - {range_label}", 180),
        "scope": text(data.get("scope") or f"Scope: {range_label} intelligence from configured MANTIS sources.", 500),
        "executive_assessment": text(data.get("executive_assessment") or data.get("executive_summary")),
        "key_judgments": strings(data.get("key_judgments"), limit=8),
        "threat_landscape": text(data.get("threat_landscape")),
        "vulnerability_and_exploit_assessment": text(data.get("vulnerability_and_exploit_assessment")),
        "ransomware_assessment": text(data.get("ransomware_assessment")),
        "actor_and_malware_assessment": text(data.get("actor_and_malware_assessment")),
        "regional_or_sector_relevance": text(data.get("regional_or_sector_relevance")),
        "priority_developments": strings(data.get("priority_developments"), limit=10),
        "recommended_actions": strings(data.get("recommended_actions"), limit=10),
        "collection_gaps": strings(data.get("collection_gaps") or data.get("caveats"), limit=8),
        "confidence": text(data.get("confidence") or "Confidence not stated", 220),
    }
    ai_service.log_audit(settings.get("model"), "todays_intelligence", "todays_intel_report", None, False, "ok", f"{time.monotonic() - started:.2f}s")
    return result
