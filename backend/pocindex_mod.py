import os
import json
import time
import re
import threading
import urllib.request
import urllib.error
import urllib.parse
import logging
import zipfile
from typing import List, Dict, Any, Set, Tuple

logger = logging.getLogger("mantis.pocindex")

DATA_DIR = os.path.join(os.path.dirname(__file__), "data", "pocindex")
os.makedirs(DATA_DIR, exist_ok=True)
CVEPROJECT_RELEASE_API = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
CVEPROJECT_ZIP = os.path.join(DATA_DIR, "cveproject_all.zip")
CVEPROJECT_ZIP_TMP = f"{CVEPROJECT_ZIP}.tmp"
CVEPROJECT_LIST = os.path.join(DATA_DIR, "CVEProject_list.json")
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_API_BASE = "https://api.osv.dev/v1"
OSV_BUCKET_BASE = "https://storage.googleapis.com/osv-vulnerabilities"
OSV_CACHE_TTL_SECONDS = 6 * 3600
OSV_RECENT_CACHE_TTL_SECONDS = 15 * 60
OSV_STATS_CACHE_TTL_SECONDS = 24 * 3600
OSV_DEFAULT_ECOSYSTEMS = [
    "npm", "PyPI", "Maven", "Go", "crates.io", "NuGet", "RubyGems", "Packagist",
    "Debian", "Ubuntu", "Alpine", "Android", "GitHub Actions", "OSS-Fuzz",
    "Linux", "Rocky Linux", "AlmaLinux", "Red Hat", "SUSE", "openSUSE",
]

URLS = {
    "trending_poc": "https://pocindex.io/trending_poc.json",
    "kev": "https://pocindex.io/kev.json",
    "cisa_kev": CISA_KEV_URL,
    "cvss": "https://pocindex.io/cvss.json",
    "advisories": "https://pocindex.io/advisories.json",
    "nuclei": "https://pocindex.io/nuclei.json",
    "epss": "https://pocindex.io/epss.json",
    "repo_meta": "https://pocindex.io/repo_meta.json",
    "CVE_list": "https://pocindex.io/CVE_list.json"
}

# In-memory storage
state = {
    "dataset": [],
    "repo_meta": {},
    "kev": {},
    "ratings": {},
    "metadata": {},
    "epss": {},
    "trending": [],
    "index_meta": None,
    "cveproject_meta": None,
    "cisa_kev_meta": None,
    "ready": False,
    "word_index": {"words": [], "postings": {}},
    "osv_cache": {},
    "osv_recent_cache": {}
}

REPLACE_STRINGS = ['HackTheBox - ', 'VulnHub - ', 'UHC - ']
POC_FIELDS = ['poc', 'nuclei', 'msf', 'edb', 'vulhub', 'collections']

def download_json(name: str, url: str) -> bool:
    path = os.path.join(DATA_DIR, f"{name}.json")
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'MANTIS'})
        with urllib.request.urlopen(req, timeout=30) as response:
            data = response.read()
            with open(path, "wb") as f:
                f.write(data)
            return True
    except Exception as e:
        logger.warning(f"Failed to download {name}: {e}")
        return False


def download_file(url: str, path: str, timeout: int = 900) -> bool:
    tmp_path = f"{path}.tmp"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'MANTIS'})
        with urllib.request.urlopen(req, timeout=timeout) as response, open(tmp_path, "wb") as f:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                f.write(chunk)
        os.replace(tmp_path, path)
        return True
    except Exception as e:
        logger.warning("Failed to download %s: %s", url, e)
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
        return False


def cleanup_cveproject_archives() -> None:
    for path in (CVEPROJECT_ZIP, CVEPROJECT_ZIP_TMP):
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception as exc:
            logger.warning("Failed to remove CVEProject archive %s: %s", path, exc)


def get_latest_cveproject_asset() -> Dict[str, Any]:
    try:
        req = urllib.request.Request(CVEPROJECT_RELEASE_API, headers={'User-Agent': 'MANTIS'})
        with urllib.request.urlopen(req, timeout=30) as response:
            release = json.loads(response.read().decode("utf-8", errors="replace"))
        for asset in release.get("assets") or []:
            name = asset.get("name") or ""
            if "all_CVEs" in name and name.endswith(".zip"):
                return {
                    "tag": release.get("tag_name") or "",
                    "published_at": release.get("published_at") or "",
                    "name": name,
                    "url": asset.get("browser_download_url") or "",
                    "size": asset.get("size") or 0,
                }
    except Exception as e:
        logger.warning("Failed to inspect CVEProject release: %s", e)
    return {}

def sync_data():
    logger.info("Starting PoC Index sync...")
    for name, url in URLS.items():
        download_json(name, url)
    sync_cveproject(force=False)
    logger.info("PoC Index sync complete.")
    load_data()

def load_json(name: str):
    path = os.path.join(DATA_DIR, f"{name}.json")
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load {name}.json: {e}")
    return None


def load_json_path(path: str, default=None):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning("Failed to load %s: %s", path, e)
    return default


def _http_json(url: str, method: str = "GET", payload: Any = None, timeout: int = 30):
    data = None
    headers = {'User-Agent': 'MANTIS'}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8", errors="replace"))


def hours_since(iso: str):
    if not iso: return None
    import datetime
    if len(iso) == 10: iso += "T00:00:00Z"
    if iso.endswith('Z'): iso = iso[:-1] + '+00:00'
    try:
        dt = datetime.datetime.fromisoformat(iso)
        dt = dt.astimezone(datetime.timezone.utc)
        now = datetime.datetime.now(datetime.timezone.utc)
        return (now - dt).total_seconds() / 3600.0
    except:
        return None

def normalize_to_spaces(value: str) -> str:
    return re.sub(r'[^a-z0-9]+', ' ', (value or "").lower()).strip()

NOT_A_REPO = {'user-attachments', 'advisories', 'security', 'orgs',
  'apps', 'marketplace', 'sponsors', 'topics', 'collections', 'settings', 'notifications'}

def repo_from_url(url: str):
    m = re.match(r'^https?://(?:www\.)?github\.com/([^/#?]+)/([^/#?]+)', url or "", re.IGNORECASE)
    if not m or m.group(1).lower() in NOT_A_REPO:
        return None
    return {"owner": m.group(1), "repo": re.sub(r'\.git$', '', m.group(2), flags=re.IGNORECASE)}

def unique_source_links(urls: List[str]) -> List[str]:
    seen = set()
    out = []
    for url in urls:
        parsed = repo_from_url(url)
        if parsed:
            key = f"github:{parsed['owner'].lower()}/{parsed['repo'].lower()}"
        else:
            key = url.rstrip('/')
        if key not in seen:
            seen.add(key)
            out.append(url)
    return out

def entry_links(entry: Dict[str, Any]) -> List[str]:
    if "_allLinks" not in entry:
        urls = []
        for f in POC_FIELDS:
            urls.extend(entry.get(f, []))
        entry["_allLinks"] = unique_source_links(urls)
    return entry["_allLinks"]

def poc_text(entry: Dict[str, Any]) -> str:
    if "_pocText" not in entry:
        entry["_pocText"] = " ".join(entry_links(entry)).lower()
    return entry["_pocText"]

def poc_space(entry: Dict[str, Any]) -> str:
    if "_pocSpace" not in entry:
        entry["_pocSpace"] = normalize_to_spaces(poc_text(entry))
    return entry["_pocSpace"]


def cve_parts(cve: str) -> Tuple[int, int]:
    parts = (cve or "").split('-')
    try:
        return int(parts[1]) if len(parts) > 1 else 0, int(parts[2]) if len(parts) > 2 else 0
    except Exception:
        return 0, 0


def first_english_description(descriptions: Any) -> str:
    if not isinstance(descriptions, list):
        return ""
    fallback = ""
    for desc in descriptions:
        if not isinstance(desc, dict):
            continue
        value = desc.get("value") or ""
        if not fallback and value:
            fallback = value
        if str(desc.get("lang") or "").lower().startswith("en") and value:
            return value
    return fallback


def cvss_severity(score: float, fallback: str = "UNKNOWN") -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return fallback or "UNKNOWN"


def as_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if value:
        return [value]
    return []


def add_unique(values: Any, value: Any) -> List[str]:
    out = [str(item) for item in as_list(values) if item]
    if value and str(value) not in out:
        out.append(str(value))
    return out


def normalize_pocindex_kev(raw: Any) -> Dict[str, Dict[str, Any]]:
    if not isinstance(raw, dict):
        return {}
    out = {}
    for cve, value in raw.items():
        cve_id = str(cve or "").strip().upper()
        if not cve_id:
            continue
        date_added = ""
        ransomware_flag = None
        if isinstance(value, list):
            date_added = str(value[0] or "") if len(value) > 0 else ""
            ransomware_flag = value[1] if len(value) > 1 else None
        elif isinstance(value, dict):
            date_added = str(value.get("date_added") or value.get("dateAdded") or "")
            ransomware_flag = value.get("known_ransomware_campaign_use")
        out[cve_id] = {
            "date_added": date_added,
            "known_ransomware_campaign_use": "Known" if ransomware_flag in (1, "1", True) else "",
            "sources": ["PoCIndex KEV"],
        }
    return out


def normalize_cisa_kev(raw: Any) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Any]]:
    meta = {}
    if not isinstance(raw, dict):
        return {}, meta
    vulnerabilities = raw.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return {}, meta
    meta = {
        "title": raw.get("title") or "CISA Known Exploited Vulnerabilities Catalog",
        "catalogVersion": raw.get("catalogVersion") or "",
        "dateReleased": raw.get("dateReleased") or "",
        "count": raw.get("count") or len(vulnerabilities),
        "source": CISA_KEV_URL,
    }
    out = {}
    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue
        cve = str(item.get("cveID") or "").strip().upper()
        if not cve:
            continue
        cwes = item.get("cwes")
        out[cve] = {
            "date_added": item.get("dateAdded") or "",
            "due_date": item.get("dueDate") or "",
            "vendor_project": item.get("vendorProject") or "",
            "product": item.get("product") or "",
            "vulnerability_name": item.get("vulnerabilityName") or "",
            "short_description": item.get("shortDescription") or "",
            "required_action": item.get("requiredAction") or "",
            "known_ransomware_campaign_use": item.get("knownRansomwareCampaignUse") or "",
            "forensic_triage": item.get("forensicTriage") or "",
            "notes": item.get("notes") or "",
            "cwes": cwes if isinstance(cwes, list) else [],
            "sources": ["CISA KEV"],
        }
    return out, meta


def merge_kev_sources(pocindex_raw: Any, cisa_raw: Any) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Any]]:
    merged = normalize_pocindex_kev(pocindex_raw)
    cisa_kev, cisa_meta = normalize_cisa_kev(cisa_raw)
    for cve, cisa_item in cisa_kev.items():
        base = merged.get(cve, {})
        sources = []
        for source in as_list(base.get("sources")) + as_list(cisa_item.get("sources")):
            if source and source not in sources:
                sources.append(source)
        base.update({k: v for k, v in cisa_item.items() if v not in (None, "", [])})
        base["sources"] = sources or ["CISA KEV"]
        merged[cve] = base
    return merged, cisa_meta


def _osv_event_values(ranges: Any, key: str) -> List[str]:
    out = []
    if not isinstance(ranges, list):
        return out
    for item in ranges:
        if not isinstance(item, dict):
            continue
        events = []
        if isinstance(item.get("database_specific"), dict):
            events += (item.get("database_specific") or {}).get("extracted_events") or []
        if isinstance(item.get("events"), list):
            events += item.get("events") or []
        for event in events:
            if isinstance(event, dict) and event.get(key) and str(event.get(key)) not in out:
                out.append(str(event.get(key)))
    return out[:8]


def normalize_osv_record(record: Dict[str, Any]) -> Dict[str, Any]:
    aliases = [str(x) for x in as_list(record.get("aliases")) if x]
    severities = []
    for item in as_list(record.get("severity")):
        if isinstance(item, dict):
            label = " ".join(str(item.get(k) or "") for k in ("type", "score")).strip()
            if label:
                severities.append(label)
    db_specific = record.get("database_specific") if isinstance(record.get("database_specific"), dict) else {}
    if db_specific.get("severity"):
        severities.append(str(db_specific.get("severity")))

    affected = []
    for item in as_list(record.get("affected")):
        if not isinstance(item, dict):
            continue
        package = item.get("package") if isinstance(item.get("package"), dict) else {}
        ranges = item.get("ranges") if isinstance(item.get("ranges"), list) else []
        repos = []
        for range_item in ranges:
            if isinstance(range_item, dict) and range_item.get("repo") and range_item.get("repo") not in repos:
                repos.append(str(range_item.get("repo")))
        versions = item.get("versions") if isinstance(item.get("versions"), list) else []
        affected.append({
            "name": package.get("name") or "",
            "ecosystem": package.get("ecosystem") or "",
            "purl": package.get("purl") or "",
            "repo": repos[0] if repos else "",
            "introduced": _osv_event_values(ranges, "introduced"),
            "fixed": _osv_event_values(ranges, "fixed"),
            "versions_count": len(versions),
        })

    references = []
    for ref in as_list(record.get("references")):
        if isinstance(ref, dict) and str(ref.get("url") or "").lower().startswith(("http://", "https://")):
            references.append({
                "type": ref.get("type") or "WEB",
                "url": ref.get("url") or "",
            })
    return {
        "found": True,
        "id": record.get("id") or "",
        "summary": record.get("summary") or "",
        "details": record.get("details") or "",
        "aliases": aliases[:16],
        "published": record.get("published") or "",
        "modified": record.get("modified") or "",
        "severity": severities[:4],
        "affected": affected[:12],
        "references": references[:12],
        "schema_version": record.get("schema_version") or "",
        "source": "OSV.dev",
    }


def _osv_primary_packages(record: Dict[str, Any]) -> List[str]:
    packages = []
    for item in as_list(record.get("affected")):
        if not isinstance(item, dict):
            continue
        package = item.get("package") if isinstance(item.get("package"), dict) else {}
        ecosystem = package.get("ecosystem") or ""
        name = package.get("name") or ""
        purl = package.get("purl") or ""
        label = f"{ecosystem}/{name}" if ecosystem and name else (name or purl)
        if label and label not in packages:
            packages.append(label)
    return packages[:5]


def _osv_has_fix(record: Dict[str, Any]) -> bool:
    for item in as_list(record.get("affected")):
        if not isinstance(item, dict):
            continue
        ranges = item.get("ranges") if isinstance(item.get("ranges"), list) else []
        if _osv_event_values(ranges, "fixed"):
            return True
    return False


def compact_osv_record(record: Dict[str, Any], modified_hint: str = "", ecosystem_hint: str = "") -> Dict[str, Any]:
    data = normalize_osv_record(record)
    packages = _osv_primary_packages(record)
    summary = data.get("summary") or data.get("details") or "See record for full details"
    return {
        "id": data.get("id") or "",
        "summary": summary,
        "published": data.get("published") or "",
        "modified": data.get("modified") or modified_hint,
        "ecosystem": ecosystem_hint,
        "packages": packages,
        "aliases": data.get("aliases") or [],
        "severity": data.get("severity") or [],
        "has_fix": _osv_has_fix(record),
        "is_malicious": str(data.get("id") or "").upper().startswith("MAL-"),
        "references_count": len(data.get("references") or []),
    }


def _osv_recent_csv_url(ecosystem: str = "") -> str:
    if ecosystem:
        return f"{OSV_BUCKET_BASE}/{urllib.parse.quote(ecosystem, safe='')}/modified_id.csv"
    return f"{OSV_BUCKET_BASE}/modified_id.csv"


def get_osv_malicious_stats() -> Dict[str, Any]:
    cache_key = "malicious_stats"
    cached = state.get("osv_cache", {}).get(cache_key)
    if cached and time.time() - cached.get("time", 0) < OSV_STATS_CACHE_TTL_SECONDS:
        return cached.get("data", {})

    total_records = 0
    malicious_records = 0
    last_modified = ""
    try:
        req = urllib.request.Request(_osv_recent_csv_url(), headers={'User-Agent': 'MANTIS'})
        with urllib.request.urlopen(req, timeout=90) as response:
            last_modified = response.headers.get("Last-Modified") or ""
            for raw in response:
                total_records += 1
                if b",MAL-" in raw or b"/MAL-" in raw:
                    malicious_records += 1
        data = {
            "malicious_packages": malicious_records,
            "total_records": total_records,
            "last_modified": last_modified,
            "source": "OSV.dev modified_id.csv",
        }
    except Exception as e:
        logger.warning("OSV malicious stats failed: %s", e)
        data = {
            "malicious_packages": 0,
            "total_records": 0,
            "error": str(e),
            "source": "OSV.dev modified_id.csv",
        }

    state.setdefault("osv_cache", {})[cache_key] = {"time": time.time(), "data": data}
    return data


def _parse_osv_recent_line(line: str, ecosystem_filter: str = "") -> Dict[str, str]:
    line = (line or "").strip()
    if not line or "," not in line:
        return {}
    modified, ident = line.split(",", 1)
    ident = ident.strip()
    modified = modified.strip()
    ecosystem = ecosystem_filter
    vuln_id = ident
    if "/" in ident:
        ecosystem, vuln_id = ident.split("/", 1)
    return {"modified": modified, "ecosystem": ecosystem, "id": vuln_id, "path": ident}


def get_osv_ecosystems() -> Dict[str, Any]:
    cache_key = "ecosystems"
    cached = state.get("osv_cache", {}).get(cache_key)
    if cached and time.time() - cached.get("time", 0) < OSV_CACHE_TTL_SECONDS:
        return cached.get("data", {})
    ecosystems = list(OSV_DEFAULT_ECOSYSTEMS)
    try:
        req = urllib.request.Request(f"{OSV_BUCKET_BASE}/ecosystems.txt", headers={'User-Agent': 'MANTIS'})
        with urllib.request.urlopen(req, timeout=15) as response:
            text = response.read().decode("utf-8", errors="replace")
        fetched = [line.strip() for line in text.splitlines() if line.strip()]
        if fetched:
            preferred = [x for x in OSV_DEFAULT_ECOSYSTEMS if x in fetched]
            rest = [x for x in fetched if x not in preferred]
            ecosystems = preferred + rest
    except Exception as e:
        logger.warning("Failed to load OSV ecosystems: %s", e)
    data = {"ecosystems": ecosystems, "source": "OSV.dev"}
    state.setdefault("osv_cache", {})[cache_key] = {"time": time.time(), "data": data}
    return data


def query_osv_vulnerability(vuln_id: str) -> Dict[str, Any]:
    clean_id = (vuln_id or "").strip()
    if not re.match(r'^[A-Za-z0-9][A-Za-z0-9_.:-]{2,128}$', clean_id):
        return {"found": False, "error": "Invalid OSV vulnerability ID."}
    cache_key = clean_id.upper()
    cached = state.get("osv_cache", {}).get(cache_key)
    if cached and time.time() - cached.get("time", 0) < OSV_CACHE_TTL_SECONDS:
        return cached.get("data", {})
    url = f"{OSV_API_BASE}/vulns/{urllib.parse.quote(clean_id, safe='')}"
    try:
        record = _http_json(url, timeout=30)
        data = normalize_osv_record(record)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            data = {"found": False, "id": clean_id, "source": "OSV.dev"}
        else:
            data = {"found": False, "id": clean_id, "error": f"OSV returned HTTP {e.code}", "source": "OSV.dev"}
    except Exception as e:
        logger.warning("OSV lookup failed for %s: %s", clean_id, e)
        data = {"found": False, "id": clean_id, "error": str(e), "source": "OSV.dev"}
    state.setdefault("osv_cache", {})[cache_key] = {"time": time.time(), "data": data}
    return data


def query_osv_recent(ecosystem: str = "", malicious: bool = False, limit: int = 50, offset: int = 0,
                     include_details: bool = False, q: str = "") -> Dict[str, Any]:
    ecosystem = (ecosystem or "").strip()
    q_clean = (q or "").strip().lower()
    limit = max(1, min(int(limit or 50), 100))
    offset = max(0, int(offset or 0))
    cache_key = f"recent:{ecosystem.lower()}:{int(bool(malicious))}:{limit}:{offset}:{int(bool(include_details))}:{q_clean}"
    cached = state.get("osv_recent_cache", {}).get(cache_key)
    if cached and time.time() - cached.get("time", 0) < OSV_RECENT_CACHE_TTL_SECONDS:
        return cached.get("data", {})

    if malicious and not ecosystem:
        combined = []
        seen = set()
        fetch_limit = max(100, limit * 3)
        for eco in ("npm", "PyPI", "Maven", "Go", "crates.io", "RubyGems", "Packagist", "NuGet"):
            part = query_osv_recent(ecosystem=eco, malicious=True, limit=fetch_limit, offset=0,
                                    include_details=include_details, q=q_clean)
            for item in part.get("items") or []:
                key = (item.get("id") or "").upper()
                if not key or key in seen:
                    continue
                seen.add(key)
                combined.append(item)
                if len(combined) >= offset + limit + 100:
                    break
            if len(combined) >= offset + limit + 100:
                break

        if q_clean:
            filtered = []
            for item in combined:
                text = f"{item.get('id')} {item.get('summary')} {item.get('ecosystem')} {' '.join(item.get('packages') or [])}".lower()
                if q_clean in text:
                    filtered.append(item)
            combined = filtered

        selected = combined[offset:offset + limit]
        data = {
            "items": selected,
            "total": len(combined),
            "total_returned": len(selected),
            "ecosystem": "",
            "malicious": True,
            "source": "OSV.dev",
        }
        state.setdefault("osv_recent_cache", {})[cache_key] = {"time": time.time(), "data": data}
        return data

    rows = []
    seen = set()
    max_scan = max(500, min(8000, (offset + limit) * (80 if malicious else 8)))
    try:
        req = urllib.request.Request(_osv_recent_csv_url(ecosystem), headers={'User-Agent': 'MANTIS'})
        with urllib.request.urlopen(req, timeout=30) as response:
            scanned = 0
            while scanned < max_scan:
                raw = response.readline()
                if not raw:
                    break
                scanned += 1
                row = _parse_osv_recent_line(raw.decode("utf-8", errors="replace"), ecosystem)
                if not row:
                    continue
                row_id = row.get("id") or ""
                if malicious and not row_id.upper().startswith("MAL-"):
                    continue
                key = row_id.upper()
                if key in seen:
                    continue
                seen.add(key)
                if len(rows) >= offset + limit:
                    break
                rows.append(row)
    except urllib.error.HTTPError as e:
        data = {"items": [], "total_returned": 0, "error": f"OSV modified feed returned HTTP {e.code}", "source": "OSV.dev"}
        state.setdefault("osv_recent_cache", {})[cache_key] = {"time": time.time(), "data": data}
        return data
    except Exception as e:
        logger.warning("OSV recent query failed: %s", e)
        data = {"items": [], "total_returned": 0, "error": str(e), "source": "OSV.dev"}
        state.setdefault("osv_recent_cache", {})[cache_key] = {"time": time.time(), "data": data}
        return data

    selected = rows[offset:offset + limit]
    items = []
    for row in selected:
        if not include_details:
            row_id = row.get("id") or ""
            row_ecosystem = row.get("ecosystem") or ecosystem
            items.append({
                "id": row_id,
                "summary": "See OSV record for full details",
                "published": "",
                "modified": row.get("modified") or "",
                "ecosystem": row_ecosystem,
                "packages": [f"{row_ecosystem}/{row_id}"] if row_ecosystem and row_id.upper().startswith("MAL-") else [],
                "aliases": [],
                "severity": [],
                "has_fix": False,
                "is_malicious": row_id.upper().startswith("MAL-"),
                "references_count": 0,
            })
            continue
        detail = query_osv_vulnerability(row.get("id") or "")
        if not detail.get("found"):
            items.append({
                "id": row.get("id") or "",
                "summary": detail.get("error") or "See record for full details",
                "published": "",
                "modified": row.get("modified") or "",
                "ecosystem": row.get("ecosystem") or ecosystem,
                "packages": [],
                "aliases": [],
                "severity": [],
                "has_fix": False,
                "is_malicious": (row.get("id") or "").upper().startswith("MAL-"),
                "references_count": 0,
            })
            continue
        cached_record = state.get("osv_cache", {}).get((row.get("id") or "").upper(), {}).get("data") or {}
        items.append({
            "id": cached_record.get("id") or row.get("id") or "",
            "summary": cached_record.get("summary") or cached_record.get("details") or "See record for full details",
            "published": cached_record.get("published") or "",
            "modified": cached_record.get("modified") or row.get("modified") or "",
            "ecosystem": row.get("ecosystem") or ecosystem,
            "packages": [
                (f"{item.get('ecosystem')}/{item.get('name')}" if item.get("ecosystem") and item.get("name") else (item.get("name") or item.get("purl") or item.get("repo") or ""))
                for item in (cached_record.get("affected") or [])[:5]
            ],
            "aliases": cached_record.get("aliases") or [],
            "severity": cached_record.get("severity") or [],
            "has_fix": any(item.get("fixed") for item in (cached_record.get("affected") or [])),
            "is_malicious": (cached_record.get("id") or row.get("id") or "").upper().startswith("MAL-"),
            "references_count": len(cached_record.get("references") or []),
        })

    data = {
        "items": items,
        "total_returned": len(items),
        "ecosystem": ecosystem,
        "malicious": bool(malicious),
        "source": "OSV.dev",
    }
    state.setdefault("osv_recent_cache", {})[cache_key] = {"time": time.time(), "data": data}
    return data


def query_osv_package(package_name: str = "", ecosystem: str = "", version: str = "", commit: str = "", purl: str = "") -> Dict[str, Any]:
    package_name = (package_name or "").strip()
    ecosystem = (ecosystem or "").strip()
    version = (version or "").strip()
    commit = (commit or "").strip()
    purl = (purl or "").strip()
    if not package_name and not purl and not commit:
        return {"found": False, "error": "Provide a package name, purl, or commit hash."}
    payload: Dict[str, Any] = {}
    if commit:
        payload["commit"] = commit
    else:
        package = {}
        if package_name:
            package["name"] = package_name
        if ecosystem:
            package["ecosystem"] = ecosystem
        if purl:
            package["purl"] = purl
        payload["package"] = package
        if version:
            payload["version"] = version
    cache_key = "query:" + json.dumps(payload, sort_keys=True).lower()
    cached = state.get("osv_cache", {}).get(cache_key)
    if cached and time.time() - cached.get("time", 0) < OSV_CACHE_TTL_SECONDS:
        return cached.get("data", {})
    try:
        response = _http_json(f"{OSV_API_BASE}/query", method="POST", payload=payload, timeout=30)
        vulns = response.get("vulns") if isinstance(response.get("vulns"), list) else []
        results = [normalize_osv_record(item) for item in vulns[:50] if isinstance(item, dict)]
        data = {
            "found": bool(results),
            "total": len(vulns),
            "results": results,
            "source": "OSV.dev",
        }
    except urllib.error.HTTPError as e:
        data = {"found": False, "total": 0, "results": [], "error": f"OSV returned HTTP {e.code}", "source": "OSV.dev"}
    except Exception as e:
        logger.warning("OSV package query failed: %s", e)
        data = {"found": False, "total": 0, "results": [], "error": str(e), "source": "OSV.dev"}
    state.setdefault("osv_cache", {})[cache_key] = {"time": time.time(), "data": data}
    return data


def finalize_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    cve = (entry.get("cve") or "").strip().upper()
    entry["cve"] = cve
    for field in POC_FIELDS:
        if not isinstance(entry.get(field), list):
            entry[field] = []
    entry["_allLinks"] = unique_source_links([url for field in POC_FIELDS for url in entry.get(field, [])])

    year, num = cve_parts(cve)
    entry["_year"] = year
    entry["_num"] = num
    entry["_cveText"] = cve.lower()

    kev_meta = state.get("kev", {}).get(cve) or {}
    entry["kev"] = bool(kev_meta)
    if kev_meta:
        entry["kev_date_added"] = kev_meta.get("date_added") or ""
        entry["kev_due_date"] = kev_meta.get("due_date") or ""
        entry["kev_vendor_project"] = kev_meta.get("vendor_project") or ""
        entry["kev_product"] = kev_meta.get("product") or ""
        entry["kev_vulnerability_name"] = kev_meta.get("vulnerability_name") or ""
        entry["kev_required_action"] = kev_meta.get("required_action") or ""
        entry["kev_known_ransomware_campaign_use"] = kev_meta.get("known_ransomware_campaign_use") or ""
        entry["kev_forensic_triage"] = kev_meta.get("forensic_triage") or ""
        entry["kev_cwes"] = kev_meta.get("cwes") or []
        entry["kev_sources"] = kev_meta.get("sources") or []
        if kev_meta.get("vendor_project"):
            entry["vendor"] = add_unique(entry.get("vendor"), kev_meta.get("vendor_project"))
        if kev_meta.get("product"):
            entry["product"] = add_unique(entry.get("product"), kev_meta.get("product"))
        if not entry.get("title") and kev_meta.get("vulnerability_name"):
            entry["title"] = kev_meta.get("vulnerability_name")

    desc = entry.get("desc", "") or (kev_meta.get("short_description") if kev_meta else "")
    for s in REPLACE_STRINGS:
        desc = desc.replace(s, "")
    entry["desc"] = desc
    entry["_descText"] = desc.lower()

    named = [entry.get("title", "")]
    named.extend(entry.get("vendor", []) if isinstance(entry.get("vendor"), list) else [])
    named.extend(entry.get("product", []) if isinstance(entry.get("product"), list) else [])
    named_str = " ".join(str(x) for x in named if x).lower()
    entry["_titleText"] = named_str
    entry["_titleSpace"] = normalize_to_spaces(named_str)

    sources = set()
    for field in POC_FIELDS:
        if entry.get(field):
            sources.add(field.upper())
    entry["_sources"] = sources

    cve_meta = state.get("metadata", {}).get(cve, {})
    cvss_val = cve_meta.get("cvss")
    cvss_score = entry.get("_cvss", 0.0) or 0.0
    if cvss_val is not None:
        try:
            cvss_score = float(cvss_val)
        except Exception:
            pass
    entry["_cvss"] = cvss_score

    if cvss_score > 0:
        entry["severity"] = cvss_severity(cvss_score)
    elif not entry.get("severity") or entry.get("severity") == "UNKNOWN":
        nuclei_rating = state.get("ratings", {}).get(cve)
        if nuclei_rating:
            if isinstance(nuclei_rating, dict):
                sev = nuclei_rating.get("SEVERITY") or nuclei_rating.get("severity") or "UNKNOWN"
                entry["severity"] = str(sev).upper()
            else:
                entry["severity"] = str(nuclei_rating).upper()
        else:
            entry["severity"] = entry.get("severity") or "UNKNOWN"
    return entry


def prepare_poc_dataset(raw: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    if not isinstance(raw, list): return {}
    out = {}
    for item in raw:
        if not isinstance(item, dict):
            continue
        entry = dict(item)
        cve = (entry.get("cve") or "").strip().upper()
        if not cve:
            continue
        entry["source"] = "PoCIndex"
        out[cve] = finalize_entry(entry)
    return out


def prepare_dataset(raw: List[Dict[str, Any]]):
    return list(prepare_poc_dataset(raw).values())


def prepare_cveproject_record(record: Dict[str, Any]) -> Dict[str, Any]:
    meta = record.get("cveMetadata") if isinstance(record.get("cveMetadata"), dict) else {}
    cna = (record.get("containers") or {}).get("cna") if isinstance(record.get("containers"), dict) else {}
    if not isinstance(cna, dict):
        cna = {}
    cve = (meta.get("cveId") or "").strip().upper()
    if not cve:
        return {}
    desc = first_english_description(cna.get("descriptions"))
    affected = cna.get("affected") if isinstance(cna.get("affected"), list) else []
    vendors, products = [], []
    for item in affected[:20]:
        if not isinstance(item, dict):
            continue
        vendor = item.get("vendor")
        product = item.get("product")
        if vendor and vendor not in vendors:
            vendors.append(str(vendor))
        if product and product not in products:
            products.append(str(product))
    return finalize_entry({
        "cve": cve,
        "desc": desc,
        "published": meta.get("datePublished") or "",
        "modified": meta.get("dateUpdated") or "",
        "state": meta.get("state") or "",
        "vendor": vendors,
        "product": products,
        "source": "CVEProject",
    })


def merge_cve_datasets(cve_records: List[Dict[str, Any]], poc_records: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged = {}
    if isinstance(cve_records, list):
        for record in cve_records:
            if isinstance(record, dict) and record.get("cve"):
                merged[record["cve"]] = finalize_entry(dict(record))
    for cve, poc in poc_records.items():
        base = merged.get(cve)
        if not base:
            merged[cve] = finalize_entry(dict(poc))
            continue
        for field in POC_FIELDS:
            if poc.get(field):
                base[field] = poc[field]
        for field in ("title", "published", "modified"):
            if not base.get(field) and poc.get(field):
                base[field] = poc[field]
        if not base.get("desc") and poc.get("desc"):
            base["desc"] = poc["desc"]
        base["source"] = "CVEProject + PoCIndex"
        merged[cve] = finalize_entry(base)
    for cve, kev in state.get("kev", {}).items():
        if cve in merged:
            continue
        merged[cve] = finalize_entry({
            "cve": cve,
            "title": kev.get("vulnerability_name") or "",
            "desc": kev.get("short_description") or kev.get("vulnerability_name") or "",
            "published": kev.get("date_added") or "",
            "modified": "",
            "vendor": [kev.get("vendor_project")] if kev.get("vendor_project") else [],
            "product": [kev.get("product")] if kev.get("product") else [],
            "source": "CISA KEV",
        })
    return list(merged.values())


def normalize_cveproject_zip(zip_path: str = CVEPROJECT_ZIP, out_path: str = CVEPROJECT_LIST, meta: Dict[str, Any] = None) -> int:
    records = []
    if not os.path.exists(zip_path):
        return 0
    with zipfile.ZipFile(zip_path) as zf:
        names = [name for name in zf.namelist() if name.endswith(".json") and "/cves/" in name.lower()]
        for name in names:
            try:
                with zf.open(name) as f:
                    record = json.loads(f.read().decode("utf-8", errors="replace"))
                entry = prepare_cveproject_record(record)
                if entry:
                    records.append(entry)
            except Exception:
                continue
    payload = {
        "meta": meta or {},
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total": len(records),
        "records": records,
    }
    tmp_path = f"{out_path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, separators=(",", ":"))
    os.replace(tmp_path, out_path)
    return len(records)


def sync_cveproject(force: bool = False) -> bool:
    asset = get_latest_cveproject_asset()
    if not asset.get("url"):
        return False
    cached = load_json_path(CVEPROJECT_LIST, {}) or {}
    cached_tag = ((cached.get("meta") or {}).get("tag") or "")
    if cached_tag == asset.get("tag") and not force:
        return True
    if not force and os.path.exists(CVEPROJECT_LIST):
        age = (time.time() - os.path.getmtime(CVEPROJECT_LIST)) / 3600.0
        if age < 24:
            cleanup_cveproject_archives()
            return True
    _set_sync_status("syncing", f"Downloading CVEProject baseline ({int((asset.get('size') or 0) / (1024 * 1024))} MB)...")
    cleanup_cveproject_archives()
    if not download_file(asset["url"], CVEPROJECT_ZIP, timeout=900):
        cleanup_cveproject_archives()
        return False
    _set_sync_status("syncing", "Importing CVEProject baseline...")
    try:
        count = normalize_cveproject_zip(CVEPROJECT_ZIP, CVEPROJECT_LIST, asset)
        logger.info("Imported %d CVEProject records.", count)
        return count > 0
    finally:
        cleanup_cveproject_archives()


def load_cveproject_records() -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    payload = load_json_path(CVEPROJECT_LIST, {}) or {}
    records = payload.get("records") if isinstance(payload.get("records"), list) else []
    meta = payload.get("meta") if isinstance(payload.get("meta"), dict) else {}
    return records, meta


def _legacy_prepare_dataset(raw: List[Dict[str, Any]]):
    if not isinstance(raw, list): return []
    out = []
    for entry in raw:
        cve = (entry.get("cve") or "").strip()
        if not cve: continue
        for field in POC_FIELDS:
            if not isinstance(entry.get(field), list):
                entry[field] = []
        entry_links(entry)
        
        parts = cve.split('-')
        entry["_cveText"] = cve.lower()
        desc = entry.get("desc", "")
        for s in REPLACE_STRINGS:
            desc = desc.replace(s, "")
        entry["_descText"] = desc.lower()
        
        try:
            entry["_year"] = int(parts[1]) if len(parts) > 1 else 0
            entry["_num"] = int(parts[2]) if len(parts) > 2 else 0
        except:
            entry["_year"] = 0
            entry["_num"] = 0
            
        named = [entry.get("title", "")]
        named.extend(entry.get("vendor", []))
        named.extend(entry.get("product", []))
        named_str = " ".join(named).lower()
        entry["_titleText"] = named_str
        entry["_titleSpace"] = normalize_to_spaces(named_str)
        
        # Attach sources
        sources = set()
        for f in POC_FIELDS:
            if entry.get(f):
                sources.add(f.upper())
        entry["_sources"] = sources
        
        # Determine severity based on CVSS score
        cvss_score = 0.0
        if "metadata" in state and cve in state["metadata"]:
            cvss_val = state["metadata"][cve].get("cvss")
            if cvss_val is not None:
                try:
                    cvss_score = float(cvss_val)
                except:
                    pass
        entry["_cvss"] = cvss_score
        
        if cvss_score >= 9.0:
            entry["severity"] = "CRITICAL"
        elif cvss_score >= 7.0:
            entry["severity"] = "HIGH"
        elif cvss_score >= 4.0:
            entry["severity"] = "MEDIUM"
        elif cvss_score > 0:
            entry["severity"] = "LOW"
        else:
            # Fallback to nuclei ratings if available
            nuclei_rating = state.get("ratings", {}).get(cve)
            if nuclei_rating:
                if isinstance(nuclei_rating, dict):
                    sev = nuclei_rating.get("SEVERITY") or nuclei_rating.get("severity") or "UNKNOWN"
                    entry["severity"] = str(sev).upper()
                else:
                    entry["severity"] = str(nuclei_rating).upper()
            else:
                entry["severity"] = "UNKNOWN"

        out.append(entry)
    return out

def build_word_index():
    postings = {}
    for i, entry in enumerate(state["dataset"]):
        text = entry["_descText"] + " " + entry["_titleText"] + " " + poc_space(entry)
        words = re.findall(r'[a-z0-9]+', text)
        for w in words:
            if w not in postings:
                postings[w] = []
            if not postings[w] or postings[w][-1] != i:
                postings[w].append(i)
    
    state["word_index"] = {
        "words": sorted(list(postings.keys())),
        "postings": postings
    }

def load_data():
    try:
        meta = load_json("trending_poc")
        if meta:
            state["index_meta"] = meta
            state["trending"] = meta.get("items", [])
            for item in state["trending"]:
                item["_pushed"] = hours_since(item.get("pushed"))
                item["_created"] = hours_since(item.get("created"))
                
        state["kev"], state["cisa_kev_meta"] = merge_kev_sources(load_json("kev") or {}, load_json("cisa_kev") or {})
        
        cvss = load_json("cvss") or {}
        advisories = load_json("advisories") or {}
        for k, v in cvss.items():
            if k not in state["metadata"]: state["metadata"][k] = {}
            state["metadata"][k]["cvss"] = v
        for k, v in advisories.items():
            if k not in state["metadata"]: state["metadata"][k] = {}
            state["metadata"][k]["advisories"] = v
            
        state["ratings"] = load_json("nuclei") or {}
        state["epss"] = load_json("epss") or {}
        state["repo_meta"] = load_json("repo_meta") or {}
        
        poc_records = prepare_poc_dataset(load_json("CVE_list") or [])
        cve_records, cve_meta = load_cveproject_records()
        state["cveproject_meta"] = cve_meta
        if cve_records:
            state["dataset"] = merge_cve_datasets(cve_records, poc_records)
        elif poc_records:
            state["dataset"] = merge_cve_datasets([], poc_records)
        if state["dataset"]:
            build_word_index()
            state["ready"] = True
            logger.info(f"Loaded {len(state['dataset'])} CVEs into PoC Index.")
    except Exception as e:
        logger.error(f"Error loading PoC Index data: {e}")

# -------------------------------------------------------
# Threading state
# -------------------------------------------------------
_sync_lock = threading.Lock()   # ensures only one sync runs at a time
_sync_status: dict = {
    "state": "idle",            # idle | syncing | ready | error
    "last_sync": None,          # ISO timestamp of last successful sync
    "message": "",
}

SYNC_INTERVAL_HOURS = 12
MAX_CACHE_AGE_HOURS = 13        # sync immediately if cache is older than this


def _cache_age_hours() -> float:
    """Return age in hours of the oldest mandatory JSON file, or inf if any is missing."""
    mandatory = [os.path.join(DATA_DIR, f"{name}.json") for name in ("CVE_list", "trending_poc", "kev", "cisa_kev")]
    mandatory.append(CVEPROJECT_LIST)
    oldest = 0.0
    for path in mandatory:
        if not os.path.exists(path):
            return float("inf")
        age = (time.time() - os.path.getmtime(path)) / 3600.0
        oldest = max(oldest, age)
    return oldest


def _set_sync_status(state_str: str, message: str = "", last_sync: str = None):
    _sync_status["state"] = state_str
    _sync_status["message"] = message
    if last_sync is not None:
        _sync_status["last_sync"] = last_sync


_load_lock = threading.Lock()


def ensure_pocindex_loaded() -> bool:
    """Lazy-load the on-disk cache if the UI reaches PoC Index before startup warm-up finishes."""
    if state.get("ready"):
        return True
    if not all(os.path.exists(os.path.join(DATA_DIR, f"{name}.json")) for name in ("CVE_list", "trending_poc", "kev")):
        return False
    if not _load_lock.acquire(blocking=False):
        return bool(state.get("ready"))
    try:
        if not state.get("ready"):
            load_data()
            if state.get("ready") and _sync_status.get("state") in {"idle", "syncing"}:
                _set_sync_status("ready", "Loaded from disk cache.")
    finally:
        _load_lock.release()
    return bool(state.get("ready"))


def _download_worker():
    """
    Background worker that:
      1. Downloads all JSON files concurrently using per-file threads.
      2. Reloads the in-memory dataset when done.
      3. Loops forever, sleeping SYNC_INTERVAL_HOURS between runs.
    Never blocks the FastAPI server.
    """
    import datetime

    # Back off if another sync is already running
    if not _sync_lock.acquire(blocking=False):
        logger.info("PoC Index: sync already in progress, skipping.")
        return

    try:
        _set_sync_status("syncing", "Downloading PoC Index datasets...")
        logger.info("PoC Index: starting background download of all datasets.")

        download_errors = []
        threads = []

        def _dl(name: str, url: str):
            ok = download_json(name, url)
            if not ok:
                download_errors.append(name)

        # Kick off one thread per file so all 8 JSONs download in parallel
        for name, url in URLS.items():
            t = threading.Thread(target=_dl, args=(name, url), daemon=True,
                                 name=f"pocindex-dl-{name}")
            t.start()
            threads.append(t)

        # Wait for all downloads to finish
        for t in threads:
            t.join()

        if download_errors:
            logger.warning("PoC Index: failed to download: %s", ", ".join(download_errors))

        # Reload from disk regardless — partial data is better than none
        if not sync_cveproject(force=False):
            logger.warning("CVEProject import unavailable; continuing with PoCIndex dataset.")

        load_data()

        ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        _set_sync_status("ready", f"Sync complete. {len(state['dataset'])} CVEs loaded.", last_sync=ts)
        logger.info("PoC Index: sync complete — %d CVEs ready.", len(state["dataset"]))

    except Exception as e:
        logger.exception("PoC Index: sync worker crashed: %s", e)
        _set_sync_status("error", str(e))
    finally:
        _sync_lock.release()


def _sync_loop():
    """
    Persistent background loop.
    On first run it checks if the cache is fresh; if not it triggers an immediate
    download in _download_worker (which runs its own threads).
    After that it sleeps SYNC_INTERVAL_HOURS and repeats forever.
    """
    while True:
        age = _cache_age_hours()
        if age >= MAX_CACHE_AGE_HOURS:
            logger.info(
                "PoC Index: cache age %.1fh >= threshold %.1fh — triggering sync.",
                age, MAX_CACHE_AGE_HOURS
            )
            # Run download on a separate thread so the loop itself is never blocked
            t = threading.Thread(target=_download_worker, daemon=True,
                                 name="pocindex-sync-worker")
            t.start()
            t.join()   # wait so we don't immediately re-schedule before the download finishes
        else:
            logger.info("PoC Index: cache age %.1fh — no sync needed.", age)

        # Sleep until next check
        time.sleep(SYNC_INTERVAL_HOURS * 3600)


def init_pocindex():
    """
    Entry point called once at MANTIS startup (already in its own thread).

    Phase 1 — Fast: load whatever is already on disk (milliseconds).
    Phase 2 — Background: launch the sync loop thread which handles the
               initial download (if cache is missing/stale) and all future
               periodic refreshes.  The FastAPI server is never blocked.
    """
    # Phase 1: immediate warm-up from cached data on disk
    logger.info("PoC Index: loading from disk cache...")
    load_data()
    if state["ready"]:
        logger.info("PoC Index: disk cache loaded — %d CVEs available immediately.", len(state["dataset"]))
        _set_sync_status("ready", "Loaded from disk cache.")
    else:
        logger.info("PoC Index: no disk cache found — fresh download will start shortly.")
        _set_sync_status("idle", "Waiting for initial download.")

    # Phase 2: start the persistent sync loop in its own daemon thread
    threading.Thread(target=_sync_loop, daemon=True,
                     name="pocindex-sync-loop").start()


def get_sync_status() -> dict:
    return dict(_sync_status)


def search_poc(query: str, severity_filter: list = None, source_filter: list = None, kev_only: bool = False, has_poc_only: bool = False, limit: int = 50, offset: int = 0, sort_by: str = "NEWEST") -> dict:
    if not state.get("dataset"):
        ensure_pocindex_loaded()
    if not state.get("dataset"):
        return {"total": 0, "results": []}

    terms = query.lower().split() if query else []
    results = []

    for entry in state["dataset"]:
        cve = entry["cve"]
        if kev_only and cve not in state["kev"]:
            continue

        if has_poc_only and not entry_links(entry):
            continue
            
        if severity_filter:
            # Match any of the selected severities
            if entry.get("severity") not in severity_filter:
                continue
                
        if source_filter:
            # Match ANY of the selected sources (OR logic)
            if not any(src in entry.get("_sources", set()) for src in source_filter):
                # Also check _allLinks for keyword matches like "github"
                if "GITHUB" in source_filter and any("github.com" in link for link in entry.get("_allLinks", [])):
                    pass
                else:
                    continue

        if terms:
            text = entry["_cveText"] + " " + entry["_descText"] + " " + entry["_titleText"] + " " + poc_text(entry)
            match = True
            for t in terms:
                if t not in text:
                    match = False
                    break
            if not match:
                continue

        results.append(entry)
        
    if sort_by == "NEWEST":
        results.sort(key=lambda x: (x.get("_year", 0), x.get("_num", 0)), reverse=True)
    elif sort_by == "POCS":
        results.sort(key=lambda x: (len(x.get("_allLinks", [])), x.get("_year", 0), x.get("_num", 0)), reverse=True)

    return {
        "total": len(results),
        "results": results[offset : offset + limit]
    }


def get_trending(limit: int = 20):
    if not state["ready"]:
        ensure_pocindex_loaded()
    if not state["ready"]: return []
    return state["trending"][:limit]


def get_stats():
    if not state["ready"]:
        ensure_pocindex_loaded()
    if not state["ready"]: return {}
    actual_total = len(state.get("dataset") or [])
    return {
        "total_cves": actual_total or (state["index_meta"].get("total_cves", 0) if state["index_meta"] else 0),
        "with_pocs": state["index_meta"].get("with_pocs", 0) if state["index_meta"] else 0,
        "kev_count": len(state["kev"]),
        "kev_source": "CISA KEV + PoCIndex KEV" if state.get("cisa_kev_meta") else "PoCIndex KEV",
        "kev_catalog_version": (state.get("cisa_kev_meta") or {}).get("catalogVersion", ""),
        "kev_date_released": (state.get("cisa_kev_meta") or {}).get("dateReleased", ""),
        "cveproject_loaded": bool(state.get("cveproject_meta")),
        "cveproject_tag": (state.get("cveproject_meta") or {}).get("tag", "")
    }
