"""Shared MISP Galaxy loader / cache / search for MANTIS.

Central mapping of UI categories to verified official MISP Galaxy cluster
files (https://github.com/MISP/misp-galaxy/tree/main/clusters). All loading,
caching, normalization, ranking and searching goes through this module so
every consumer (sidebar tabs, keyword lookup, API) uses one implementation.

Design notes (verified against the official repository, Sep 2026):
- Every cluster file follows the standard Galaxy schema:
  {"name", "uuid", "description", "type", "values": [
      {"value", "uuid"?, "description"?, "meta": {...}, "related"?}]}
- Meta keys differ per Galaxy (refs/synonyms/country/official-refs/website/
  group_attack_id/category/status/...). stalkerware.json entries have NO
  description key at all. Normalization therefore never assumes fields exist.
- ``related`` (when present) is a list of {"dest-uuid", "tags", "type"}.
"""

import json
import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger("mantis.galaxy")

BASE_URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/"
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "misp")

# ---------------------------------------------------------------------------
# Central category mapping (single source of truth).
# key -> {file, label, short, group, entity}
# group: "threat-actor" | "malware-tools"  (sidebar section + All-search scope)
# entity: display string used on result cards ("Threat Actor" / "Malware / Tool")
# ---------------------------------------------------------------------------
MISP_GALAXY_CATEGORIES: Dict[str, Dict[str, str]] = {
    # --- Threat Actor section (official Galaxy names verified Sep 2026) ---
    "threat-actor": {
        "file": "threat-actor.json", "label": "MISP Threat Actor",
        "short": "MISP", "group": "threat-actor", "entity": "Threat Actor",
    },
    "360net": {
        "file": "360net.json", "label": "360.net Threat Actors",
        "short": "360.net", "group": "threat-actor", "entity": "Threat Actor",
    },
    "microsoft-activity-group": {
        "file": "microsoft-activity-group.json", "label": "Microsoft Activity Group",
        "short": "Microsoft", "group": "threat-actor", "entity": "Threat Actor",
    },
    "tidal-groups": {
        "file": "tidal-groups.json", "label": "Tidal Groups",
        "short": "Tidal", "group": "threat-actor", "entity": "Threat Actor",
    },
    "surveillance-vendor": {
        "file": "surveillance-vendor.json", "label": "Surveillance Vendor",
        "short": "Surveillance Vendor", "group": "threat-actor", "entity": "Threat Actor",
    },
    # --- Malware & Tools section ---
    "tool": {
        "file": "tool.json", "label": "Tool",
        "short": "Tool", "group": "malware-tools", "entity": "Malware / Tool",
    },
    "rat": {
        "file": "rat.json", "label": "RAT",
        "short": "RAT", "group": "malware-tools", "entity": "Malware / Tool",
    },
    "ransomware": {
        "file": "ransomware.json", "label": "Ransomware",
        "short": "Ransomware", "group": "malware-tools", "entity": "Malware / Tool",
    },
    "botnet": {
        "file": "botnet.json", "label": "Botnet",
        "short": "Botnet", "group": "malware-tools", "entity": "Malware / Tool",
    },
    "android": {
        "file": "android.json", "label": "Android",
        "short": "Android", "group": "malware-tools", "entity": "Malware / Tool",
    },
    "rmm-tool": {
        "file": "rmm-tool.json", "label": "RMM Tools",
        "short": "RMM Tools", "group": "malware-tools", "entity": "Malware / Tool",
    },
    "stalkerware": {
        "file": "stalkerware.json", "label": "Stalkerware",
        "short": "Stalkerware", "group": "malware-tools", "entity": "Malware / Tool",
    },
    "exploit-kit": {
        "file": "exploit-kit.json", "label": "Exploit Kit",
        "short": "Exploit Kit", "group": "malware-tools", "entity": "Malware / Tool",
    },
    "cryptominers": {
        "file": "cryptominers.json", "label": "Cryptominer",
        "short": "Cryptominer", "group": "malware-tools", "entity": "Malware / Tool",
    },
    "tds": {
        "file": "tds.json", "label": "TDS",
        "short": "TDS", "group": "malware-tools", "entity": "Malware / Tool",
    },
    # --- Malpedia section ---
    "malpedia-win": {
        "file": "malpedia-win.json", "label": "Malpedia Windows",
        "short": "Windows", "group": "malware-tools", "entity": "Malware / Tool",
    },
    "malpedia-elf": {
        "file": "malpedia-elf.json", "label": "Malpedia Linux",
        "short": "Linux", "group": "malware-tools", "entity": "Malware / Tool",
    },
    "malpedia-osx": {
        "file": "malpedia-osx.json", "label": "Malpedia Macos",
        "short": "Macos", "group": "malware-tools", "entity": "Malware / Tool",
    },
    "malpedia-apk": {
        "file": "malpedia-apk.json", "label": "Malpedia Android",
        "short": "Android", "group": "malware-tools", "entity": "Malware / Tool",
    },
    "malpedia-scripts": {
        "file": "malpedia-scripts.json", "label": "Malpedia Scripts",
        "short": "Scripts", "group": "malware-tools", "entity": "Malware / Tool",
    },
    "malpedia-other": {
        "file": "malpedia-other.json", "label": "Malpedia Others",
        "short": "Others", "group": "malware-tools", "entity": "Malware / Tool",
    },
}

# Virtual "All" scopes accepted by the search API (not real categories).
GALAXY_GROUP_SCOPES = {
    "all": "All Galaxies",
    "all-threat-actors": "All Threat Actors",
    "all-malware-tools": "All Malware & Tools",
}

# Extra cluster files downloaded/cached for legacy consumers (keyword lookup
# walks the whole cache dir) but not exposed as UI categories.
MISP_GALAXY_EXTRA_FILES = [
    "mitre-attack-pattern.json",
    "backdoor.json",
    "banker.json",
    "stealer.json",
    "wiper.json",
]

# NOTE: "malware.json" is intentionally absent: it does not exist in the
# official repository (verified: HTTP 404) and was dead weight in the old list.

CACHE_TTL_SECONDS = 24 * 3600

_galaxy_cache: Dict[str, Dict[str, Any]] = {}  # category -> {"values": [...], "loaded_at": ts}
_galaxy_normalized_cache: Dict[str, Dict[str, Any]] = {}  # category -> {"values": [...], "loaded_at": ts}
_cache_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Loading / cache
# ---------------------------------------------------------------------------
def categories_for_scope(scope: str) -> Optional[List[str]]:
    """Resolve a category key or virtual All-scope to a list of categories."""
    scope = (scope or "").strip().lower()
    if scope in MISP_GALAXY_CATEGORIES:
        return [scope]
    if scope in ("all", "all-galaxies"):
        return list(MISP_GALAXY_CATEGORIES.keys())
    if scope == "all-threat-actors":
        return [k for k, v in MISP_GALAXY_CATEGORIES.items() if v["group"] == "threat-actor"]
    if scope == "all-malware-tools":
        return [k for k, v in MISP_GALAXY_CATEGORIES.items() if v["group"] == "malware-tools"]
    return None


def _read_local_file(filename: str) -> Optional[Dict[str, Any]]:
    path = os.path.join(DATA_DIR, filename)
    try:
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning("galaxy cache read failed for %s: %s", filename, e)
        return None


def _fetch_and_cache(filename: str) -> Optional[Dict[str, Any]]:
    try:
        logger.info("fetching galaxy %s ...", filename)
        resp = requests.get(f"{BASE_URL}{filename}", timeout=20)
        if resp.status_code != 200:
            logger.warning("galaxy fetch %s: HTTP %s", filename, resp.status_code)
            return None
        data = resp.json()
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(os.path.join(DATA_DIR, filename), "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception as e:
            logger.warning("galaxy cache write failed for %s: %s", filename, e)
        return data
    except Exception as e:
        logger.warning("galaxy fetch failed for %s: %s", filename, e)
        return None


def load_galaxy(category: str, refresh: bool = False) -> List[Dict[str, Any]]:
    """Return raw ``values`` entries for a category (local cache first).

    Prefers the on-disk cache populated by the startup updater; fetches from
    GitHub only on cache miss (or when refresh=True and the fetch succeeds).
    Never raises: returns [] when unavailable.
    """
    if category not in MISP_GALAXY_CATEGORIES:
        return []
    filename = MISP_GALAXY_CATEGORIES[category]["file"]
    now = time.time()
    with _cache_lock:
        cached = _galaxy_cache.get(category)
        if cached and not refresh and (now - cached.get("loaded_at", 0)) < CACHE_TTL_SECONDS:
            return cached["values"]
    data = None if refresh else _read_local_file(filename)
    if data is None:
        data = _fetch_and_cache(filename)
    if data is None and refresh:
        data = _read_local_file(filename)  # fall back to stale disk copy
    values = data.get("values", []) if isinstance(data, dict) else []
    if not isinstance(values, list):
        values = []
    with _cache_lock:
        # Stamp AFTER the fetch so the TTL is measured from completion.
        _galaxy_cache[category] = {"values": values, "loaded_at": time.time()}
        _galaxy_normalized_cache.pop(category, None)
    return values


def normalized_galaxy(category: str) -> List[Dict[str, Any]]:
    """Return normalized records for a category, cached alongside raw values."""
    if category not in MISP_GALAXY_CATEGORIES:
        return []
    now = time.time()
    with _cache_lock:
        cached = _galaxy_normalized_cache.get(category)
        if cached and (now - cached.get("loaded_at", 0)) < CACHE_TTL_SECONDS:
            return [dict(v) for v in cached["values"]]
    values = load_galaxy(category)
    normalized = []
    for item in values:
        n = normalize_entry(category, item)
        if n:
            normalized.append(n)
    with _cache_lock:
        _galaxy_normalized_cache[category] = {"values": normalized, "loaded_at": time.time()}
    return [dict(v) for v in normalized]


def refresh_galaxy(category: str) -> bool:
    """Force re-fetch of one category. Returns True when fresh data loaded."""
    if category not in MISP_GALAXY_CATEGORIES:
        return False
    filename = MISP_GALAXY_CATEGORIES[category]["file"]
    data = _fetch_and_cache(filename)
    if data is None:
        return False
    values = data.get("values", [])
    if not isinstance(values, list):
        values = []
    with _cache_lock:
        _galaxy_cache[category] = {"values": values, "loaded_at": time.time()}
        _galaxy_normalized_cache.pop(category, None)
    return True


def clear_galaxy_cache() -> None:
    with _cache_lock:
        _galaxy_cache.clear()
        _galaxy_normalized_cache.clear()


# ---------------------------------------------------------------------------
# Normalization (common result structure; missing fields are simply omitted)
# ---------------------------------------------------------------------------
def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if str(v).strip()]
    if str(value).strip():
        return [str(value)]
    return []


def _collect_aliases(item: Dict[str, Any]) -> List[str]:
    aliases: List[str] = []
    for syn in _as_list(item.get("synonyms")):
        if syn not in aliases:
            aliases.append(syn)
    meta = item.get("meta", {}) if isinstance(item.get("meta"), dict) else {}
    for syn in _as_list(meta.get("synonyms")):
        if syn not in aliases:
            aliases.append(syn)
    return aliases


def _collect_refs(meta: Dict[str, Any]) -> List[str]:
    refs: List[str] = []
    for key in ("refs", "official-refs", "ransomnotes-refs"):
        for r in _as_list(meta.get(key)):
            if r not in refs:
                refs.append(r)
    return refs


def _collect_external_ids(meta: Dict[str, Any]) -> Dict[str, List[str]]:
    """MITRE / ATT&CK style identifiers present in Galaxy metadata."""
    out: Dict[str, List[str]] = {}
    for key, val in meta.items():
        kl = str(key).lower()
        if kl in ("group_attack_id",) or "mitre" in kl or kl in ("attack_id", "technique_id"):
            vals = _as_list(val)
            if vals:
                out[str(key)] = vals
    return out


def normalize_entry(category: str, item: Any) -> Optional[Dict[str, Any]]:
    """Normalize one raw Galaxy value entry. Returns None when unusable."""
    if not isinstance(item, dict):
        return None
    name = str(item.get("value", "") or "").strip()
    if not name:
        return None
    meta = item.get("meta", {})
    if not isinstance(meta, dict):
        meta = {}
    spec = MISP_GALAXY_CATEGORIES.get(category, {})
    country = _as_list(meta.get("country"))
    if not country:
        # Fallbacks used by specific Galaxies (verified field names).
        for key in ("cfr-suspected-state-sponsor", "microsoft-origin-threat"):
            country = _as_list(meta.get(key))
            if country:
                break
    related = item.get("related", [])
    if not isinstance(related, list):
        related = []
    result: Dict[str, Any] = {
        "name": name,
        "uuid": str(item.get("uuid", "") or ""),
        "category": category,
        "galaxy": spec.get("file", "").replace(".json", ""),
        "galaxy_label": spec.get("label", category),
        "group": spec.get("group", ""),
        "entity": spec.get("entity", ""),
        "aliases": _collect_aliases(item),
        "country": country,
        "refs": _collect_refs(meta),
        "external_ids": _collect_external_ids(meta),
        "related": [
            {"dest-uuid": r.get("dest-uuid", ""), "type": r.get("type", ""),
             "tags": list(r.get("tags", []) or []) if isinstance(r.get("tags"), list) else []}
            for r in related if isinstance(r, dict) and r.get("dest-uuid")
        ],
        "meta": meta,  # provider-specific metadata preserved for analysts
    }
    description = str(item.get("description", "") or "").strip()
    if description:
        result["description"] = description
    return result


# ---------------------------------------------------------------------------
# Ranking + search
# ---------------------------------------------------------------------------
# Lower is better. (0, uuid) beats everything and is not in the public spec
# list; the rest follow the spec order 1..7.
MATCH_LABELS = {
    0: "Matched UUID",
    1: "Matched name",
    2: "Matched alias",
    3: "Matched name",
    4: "Matched alias",
    5: "Matched name",
    6: "Matched alias",
    7: "Matched description",
}


def _rank_entry(name: str, aliases: List[str], text: str, uuid: str, query: str):
    q = query.lower()
    nl = name.lower()
    if q == uuid.lower() and q:
        return 0, uuid
    if q == nl:
        return 1, name
    for a in aliases:
        if q == a.lower():
            return 2, a
    if nl.startswith(q):
        return 3, name
    for a in aliases:
        if a.lower().startswith(q):
            return 4, a
    if q in nl:
        return 5, name
    for a in aliases:
        if q in a.lower():
            return 6, a
    if q in text:
        return 7, ""
    return None


def _clamp_limit(limit: int) -> int:
    try:
        return max(1, min(int(limit or 100), 500))
    except (TypeError, ValueError):
        return 100


def _clamp_offset(offset: int) -> int:
    try:
        return max(0, int(offset or 0))
    except (TypeError, ValueError):
        return 0


def _match_galaxy(category: str, q: str) -> List[Dict[str, Any]]:
    """Full ranked match list for one Galaxy (no slicing)."""
    normalized = normalized_galaxy(category)
    if not q:
        normalized.sort(key=lambda e: e["name"].lower())
        for n in normalized:
            n["match_rank"] = 8
            n["matched_on"] = "Browse"
            n["matched_value"] = ""
        return normalized
    scored = []
    seen: set = set()
    for n in normalized:
        haystack = " ".join([
            n.get("description", ""),
            " ".join(n.get("country", [])),
            " ".join(str(v) for vals in n.get("external_ids", {}).values() for v in vals),
            " ".join(str(v) for v in n.get("meta", {}).values() if isinstance(v, (str, int))),
        ]).lower()
        rank = _rank_entry(n["name"], n.get("aliases", []), haystack, n.get("uuid", ""), q)
        if rank is not None:
            dup_key = (n.get("uuid", ""), n["name"].lower())
            if dup_key in seen:
                continue  # exact duplicate within the same Galaxy
            seen.add(dup_key)
            rank_no, matched_value = rank
            n["match_rank"] = rank_no
            n["matched_on"] = MATCH_LABELS[rank_no]
            n["matched_value"] = matched_value
            scored.append(n)
    scored.sort(key=lambda e: (e["match_rank"], e["name"].lower()))
    return scored


def search_galaxy(category: str, query: str, limit: int = 100, offset: int = 0) -> Dict[str, Any]:
    """Search one Galaxy. Empty query browses (name-sorted, capped)."""
    if category not in MISP_GALAXY_CATEGORIES:
        return {"category": category, "query": query, "total": 0, "results": [],
                "error": f"Unknown galaxy category: {category}"}
    limit = _clamp_limit(limit)
    offset = _clamp_offset(offset)
    q = (query or "").strip()
    scored = _match_galaxy(category, q)
    return {"category": category, "query": q, "total": len(scored),
            "limit": limit, "offset": offset,
            "results": scored[offset:offset + limit]}


def search_multiple_galaxies(categories: List[str], query: str,
                             limit: int = 100, offset: int = 0) -> Dict[str, Any]:
    """Search several Galaxies. Records stay independent per source Galaxy.

    Only exact duplicates from the SAME galaxy+UUID are collapsed. When one
    name exists in several Galaxies each record is kept and flagged with
    ``possible_related`` (no claim they are the same entity).
    """
    valid = [c for c in (categories or []) if c in MISP_GALAXY_CATEGORIES]
    limit = _clamp_limit(limit)
    offset = _clamp_offset(offset)
    q = (query or "").strip()
    merged: List[Dict[str, Any]] = []
    seen: set = set()
    for cat in valid:
        for n in _match_galaxy(cat, q):
            key = (cat, n.get("uuid", ""), n.get("name", "").lower())
            if key in seen:
                continue  # exact duplicate from the same Galaxy
            seen.add(key)
            merged.append(n)
    # Flag names appearing in more than one Galaxy (independent records).
    by_name: Dict[str, set] = {}
    for n in merged:
        by_name.setdefault(n["name"].lower(), set()).add(n["category"])
    for n in merged:
        others = sorted(g for g in by_name[n["name"].lower()] if g != n["category"])
        n["possible_related"] = bool(others)
        if others:
            n["related_galaxies"] = others
    merged.sort(key=lambda e: (e.get("match_rank", 8), e["name"].lower()))
    return {"query": (query or "").strip(), "categories": valid,
            "total": len(merged), "limit": limit, "offset": offset,
            "results": merged[offset:offset + limit]}


def search_scope(scope: str, query: str, limit: int = 100, offset: int = 0) -> Dict[str, Any]:
    """Search a single category or a virtual All-scope. Returns error dict
    (with ``status`` 404) for unknown scopes so routes can reject them."""
    cats = categories_for_scope(scope)
    if cats is None:
        return {"error": f"Unknown galaxy category: {scope}", "status": 404}
    if len(cats) == 1:
        out = search_galaxy(cats[0], query, limit=limit, offset=offset)
        out["scope"] = scope
        return out
    out = search_multiple_galaxies(cats, query, limit=limit, offset=offset)
    out["scope"] = scope
    return out
