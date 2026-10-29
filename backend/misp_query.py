import logging
import os
import json
import time
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple

import requests

logger = logging.getLogger("mantis.misp")

MISP_QUERY_MAX_RESULTS = 500
MISP_API_TIMEOUT = 25
MISP_LIVE_LIMIT = 50
MISP_CACHE_TTL_SECONDS = 300
_MISP_LIVE_CACHE: Dict[Tuple[str, str, str], Tuple[float, Dict[str, Any]]] = {}


def _first_env(*names: str) -> str:
    for name in names:
        val = (os.environ.get(name) or "").strip()
        if val:
            return val
    return ""


def _boolish(value: Any, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"0", "false", "no", "off", "disable", "disabled"}:
        return False
    if text in {"1", "true", "yes", "on", "enable", "enabled"}:
        return True
    return default


def _resolve_misp_url(misp_url: str = "") -> str:
    url = (misp_url or "").strip() or _first_env("MISP_URL", "MANTIS_MISP_URL", "IOCINTEL_MISP_URL")
    return url.rstrip("/")


def _resolve_misp_key(misp_key: str = "") -> str:
    return (misp_key or "").strip() or _first_env("MISP_API_KEY", "MISP_AUTH_KEY", "MANTIS_MISP_KEY", "MANTIS_MISP_API_KEY", "IOCINTEL_MISP_KEY", "IOCINTEL_MISP_API_KEY")


def _resolve_verify_ssl(verify_ssl: Any = None) -> bool:
    env_val = _first_env("MISP_VERIFY_SSL", "MANTIS_MISP_VERIFY_SSL", "IOCINTEL_MISP_VERIFY_SSL")
    if env_val:
        return _boolish(env_val, True)
    return _boolish(verify_ssl, True)


def _misp_headers(api_key: str) -> Dict[str, str]:
    return {
        "Authorization": api_key,
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "MANTIS-MISP-ReadOnly/1.0",
    }


def _misp_request(method: str, base_url: str, path: str, api_key: str, verify_ssl: bool, **kwargs) -> Any:
    url = f"{base_url}/{path.lstrip('/')}"
    headers = kwargs.pop("headers", {})
    merged_headers = _misp_headers(api_key)
    merged_headers.update(headers)
    resp = requests.request(
        method,
        url,
        headers=merged_headers,
        timeout=MISP_API_TIMEOUT,
        verify=verify_ssl,
        **kwargs,
    )
    resp.raise_for_status()
    if not resp.text:
        return {}
    return resp.json()


def _listify(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _misp_response_items(data: Any, preferred_key: str) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if not isinstance(data, dict):
        return []
    body = data.get("response", data.get("Response", data))
    if isinstance(body, list):
        return [x for x in body if isinstance(x, dict)]
    if isinstance(body, dict):
        if isinstance(body.get(preferred_key), list):
            return [x for x in body.get(preferred_key, []) if isinstance(x, dict)]
        if isinstance(body.get("Attribute"), list):
            return [x for x in body.get("Attribute", []) if isinstance(x, dict)]
        if isinstance(body.get("Event"), list):
            return [x for x in body.get("Event", []) if isinstance(x, dict)]
        if preferred_key in body and isinstance(body[preferred_key], dict):
            return [body[preferred_key]]
        return [body]
    return []


def _tag_name(tag: Any) -> str:
    if isinstance(tag, dict):
        return _safe_str(tag.get("name") or tag.get("Name") or tag.get("tag")).strip()
    return _safe_str(tag).strip()


def _extract_tags(*containers: Any) -> List[str]:
    names: List[str] = []
    seen = set()
    for container in containers:
        if not isinstance(container, dict):
            continue
        candidates = []
        candidates.extend(_listify(container.get("Tag")))
        candidates.extend(_listify(container.get("EventTag")))
        candidates.extend(_listify(container.get("AttributeTag")))
        for item in candidates:
            if isinstance(item, dict) and item.get("Tag"):
                item = item.get("Tag")
            name = _tag_name(item)
            if name and name not in seen:
                seen.add(name)
                names.append(name)
    return names


def _extract_galaxies(*containers: Any) -> List[Dict[str, str]]:
    galaxies: List[Dict[str, str]] = []
    seen = set()
    for container in containers:
        if not isinstance(container, dict):
            continue
        raw_items = []
        raw_items.extend(_listify(container.get("Galaxy")))
        raw_items.extend(_listify(container.get("GalaxyCluster")))
        for galaxy in raw_items:
            if not isinstance(galaxy, dict):
                continue
            clusters = _listify(galaxy.get("GalaxyCluster")) or [galaxy]
            for cluster in clusters:
                if not isinstance(cluster, dict):
                    continue
                name = _safe_str(cluster.get("value") or cluster.get("tag_name") or cluster.get("name")).strip()
                gtype = _safe_str(galaxy.get("type") or cluster.get("type") or galaxy.get("name")).strip()
                uuid = _safe_str(cluster.get("uuid")).strip()
                key = (name, gtype, uuid)
                if not name or key in seen:
                    continue
                seen.add(key)
                galaxies.append({
                    "name": name,
                    "type": gtype,
                    "uuid": uuid,
                    "description": _safe_str(cluster.get("description")).strip(),
                })
    return galaxies


def _attribute_type_filter(query_type: str, indicator: str) -> List[str]:
    query_type = (query_type or "").lower()
    if query_type == "hash":
        length = len((indicator or "").strip())
        if length == 32:
            return ["md5", "filename|md5"]
        if length == 40:
            return ["sha1", "filename|sha1"]
        if length == 64:
            return ["sha256", "filename|sha256", "malware-sample"]
        if length == 128:
            return ["sha512", "filename|sha512"]
        return ["md5", "sha1", "sha256", "sha512", "filename|md5", "filename|sha1", "filename|sha256", "filename|sha512", "malware-sample"]
    if query_type == "domain":
        return ["domain", "hostname", "domain|ip"]
    if query_type == "ip":
        return ["ip-src", "ip-dst", "domain|ip"]
    if query_type == "url":
        return ["url", "uri", "link"]
    return []


def _normalize_attribute(item: Dict[str, Any], indicator: str = "") -> Dict[str, Any]:
    attr = item.get("Attribute") if isinstance(item.get("Attribute"), dict) else item
    event = attr.get("Event") if isinstance(attr.get("Event"), dict) else item.get("Event", {})
    if not isinstance(event, dict):
        event = {}
    tags = _extract_tags(attr, item)
    sightings = _listify(attr.get("Sighting")) + _listify(item.get("Sighting"))
    return {
        "id": _safe_str(attr.get("id")),
        "uuid": _safe_str(attr.get("uuid")),
        "type": _safe_str(attr.get("type")),
        "category": _safe_str(attr.get("category")),
        "value": _safe_str(attr.get("value")),
        "comment": _safe_str(attr.get("comment")),
        "to_ids": bool(attr.get("to_ids")),
        "first_seen": _safe_str(attr.get("first_seen")),
        "last_seen": _safe_str(attr.get("last_seen")),
        "event_id": _safe_str(attr.get("event_id") or event.get("id")),
        "event_uuid": _safe_str(event.get("uuid")),
        "event_info": _safe_str(event.get("info")),
        "event_date": _safe_str(event.get("date")),
        "org": _safe_str((event.get("Orgc") or event.get("Org") or {}).get("name") if isinstance(event.get("Orgc") or event.get("Org"), dict) else ""),
        "tags": tags,
        "sightings": len(sightings),
        "galaxies": _extract_galaxies(attr, item, event),
        "is_exact_match": _safe_str(attr.get("value")).lower() == (indicator or "").lower(),
    }


def _normalize_event(item: Dict[str, Any], indicator: str = "") -> Dict[str, Any]:
    event = item.get("Event") if isinstance(item.get("Event"), dict) else item
    if not isinstance(event, dict):
        return {}
    attrs = [a for a in _listify(event.get("Attribute")) if isinstance(a, dict)]
    reports = [r for r in _listify(event.get("EventReport")) if isinstance(r, dict)]
    related = []
    indicator_l = (indicator or "").lower()
    for attr in attrs:
        value = _safe_str(attr.get("value"))
        if not value or value.lower() == indicator_l:
            continue
        related.append({
            "type": _safe_str(attr.get("type")),
            "category": _safe_str(attr.get("category")),
            "value": value,
            "to_ids": bool(attr.get("to_ids")),
            "event_id": _safe_str(event.get("id")),
            "event_info": _safe_str(event.get("info")),
            "tags": _extract_tags(attr),
            "relationship": "same_misp_event",
        })
        if len(related) >= 100:
            break
    return {
        "id": _safe_str(event.get("id")),
        "uuid": _safe_str(event.get("uuid")),
        "info": _safe_str(event.get("info")),
        "date": _safe_str(event.get("date")),
        "published": bool(event.get("published")),
        "analysis": _safe_str(event.get("analysis")),
        "threat_level_id": _safe_str(event.get("threat_level_id")),
        "org": _safe_str((event.get("Orgc") or event.get("Org") or {}).get("name") if isinstance(event.get("Orgc") or event.get("Org"), dict) else ""),
        "tags": _extract_tags(event),
        "galaxies": _extract_galaxies(event),
        "reports": [
            {
                "id": _safe_str(r.get("id")),
                "uuid": _safe_str(r.get("uuid")),
                "name": _safe_str(r.get("name")),
                "timestamp": _safe_str(r.get("timestamp")),
                "content": _safe_str(r.get("content"))[:4000],
            }
            for r in reports[:10]
        ],
        "related_attributes": related,
        "attribute_count": len(attrs),
    }


def _warninglist_check(base_url: str, api_key: str, verify_ssl: bool, indicator: str) -> List[Dict[str, Any]]:
    checks = [
        ("POST", "warninglists/checkValue", {"json": {"value": indicator}}),
        ("GET", f"warninglists/checkValue/{urllib.parse.quote(indicator, safe='')}", {}),
    ]
    for method, path, kwargs in checks:
        try:
            data = _misp_request(method, base_url, path, api_key, verify_ssl, **kwargs)
        except requests.HTTPError as e:
            status = getattr(e.response, "status_code", 0)
            if status in {404, 405}:
                continue
            logger.debug("MISP warning-list check failed: %s", e)
            return []
        except Exception as e:
            logger.debug("MISP warning-list check failed: %s", e)
            return []
        items = []
        body = data.get("response", data) if isinstance(data, dict) else data
        for item in _listify(body):
            if isinstance(item, dict):
                wl = item.get("Warninglist") if isinstance(item.get("Warninglist"), dict) else item
                name = _safe_str(wl.get("name") or wl.get("description")).strip()
                if name:
                    items.append({
                        "name": name,
                        "id": _safe_str(wl.get("id")),
                        "description": _safe_str(wl.get("description")),
                    })
        return items
    return []


def _unique_strings(values: List[str], limit: int = 100) -> List[str]:
    out = []
    seen = set()
    for value in values:
        text = _safe_str(value).strip()
        if text and text not in seen:
            seen.add(text)
            out.append(text)
        if len(out) >= limit:
            break
    return out


def query_misp_ioc(indicator: str, query_type: str, misp_url: str = "", misp_key: str = "", verify_ssl: Any = None, limit: int = MISP_LIVE_LIMIT) -> Dict[str, Any]:
    """Read-only MISP IOC lookup.

    This function only searches existing MISP data and never creates events,
    submits attributes, uploads samples, triggers enrichment, publishes, syncs,
    or modifies sightings/tags/galaxies/configuration.
    """
    value = (indicator or "").strip()
    if not value:
        return {"error": "Empty indicator.", "configured": False}

    base_url = _resolve_misp_url(misp_url)
    api_key = _resolve_misp_key(misp_key)
    verify = _resolve_verify_ssl(verify_ssl)
    if not base_url or not api_key:
        return {
            "error": "MISP URL and API key are required. Configure them in Settings or set MISP_URL and MISP_API_KEY.",
            "configured": False,
            "provider": "MISP",
            "passive_only": True,
            "read_only": True,
        }

    cache_key = (base_url, (query_type or "").lower(), value.lower())
    cached = _MISP_LIVE_CACHE.get(cache_key)
    now = time.time()
    if cached and now - cached[0] < MISP_CACHE_TTL_SECONDS:
        out = dict(cached[1])
        out["cache"] = {"hit": True, "ttl_seconds": MISP_CACHE_TTL_SECONDS}
        return out

    provider_errors: List[str] = []
    attr_payload: Dict[str, Any] = {
        "returnFormat": "json",
        "value": value,
        "includeContext": 1,
        "includeSightings": 1,
        "includeEventTags": 1,
        "includeProposals": 0,
        "includeDecayScore": 1,
        "enforceWarninglist": 0,
        "limit": max(1, min(int(limit or MISP_LIVE_LIMIT), 200)),
        "page": 1,
    }
    types = _attribute_type_filter(query_type, value)
    if types:
        attr_payload["type_attribute"] = types

    try:
        attr_data = _misp_request("POST", base_url, "attributes/restSearch", api_key, verify, json=attr_payload)
    except Exception as e:
        logger.warning("MISP attribute search failed for %s: %s", value, e)
        return {
            "error": f"MISP attribute search failed: {str(e)[:300]}",
            "configured": True,
            "provider": "MISP",
            "passive_only": True,
            "read_only": True,
        }

    attributes = [_normalize_attribute(item, value) for item in _misp_response_items(attr_data, "Attribute")]
    attributes = [a for a in attributes if a.get("value")]
    event_ids = _unique_strings([a.get("event_id", "") for a in attributes], limit=25)

    events: List[Dict[str, Any]] = []
    if event_ids:
        event_payload = {
            "returnFormat": "json",
            "eventid": event_ids,
            "metadata": 0,
            "includeEventTags": 1,
            "includeGalaxy": 1,
            "includeEventReports": 1,
            "includeWarninglistHits": 1,
        }
        try:
            event_data = _misp_request("POST", base_url, "events/restSearch", api_key, verify, json=event_payload)
            events = [_normalize_event(item, value) for item in _misp_response_items(event_data, "Event")]
            events = [e for e in events if e.get("id") or e.get("uuid")]
        except Exception as e:
            provider_errors.append(f"Event context fetch failed: {str(e)[:200]}")

    warninglists = _warninglist_check(base_url, api_key, verify, value)
    all_tags = _unique_strings([tag for a in attributes for tag in a.get("tags", [])] + [tag for e in events for tag in e.get("tags", [])], limit=150)

    galaxy_seen = set()
    galaxies: List[Dict[str, str]] = []
    for galaxy in [g for a in attributes for g in a.get("galaxies", [])] + [g for e in events for g in e.get("galaxies", [])]:
        key = (galaxy.get("name"), galaxy.get("type"), galaxy.get("uuid"))
        if galaxy.get("name") and key not in galaxy_seen:
            galaxy_seen.add(key)
            galaxies.append(galaxy)

    related_seen = set()
    related_indicators = []
    for event in events:
        for rel in event.get("related_attributes", []):
            key = (rel.get("type"), rel.get("value"), rel.get("event_id"))
            if rel.get("value") and key not in related_seen:
                related_seen.add(key)
                related_indicators.append(rel)
            if len(related_indicators) >= 150:
                break

    event_reports = []
    for event in events:
        for report in event.get("reports", []):
            report = dict(report)
            report["event_id"] = event.get("id")
            report["event_info"] = event.get("info")
            event_reports.append(report)

    result = {
        "provider": "MISP",
        "indicator": value,
        "query_type": query_type,
        "configured": True,
        "passive_only": True,
        "read_only": True,
        "mutation_guardrails": {
            "event_create": False,
            "attribute_submit": False,
            "sample_upload": False,
            "publish": False,
            "enrichment": False,
            "sync": False,
            "tag_or_sighting_modify": False,
        },
        "summary": {
            "attribute_matches": len(attributes),
            "event_matches": len(events) or len(event_ids),
            "related_indicators": len(related_indicators),
            "tags": len(all_tags),
            "galaxies": len(galaxies),
            "warninglist_matches": len(warninglists),
            "sightings": sum(int(a.get("sightings") or 0) for a in attributes),
            "event_reports": len(event_reports),
        },
        "attributes": attributes[:100],
        "events": events[:25],
        "related_indicators": related_indicators[:150],
        "tags": all_tags,
        "galaxies": galaxies[:75],
        "warninglists": warninglists,
        "event_reports": event_reports[:25],
        "provider_errors": provider_errors,
        "semantics": "MISP results are structured intelligence context and correlations from an existing MISP instance, not a malware verdict.",
    }
    _MISP_LIVE_CACHE[cache_key] = (now, result)
    return dict(result)


def query_misp_galaxy(keyword: str) -> Dict[str, Any]:
    """Substring search over cached MISP galaxy files. Always returns
    {"results": [...]} (empty list when nothing matches or input is empty)."""
    res: Dict[str, Any] = {"results": []}
    if not isinstance(keyword, str):
        return res
    keyword_lower = keyword.strip().lower()
    if not keyword_lower:
        return res
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "misp")
    if not os.path.exists(data_dir):
        return res
    
    for filename in os.listdir(data_dir):
        if not filename.endswith(".json"):
            continue
            
        filepath = os.path.join(data_dir, filename)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                cluster_data = json.load(f)
                
            cluster_name = cluster_data.get("name", "Unknown Cluster")
            
            for item in cluster_data.get("values", []):
                val = item.get("value", "")
                
                # Retrieve synonyms from meta or root
                synonyms = []
                meta_synonyms = item.get("meta", {}).get("synonyms", [])
                if isinstance(meta_synonyms, list):
                    synonyms.extend(meta_synonyms)
                elif isinstance(meta_synonyms, str):
                    synonyms.append(meta_synonyms)
                    
                root_synonyms = item.get("synonyms", [])
                if isinstance(root_synonyms, list):
                    synonyms.extend(root_synonyms)
                elif isinstance(root_synonyms, str):
                    synonyms.append(root_synonyms)
                
                match = False
                if keyword_lower in val.lower():
                    match = True
                else:
                    for syn in synonyms:
                        if keyword_lower in syn.lower():
                            match = True
                            break
                            
                if match:
                    res["results"].append({
                        "cluster": cluster_name,
                        "value": val,
                        "description": item.get("description", ""),
                        "synonyms": synonyms,
                        "meta": item.get("meta", {})
                    })
                    if len(res["results"]) >= MISP_QUERY_MAX_RESULTS:
                        return res
        except Exception as e:
            logger.warning("skipping unreadable MISP cluster %s: %s", filepath, e)
            continue

    return res
