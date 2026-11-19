"""Country and industry report pages built from existing ransomware and CTI data.

Both views reuse ransomware_monitor.recent_victims() (one upstream fetch per call) and
the local CTI article index. No new external sources are queried.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List, Tuple

import ransomware_monitor as rw


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _victims_for_period(days: int, rwlive_key: str = "") -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Full victim list for the period (overview() truncates its lists to 100)."""
    victims, sources = rw.recent_victims(days, rwlive_key)
    return victims, sources


def _country_key(victim: Dict[str, Any]) -> str:
    return _clean(victim.get("country_code")) or _clean(victim.get("country"))


def _matches_country(victim: Dict[str, Any], key: str) -> bool:
    return _country_key(victim).lower() == key.lower()


def _matches_sector(victim: Dict[str, Any], sector: str) -> bool:
    return _clean(victim.get("sector")).lower() == sector.lower()


def _rollup(victims: List[Dict[str, Any]], limit: int = 50) -> List[Dict[str, Any]]:
    """Count victims per country and return ranked rows with top groups and sectors."""
    buckets: Dict[str, Dict[str, Any]] = {}
    for v in victims:
        key = _country_key(v)
        if not key:
            continue
        row = buckets.setdefault(key, {"key": key, "name": _clean(v.get("country")) or key,
                                        "country_code": _clean(v.get("country_code")),
                                        "count": 0, "groups": Counter(), "sectors": Counter()})
        row["count"] += 1
        if v.get("group"):
            row["groups"][v["group"]] += 1
        if v.get("sector"):
            row["sectors"][v["sector"]] += 1
    ranked = sorted(buckets.values(), key=lambda r: r["count"], reverse=True)[:limit]
    out = []
    for r in ranked:
        out.append({
            "key": r["key"], "name": r["name"], "country_code": r["country_code"],
            "count": r["count"],
            "top_groups": [{"name": n, "count": c} for n, c in r["groups"].most_common(5)],
            "top_sectors": [{"name": n, "count": c} for n, c in r["sectors"].most_common(5)],
        })
    return out


def _cti_hits(terms: List[str], limit: int = 12) -> List[Dict[str, Any]]:
    """Local CTI articles matching any of the terms, deduplicated by URL/title."""
    import cti_query
    seen, hits = set(), []
    for term in terms:
        if not term or len(term) < 3:
            continue
        try:
            results = cti_query.query_cti_articles(term, limit=limit).get("results", [])
        except Exception:
            continue
        for item in results:
            key = item.get("url") or item.get("title")
            if not key or key in seen:
                continue
            seen.add(key)
            hits.append({"title": item.get("title"), "source": item.get("source"),
                         "url": item.get("url"), "published": item.get("published") or item.get("date"),
                         "matched_on": term})
            if len(hits) >= limit:
                return hits
    return hits


def list_countries(days: int = 365, rwlive_key: str = "") -> Dict[str, Any]:
    victims, sources = _victims_for_period(days, rwlive_key)
    return {"days": days, "total_victims": len(victims), "countries": _rollup(victims),
            "sources": sources}


def list_industries(days: int = 365, rwlive_key: str = "") -> Dict[str, Any]:
    victims, sources = _victims_for_period(days, rwlive_key)
    buckets = Counter(_clean(v.get("sector")) for v in victims if _clean(v.get("sector")))
    rows = []
    for sector, count in buckets.most_common(50):
        sub = [v for v in victims if _matches_sector(v, sector)]
        rows.append({
            "name": sector, "count": count,
            "top_groups": [{"name": n, "count": c} for n, c in Counter(v.get("group") for v in sub if v.get("group")).most_common(5)],
            "top_countries": [{"name": n, "count": c} for n, c in Counter(v.get("country") for v in sub if v.get("country")).most_common(5)],
        })
    return {"days": days, "total_victims": len(victims), "industries": rows, "sources": sources}


def country_detail(code: str, days: int = 365, rwlive_key: str = "") -> Dict[str, Any]:
    code = _clean(code).upper()
    all_victims, sources = _victims_for_period(days, rwlive_key)
    victims = [v for v in all_victims if _matches_country(v, code)]
    name = next((v.get("country") for v in victims if v.get("country")), code)
    sectors = Counter(_clean(v.get("sector")) for v in victims if _clean(v.get("sector")))
    groups = Counter(_clean(v.get("group")) for v in victims if _clean(v.get("group")))
    terms = [name] + [g for g, _ in groups.most_common(3)]
    return {
        "code": code, "name": name, "days": days,
        "victims": len(victims),
        "top_sectors": [{"name": n, "count": c} for n, c in sectors.most_common(8)],
        "top_groups": [{"name": n, "count": c} for n, c in groups.most_common(8)],
        "recent_victims": victims[:25],
        "cti_articles": _cti_hits(terms),
        "cti_search_terms": terms,
        "sources": sources,
    }


def industry_detail(sector: str, days: int = 365, rwlive_key: str = "") -> Dict[str, Any]:
    sector = _clean(sector)
    all_victims, sources = _victims_for_period(days, rwlive_key)
    victims = [v for v in all_victims if _matches_sector(v, sector)]
    countries = Counter(v.get("country") for v in victims if v.get("country"))
    groups = Counter(_clean(v.get("group")) for v in victims if _clean(v.get("group")))
    terms = [sector] + [g for g, _ in groups.most_common(3)]
    return {
        "name": sector, "days": days,
        "victims": len(victims),
        "top_countries": [{"name": n, "count": c} for n, c in countries.most_common(8)],
        "top_groups": [{"name": n, "count": c} for n, c in groups.most_common(8)],
        "recent_victims": victims[:25],
        "cti_articles": _cti_hits(terms),
        "cti_search_terms": terms,
        "sources": sources,
    }
