"""CTI Articles: local search for Keyword Lookup + IOC mention correlation.

Ranking (keyword): 1 exact IOC/value, 2 exact title, 3 title contains,
4 extracted-intelligence match, 5 body match. Publishers are never
contacted with analyst queries — everything here reads the local DB.
Mentions are context ("Article Mention"), never a malicious verdict.
"""
import logging
import time

import cti_db as db
from intel_query import (
    classify_canonical_ioc,
    get_hash_type,
    is_defanged,
    normalize_domain,
    normalize_ip,
    normalize_url,
    refang_value,
)

logger = logging.getLogger("mantis.cti.query")

HASH_TYPES = ("md5", "sha1", "sha256", "sha3_384", "sha512")
IP_TYPES = ("ipv4", "ipv6")
MAX_RESULTS = 50

CTI_CATEGORY_GROUPS = {
    "Analyst": {
        "Analyst", "Research", "Security Research", "Analyst Research",
        "Malware Analysis / DFIR / Technical Research", "Vulnerability / Exploitation Research",
        "Threat Intelligence", "Core Threat Intelligence / Threat Research", "Malware & DFIR",
        "Vulnerabilities & Exploits"
    },
    "Community": {
        "Community", "Blog", "General Security & Blogs", "Blogs", "Security Blogs", "Other", ""
    },
    "Government": {
        "Government", "CERT", "Gov", "Advisories", "CERT / Gov"
    },
    "Media": {
        "Media", "News", "Security News", "Journalism", "Security News / Campaign Discovery", "Podcasts & Video", "Podcasts & YouTube"
    },
    "Vendor": {
        "Vendor", "Vendors", "Product Blogs", "Vendor Research", "Vendors & Product Blogs"
    },
}

STANDARD_CATEGORIES = {"Analyst", "Community", "Government", "Media", "Vendor"}

_RAW_TO_DISPLAY_CATEGORY = {
    raw.lower(): display
    for display, raw_values in CTI_CATEGORY_GROUPS.items()
    for raw in raw_values
}


def source_raw_category(source: dict) -> str:
    upstream = (source.get("upstream") or "").strip()
    raw = ((upstream.split("|", 1)[0] if upstream else "") or "Community").strip()
    return raw or "Community"


def display_category(raw_category: str) -> str:
    raw = (raw_category or "").strip()
    if raw in STANDARD_CATEGORIES:
        return raw
    low = raw.lower()
    if low in _RAW_TO_DISPLAY_CATEGORY:
        return _RAW_TO_DISPLAY_CATEGORY[low]
    if "cert" in low or "gov" in low or "cisa" in low:
        return "Government"
    if "news" in low or "press" in low or "media" in low or "journal" in low or "darknet" in low or "tech" in low:
        return "Media"
    if "vendor" in low or "product" in low or "corp" in low or "inc" in low or "cloud" in low or "labs" in low or "security" in low:
        return "Vendor"
    if "research" in low or "analyst" in low or "dfir" in low or "blog" in low:
        return "Analyst"
    return "Community"


def category_source_values(display: str) -> list[str]:
    category = (display or "").strip()
    if not category or category == "All":
        return []
    values = CTI_CATEGORY_GROUPS.get(category)
    return sorted(v for v in (values or {category}) if v)


def _attach_source_category(row: dict, conn) -> dict:
    if row.get("source_category"):
        return row
    source_id = row.get("source_id", "")
    if not source_id:
        row["source_category"] = "Other"
        return row
    src = conn.execute("SELECT upstream FROM sources WHERE id = ?", (source_id,)).fetchone()
    row["source_category"] = source_raw_category(dict(src) if src else {})
    return row


def _canonical_indicator(text: str):
    """(kind, canonical) for exact-IOC matching, refanging defanged input."""
    raw = (text or "").strip()
    if not raw:
        return "", ""
    candidate = refang_value(raw) if is_defanged(raw) else raw
    kind = classify_canonical_ioc(candidate)
    if kind == "hash":
        return get_hash_type(candidate), candidate.lower()
    if kind == "ip":
        norm = normalize_ip(candidate)
        if not norm:
            return "", ""
        import ipaddress
        try:
            v = "ipv6" if ipaddress.ip_address(norm).version == 6 else "ipv4"
        except ValueError:
            return "", ""
        return v, norm
    if kind == "domain":
        norm = normalize_domain(candidate)
        return ("domain", norm) if norm else ("", "")
    if kind == "url":
        norm = normalize_url(candidate)
        return ("url", norm) if norm else ("", "")
    low = candidate.strip()
    if low[:4].upper() == "CVE-" and len(low) <= 20:
        return "cve", low.upper()
    import re
    if re.match(r"^T\d{4}(\.\d{3})?$", low.upper()):
        return "attack", low.upper()
    return "", ""


def _summarize(article: dict, matched_on: str, matched_value: str,
               conn=None) -> dict:
    inds = db.article_indicators(article["id"], conn=conn)
    counts = {"hashes": 0, "domains": 0, "ips": 0, "urls": 0,
              "cves": 0, "attack": 0, "asn": 0}
    for ind in inds:
        t = ind["type"]
        if t in HASH_TYPES:
            counts["hashes"] += 1
        elif t == "domain":
            counts["domains"] += 1
        elif t in IP_TYPES:
            counts["ips"] += 1
        elif t == "url":
            counts["urls"] += 1
        elif t == "cve":
            counts["cves"] += 1
        elif t == "attack":
            counts["attack"] += 1
        elif t == "asn":
            counts["asn"] += 1
    order = {"ipv4": 0, "ipv6": 0, "domain": 1, "url": 2, "cve": 3,
             "attack": 4, "asn": 5, "md5": 6, "sha1": 6, "sha256": 6,
             "sha3_384": 6, "sha512": 6}
    top = sorted(inds, key=lambda i: (order.get(i["type"], 9), i["value"]))[:4]
    return {
        "id": article["id"],
        "title": article.get("title", ""),
        "source": article.get("source_name", ""),
        "category": display_category(article.get("source_category", "")),
        "author": article.get("author", ""),
        "published": article.get("published_at", "") or article.get("fetched_at", ""),
        "url": article.get("url", ""),
        "excerpt": article.get("excerpt", ""),
        "matched_on": matched_on,
        "matched_value": matched_value or "",
        "indicator_counts": counts,
        "indicator_total": sum(counts.values()),
        "top_indicators": [{"type": i["type"], "value": i["value"],
                            "observed": i["observed_value"]} for i in top],
    }


def query_cti_articles(keyword: str, limit: int = MAX_RESULTS,
                       category: str = "") -> dict:
    """Ranked local CTI search for Keyword Lookup."""
    q = (keyword or "").strip()
    if not q:
        return {"total": 0, "results": []}
    db.init_db()
    conn = db.connect()
    try:
        best = {}  # article_id -> (rank, matched_on, matched_value, row)
        ql = q.lower()
        allowed_categories = set(category_source_values(category))

        def consider(aid: int, rank: int, on: str, val: str, existing_row: dict = None):
            if aid in best and best[aid][0] <= rank:
                return
            if existing_row:
                row = dict(existing_row)
                if "source_name" not in row or row["source_name"] is None:
                    row["source_name"] = db.source_name(conn, row.get("source_id", ""))
            else:
                row = db.get_article(aid, conn=conn)
                if not row:
                    return
                row["source_name"] = db.source_name(conn, row.get("source_id", ""))
            row = _attach_source_category(row, conn)
            if "[virtual event]" in (row.get("title") or "").lower() or "[virtual event]" in (row.get("excerpt") or "").lower():
                return
            if allowed_categories and row.get("source_category", "") not in allowed_categories:
                return
            best[aid] = (rank, on, val, row)

        # 1. exact IOC / value match
        kind, canon = _canonical_indicator(q)
        if kind and canon:
            rows, _total = db.indicator_articles(kind, canon)
            for row in rows:
                consider(row["id"], 1, "Exact indicator match", canon, existing_row=row)
        # 2/3. title exact / contains
        for row in conn.execute(
                "SELECT a.*, s.name AS source_name FROM articles a"
                " LEFT JOIN sources s ON s.id = a.source_id"
                " WHERE LOWER(a.title) = ? ORDER BY COALESCE(NULLIF(a.published_at, ''), a.fetched_at) DESC LIMIT 20",
                (ql,)).fetchall():
            consider(row["id"], 2, "Exact title match", row["title"], existing_row=row)
        for row in conn.execute(
                "SELECT a.*, s.name AS source_name FROM articles a"
                " LEFT JOIN sources s ON s.id = a.source_id"
                " WHERE LOWER(a.title) LIKE ? ORDER BY COALESCE(NULLIF(a.published_at, ''), a.fetched_at) DESC LIMIT 20",
                (f"%{ql}%",)).fetchall():
            consider(row["id"], 3, "Title match", row["title"], existing_row=row)
        # 4. extracted-intelligence substring match
        for row in conn.execute(
                "SELECT DISTINCT a.*, s.name AS source_name FROM article_indicators i"
                " JOIN articles a ON a.id = i.article_id"
                " LEFT JOIN sources s ON s.id = a.source_id"
                " WHERE LOWER(i.value) LIKE ? OR LOWER(i.observed_value) LIKE ?"
                " ORDER BY COALESCE(NULLIF(a.published_at, ''), a.fetched_at) DESC LIMIT 20",
                (f"%{ql}%", f"%{ql}%")).fetchall():
            if row["id"] not in best:
                consider(row["id"], 4, "Extracted intelligence match", q, existing_row=row)
        # 5. body match (FTS)
        for aid, _rank in db.fts_search(q, limit=20):
            if aid not in best:
                consider(aid, 5, "Article body match", q)
        # sort by rank asc, then newest first within each rank
        from itertools import groupby
        by_rank = sorted(best.values(), key=lambda b: b[0])
        ranked = []
        for _rank, grp in groupby(by_rank, key=lambda b: b[0]):
            ranked.extend(sorted(grp,
                                 key=lambda b: (_sort_key(b[3]), b[3].get("id", 0)),
                                 reverse=True))
        results = [_summarize(row, on, val, conn=conn)
                   for _rank, on, val, row in ranked[:max(1, limit)]]
        return {"total": len(best), "results": results}
    finally:
        conn.close()


def _sort_key(row: dict):
    return (row.get("published_at") or row.get("fetched_at") or "")


def article_mentions(kind: str, value: str, limit: int = 10) -> dict:
    """Newest local articles mentioning an IOC (Hash/Domain/IP/URL Lookup)."""
    kind = (kind or "").strip().lower()
    raw = (value or "").strip()
    if not raw:
        return {"total": 0, "articles": []}
    db.init_db()
    queries = []
    if kind == "hash":
        ht = get_hash_type(raw.lower())
        if ht in HASH_TYPES:
            queries.append((ht, raw.lower()))
    elif kind in ("domain", "url"):
        canon = refang_value(raw) if is_defanged(raw) else raw
        norm = normalize_domain(canon) if kind == "domain" else normalize_url(canon)
        if norm:
            queries.append((kind, norm))
    elif kind == "ip":
        canon = refang_value(raw) if is_defanged(raw) else raw
        norm = normalize_ip(canon)
        if norm:
            import ipaddress
            try:
                v = "ipv6" if ipaddress.ip_address(norm).version == 6 else "ipv4"
                queries.append((v, norm))
            except ValueError:
                pass
    merged = {}
    for itype, val in queries:
        rows, _total = db.indicator_articles(itype, val, limit=limit)
        for row in rows:
            merged[row["id"]] = row
    ordered = sorted(merged.values(),
                     key=lambda r: (r.get("published_at") or r.get("fetched_at") or ""),
                     reverse=True)[:max(1, limit)]
    return {"total": len(merged), "articles": [
        {"id": r["id"], "title": r.get("title", ""),
         "source": r.get("source_name", ""), "author": r.get("author", ""),
         "published": r.get("published_at", "") or r.get("fetched_at", ""),
         "url": r.get("url", "")} for r in ordered]}


def recent(source_id: str = "", hours: int = 0, limit: int = 50,
           offset: int = 0, category: str = "") -> dict:
    """Newest-first article feed with optional source / time filters."""
    db.init_db()
    since = ""
    if hours and hours > 0:
        since = time.strftime("%Y-%m-%dT%H:%M:%S",
                              time.gmtime(time.time() - hours * 3600))
    conn = db.connect()
    try:
        rows, total = db.recent_articles(source_id=source_id, since_iso=since,
                                         limit=limit, offset=offset, conn=conn,
                                         source_categories=category_source_values(category))
        return {"total": total, "limit": limit, "offset": offset,
                "results": [_summarize(r, "", "", conn=conn) for r in rows]}
    finally:
        conn.close()


def details(article_id: int) -> dict:
    """Article Details + grouped extracted intelligence for manual pivots."""
    db.init_db()
    conn = db.connect()
    try:
        article = db.get_article(article_id, conn=conn)
        if not article:
            return {"error": "Article not found"}
        article["source_name"] = db.source_name(conn, article.get("source_id", ""))
        groups = {"hashes": [], "domains": [], "ips": [],
                  "urls": [], "cves": [], "attack": [], "asn": []}
        for ind in db.article_indicators(article_id, conn=conn):
            t = ind["type"]
            entry = {"value": ind["value"], "observed": ind["observed_value"]}
            if t in HASH_TYPES:
                groups["hashes"].append(entry)
            elif t == "domain":
                groups["domains"].append(entry)
            elif t in IP_TYPES:
                groups["ips"].append(entry)
            elif t == "url":
                groups["urls"].append(entry)
            elif t == "cve":
                groups["cves"].append(entry)
            elif t == "attack":
                groups["attack"].append(entry)
            elif t == "asn":
                groups["asn"].append(entry)

        # Malpedia taxonomy
        actors, families = db.scan_malpedia_entities(article.get("content_text", ""), conn=conn)
        groups["actors"] = [{"value": a["name"], "observed": a["name"], "description": a.get("description", "")} for a in actors]
        groups["malware"] = [{"value": f["name"], "observed": f["name"], "description": f.get("description", "")} for f in families]

        counts = {k: len(v) for k, v in groups.items()}
        return {
            "id": article["id"],
            "title": article.get("title", ""),
            "source": article.get("source_name", ""),
            "author": article.get("author", ""),
            "published": article.get("published_at", ""),
            "modified": article.get("modified_at", ""),
            "fetched": article.get("fetched_at", ""),
            "url": article.get("url", ""),
            "excerpt": article.get("excerpt", ""),
            "content_html": article.get("content_html", ""),
            "indicator_counts": counts,
            "indicator_total": sum(counts.values()),
            "indicators": groups,
        }
    finally:
        conn.close()


def sources_status():
    """Registry rows with a display status for the Sources view."""
    db.init_db()
    out = []
    for s in db.get_sources():
        if not s.get("feed_url"):
            status = "Feed Not Found"
        elif not s.get("enabled"):
            status = "Disabled"
        elif db.is_media_feed(s):
            status = "Skipped"
        elif s.get("last_error"):
            err = s.get("last_error")
            if err.startswith("BLOCKED"):
                status = "Error · HTTP 403 / automated access blocked"
            elif err.startswith("HTML_NO_FEED"):
                status = "Error · HTML returned; no RSS/Atom feed discovered"
            elif err.startswith("TEMPORARY_ERROR"):
                status = "Temporary error · connection timed out"
            elif err.startswith("RATE_LIMITED"):
                status = "Rate limited · HTTP 429"
            elif err.startswith("INVALID_FEED"):
                status = "Invalid feed · malformed XML"
            else:
                status = "Error"
        elif s.get("last_success"):
            status = "Active"
        else:
            status = "Pending"
        raw_category = source_raw_category(s)
        out.append({
            **s,
            "status": status,
            "category": raw_category,
            "display_category": display_category(raw_category),
        })
    return {"total": len(out), "sources": out}
