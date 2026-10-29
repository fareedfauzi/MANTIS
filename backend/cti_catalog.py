"""CTI Articles: Awesome Security Feeds catalog + approved-domain matching.

The catalog is a resolver only: it maps approved domains to known RSS/Atom
feeds. Article collection never depends on the catalog being reachable —
the local feed registry (cti_db) is the source of truth at sync time.

Modular: additional catalogs can be added as more ``fetch_*_catalog``
functions returning the same normalized entry shape.
"""
import json
import logging
import os
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

import cti_config as cfg

logger = logging.getLogger("mantis.cti.catalog")


def _read_local_catalog():
    try:
        with open(cfg.CTI_CATALOG_PATH, "r", encoding="utf-8") as f:
            wrapper = json.load(f)
        if isinstance(wrapper, dict) and isinstance(wrapper.get("feeds"), list):
            return wrapper
    except (OSError, ValueError):
        pass
    return None


def _catalog_age_s() -> float:
    try:
        return time.time() - os.path.getmtime(cfg.CTI_CATALOG_PATH)
    except OSError:
        return float("inf")


def parse_opml_file(path: str):
    """OPML (sec_feeds_full.xml) -> normalized entries. Category outlines
    provide the category for nested feed outlines (xmlUrl)."""
    entries = []

    def walk(node, category: str):
        for child in list(node):
            if child.tag != "outline":
                walk(child, category)  # e.g. <body> wrapping the outlines
                continue
            xml_url = (child.get("xmlUrl") or "").strip()
            if xml_url:
                entries.append({
                    "url": xml_url,
                    "title": (child.get("title") or child.get("text") or "").strip() or xml_url,
                    "type": (child.get("type") or "").strip().lower(),
                    "category": category,
                    "description": (child.get("description") or "").strip(),
                })
            else:
                walk(child, (child.get("title") or child.get("text") or "").strip() or category)

    tree = ET.parse(path)
    walk(tree.getroot(), "")
    return [e for e in (normalize_catalog_entry(r) for r in entries) if e]


def load_local_catalog_files():
    """User-provided catalog copies in data/ (feeds.json / sec_feeds_full.xml).

    Returns (entries, path) using the newest file present, or (None, "").
    These take precedence over the network catalog when present.
    """
    candidates = [p for p in (cfg.CTI_LOCAL_CATALOG_JSON, cfg.CTI_LOCAL_CATALOG_OPML)
                  if os.path.isfile(p)]
    if not candidates:
        return None, ""
    path = max(candidates, key=lambda p: os.path.getmtime(p))
    try:
        if path.lower().endswith(".json"):
            with open(path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            feeds = payload.get("feeds") if isinstance(payload, dict) else None
            if not isinstance(feeds, list):
                raise ValueError("unexpected catalog shape")
            entries = [e for e in (normalize_catalog_entry(r) for r in feeds) if e]
        else:
            entries = parse_opml_file(path)
        if not entries:
            raise ValueError("no usable feeds")
        return entries, path
    except Exception as e:
        logger.warning("CTI local catalog unreadable %s (%s)", path, e)
        return None, ""


def _write_cache(entries, generated_at: str = ""):
    try:
        os.makedirs(cfg.DATA_DIR, exist_ok=True)
        tmp_path = cfg.CTI_CATALOG_PATH + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump({"fetched_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                       "url": cfg.CTI_CATALOG_URL,
                       "generated_at": generated_at,
                       "feeds": entries}, f)
        os.replace(tmp_path, cfg.CTI_CATALOG_PATH)
    except OSError as e:
        logger.warning("CTI catalog cache write failed (%s)", e)


def fetch_awesome_catalog(force: bool = False):
    """Return (entries, meta). Entries are normalized dicts; never raises.

    Precedence: user-provided data/feeds.json or data/sec_feeds_full.xml
    (newest wins) -> fresh local cache -> network -> any stale cache.
    The working cache copy is refreshed whenever a better source loads.
    """
    local_entries, local_path = load_local_catalog_files()
    if local_entries:
        _write_cache(local_entries)
        try:
            age = round(time.time() - os.path.getmtime(local_path), 1)
        except OSError:
            age = 0
        logger.info("CTI catalog loaded from local file %s (%d feeds)",
                    os.path.basename(local_path), len(local_entries))
        return local_entries, {"cached": True, "local_file": os.path.basename(local_path),
                               "age_s": age}
    local = _read_local_catalog()
    if not force and local is not None and _catalog_age_s() < cfg.CATALOG_TTL_SECONDS:
        return list(local["feeds"]), {"cached": True, "age_s": round(_catalog_age_s(), 1)}
    try:
        req = urllib.request.Request(cfg.CTI_CATALOG_URL,
                                     headers={"User-Agent": cfg.CTI_USER_AGENT})
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.load(resp)
        feeds = payload.get("feeds") if isinstance(payload, dict) else None
        if not isinstance(feeds, list):
            raise ValueError("unexpected catalog shape")
        entries = [normalize_catalog_entry(e) for e in feeds]
        entries = [e for e in entries if e]
        _write_cache(entries, payload.get("generated_at", ""))
        logger.info("CTI catalog refreshed: %d feeds", len(entries))
        return entries, {"cached": False, "age_s": 0}
    except Exception as e:
        logger.warning("CTI catalog refresh failed (%s); using local copy", e)
        if local is not None:
            return list(local["feeds"]), {"cached": True, "age_s": round(_catalog_age_s(), 1),
                                          "error": str(e)[:200]}
        return [], {"cached": False, "error": str(e)[:200]}


def normalize_catalog_entry(raw: dict):
    """Catalog dict -> {feed_url, title, feed_type, category, description}."""
    if not isinstance(raw, dict):
        return None
    url = (raw.get("url") or "").strip()
    if not url.lower().startswith(("http://", "https://")):
        return None
    feed_type = (raw.get("type") or "").strip().lower()
    return {
        "feed_url": url,
        "title": (raw.get("title") or "").strip() or url,
        "feed_type": feed_type if feed_type in ("rss", "atom") else "",
        "category": (raw.get("category") or "").strip(),
        "description": (raw.get("description") or "").strip(),
    }


def feed_host(feed_url: str) -> str:
    try:
        return (urllib.parse.urlsplit(feed_url).hostname or "").lower()
    except ValueError:
        return ""


def domain_matches(domain: str, host: str) -> bool:
    """Approved domain D matches feed host H iff H == D or H is a subdomain.

    Publication subdomains (slowmist.medium.com) therefore match only their
    own feeds; medium.com itself is never approved so broad hosts stay out.
    """
    domain = (domain or "").lower().strip().strip(".")
    host = (host or "").lower().strip().strip(".")
    if not domain or not host:
        return False
    return host == domain or host.endswith("." + domain)


def match_feeds_for_domain(domain: str, entries) -> list:
    """All catalog feeds belonging to an approved domain (may be several).

    A leading www. on the approved domain is ignored for matching so
    "www.example.com" still resolves example.com feeds.
    """
    domain = (domain or "").lower().strip()
    variants = {domain}
    if domain.startswith("www."):
        variants.add(domain[4:])
    out = []
    for e in entries or []:
        host = feed_host(e.get("feed_url", ""))
        if any(domain_matches(v, host) for v in variants):
            out.append({
                "feed_url": e["feed_url"],
                "title": e.get("title") or e["feed_url"],
                "feed_type": e.get("feed_type") or "",
                "category": e.get("category") or "",
                "description": e.get("description") or "",
                "domain": domain,
                "discovery": "awesome-security-feeds",
            })
    return out
