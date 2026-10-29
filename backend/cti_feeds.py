"""CTI Articles: feed autodiscovery fallback + approved-domain resolution.

Autodiscovery is deliberately lightweight (advertised <link> tags, common
paths, WordPress) — not a general-purpose crawler. Results feed the local
registry; collection never re-runs discovery on the hot path.
"""
import logging
import re
import urllib.parse
import urllib.request

import feedparser

import cti_config as cfg
import cti_catalog as catalog

logger = logging.getLogger("mantis.cti.feeds")

ALTERNATE_LINK_RE = re.compile(
    r'<link[^>]+type=["\']application/(?:rss|atom)\+xml["\'][^>]*>',
    re.IGNORECASE)
HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)

COMMON_FEED_PATHS = ("/feed", "/feed/", "/rss", "/rss/", "/atom.xml",
                     "/feed.xml", "/rss.xml", "/blog/feed", "/blog/rss",
                     "/blog/feed/", "/news/feed", "/feed/rss")


def _http_get(url: str, timeout: int):
    req = urllib.request.Request(url, headers={"User-Agent": cfg.CTI_USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        ctype = (resp.headers.get("Content-Type") or "").lower()
        return resp.read(cfg.ARTICLE_MAX_BYTES + 1), ctype


def _looks_like_feed(parsed) -> bool:
    try:
        entries = list(getattr(parsed, "entries", []) or [])
        if entries:
            return True  # recoverable entries count even when bozo is set
        if getattr(parsed, "bozo", 0):
            return False
        feed = getattr(parsed, "feed", {}) or {}
        return bool(feed.get("title"))
    except Exception:
        return False


def _try_feed_url(url: str):
    """GET a candidate URL; return feed info when it parses as RSS/Atom."""
    try:
        body, _ctype = _http_get(url, cfg.FEED_TIMEOUT_SECONDS)
        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            return None
        parsed = feedparser.parse(text)
        if not _looks_like_feed(parsed):
            return None
        feed = parsed.feed or {}
        return {"feed_url": url,
                "title": (feed.get("title") or "").strip() or url,
                "feed_type": "atom" if "atom" in url.lower() else "rss"}
    except Exception:
        return None


def autodiscover_domain(domain: str) -> list:
    """Lightweight RSS/Atom discovery for one approved domain."""
    domain = (domain or "").lower().strip().strip(".")
    if not domain:
        return []
    found = []
    seen = set()

    def add(info: dict):
        if info and info["feed_url"] not in seen:
            seen.add(info["feed_url"])
            info = dict(info)
            info["domain"] = domain
            info["discovery"] = "autodiscovery"
            found.append(info)

    html = ""
    base = f"https://{domain}"
    try:
        body, _ctype = _http_get(base, cfg.FEED_TIMEOUT_SECONDS)
        html = body.decode("utf-8", errors="replace")[:500000]
    except Exception as e:
        logger.info("CTI autodiscovery: %s unreachable (%s)", domain, e)
    if html:
        head = html[:200000]
        for tag in ALTERNATE_LINK_RE.findall(head):
            m = HREF_RE.search(tag)
            if m:
                add(_try_feed_url(urllib.parse.urljoin(base + "/", m.group(1).strip())))
        is_wp = ("wp-content" in html) or ("wp-json" in html) or ("WordPress" in html)
    else:
        is_wp = False
    paths = list(COMMON_FEED_PATHS)
    if is_wp and "/feed" not in paths:
        paths.insert(0, "/feed")
    # Advertised <link> feeds are all kept (distinct shows); the common-path
    # probe stops at the first hit since /feed vs /feed/ vs /rss are usually
    # the same feed served under aliases.
    for path in paths:
        hit = _try_feed_url(base + path)
        if hit:
            add(hit)
            break
    return found


def resolve_domain_feeds(domain: str, catalog_entries) -> list:
    """Catalog matches first; autodiscovery fallback; else Feed Not Found."""
    matched = catalog.match_feeds_for_domain(domain, catalog_entries)
    if matched:
        return matched
    auto = autodiscover_domain(domain)
    if auto:
        return auto
    return [{"feed_url": "", "title": domain, "feed_type": "",
             "category": "", "description": "",
             "domain": domain.lower().strip(), "discovery": "not-found"}]


def resolve_all_feeds(catalog_entries=None) -> list:
    """Resolve every approved domain + manually pinned feeds to feed rows."""
    if catalog_entries is None:
        catalog_entries, _meta = catalog.fetch_awesome_catalog()
    out = []
    for domain in cfg.approved_domains():
        out.extend(resolve_domain_feeds(domain, catalog_entries))
    for manual in cfg.extra_feeds():
        host = catalog.feed_host(manual["url"]) or manual["url"]
        out.append({"feed_url": manual["url"], "title": manual["name"],
                    "feed_type": "", "category": "", "description": "",
                    "domain": host, "discovery": "manual"})
    return out
