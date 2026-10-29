"""CTI Articles: configuration (allowlist, catalog, sync politeness).

The approved domain list is the allowlist: only feeds mapped to these
domains are ever collected. Override with MANTIS_CTI_DOMAINS (comma
separated, replaces the defaults). Manually pinned feeds via
MANTIS_CTI_EXTRA_FEEDS as "Name|https://.../feed.xml;...".
"""
import os
import re
import urllib.parse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

CTI_DB_PATH = os.path.join(DATA_DIR, "cti_articles.db")
CTI_CATALOG_PATH = os.path.join(DATA_DIR, "cti_catalog.json")

# User-provided local catalog copies (Awesome Security Feeds exports).
# When present these take precedence over the network catalog: fully
# local-first, no download needed.
CTI_LOCAL_CATALOG_JSON = os.path.join(DATA_DIR, "feeds.json")
CTI_LOCAL_CATALOG_OPML = os.path.join(DATA_DIR, "sec_feeds_full.xml")

CTI_CATALOG_URL = "https://awesomesecurityfeeds.com/data/feeds.min.json"
CTI_USER_AGENT = "Mozilla/5.0 (compatible; MANTIS-CTI/1.0; passive research client)"

# Default approved source domains (allowlist). Publication subdomains are
# matched exactly so broad hosts like medium.com are never ingested whole.
DEFAULT_APPROVED_DOMAINS = [
    "securelist.com",
    "talosintelligence.com",
    "thedfirreport.com",
    "thehackernews.com",
    "bleepingcomputer.com",
    "welivesecurity.com",
    "unit42.paloaltonetworks.com",
    "sentinelone.com",
    "rapid7.com",
    "sophos.com",
    "trendmicro.com",
    "checkmarx.com",
    "malware.news",
    "slowmist.medium.com",
    "socfortress.medium.com",
    "bi-zone.medium.com",
]


def _env_list(name: str):
    raw = os.environ.get(name, "").strip()
    if not raw:
        return []
    return [p.strip().lower() for p in raw.replace(";", ",").split(",") if p.strip()]


def approved_domains():
    """Allowlist: env override wins, otherwise the built-in defaults."""
    override = _env_list("MANTIS_CTI_DOMAINS") or _env_list("IOCINTEL_CTI_DOMAINS")
    if override:
        return sorted(set(override))
    return list(DEFAULT_APPROVED_DOMAINS)


def extra_feeds():
    """Manually pinned feeds: [{'name': ..., 'url': ...}]."""
    out = []
    raw = (os.environ.get("MANTIS_CTI_EXTRA_FEEDS", "")
           or os.environ.get("IOCINTEL_CTI_EXTRA_FEEDS", "")).strip()
    if not raw:
        return out
    for chunk in raw.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "|" in chunk:
            name, url = chunk.split("|", 1)
        else:
            name, url = chunk, chunk
        url = url.strip()
        if url.lower().startswith(("http://", "https://")):
            out.append({"name": name.strip() or url, "url": url})
    return out


def curated_feeds_file() -> str:
    """Path of the curated feed list (env override or data/cti_feeds.txt)."""
    for var in ("MANTIS_CTI_FEEDS_FILE", "IOCINTEL_CTI_FEEDS_FILE"):
        raw = os.environ.get(var, "").strip()
        if raw:
            return raw
    return os.path.join(DATA_DIR, "cti_feeds.txt")


def _pretty_name(url: str) -> str:
    """Readable source name derived from a feed URL (first-sync placeholder;
    replaced by the real feed title once the feed is polled)."""
    try:
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
    except ValueError:
        host = ""
    host = host[4:] if host.startswith("www.") else host
    parts = [p for p in host.split(".") if p]
    core = ""
    if parts:
        core = parts[-2] if len(parts) >= 2 and parts[-1] in (
            "com", "org", "net", "io", "eu", "de", "co", "gov", "edu") else parts[0]
    label = re.sub(r"[^a-z0-9]+", " ", core).strip().title() or url
    return label


def curated_feeds() -> list:
    """Parse the curated feed file: [{'name', 'url', 'category'}].

    '## Heading' lines set the category for following URLs; '#' lines and
    blanks are ignored. Missing file -> [] (other sources still work).
    """
    path = curated_feeds_file()
    out = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return out
    category = ""
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("##"):
            category = stripped.lstrip("#").strip()
            continue
        if stripped.startswith("#"):
            continue
        url = stripped.split()[0]
        if not url.lower().startswith(("http://", "https://")):
            continue
        out.append({"name": _pretty_name(url), "url": url, "category": category})
    return out


def _env_int(name: str, default: int) -> int:
    for var in (f"MANTIS_{name}", f"IOCINTEL_{name}"):
        raw = os.environ.get(var, "").strip()
        if raw:
            try:
                return int(raw)
            except ValueError:
                continue
    return default


CATALOG_TTL_SECONDS = _env_int("CTI_CATALOG_TTL_S", 7 * 24 * 3600)
SYNC_INTERVAL_SECONDS = _env_int("CTI_SYNC_INTERVAL_S", 3 * 3600)
FEED_TIMEOUT_SECONDS = _env_int("CTI_FEED_TIMEOUT_S", 20)
ARTICLE_TIMEOUT_SECONDS = _env_int("CTI_ARTICLE_TIMEOUT_S", 15)
ARTICLE_MAX_BYTES = _env_int("CTI_ARTICLE_MAX_BYTES", 2 * 1024 * 1024)
MAX_NEW_PER_FEED = _env_int("CTI_MAX_NEW_PER_FEED", 25)
SYNC_WORKERS = _env_int("CTI_SYNC_WORKERS", 4)
