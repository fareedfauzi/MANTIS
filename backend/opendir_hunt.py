"""
Open Directory Hunting engine for MANTIS.

Pipeline:  provider discovery -> URL normalization -> SSRF-checked verification
           -> bounded recursive enumeration (metadata only) -> interest scoring
           -> SQLite persistence.

Nothing here downloads file bodies, executes content, or port-scans. Provider
results are treated as candidate URLs only until a live HTTP response confirms
a directory listing.
"""

from __future__ import annotations

import base64
import concurrent.futures as cf
import datetime as dt
import html as html_lib
import ipaddress
import json
import os
import posixpath
import re
import socket
import sqlite3
import threading
import time
import urllib.parse
import uuid
from html.parser import HTMLParser  # noqa: F401  (kept for callers that extend parsing)
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
DB_PATH = os.environ.get("MANTIS_OPENDIR_DB") or os.path.join(DATA_DIR, "opendir_hunt.db")

USER_AGENT = "MANTIS-OpenDirHunt/1.0 (+defensive research; metadata-only)"
ALLOWED_SCHEMES = ("http", "https")
DEFAULT_PORTS = {"http": 80, "https": 443}

STATUS_DISCOVERED = "discovered"
STATUS_VERIFIED = "verified"
STATUS_REJECTED = "rejected"
STATUS_INACCESSIBLE = "inaccessible"
STATUS_ERROR = "error"

JOB_QUEUED, JOB_RUNNING, JOB_COMPLETED = "queued", "running", "completed"
JOB_FAILED, JOB_CANCELLED, JOB_INTERRUPTED = "failed", "cancelled", "interrupted"
JOB_ACTIVE = (JOB_QUEUED, JOB_RUNNING)
JOB_STAGES = [
    "queued", "provider_discovery", "url_normalization", "directory_verification",
    "file_enumeration", "interest_scoring", "database_persistence", "completed",
]


class UnsafeTarget(ValueError):
    """Raised when a URL or resolved address is not allowed to be fetched."""


class ProviderError(Exception):
    """Provider-specific failure. kind is one of the PROVIDER_ERROR_KINDS."""

    def __init__(self, kind: str, message: str, provider: str = ""):
        super().__init__(message)
        self.kind = kind
        self.message = message
        self.provider = provider


PROVIDER_ERROR_KINDS = (
    "missing_key", "invalid_key", "quota", "timeout", "malformed",
    "unsupported_query", "missing_config", "http_error",
)


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _iso_in(seconds: int) -> str:
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

_MIGRATIONS: List[Tuple[int, str]] = [
    (1, """
    CREATE TABLE opendir_directories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL UNIQUE,
        host TEXT NOT NULL,
        ip TEXT,
        port INTEGER NOT NULL,
        scheme TEXT NOT NULL,
        path TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'discovered',
        http_status INTEGER,
        content_type TEXT,
        server TEXT,
        title TEXT,
        listing_type TEXT,
        listing_confidence INTEGER,
        file_count INTEGER NOT NULL DEFAULT 0,
        subdir_count INTEGER NOT NULL DEFAULT 0,
        interest_score INTEGER NOT NULL DEFAULT 0,
        interest_class TEXT,
        interest_reasons TEXT NOT NULL DEFAULT '[]',
        override TEXT,
        override_note TEXT,
        country TEXT,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        last_checked TEXT,
        verified_at TEXT,
        error TEXT
    );
    CREATE INDEX idx_opendir_dir_status ON opendir_directories(status);
    CREATE INDEX idx_opendir_dir_score ON opendir_directories(interest_score);
    CREATE INDEX idx_opendir_dir_host ON opendir_directories(host);

    CREATE TABLE opendir_discovery_sources (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        directory_id INTEGER NOT NULL REFERENCES opendir_directories(id) ON DELETE CASCADE,
        provider TEXT NOT NULL,
        query TEXT NOT NULL,
        source_kind TEXT NOT NULL,
        job_id TEXT,
        discovered_at TEXT NOT NULL,
        UNIQUE(directory_id, provider, query, source_kind)
    );

    CREATE TABLE opendir_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        directory_id INTEGER NOT NULL REFERENCES opendir_directories(id) ON DELETE CASCADE,
        url TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        parent_url TEXT NOT NULL,
        extension TEXT NOT NULL DEFAULT '',
        size INTEGER,
        modified_at TEXT,
        is_dir INTEGER NOT NULL DEFAULT 0,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        removed_at TEXT
    );
    CREATE INDEX idx_opendir_files_dir ON opendir_files(directory_id);
    CREATE INDEX idx_opendir_files_name ON opendir_files(name);
    CREATE INDEX idx_opendir_files_ext ON opendir_files(extension);
    CREATE INDEX idx_opendir_files_seen ON opendir_files(last_seen);

    CREATE TABLE opendir_hunting_jobs (
        id TEXT PRIMARY KEY,
        mode TEXT NOT NULL,
        query TEXT NOT NULL,
        providers TEXT NOT NULL DEFAULT '[]',
        options TEXT NOT NULL DEFAULT '{}',
        dedupe_key TEXT NOT NULL,
        status TEXT NOT NULL,
        stage TEXT NOT NULL DEFAULT 'queued',
        cancel_requested INTEGER NOT NULL DEFAULT 0,
        counters TEXT NOT NULL DEFAULT '{}',
        created_by TEXT,
        created_at TEXT NOT NULL,
        started_at TEXT,
        completed_at TEXT,
        error TEXT
    );
    CREATE INDEX idx_opendir_jobs_status ON opendir_hunting_jobs(status);
    CREATE INDEX idx_opendir_jobs_dedupe ON opendir_hunting_jobs(dedupe_key);

    CREATE TABLE opendir_job_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id TEXT NOT NULL REFERENCES opendir_hunting_jobs(id) ON DELETE CASCADE,
        ts TEXT NOT NULL,
        level TEXT NOT NULL,
        stage TEXT,
        message TEXT NOT NULL
    );
    CREATE INDEX idx_opendir_events_job ON opendir_job_events(job_id);

    CREATE TABLE opendir_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    """),
    (2, """
    CREATE TABLE opendir_directory_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        directory_id INTEGER NOT NULL REFERENCES opendir_directories(id) ON DELETE CASCADE,
        job_id TEXT,
        taken_at TEXT NOT NULL,
        status TEXT NOT NULL,
        file_count INTEGER NOT NULL DEFAULT 0,
        subdir_count INTEGER NOT NULL DEFAULT 0,
        entries TEXT NOT NULL DEFAULT '[]'
    );
    CREATE INDEX idx_opendir_snap_dir ON opendir_directory_snapshots(directory_id, taken_at);

    CREATE TABLE opendir_watchlist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        directory_id INTEGER NOT NULL UNIQUE REFERENCES opendir_directories(id) ON DELETE CASCADE,
        enabled INTEGER NOT NULL DEFAULT 1,
        interval_minutes INTEGER NOT NULL DEFAULT 1440,
        last_scan_at TEXT,
        next_scan_at TEXT,
        monitoring_status TEXT NOT NULL DEFAULT 'pending',
        notes TEXT NOT NULL DEFAULT '',
        created_by TEXT,
        created_at TEXT NOT NULL
    );

    CREATE TABLE opendir_change_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        directory_id INTEGER NOT NULL REFERENCES opendir_directories(id) ON DELETE CASCADE,
        detected_at TEXT NOT NULL,
        change_type TEXT NOT NULL,
        subject TEXT NOT NULL,
        old_value TEXT,
        new_value TEXT
    );
    CREATE INDEX idx_opendir_changes_dir ON opendir_change_events(directory_id, detected_at);
    """),
]

_db_lock = threading.RLock()
_db_ready = False


def _connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def init_db() -> None:
    """Apply numbered migrations once. Safe to call repeatedly."""
    global _db_ready
    with _db_lock:
        if _db_ready:
            return
        conn = _connect()
        try:
            conn.execute("CREATE TABLE IF NOT EXISTS opendir_schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
            applied = {r["version"] for r in conn.execute("SELECT version FROM opendir_schema_migrations")}
            for version, sql in _MIGRATIONS:
                if version in applied:
                    continue
                conn.executescript("BEGIN;" + sql + "COMMIT;")
                conn.execute("INSERT INTO opendir_schema_migrations(version, applied_at) VALUES (?, ?)", (version, utcnow()))
                conn.commit()
            _recover_interrupted_jobs(conn)
            conn.commit()
        finally:
            conn.close()
        _db_ready = True


def _recover_interrupted_jobs(conn: sqlite3.Connection) -> None:
    """Jobs left queued/running by a previous process cannot resume; mark them."""
    ts = utcnow()
    rows = conn.execute("SELECT id FROM opendir_hunting_jobs WHERE status IN (?, ?)", JOB_ACTIVE).fetchall()
    for r in rows:
        conn.execute("UPDATE opendir_hunting_jobs SET status=?, completed_at=?, error=? WHERE id=?",
                     (JOB_INTERRUPTED, ts, "Application restarted while job was active", r["id"]))
        conn.execute("INSERT INTO opendir_job_events(job_id, ts, level, stage, message) VALUES (?,?,?,?,?)",
                     (r["id"], ts, "warning", None, "Job interrupted by application restart"))


def db() -> sqlite3.Connection:
    init_db()
    return _connect()


# ---------------------------------------------------------------------------
# URL normalization and destination safety
# ---------------------------------------------------------------------------

_BLOCKED_HOSTNAMES = {"localhost", "metadata", "metadata.google.internal", "instance-data", "metadata.azure.internal"}
_EXTRA_BLOCKED_NETS = [
    ipaddress.ip_network("100.64.0.0/10"),   # carrier-grade NAT
    ipaddress.ip_network("198.18.0.0/15"),   # benchmarking
    ipaddress.ip_network("192.0.0.0/24"),    # IETF protocol assignments
    ipaddress.ip_network("169.254.169.254/32"),  # cloud metadata
    ipaddress.ip_network("fd00:ec2::254/128"),   # AWS IPv6 metadata
]


def _ip_blocked(ip: ipaddress._BaseAddress) -> Optional[str]:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback:
        return "loopback"
    if ip.is_private:
        return "private"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_reserved:
        return "reserved"
    if ip.is_unspecified:
        return "unspecified"
    for net in _EXTRA_BLOCKED_NETS:
        if ip in net:
            return "metadata/reserved range"
    return None


def normalize_url(raw: str, base: Optional[str] = None) -> Dict[str, Any]:
    """Return canonical components for an http(s) URL. Raises UnsafeTarget on bad schemes."""
    text = (raw or "").strip()
    if not text or any(ord(c) < 32 for c in text):
        raise UnsafeTarget("Empty or control-character URL")
    if base:
        text = urllib.parse.urljoin(base, text)
    parts = urllib.parse.urlsplit(text)
    scheme = (parts.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UnsafeTarget(f"Unsupported URL scheme: {scheme or '(none)'}")
    host = (parts.hostname or "").strip().rstrip(".").lower()
    if not host:
        raise UnsafeTarget("URL has no host")
    try:
        port = parts.port or DEFAULT_PORTS[scheme]
    except ValueError as exc:
        raise UnsafeTarget(f"Invalid port: {exc}")
    if not (1 <= port <= 65535):
        raise UnsafeTarget("Port out of range")
    if parts.username or parts.password:
        raise UnsafeTarget("Credentials in URL are not allowed")

    path = urllib.parse.unquote(parts.path or "/")
    if not path.startswith("/"):
        path = "/" + path
    trailing = path.endswith("/")
    segments: List[str] = []
    for seg in path.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if segments:
                segments.pop()
            continue
        segments.append(seg)
    norm = "/" + "/".join(segments)
    if trailing and norm != "/":
        norm += "/"
    quoted = urllib.parse.quote(norm, safe="/:@!$&'()*+,;=-._~")
    ip_host = f"[{host}]" if ":" in host else host
    netloc = ip_host if port == DEFAULT_PORTS[scheme] else f"{ip_host}:{port}"
    canonical = f"{scheme}://{netloc}{quoted}"
    return {
        "url": canonical,
        "scheme": scheme,
        "host": host,
        "port": port,
        "path": quoted,
        "is_dir": quoted.endswith("/"),
    }


def dir_url(raw: str, base: Optional[str] = None) -> str:
    """Canonical directory URL (always trailing slash, no query/fragment)."""
    info = normalize_url(raw, base)
    url = info["url"]
    if not info["is_dir"]:
        url += "/"
    return url


def resolve_destination(host: str, port: int, allow_private: bool = False) -> List[str]:
    """Resolve host and refuse if any address is non-public. Returns resolved IPs."""
    if host in _BLOCKED_HOSTNAMES or host.endswith(".internal") or host.endswith(".local"):
        if not allow_private:
            raise UnsafeTarget(f"Blocked hostname: {host}")
    try:
        literal = ipaddress.ip_address(host)
        addrs = [str(literal)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise UnsafeTarget(f"DNS resolution failed for {host}: {exc}")
        addrs = sorted({info[4][0] for info in infos})
    if not addrs:
        raise UnsafeTarget(f"No addresses for {host}")
    if not allow_private:
        for a in addrs:
            reason = _ip_blocked(ipaddress.ip_address(a))
            if reason:
                raise UnsafeTarget(f"Destination {host} resolves to {reason} address {a}")
    return addrs


class HostRateLimiter:
    """Minimum interval between requests to the same host (process-wide)."""

    def __init__(self, min_interval: float):
        self.min_interval = max(0.0, float(min_interval))
        self._last: Dict[str, float] = {}
        self._lock = threading.Lock()

    def wait(self, host: str) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            due = self._last.get(host, 0.0) + self.min_interval
            start = max(now, due)
            self._last[host] = start
        delay = start - now
        if delay > 0:
            time.sleep(delay)


_GLOBAL_CONCURRENCY = threading.BoundedSemaphore(int(os.environ.get("MANTIS_OPENDIR_MAX_CONCURRENT_FETCHES", "8")))


def safe_get(url: str, *, allow_private: bool = False, timeout: float = 15.0, max_bytes: int = 2_000_000,
             max_redirects: int = 3, rate_limiter: Optional[HostRateLimiter] = None,
             session: Optional[requests.Session] = None) -> Dict[str, Any]:
    """GET a URL with per-hop SSRF checks, manual redirects and a body-size cap.

    Redirects are not followed automatically. Each Location is normalized and
    its destination re-validated before the next request.
    """
    sess = session or requests.Session()
    sess.trust_env = False  # never route through env proxies: they would bypass the address checks
    current = url
    hops: List[str] = []
    for _ in range(max_redirects + 1):
        info = normalize_url(current)
        resolve_destination(info["host"], info["port"], allow_private=allow_private)
        if rate_limiter is not None:
            rate_limiter.wait(info["host"])
        with _GLOBAL_CONCURRENCY:
            try:
                resp = sess.get(info["url"], allow_redirects=False, stream=True, timeout=(min(timeout, 8), timeout),
                                headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.5"})
            except requests.Timeout:
                raise TimeoutError(f"Timed out fetching {info['url']}")
            except requests.RequestException as exc:
                raise ConnectionError(f"Request failed for {info['url']}: {type(exc).__name__}")
            try:
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if not location:
                        return {"status": resp.status_code, "url": info["url"], "headers": {}, "text": "", "truncated": False, "redirects": hops}
                    hops.append(info["url"])
                    current = urllib.parse.urljoin(info["url"], location)
                    continue
                body = bytearray()
                truncated = False
                for chunk in resp.iter_content(chunk_size=65536):
                    if not chunk:
                        continue
                    body.extend(chunk)
                    if len(body) > max_bytes:
                        truncated = True
                        del body[max_bytes:]
                        break
                enc = resp.encoding or "utf-8"
                try:
                    text = body.decode(enc, errors="replace")
                except LookupError:
                    text = body.decode("utf-8", errors="replace")
                return {
                    "status": resp.status_code,
                    "url": info["url"],
                    "headers": {
                        "content-type": resp.headers.get("Content-Type", ""),
                        "server": resp.headers.get("Server", ""),
                    },
                    "text": text,
                    "truncated": truncated,
                    "redirects": hops,
                }
            finally:
                resp.close()
    raise UnsafeTarget(f"Too many redirects starting at {url}")


# ---------------------------------------------------------------------------
# Directory listing detection
# ---------------------------------------------------------------------------

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_HEADING_RE = re.compile(r"<h[1-2][^>]*>(.*?)</h[1-2]>", re.I | re.S)
_SORT_LINK_RE = re.compile(r"href=[\"']\?C=[NMSD];O=[AD][\"']", re.I)
_ANCHOR_RE = re.compile(r"<a\s[^>]*?href\s*=\s*([\"'])(.*?)\1[^>]*>(.*?)</a>", re.I | re.S)
_TAG_RE = re.compile(r"<[^>]+>")


def _text(fragment: str) -> str:
    return re.sub(r"\s+", " ", html_lib.unescape(_TAG_RE.sub(" ", fragment))).strip()


def extract_title(page: str) -> str:
    m = _TITLE_RE.search(page or "")
    return _text(m.group(1))[:300] if m else ""


def detect_listing(page: str, status: int, server: str = "", entry_count: int = 0) -> Dict[str, Any]:
    """Confidence-based open-directory detector. Each signal contributes once.

    A page is a listing at confidence >= 50. Mentioning "Index of" in body text
    alone (an ordinary article, a changelog) does not reach the threshold.
    """
    result = {"is_listing": False, "confidence": 0, "listing_type": None, "title": "", "signals": []}
    if status != 200 or not page:
        return result
    low = page.lower()
    title = extract_title(page)
    tlow = title.lower()
    heading = _text(_HEADING_RE.search(page).group(1)).lower() if _HEADING_RE.search(page) else ""
    signals: List[Tuple[str, int]] = []

    if re.match(r"^\s*index of\b", tlow):
        signals.append(("title_index_of", 30))
    elif "directory listing" in tlow or "directory browsing" in tlow:
        signals.append(("title_directory_listing", 30))
    if heading.startswith("index of") or heading.startswith("directory listing"):
        signals.append(("heading_listing", 20))
    if "parent directory" in low:
        signals.append(("parent_directory_link", 25))
    if _SORT_LINK_RE.search(page):
        signals.append(("apache_sort_links", 25))
    if '<pre><a href="../">' in low or "<pre><a href='../'>" in low:
        signals.append(("nginx_pre_listing", 25))
    if re.search(r">\s*name\s*<", low) and re.search(r"last modified|date modified", low):
        signals.append(("column_headers", 15))
    if entry_count >= 2:
        signals.append(("multiple_entry_links", 10))

    total = min(100, sum(w for _, w in signals))
    structural = {"parent_directory_link", "apache_sort_links", "nginx_pre_listing"}
    has_structure = entry_count >= 1 or any(s in structural for s, _ in signals)
    is_listing = total >= 50 and has_structure

    listing_type = None
    if is_listing:
        if "directory listing for" in low:
            listing_type = "python-http-server"
        elif "lighttpd" in low or 'class="n"' in low or "lighttpd" in (server or "").lower():
            listing_type = "lighttpd"
        elif "[to parent directory]" in low and ("microsoft-iis" in (server or "").lower() or "<dir>" in low or "iis" in low):
            listing_type = "iis"
        elif _SORT_LINK_RE.search(page) or 'alt="[dir]"' in low or "apache" in (server or "").lower():
            listing_type = "apache"
        elif '<pre><a href="../">' in low or '<pre><a href=\'../\'>' in low:
            listing_type = "nginx"
        elif "[to parent directory]" in low:
            listing_type = "iis"
        else:
            listing_type = "custom"

    result.update({
        "is_listing": is_listing,
        "confidence": total,
        "listing_type": listing_type,
        "title": title,
        "signals": [s for s, _ in signals],
    })
    return result


# ---------------------------------------------------------------------------
# Entry parsing (files and subdirectories)
# ---------------------------------------------------------------------------

_DATE_PATTERNS = [
    (re.compile(r"\b(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?"), "%Y-%m-%d %H:%M:%S"),          # Apache, Python-ish
    (re.compile(r"\b(\d{2})-([A-Za-z]{3})-(\d{4}) (\d{2}):(\d{2})"), "%d-%b-%Y %H:%M"),                        # nginx
    (re.compile(r"\b(\d{1,2}/\d{1,2}/\d{4})\s+(\d{1,2}:\d{2}\s*[AaPp][Mm])"), "%m/%d/%Y %I:%M %p"),           # IIS
    (re.compile(r"\b(\d{4})-([A-Za-z]{3})-(\d{2}) (\d{2}):(\d{2}):(\d{2})"), "%Y-%b-%d %H:%M:%S"),             # lighttpd
]
_SIZE_RE = re.compile(r"^\s*(<dir>|\[dir\]|-|\d[\d,]*(?:\.\d+)?\s*(?:[KMGT]i?B?|B)?)\b", re.I)


def parse_timestamp(text: str) -> Optional[str]:
    """Parse a listing timestamp to ISO-8601 (UTC assumed: listing servers rarely state a zone)."""
    if not text:
        return None
    for rx, fmt in _DATE_PATTERNS:
        m = rx.search(text)
        if not m:
            continue
        raw = m.group(0)
        raw = re.sub(r"\s+", " ", raw).strip()
        for candidate in (raw, raw.replace("  ", " ")):
            for f in (fmt, fmt.replace(":%S", "")):
                try:
                    return dt.datetime.strptime(candidate, f).strftime("%Y-%m-%dT%H:%M:%SZ")
                except ValueError:
                    continue
    return None


_SIZE_TOKEN_RE = re.compile(r"(<dir>|\[dir\]|(?<![\w.])-(?![\w])|(?<![\w.])\d[\d,]*(?:\.\d+)?\s*(?:[KMGT]i?B?|B)?(?![\w]))", re.I)


def _strip_timestamps(text: str) -> str:
    out = text or ""
    for rx, _ in _DATE_PATTERNS:
        out = rx.sub(" ", out)
    return out


def parse_size(text: str) -> Optional[int]:
    """Parse the size column ('1.5K', '12,345', '-', '<dir>') from a listing row.

    Timestamps are removed first so the year in a date is never read as a size.
    Directories return None.
    """
    tokens = _SIZE_TOKEN_RE.findall(_strip_timestamps(text or ""))
    if not tokens:
        return None
    token = tokens[-1].strip().lower()
    if token in ("-", "<dir>", "[dir]"):
        return None
    mult = {"k": 1024, "m": 1024 ** 2, "g": 1024 ** 3, "t": 1024 ** 4}
    num = re.match(r"([\d,]*\.?\d+)", token.replace(",", ""))
    if not num:
        return None
    value = float(num.group(1))
    unit = re.search(r"([kmgt])", token)
    if unit:
        value *= mult[unit.group(1)]
    return int(value)


def parse_entries(page: str, base_url: str) -> List[Dict[str, Any]]:
    """Extract child entries of a listing. Parent, sort, anchor and external links are skipped."""
    base = normalize_url(base_url)
    base_path = base["path"] if base["path"].endswith("/") else base["path"] + "/"
    entries: List[Dict[str, Any]] = []
    seen: set = set()
    matches = list(_ANCHOR_RE.finditer(page or ""))
    for i, m in enumerate(matches):
        href = html_lib.unescape(m.group(2)).strip()
        if not href or href.startswith(("?", "#", "mailto:", "javascript:", "data:")):
            continue
        if "?C=" in href or "?c=" in href:
            continue
        if href.startswith(("../", "..")) or href in ("/", "./"):
            continue
        label = _text(m.group(3)).lower()
        if label in ("parent directory", "[to parent directory]", "../", "..", "parent"):
            continue
        try:
            child = normalize_url(href, base=base_url)
        except UnsafeTarget:
            continue
        if child["host"] != base["host"] or child["port"] != base["port"] or child["scheme"] != base["scheme"]:
            continue
        if not child["path"].startswith(base_path) or child["path"] == base_path:
            continue
        # Context: text between this anchor and the next anchor or row boundary.
        end_limit = matches[i + 1].start() if i + 1 < len(matches) else len(page)
        boundary = re.search(r"<tr|<li|</pre>|<br", page[m.end():end_limit], re.I)
        context_raw = page[m.end(): m.end() + boundary.start()] if boundary else page[m.end():end_limit]
        context = _text(context_raw)
        is_dir = child["is_dir"] or "<dir>" in context_raw.lower() or "[dir]" in context_raw.lower()
        url = child["url"] + ("/" if is_dir and not child["url"].endswith("/") else "")
        if url in seen:
            continue
        seen.add(url)
        name = urllib.parse.unquote(child["path"].rstrip("/").rsplit("/", 1)[-1]) or child["path"]
        entries.append({
            "url": url,
            "name": name,
            "is_dir": bool(is_dir),
            "size": None if is_dir else parse_size(context),
            "modified_at": parse_timestamp(context),
        })
    return entries


# ---------------------------------------------------------------------------
# File categorisation and scoring
# ---------------------------------------------------------------------------

FILE_CATEGORIES: Dict[str, List[str]] = {
    "executable": [".exe", ".dll", ".sys", ".elf", ".so", ".bin", ".msi"],
    "script": [".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".sh", ".py", ".php", ".aspx", ".jsp"],
    "archive": [".zip", ".rar", ".7z", ".tar", ".gz", ".tgz"],
    "config_data": [".json", ".xml", ".ini", ".cfg", ".conf", ".dat", ".db", ".sqlite"],
}
SUSPICIOUS_NAME_PATTERNS: List[str] = [
    "loader", "payload", "shell", "webshell", "reverse", "stealer", "inject",
    "dropper", "backdoor", "crypt", "miner",
]
SERVER_SIDE_EXTS = {".php", ".aspx", ".jsp"}

DEFAULT_SCORING_RULES: Dict[str, Any] = {
    "weights": {
        "suspicious_filename": 15,
        "executable_and_script": 20,
        "multiple_suspicious_filenames": 15,
        "executable_and_config": 10,
        "suspicious_directory_name": 10,
        "archive_and_executable": 10,
        "recent_suspicious_inventory": 10,
        "server_script_with_binaries": 10,
    },
    "thresholds": {"high": 70, "medium": 40},
    "categories": FILE_CATEGORIES,
    "name_patterns": SUSPICIOUS_NAME_PATTERNS,
    "recent_window_days": 30,
}


def get_scoring_rules() -> Dict[str, Any]:
    with db() as conn:
        row = conn.execute("SELECT value FROM opendir_settings WHERE key='scoring_rules'").fetchone()
    if not row:
        return json.loads(json.dumps(DEFAULT_SCORING_RULES))
    stored = json.loads(row["value"])
    merged = json.loads(json.dumps(DEFAULT_SCORING_RULES))
    for k, v in stored.items():
        if isinstance(v, dict) and isinstance(merged.get(k), dict):
            merged[k].update(v)
        else:
            merged[k] = v
    return merged


def _extension(name: str) -> str:
    _, ext = posixpath.splitext(name.lower())
    return ext


def _category(ext: str, rules: Dict[str, Any]) -> Optional[str]:
    for cat, exts in rules["categories"].items():
        if ext in exts:
            return cat
    return None


def score_directory(files: List[Dict[str, Any]], dir_name: str, rules: Optional[Dict[str, Any]] = None,
                    now: Optional[dt.datetime] = None) -> Dict[str, Any]:
    """Explainable 0-100 interest score. Each rule counts once; total is capped at 100.

    `files` items need: name, is_dir, modified_at (only used if present).
    Discovery time is never used as an upload time.
    """
    rules = rules or DEFAULT_SCORING_RULES
    w = rules["weights"]
    pats = [p.lower() for p in rules["name_patterns"]]
    now = now or dt.datetime.now(dt.timezone.utc)
    real = [f for f in files if not f.get("is_dir")]
    cats: Dict[str, List[Dict[str, Any]]] = {}
    suspicious: List[Dict[str, Any]] = []
    for f in real:
        ext = _extension(f["name"])
        cat = _category(ext, rules)
        if cat:
            cats.setdefault(cat, []).append(f)
        lname = f["name"].lower()
        if any(p in lname for p in pats):
            suspicious.append(f)

    reasons: List[Dict[str, Any]] = []

    def add(rule: str, label: str):
        reasons.append({"rule": rule, "points": int(w[rule]), "label": label})

    if suspicious:
        add("suspicious_filename", f"Suspicious filename pattern: {suspicious[0]['name']}")
    if cats.get("executable") and cats.get("script"):
        add("executable_and_script", "Executable and script in the same directory")
    if len(suspicious) >= 2:
        add("multiple_suspicious_filenames", f"{len(suspicious)} files match suspicious name patterns")
    if cats.get("executable") and cats.get("config_data"):
        add("executable_and_config", "Executable and configuration/data file in the same directory")
    if any(p in dir_name.lower() for p in pats):
        add("suspicious_directory_name", f"Suspicious directory name: {dir_name}")
    if cats.get("archive") and cats.get("executable"):
        add("archive_and_executable", "Archive and executable in the same directory")
    recent = []
    cutoff = now - dt.timedelta(days=int(rules.get("recent_window_days", 30)))
    for f in suspicious:
        ts = f.get("modified_at")
        if not ts:
            continue
        try:
            when = dt.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
        except ValueError:
            continue
        if when >= cutoff:
            recent.append(f)
    if recent:
        add("recent_suspicious_inventory", f"{len(recent)} suspicious file(s) with a listed modification time in the last {rules.get('recent_window_days', 30)} days")
    server_side = cats.get("script") and any(_extension(f["name"]) in SERVER_SIDE_EXTS for f in cats["script"])
    if server_side and cats.get("executable"):
        add("server_script_with_binaries", "Server-side script mixed with binary payloads")

    total = min(100, sum(r["points"] for r in reasons))
    th = rules["thresholds"]
    if total >= th["high"]:
        cls = "high"
    elif total >= th["medium"]:
        cls = "medium"
    else:
        cls = "low"
    return {"score": total, "classification": cls, "reasons": reasons,
            "counts": {"files": len(real), "suspicious": len(suspicious), "categories": {k: len(v) for k, v in cats.items()}}}


def effective_classification(row: Dict[str, Any]) -> str:
    override = row.get("override")
    if override == "false_positive":
        return "dismissed"
    if override == "confirmed_interest":
        return "high"
    return row.get("interest_class") or "low"


# ---------------------------------------------------------------------------
# Provider adapters
# ---------------------------------------------------------------------------

# Neutral listing patterns; each adapter translates them to its own syntax.
# None means the provider cannot express the pattern (documented, not guessed).
NEUTRAL_PATTERNS: Dict[str, Dict[str, Any]] = {
    "title_index_of": {"title": "Index of /"},
    "title_directory_listing": {"title": "Directory listing for /"},
    "body_parent_directory": {"body": "Parent Directory"},
    "body_name_and_modified": {"body": "Name", "and_body": "Last modified"},
}


def _fofa_expr(pattern: str) -> Optional[str]:
    spec = NEUTRAL_PATTERNS.get(pattern)
    if not spec:
        return pattern  # raw provider syntax passed through unchanged
    if "title" in spec:
        return f'title="{spec["title"]}"'
    if "and_body" in spec:
        return f'body="{spec["body"]}" && body="{spec["and_body"]}"'
    return f'body="{spec["body"]}"'


def _shodan_expr(pattern: str) -> Optional[str]:
    spec = NEUTRAL_PATTERNS.get(pattern)
    if not spec:
        return pattern
    if "title" in spec:
        return f'http.title:"{spec["title"]}"'
    if "and_body" in spec:
        return f'http.html:"{spec["body"]}" http.html:"{spec["and_body"]}"'
    return f'http.html:"{spec["body"]}"'


def _censys_expr(pattern: str) -> Optional[str]:
    spec = NEUTRAL_PATTERNS.get(pattern)
    if not spec:
        return pattern
    if "title" in spec:
        return f'services.http.response.html_title: "{spec["title"]}"'
    if "and_body" in spec:
        return (f'services.http.response.body: "{spec["body"]}" and '
                f'services.http.response.body: "{spec["and_body"]}"')
    return f'services.http.response.body: "{spec["body"]}"'


def _zoomeye_expr(pattern: str) -> Optional[str]:
    spec = NEUTRAL_PATTERNS.get(pattern)
    if not spec:
        return pattern
    if "and_body" in spec:
        return None  # boolean operators are not documented for ZoomEye; do not guess
    if "title" in spec:
        return f'title="{spec["title"]}"'
    return f'body="{spec["body"]}"'


class ProviderAdapter:
    name = ""
    label = ""
    supports_country_filter = False
    max_page_size = 100
    translate = staticmethod(lambda pattern: None)

    def __init__(self, api_key: str = "", timeout: float = 20.0):
        self.api_key = (api_key or "").strip()
        self.timeout = timeout

    def translate_query(self, query: str) -> str:
        """`query` is a neutral pattern name, or raw provider syntax for keyword hunts."""
        expr = self.translate(query)
        if expr is None:
            raise ProviderError("unsupported_query", f"{self.label} cannot express pattern '{query}'", self.name)
        return expr

    def search(self, query: str, page: int = 1, size: int = 50, country: str = "") -> Dict[str, Any]:
        raise NotImplementedError

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        try:
            resp = requests.request(method, url, timeout=self.timeout, **kwargs)
        except requests.Timeout:
            raise ProviderError("timeout", f"{self.label} request timed out", self.name)
        except requests.RequestException as exc:
            raise ProviderError("http_error", f"{self.label} request failed: {type(exc).__name__}", self.name)
        if resp.status_code in (401, 403):
            raise ProviderError("invalid_key", f"{self.label} rejected the API key (HTTP {resp.status_code})", self.name)
        if resp.status_code == 402 or resp.status_code == 429:
            raise ProviderError("quota", f"{self.label} quota or rate limit reached (HTTP {resp.status_code})", self.name)
        if resp.status_code >= 400:
            raise ProviderError("http_error", f"{self.label} returned HTTP {resp.status_code}", self.name)
        return resp

    def _json(self, resp: requests.Response) -> Dict[str, Any]:
        try:
            data = resp.json()
        except ValueError:
            raise ProviderError("malformed", f"{self.label} returned non-JSON content", self.name)
        if not isinstance(data, dict):
            raise ProviderError("malformed", f"{self.label} returned an unexpected payload", self.name)
        return data


def _host_port_url(host: str, port: Any, protocol: str = "") -> Optional[str]:
    try:
        port_i = int(port)
    except (TypeError, ValueError):
        return None
    scheme = "https" if (protocol or "").lower() in ("https", "ssl", "tls") or port_i == 443 else "http"
    if not host:
        return None
    netloc = host if (scheme == "http" and port_i == 80) or (scheme == "https" and port_i == 443) else f"{host}:{port_i}"
    return f"{scheme}://{netloc}/"


class FofaAdapter(ProviderAdapter):
    name, label = "fofa", "FOFA"
    translate = staticmethod(_fofa_expr)
    max_page_size = 100
    supports_country_filter = True
    env_keys = ("FOFA_API_KEY", "MANTIS_FOFA_KEY", "IOCINTEL_FOFA_KEY", "FOFA_KEY")

    def search(self, query: str, page: int = 1, size: int = 50, country: str = "") -> Dict[str, Any]:
        key = self.api_key or next((os.environ.get(k, "") for k in self.env_keys if os.environ.get(k)), "")
        if not key:
            raise ProviderError("missing_key", "FOFA API key not configured", self.name)
        expr = self.translate_query(query)
        if country:
            expr = f'{expr} && country="{country}"'
        params = {
            "key": key,
            "qbase64": base64.b64encode(expr.encode("utf-8")).decode("ascii"),
            "fields": "link,host,ip,port,protocol,title,country,country_name,lastupdatetime",
            "page": max(1, int(page)),
            "size": max(1, min(int(size), self.max_page_size)),
            "full": "false",
        }
        data = self._json(self._request("GET", "https://fofa.info/api/v1/search/all", params=params,
                                        headers={"User-Agent": USER_AGENT}))
        if data.get("error"):
            msg = str(data.get("errmsg") or "FOFA error")
            kind = "invalid_key" if "key" in msg.lower() else "http_error"
            raise ProviderError(kind, msg[:200].replace(key, "[redacted]"), self.name)
        rows = data.get("results")
        fields = data.get("fields") or []
        if not isinstance(rows, list) or not fields:
            raise ProviderError("malformed", "FOFA response is missing results or fields", self.name)
        results = []
        for row in rows:
            if not isinstance(row, list):
                continue
            rec = dict(zip(fields, row))
            url = rec.get("link") or _host_port_url(rec.get("host") or rec.get("ip") or "", rec.get("port"), rec.get("protocol") or "")
            if url:
                results.append({"url": url, "host": rec.get("host") or "", "ip": rec.get("ip") or "",
                                "port": rec.get("port"), "title": rec.get("title") or "",
                                "country": rec.get("country") or ""})
        return {"results": results, "total": int(data.get("size") or 0), "page": page, "has_more": len(rows) >= size}


class ZoomEyeAdapter(ProviderAdapter):
    name, label = "zoomeye", "ZoomEye"
    translate = staticmethod(_zoomeye_expr)
    max_page_size = 100
    env_keys = ("ZOOMEYE_API_KEY", "MANTIS_ZOOMEYE_API_KEY", "IOCINTEL_ZOOMEYE_API_KEY")

    def search(self, query: str, page: int = 1, size: int = 50, country: str = "") -> Dict[str, Any]:
        key = self.api_key or next((os.environ.get(k, "") for k in self.env_keys if os.environ.get(k)), "")
        if not key:
            raise ProviderError("missing_key", "ZoomEye API key not configured", self.name)
        expr = self.translate_query(query)
        if country:
            raise ProviderError("unsupported_query", "ZoomEye country filter is not wired in this adapter", self.name)
        body = {
            "qbase64": base64.b64encode(expr.encode("utf-8")).decode("ascii"),
            "fields": "url,ip,port,domain,title,country.name",
            "page": max(1, int(page)),
            "pagesize": max(1, min(int(size), self.max_page_size)),
        }
        data = self._json(self._request("POST", "https://api.zoomeye.ai/v2/search",
                                        json=body, headers={"API-KEY": key, "User-Agent": USER_AGENT,
                                                            "Content-Type": "application/json"}))
        if data.get("code") not in (None, 60000):
            raise ProviderError("http_error", str(data.get("message") or "ZoomEye error")[:200], self.name)
        rows = data.get("data")
        if not isinstance(rows, list):
            raise ProviderError("malformed", "ZoomEye response is missing data", self.name)
        results = []
        for rec in rows:
            if not isinstance(rec, dict):
                continue
            url = rec.get("url") or _host_port_url(rec.get("ip") or rec.get("domain") or "", rec.get("port"))
            if url:
                country_name = (rec.get("country") or {}).get("name", "") if isinstance(rec.get("country"), dict) else ""
                results.append({"url": url, "host": rec.get("domain") or rec.get("ip") or "", "ip": rec.get("ip") or "",
                                "port": rec.get("port"), "title": rec.get("title") or "", "country": country_name})
        return {"results": results, "total": int(data.get("total") or 0), "page": page, "has_more": len(rows) >= size}


class ShodanAdapter(ProviderAdapter):
    name, label = "shodan", "Shodan"
    translate = staticmethod(_shodan_expr)
    max_page_size = 100  # Shodan returns 100 hosts per page
    env_keys = ("SHODAN_API_KEY", "MANTIS_SHODAN_KEY", "IOCINTEL_SHODAN_KEY")

    def search(self, query: str, page: int = 1, size: int = 50, country: str = "") -> Dict[str, Any]:
        key = self.api_key or next((os.environ.get(k, "") for k in self.env_keys if os.environ.get(k)), "")
        if not key:
            raise ProviderError("missing_key", "Shodan API key not configured", self.name)
        expr = self.translate_query(query)
        if country:
            expr = f"{expr} country:{country}"
        data = self._json(self._request("GET", "https://api.shodan.io/shodan/host/search",
                                        params={"key": key, "query": expr, "page": max(1, int(page)), "minify": "true"},
                                        headers={"User-Agent": USER_AGENT}))
        if data.get("error"):
            raise ProviderError("invalid_key" if "api key" in str(data.get("error")).lower() else "http_error",
                                str(data.get("error"))[:200], self.name)
        rows = data.get("matches")
        if not isinstance(rows, list):
            raise ProviderError("malformed", "Shodan response is missing matches", self.name)
        results = []
        for rec in rows[:size]:
            if not isinstance(rec, dict):
                continue
            host = (rec.get("hostnames") or [""])[0] if rec.get("hostnames") else ""
            http = rec.get("http") or {}
            host = http.get("host") or host or rec.get("ip_str") or ""
            proto = "https" if rec.get("ssl") else "http"
            url = _host_port_url(host, rec.get("port"), proto)
            if url:
                results.append({"url": url, "host": host, "ip": rec.get("ip_str") or "", "port": rec.get("port"),
                                "title": http.get("title") or "", "country": (rec.get("location") or {}).get("country_name", "")})
        total = int(data.get("total") or 0)
        return {"results": results, "total": total, "page": page, "has_more": page * 100 < total}


class CensysAdapter(ProviderAdapter):
    name, label = "censys", "Censys"
    translate = staticmethod(_censys_expr)
    max_page_size = 100
    env_keys = ("CENSYS_PAT", "CENSYS_API_KEY", "CENSYS_API_TOKEN")
    env_org = ("CENSYS_ORG_ID", "CENSYS_ORGANIZATION_ID")

    def search(self, query: str, page: int = 1, size: int = 50, country: str = "") -> Dict[str, Any]:
        key = self.api_key or next((os.environ.get(k, "") for k in self.env_keys if os.environ.get(k)), "")
        if not key:
            raise ProviderError("missing_key", "Censys PAT not configured", self.name)
        org = next((os.environ.get(k, "") for k in self.env_org if os.environ.get(k)), "")
        if not org:
            raise ProviderError("missing_config", "Censys organization ID (CENSYS_ORG_ID) not configured on server", self.name)
        expr = self.translate_query(query)
        if country:
            expr = f'{expr} and location.country: "{country}"'
        headers = {"Authorization": f"Bearer {key}", "Accept": "application/json",
                   "Content-Type": "application/json", "User-Agent": USER_AGENT, "X-Organization-ID": org}
        body = {"query": expr, "page_size": max(1, min(int(size), self.max_page_size))}
        data = self._json(self._request("POST", "https://api.platform.censys.io/v3/global/search/query",
                                        json=body, headers=headers, params={"organization_id": org}))
        result = data.get("result") if isinstance(data.get("result"), dict) else data
        hits = result.get("hits") if isinstance(result, dict) else None
        if not isinstance(hits, list):
            raise ProviderError("malformed", "Censys response is missing hits", self.name)
        results = []
        for hit in hits:
            if not isinstance(hit, dict):
                continue
            ip = hit.get("ip") or ""
            services = hit.get("services") or []
            for svc in services if isinstance(services, list) else []:
                if not isinstance(svc, dict):
                    continue
                proto = (svc.get("protocol") or svc.get("service_name") or "").lower()
                url = _host_port_url(ip, svc.get("port"), "https" if "https" in proto or "tls" in proto else "http")
                if url:
                    results.append({"url": url, "host": ip, "ip": ip, "port": svc.get("port"), "title": "", "country": ""})
        return {"results": results, "total": int(result.get("total_hits") or 0) if isinstance(result, dict) else 0,
                "page": page, "has_more": False}


ADAPTERS: Dict[str, type] = {
    "fofa": FofaAdapter,
    "zoomeye": ZoomEyeAdapter,
    "censys": CensysAdapter,
    "shodan": ShodanAdapter,
}
PROVIDER_ORDER = ["fofa", "zoomeye", "censys", "shodan"]


def provider_status(user_keys: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    """Which providers can run now. Never returns key values."""
    user_keys = user_keys or {}
    out = []
    for name in PROVIDER_ORDER:
        cls = ADAPTERS[name]
        has_user = bool((user_keys.get(name) or "").strip())
        has_env = any(os.environ.get(k) for k in getattr(cls, "env_keys", ()))
        configured = has_user or has_env
        status = "ready" if configured else "missing_key"
        if name == "censys" and configured and not any(os.environ.get(k) for k in CensysAdapter.env_org):
            status = "missing_config"
        out.append({"provider": name, "label": cls.label, "configured": configured,
                    "key_source": "user" if has_user else ("server" if has_env else None),
                    "status": status, "country_filter": cls.supports_country_filter,
                    "max_page_size": cls.max_page_size})
    return out


def run_provider_search(provider: str, query: str, api_key: str = "", page: int = 1,
                        size: int = 50, country: str = "") -> Dict[str, Any]:
    """Run one provider search. Returns {ok, results, ...} or {ok: False, error_kind, error}.

    Failures never raise into the job pipeline: a skipped provider is recorded and the
    job continues with the others.
    """
    cls = ADAPTERS.get(provider)
    if not cls:
        return {"ok": False, "provider": provider, "error_kind": "missing_config", "error": f"Unknown provider {provider}"}
    try:
        out = cls(api_key=api_key).search(query, page=page, size=size, country=country)
        out.update({"ok": True, "provider": provider, "query": query})
        return out
    except ProviderError as exc:
        return {"ok": False, "provider": provider, "query": query, "error_kind": exc.kind, "error": exc.message}
    except Exception as exc:  # defensive: adapter bugs must not kill the job
        return {"ok": False, "provider": provider, "query": query, "error_kind": "malformed",
                "error": f"Unexpected provider failure: {type(exc).__name__}"}


# ---------------------------------------------------------------------------
# Verification and bounded enumeration
# ---------------------------------------------------------------------------

DEFAULT_CRAWL_OPTIONS: Dict[str, Any] = {
    "max_depth": 2,
    "max_files_per_dir": 500,
    "max_dirs": 50,
    "max_requests": 200,
    "timeout": 15.0,
    "max_bytes": 2_000_000,
    "workers": 4,
    "min_host_interval": 1.0,
    "allow_private": False,  # tests only; never exposed through the API
}


def _merge_options(opts: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    merged = dict(DEFAULT_CRAWL_OPTIONS)
    for k, v in (opts or {}).items():
        if k in merged and v is not None:
            merged[k] = v
    merged["max_depth"] = max(0, min(int(merged["max_depth"]), 6))
    merged["max_files_per_dir"] = max(1, min(int(merged["max_files_per_dir"]), 5000))
    merged["max_dirs"] = max(1, min(int(merged["max_dirs"]), 500))
    merged["max_requests"] = max(1, min(int(merged["max_requests"]), 2000))
    merged["workers"] = max(1, min(int(merged["workers"]), 8))
    merged["timeout"] = max(2.0, min(float(merged["timeout"]), 60.0))
    merged["max_bytes"] = max(10_000, min(int(merged["max_bytes"]), 10_000_000))
    return merged


class CrawlResult:
    def __init__(self):
        self.root: Optional[Dict[str, Any]] = None       # verification of start URL
        self.directories: Dict[str, Dict[str, Any]] = {}  # canonical dir url -> info
        self.files: List[Dict[str, Any]] = []
        self.errors: List[Dict[str, str]] = []
        self.requests = 0
        self.cancelled = False


def verify_directory(url: str, opts: Dict[str, Any], rate: HostRateLimiter, session: Optional[requests.Session] = None) -> Dict[str, Any]:
    """Fetch one directory URL and decide whether it is a listing. Returns verification info + entries."""
    try:
        resp = safe_get(url, allow_private=opts["allow_private"], timeout=opts["timeout"],
                        max_bytes=opts["max_bytes"], rate_limiter=rate, session=session)
    except UnsafeTarget as exc:
        return {"url": url, "status": STATUS_REJECTED, "error": f"Rejected: {exc}", "http_status": None, "entries": []}
    except (TimeoutError, ConnectionError) as exc:
        return {"url": url, "status": STATUS_INACCESSIBLE, "error": str(exc), "http_status": None, "entries": []}
    final = resp["url"]
    if final != url:
        # Redirect to another path or host: only accept it when it stays inside the same directory tree.
        pass
    det = detect_listing(resp["text"], resp["status"], resp["headers"].get("server", ""),
                         entry_count=len(parse_entries(resp["text"], final)) if resp["status"] == 200 else 0)
    info = {
        "url": final,
        "requested_url": url,
        "http_status": resp["status"],
        "content_type": resp["headers"].get("content-type", ""),
        "server": resp["headers"].get("server", ""),
        "title": det["title"],
        "listing_type": det["listing_type"],
        "listing_confidence": det["confidence"],
        "signals": det["signals"],
        "truncated": resp["truncated"],
        "error": None,
        "entries": [],
    }
    if det["is_listing"]:
        info["status"] = STATUS_VERIFIED
        info["entries"] = parse_entries(resp["text"], final)
    elif resp["status"] in (401, 403):
        info["status"] = STATUS_INACCESSIBLE
        info["error"] = f"HTTP {resp['status']}: access denied"
    elif resp["status"] >= 400:
        info["status"] = STATUS_INACCESSIBLE
        info["error"] = f"HTTP {resp['status']}"
    else:
        info["status"] = STATUS_REJECTED
        info["error"] = "Not a directory listing (confidence %d)" % det["confidence"]
    return info


def crawl(start_url: str, opts: Optional[Dict[str, Any]] = None, is_cancelled=lambda: False,
          on_directory=None, on_event=None) -> CrawlResult:
    """Bounded breadth-first enumeration. Metadata only. Canonical-URL visited set prevents loops."""
    opts = _merge_options(opts)
    res = CrawlResult()
    rate = HostRateLimiter(opts["min_host_interval"])
    session = requests.Session()
    session.trust_env = False
    root_url = dir_url(start_url)
    root_host = normalize_url(root_url)
    visited = set()
    frontier: List[Tuple[str, int]] = [(root_url, 0)]
    emit = on_event or (lambda *a, **k: None)

    with cf.ThreadPoolExecutor(max_workers=opts["workers"]) as pool:
        first = True
        while frontier:
            if is_cancelled():
                res.cancelled = True
                break
            batch = []
            for url, depth in frontier:
                if url in visited:
                    continue
                if len(res.directories) + len(batch) >= opts["max_dirs"] or res.requests + len(batch) >= opts["max_requests"]:
                    break
                visited.add(url)
                batch.append((url, depth))
            frontier = []
            if not batch:
                break
            futures = {pool.submit(verify_directory, u, opts, rate, session): (u, d) for u, d in batch}
            res.requests += len(batch)
            for fut in cf.as_completed(futures):
                url, depth = futures[fut]
                info = fut.result()
                info["depth"] = depth
                if first and url == root_url:
                    res.root = info
                    first = False
                res.directories[url] = {k: v for k, v in info.items() if k != "entries"}
                if info["status"] != STATUS_VERIFIED:
                    if depth == 0:
                        continue
                    res.errors.append({"url": url, "error": info.get("error") or "not a listing"})
                    continue
                entries = info["entries"]
                dir_files = [e for e in entries if not e["is_dir"]]
                if len(dir_files) > opts["max_files_per_dir"]:
                    dir_files = dir_files[: opts["max_files_per_dir"]]
                    emit("warning", f"File cap reached in {url}; {len(entries)} entries, keeping {opts['max_files_per_dir']} files")
                for e in dir_files:
                    res.files.append({**e, "parent_url": url, "directory_url": root_url})
                subdirs = [e for e in entries if e["is_dir"]]
                for e in subdirs:
                    try:
                        child = dir_url(e["url"])
                    except UnsafeTarget:
                        continue
                    if normalize_url(child)["host"] != root_host["host"]:
                        continue
                    if not normalize_url(child)["path"].startswith(root_host["path"]):
                        continue
                    if depth + 1 <= opts["max_depth"] and child not in visited:
                        frontier.append((child, depth + 1))
                res.directories[url]["subdir_count"] = len(subdirs)
                res.directories[url]["file_count"] = len(dir_files)
                if on_directory:
                    on_directory(url, info)
            if res.cancelled:
                break
    session.close()
    return res


def persist_crawl(conn: sqlite3.Connection, root_url: str, crawl_res: CrawlResult, job_id: Optional[str] = None,
                  source: Optional[Dict[str, str]] = None, scan_time: Optional[str] = None) -> Dict[str, int]:
    """Upsert directories and files, record provenance, mark files absent from this scan as removed."""
    ts = scan_time or utcnow()
    info = normalize_url(root_url)
    counts = {"directories": 0, "files": 0, "removed": 0}
    dir_ids: Dict[str, int] = {}
    for url, d in crawl_res.directories.items():
        u = normalize_url(url)
        status = d["status"]
        row = conn.execute("SELECT id, interest_score FROM opendir_directories WHERE url=?", (url,)).fetchone()
        if row is None:
            cur = conn.execute(
                """INSERT INTO opendir_directories(url, host, ip, port, scheme, path, status, http_status, content_type,
                   server, title, listing_type, listing_confidence, file_count, subdir_count, first_seen, last_seen,
                   last_checked, verified_at, error)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (url, u["host"], None, u["port"], u["scheme"], u["path"], status, d.get("http_status"),
                 d.get("content_type"), d.get("server"), d.get("title"), d.get("listing_type"),
                 d.get("listing_confidence"), d.get("file_count", 0), d.get("subdir_count", 0),
                 ts, ts, ts, ts if status == STATUS_VERIFIED else None, d.get("error")))
            dir_ids[url] = cur.lastrowid
        else:
            dir_ids[url] = row["id"]
            conn.execute(
                """UPDATE opendir_directories SET status=?, http_status=?, content_type=?, server=?, title=?,
                   listing_type=?, listing_confidence=?, file_count=?, subdir_count=?, last_seen=?, last_checked=?,
                   verified_at=COALESCE(?, verified_at), error=? WHERE id=?""",
                (status, d.get("http_status"), d.get("content_type"), d.get("server"), d.get("title"),
                 d.get("listing_type"), d.get("listing_confidence"), d.get("file_count", 0), d.get("subdir_count", 0),
                 ts if status == STATUS_VERIFIED else None, ts, ts if status == STATUS_VERIFIED else None,
                 d.get("error"), row["id"]))
        counts["directories"] += 1
        if source:
            conn.execute(
                """INSERT OR IGNORE INTO opendir_discovery_sources(directory_id, provider, query, source_kind, job_id, discovered_at)
                   VALUES (?,?,?,?,?,?)""",
                (dir_ids[url], source["provider"], source["query"], source["source_kind"], job_id, ts))

    root_id = dir_ids.get(dir_url(root_url))
    if root_id is None:
        return counts
    seen_files = set()
    for f in crawl_res.files:
        seen_files.add(f["url"])
        parent_id = dir_ids.get(f["parent_url"], root_id)
        ext = _extension(f["name"])
        existing = conn.execute("SELECT id FROM opendir_files WHERE url=?", (f["url"],)).fetchone()
        if existing is None:
            conn.execute(
                """INSERT INTO opendir_files(directory_id, url, name, parent_url, extension, size, modified_at, is_dir,
                   first_seen, last_seen) VALUES (?,?,?,?,?,?,?,0,?,?)""",
                (parent_id, f["url"], f["name"], f["parent_url"], ext, f.get("size"), f.get("modified_at"), ts, ts))
        else:
            conn.execute("""UPDATE opendir_files SET size=?, modified_at=?, last_seen=?, removed_at=NULL, directory_id=?
                            WHERE id=?""", (f.get("size"), f.get("modified_at"), ts, parent_id, existing["id"]))
        counts["files"] += 1
    # Files that belonged to scanned directories but were not listed this time are marked removed.
    scanned = [u for u, d in crawl_res.directories.items() if d["status"] == STATUS_VERIFIED]
    for du in scanned:
        did = dir_ids[du]
        rows = conn.execute("SELECT id, url FROM opendir_files WHERE directory_id=? AND removed_at IS NULL", (did,)).fetchall()
        for r in rows:
            if r["url"] not in seen_files:
                conn.execute("UPDATE opendir_files SET removed_at=? WHERE id=?", (ts, r["id"]))
                counts["removed"] += 1
    return counts


def build_interest(conn: sqlite3.Connection, directory_id: int, url: str, rules: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Score a directory from its currently-present files and store the result."""
    files = [dict(r) for r in conn.execute(
        "SELECT name, size, modified_at, is_dir FROM opendir_files WHERE directory_id=? AND removed_at IS NULL", (directory_id,))]
    dir_name = posixpath.basename(normalize_url(url)["path"].rstrip("/")) or "/"
    dir_name = urllib.parse.unquote(dir_name)
    scored = score_directory(files, dir_name, rules or get_scoring_rules())
    conn.execute("UPDATE opendir_directories SET interest_score=?, interest_class=?, interest_reasons=? WHERE id=?",
                 (scored["score"], scored["classification"], json.dumps(scored["reasons"]), directory_id))
    return scored


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------

_JOB_POOL = cf.ThreadPoolExecutor(max_workers=int(os.environ.get("MANTIS_OPENDIR_JOB_WORKERS", "2")),
                                  thread_name_prefix="opendir-job")
_CANCEL_FLAGS: Dict[str, threading.Event] = {}
_CANCEL_LOCK = threading.Lock()


def _event(conn, job_id: str, level: str, message: str, stage: Optional[str] = None) -> None:
    conn.execute("INSERT INTO opendir_job_events(job_id, ts, level, stage, message) VALUES (?,?,?,?,?)",
                 (job_id, utcnow(), level, stage, message[:500]))


def _set_stage(conn, job_id: str, stage: str) -> None:
    conn.execute("UPDATE opendir_hunting_jobs SET stage=? WHERE id=?", (stage, job_id))


def _bump(conn, job_id: str, **delta: int) -> None:
    row = conn.execute("SELECT counters FROM opendir_hunting_jobs WHERE id=?", (job_id,)).fetchone()
    counters = json.loads(row["counters"]) if row else {}
    for k, v in delta.items():
        counters[k] = counters.get(k, 0) + v
    conn.execute("UPDATE opendir_hunting_jobs SET counters=? WHERE id=?", (json.dumps(counters), job_id))


def _dedupe_key(mode: str, query: str, providers: List[str], options: Dict[str, Any]) -> str:
    return json.dumps([mode, query.strip().lower(), sorted(providers), sorted((k, str(v)) for k, v in options.items())])


def create_job(mode: str, query: str, providers: List[str], options: Dict[str, Any], user_id: str,
               api_keys: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Create and start a job. Returns the existing active job when an identical one is already running."""
    if mode not in ("global", "targeted", "keyword"):
        raise ValueError("mode must be global, targeted or keyword")
    query = (query or "").strip()
    if not query and mode != "global":
        raise ValueError("query is required")
    if mode == "targeted":
        info = normalize_url(query)  # raises UnsafeTarget
        query = dir_url(info["url"])
    providers = [p for p in providers if p in ADAPTERS] if mode != "targeted" else []
    if mode != "targeted" and not providers:
        raise ValueError("select at least one known provider")
    options = _merge_options(options)
    key = _dedupe_key(mode, query, providers, {k: options[k] for k in ("max_depth", "max_files_per_dir", "max_dirs")})
    with _db_lock:
        conn = db()
        try:
            existing = conn.execute("SELECT id FROM opendir_hunting_jobs WHERE dedupe_key=? AND status IN (?,?)",
                                    (key, *JOB_ACTIVE)).fetchone()
            if existing:
                return {"id": existing["id"], "deduplicated": True}
            job_id = uuid.uuid4().hex
            conn.execute(
                """INSERT INTO opendir_hunting_jobs(id, mode, query, providers, options, dedupe_key, status, stage,
                   counters, created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (job_id, mode, query, json.dumps(providers), json.dumps(options), key, JOB_QUEUED, "queued",
                 json.dumps({}), user_id, utcnow()))
            _event(conn, job_id, "info", f"Job created by {user_id} ({mode})", "queued")
            conn.commit()
        finally:
            conn.close()
    with _CANCEL_LOCK:
        _CANCEL_FLAGS[job_id] = threading.Event()
    keys = dict(api_keys or {})
    _JOB_POOL.submit(_run_job, job_id, keys)
    return {"id": job_id, "deduplicated": False}


def request_cancel(job_id: str) -> Dict[str, Any]:
    conn = db()
    try:
        row = conn.execute("SELECT status FROM opendir_hunting_jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            raise LookupError("job not found")
        if row["status"] not in JOB_ACTIVE:
            return {"id": job_id, "status": row["status"], "cancel_requested": False}
        conn.execute("UPDATE opendir_hunting_jobs SET cancel_requested=1 WHERE id=?", (job_id,))
        _event(conn, job_id, "warning", "Cancellation requested")
        conn.commit()
    finally:
        conn.close()
    with _CANCEL_LOCK:
        flag = _CANCEL_FLAGS.get(job_id)
    if flag:
        flag.set()
    return {"id": job_id, "status": "cancelling", "cancel_requested": True}


def _is_cancelled(job_id: str) -> bool:
    with _CANCEL_LOCK:
        flag = _CANCEL_FLAGS.get(job_id)
    return bool(flag and flag.is_set())


def _run_job(job_id: str, keys: Dict[str, str]) -> None:
    conn = db()
    try:
        row = conn.execute("SELECT * FROM opendir_hunting_jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            return
        conn.execute("UPDATE opendir_hunting_jobs SET status=?, started_at=? WHERE id=?", (JOB_RUNNING, utcnow(), job_id))
        conn.commit()
        mode, query = row["mode"], row["query"]
        providers = json.loads(row["providers"])
        options = json.loads(row["options"])
        if mode == "targeted":
            _run_targeted(conn, job_id, query, options, source=None)
        else:
            _run_discovery(conn, job_id, mode, query, providers, options, keys)
        final = JOB_CANCELLED if _is_cancelled(job_id) else JOB_COMPLETED
        if final == JOB_COMPLETED:
            _set_stage(conn, job_id, "completed")
        conn.execute("UPDATE opendir_hunting_jobs SET status=?, completed_at=? WHERE id=?", (final, utcnow(), job_id))
        _event(conn, job_id, "info", f"Job {final}", "completed" if final == JOB_COMPLETED else None)
        conn.commit()
    except Exception as exc:  # worker failure must be visible to the user, not swallowed
        try:
            conn.execute("UPDATE opendir_hunting_jobs SET status=?, error=?, completed_at=? WHERE id=?",
                         (JOB_FAILED, f"{type(exc).__name__}: {str(exc)[:300]}", utcnow(), job_id))
            _event(conn, job_id, "error", f"Job failed: {type(exc).__name__}")
            conn.commit()
        except Exception:
            pass
    finally:
        conn.close()
        with _CANCEL_LOCK:
            _CANCEL_FLAGS.pop(job_id, None)


def _run_discovery(conn, job_id, mode, query, providers, options, keys):
    """Provider discovery -> normalization -> verification -> enumeration -> scoring -> persistence."""
    _set_stage(conn, job_id, "provider_discovery")
    conn.commit()
    candidates: Dict[str, Dict[str, Any]] = {}
    per_page = int(options.get("per_page", 50))
    max_results = int(options.get("max_results_per_provider", 100))
    country = (options.get("country") or "").strip().upper()[:2]
    for prov in providers:
        if _is_cancelled(job_id):
            break
        fetched, page = 0, 1
        while fetched < max_results and not _is_cancelled(job_id):
            out = run_provider_search(prov, query, api_key=keys.get(prov, ""), page=page,
                                      size=min(per_page, max_results - fetched), country=country)
            if not out.get("ok"):
                _event(conn, job_id, "warning", f"{prov} skipped: {out.get('error_kind')}: {out.get('error')}", "provider_discovery")
                _bump(conn, job_id, provider_errors=1)
                conn.commit()
                break
            batch = out.get("results", [])
            if not batch:
                _event(conn, job_id, "info", f"{prov}: no results on page {page}", "provider_discovery")
                break
            for r in batch:
                candidates.setdefault(r["url"], {"providers": [], "query": query})
                candidates[r["url"]]["providers"].append(prov)
            fetched += len(batch)
            _bump(conn, job_id, provider_results=len(batch))
            conn.commit()
            if not out.get("has_more"):
                break
            page += 1
        _event(conn, job_id, "info", f"{prov}: {fetched} candidate URL(s)", "provider_discovery")
        conn.commit()

    _set_stage(conn, job_id, "url_normalization")
    normalized: Dict[str, Dict[str, Any]] = {}
    for raw, meta in candidates.items():
        try:
            canon = dir_url(raw)
        except UnsafeTarget as exc:
            _bump(conn, job_id, rejected=1)
            _event(conn, job_id, "warning", f"Rejected candidate: {exc}", "url_normalization")
            continue
        normalized.setdefault(canon, {"providers": set(), "query": meta["query"]})["providers"].update(meta["providers"])
    conn.commit()
    _bump(conn, job_id, discovered=len(normalized))
    conn.commit()

    _set_stage(conn, job_id, "directory_verification")
    conn.commit()
    max_roots = int(options.get("max_roots", 50))
    roots = sorted(normalized.keys())[:max_roots]
    for canon in roots:
        if _is_cancelled(job_id):
            break
        meta = normalized[canon]
        source_kind = "search_index"
        # Each candidate is verified live. Search-engine matches are not treated as confirmed.
        for prov in sorted(meta["providers"]):
            _record_source(conn, canon, prov, meta["query"], source_kind, job_id)
        _crawl_and_persist(conn, job_id, canon, options, source_kind="search_index", provider=",".join(sorted(meta["providers"])), query=meta["query"], emit_stage=True)
    if mode == "keyword":
        _bump(conn, job_id, keyword_candidates=len(roots))


def _record_source(conn, url, provider, query, source_kind, job_id):
    conn.execute("""INSERT OR IGNORE INTO opendir_discovery_sources(directory_id, provider, query, source_kind, job_id, discovered_at)
                    SELECT id, ?, ?, ?, ?, ? FROM opendir_directories WHERE url=?""",
                 (provider, query, source_kind, job_id, utcnow(), url))


def _run_targeted(conn, job_id, url, options, source):
    _crawl_and_persist(conn, job_id, url, options, source_kind="targeted", provider="user", query=url, emit_stage=True)


def _crawl_and_persist(conn, job_id, url, options, source_kind, provider, query, emit_stage=True):
    if _is_cancelled(job_id):
        return
    if emit_stage:
        _set_stage(conn, job_id, "directory_verification")
    _event(conn, job_id, "info", f"Verifying {url}", "directory_verification")
    conn.commit()
    counts = {"verified": 0, "rejected": 0}

    def on_dir(durl, info):
        _bump(conn, job_id, enumerated_directories=1)

    def on_event(level, msg):
        _event(conn, job_id, level, msg, "file_enumeration")

    res = crawl(url, options, is_cancelled=lambda: _is_cancelled(job_id), on_directory=on_dir, on_event=on_event)
    _set_stage(conn, job_id, "file_enumeration")
    conn.commit()
    if res.root is None:
        _bump(conn, job_id, errors=1)
        _event(conn, job_id, "error", f"No verification result for {url}", "directory_verification")
        return
    root = res.root
    if root["status"] == STATUS_VERIFIED:
        counts["verified"] += 1
        _bump(conn, job_id, verified=1)
        _event(conn, job_id, "info", f"Listing confirmed ({root['listing_type']}, confidence {root['listing_confidence']}): {url}", "directory_verification")
    else:
        counts["rejected"] += 1
        _bump(conn, job_id, **({"rejected": 1} if root["status"] == STATUS_REJECTED else {"errors": 1}))
        _event(conn, job_id, "warning" if root["status"] == STATUS_REJECTED else "error",
               f"{root['status']}: {root.get('error')}", "directory_verification")
    for err in res.errors:
        _bump(conn, job_id, errors=1)
    if root["status"] != STATUS_VERIFIED:
        _persist_root_only(conn, url, res, job_id, source_kind, provider, query)
        conn.commit()
        return

    _set_stage(conn, job_id, "interest_scoring")
    conn.commit()
    counts_p = persist_crawl(conn, url, res, job_id=job_id,
                             source={"provider": provider, "query": query, "source_kind": source_kind})
    _bump(conn, job_id, files=counts_p["files"], removed=counts_p["removed"])
    root_row = conn.execute("SELECT id FROM opendir_directories WHERE url=?", (dir_url(url),)).fetchone()
    if root_row:
        for du in res.directories:
            r = conn.execute("SELECT id FROM opendir_directories WHERE url=?", (du,)).fetchone()
            if r and res.directories[du]["status"] == STATUS_VERIFIED:
                build_interest(conn, r["id"], du)
    _set_stage(conn, job_id, "database_persistence")
    conn.commit()


def _persist_root_only(conn, url, res, job_id, source_kind, provider, query):
    persist_crawl(conn, url, res, job_id=job_id, source={"provider": provider, "query": query, "source_kind": source_kind})


def take_snapshot(conn: sqlite3.Connection, directory_id: int, url: str, job_id: Optional[str], status: str,
                  entries: List[Dict[str, Any]]) -> None:
    files = [e for e in entries if not e.get("is_dir")]
    subdirs = [e for e in entries if e.get("is_dir")]
    conn.execute(
        """INSERT INTO opendir_directory_snapshots(directory_id, job_id, taken_at, status, file_count, subdir_count, entries)
           VALUES (?,?,?,?,?,?,?)""",
        (directory_id, job_id, utcnow(), status, len(files), len(subdirs),
         json.dumps([{"name": e["name"], "url": e["url"], "is_dir": bool(e.get("is_dir")),
                      "size": e.get("size"), "modified_at": e.get("modified_at")} for e in entries])))


def diff_snapshots(prev: Optional[Dict[str, Any]], cur: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Compare two snapshots. Only reports what the listings literally show (no content inference)."""
    changes: List[Dict[str, Any]] = []
    if cur["status"] != "verified":
        if prev and prev.get("status") == "verified":
            changes.append({"change_type": "became_inaccessible", "subject": "directory", "old_value": "verified", "new_value": cur["status"]})
        return changes
    if prev and prev.get("status") != "verified":
        changes.append({"change_type": "became_accessible", "subject": "directory", "old_value": prev.get("status"), "new_value": "verified"})
    if not prev or prev.get("status") != "verified":
        return changes
    old = {e["url"]: e for e in json.loads(prev["entries"])}
    new = {e["url"]: e for e in json.loads(cur["entries"])}
    for u, e in new.items():
        if u not in old:
            changes.append({"change_type": "subdirectory_added" if e["is_dir"] else "file_added", "subject": e["name"],
                            "old_value": None, "new_value": str(e.get("size"))})
            continue
        o = old[u]
        if o.get("size") != e.get("size") and not e["is_dir"]:
            changes.append({"change_type": "size_changed", "subject": e["name"], "old_value": str(o.get("size")), "new_value": str(e.get("size"))})
        if o.get("modified_at") != e.get("modified_at") and e.get("modified_at"):
            changes.append({"change_type": "timestamp_changed", "subject": e["name"], "old_value": o.get("modified_at"), "new_value": e.get("modified_at")})
    for u, o in old.items():
        if u not in new:
            changes.append({"change_type": "subdirectory_removed" if o["is_dir"] else "file_removed", "subject": o["name"],
                            "old_value": str(o.get("size")), "new_value": None})
    return changes


# ---------------------------------------------------------------------------
# Watchlist monitoring
# ---------------------------------------------------------------------------

def rescan_watched(directory_id: int, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Re-verify one watched directory, store a snapshot and record changes against the previous one."""
    conn = db()
    try:
        row = conn.execute("SELECT url FROM opendir_directories WHERE id=?", (directory_id,)).fetchone()
        if not row:
            return {"directory_id": directory_id, "error": "directory not found"}
        opts = _merge_options({**(options or {}), "max_depth": 0})  # monitoring compares the top-level listing
        rate = HostRateLimiter(opts["min_host_interval"])
        info = verify_directory(row["url"], opts, rate)
        prev_row = conn.execute(
            "SELECT status, entries FROM opendir_directory_snapshots WHERE directory_id=? ORDER BY id DESC LIMIT 1",
            (directory_id,)).fetchone()
        prev = dict(prev_row) if prev_row else None
        current = {"status": info["status"], "entries": json.dumps([
            {"name": e["name"], "url": e["url"], "is_dir": e["is_dir"], "size": e.get("size"), "modified_at": e.get("modified_at")}
            for e in info.get("entries", [])])}
        changes = diff_snapshots(prev, current)
        ts = utcnow()
        take_snapshot(conn, directory_id, row["url"], None, info["status"], info.get("entries", []))
        for c in changes:
            conn.execute(
                "INSERT INTO opendir_change_events(directory_id, detected_at, change_type, subject, old_value, new_value) VALUES (?,?,?,?,?,?)",
                (directory_id, ts, c["change_type"], c["subject"], c.get("old_value"), c.get("new_value")))
        if info["status"] == STATUS_VERIFIED:
            # Keep the live file inventory current too; a change here re-scores the directory.
            crawl_res = CrawlResult()
            crawl_res.root = info
            crawl_res.directories[row["url"]] = {k: v for k, v in info.items() if k != "entries"}
            crawl_res.directories[row["url"]]["file_count"] = sum(1 for e in info["entries"] if not e["is_dir"])
            crawl_res.directories[row["url"]]["subdir_count"] = sum(1 for e in info["entries"] if e["is_dir"])
            for e in info["entries"]:
                if not e["is_dir"]:
                    crawl_res.files.append({**e, "parent_url": row["url"], "directory_url": row["url"]})
            persist_crawl(conn, row["url"], crawl_res, job_id=None, scan_time=ts)
            build_interest(conn, directory_id, row["url"])
        conn.execute(
            "UPDATE opendir_watchlist SET last_scan_at=?, monitoring_status=?, next_scan_at=? WHERE directory_id=?",
            (ts, info["status"], _iso_in(0), directory_id))
        conn.execute("UPDATE opendir_directories SET last_checked=?, status=?, error=? WHERE id=?",
                     (ts, info["status"], info.get("error"), directory_id))
        conn.commit()
        return {"directory_id": directory_id, "status": info["status"], "changes": len(changes)}
    finally:
        conn.close()


def run_due_watches(limit: int = 20) -> List[Dict[str, Any]]:
    """Re-scan watched directories whose next scan time has passed."""
    conn = db()
    try:
        due = [r["directory_id"] for r in conn.execute(
            "SELECT directory_id FROM opendir_watchlist WHERE enabled=1 AND (next_scan_at IS NULL OR next_scan_at <= ?) LIMIT ?",
            (utcnow(), limit))]
    finally:
        conn.close()
    results = []
    for did in due:
        try:
            results.append(rescan_watched(did))
        except Exception as exc:
            results.append({"directory_id": did, "error": f"{type(exc).__name__}: {str(exc)[:200]}"})
        # Schedule the next scan from the configured interval, not from now-in-DB.
        conn = db()
        try:
            conn.execute(
                "UPDATE opendir_watchlist SET next_scan_at=? WHERE directory_id=?",
                (_iso_in(60 * int(conn.execute("SELECT interval_minutes FROM opendir_watchlist WHERE directory_id=?",
                                               (did,)).fetchone()["interval_minutes"])), did))
            conn.commit()
        finally:
            conn.close()
    return results


_WATCH_THREAD: Optional[threading.Thread] = None


def start_watch_scheduler(poll_seconds: int = 60) -> None:
    """Start one daemon thread that runs due watchlist scans. Idempotent."""
    global _WATCH_THREAD
    if _WATCH_THREAD and _WATCH_THREAD.is_alive():
        return

    def loop():
        while True:
            try:
                run_due_watches()
            except Exception:
                pass
            time.sleep(poll_seconds)

    _WATCH_THREAD = threading.Thread(target=loop, name="opendir-watch", daemon=True)
    _WATCH_THREAD.start()
