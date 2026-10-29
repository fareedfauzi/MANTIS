"""CTI Articles: local SQLite repository (data/cti_articles.db).

Tables: sources (feed registry), articles, article_indicators,
articles_fts (FTS5 full-text index, synced manually on write).
One connection per call (WAL mode); no file-per-article storage.
"""
import hashlib
import logging
import os
import shutil
import sqlite3
import threading
import time
import urllib.parse

import cti_config as cfg

logger = logging.getLogger("mantis.cti.db")
_INIT_DB_LOCK = threading.RLock()
_INITIALIZED_DB_PATHS: set[str] = set()
_CORRUPT_DB_MARKERS = (
    "database disk image is malformed",
    "file is not a database",
    "database schema is locked",
    "malformed database schema",
)

TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "fbclid", "gclid", "msclkid", "mc_cid", "mc_eid",
    "igshid", "_hsenc", "_hsmi", "vero_conv", "vero_id",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    domain TEXT NOT NULL DEFAULT '',
    feed_url TEXT NOT NULL DEFAULT '',
    feed_type TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    discovery TEXT NOT NULL DEFAULT '',
    upstream TEXT NOT NULL DEFAULT '',
    last_attempt TEXT DEFAULT '',
    last_success TEXT DEFAULT '',
    last_new_article TEXT DEFAULT '',
    article_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL DEFAULT '',
    canonical_url TEXT NOT NULL DEFAULT '',
    url_norm TEXT NOT NULL DEFAULT '',
    author TEXT NOT NULL DEFAULT '',
    published_at TEXT DEFAULT '',
    modified_at TEXT DEFAULT '',
    fetched_at TEXT NOT NULL DEFAULT '',
    content_text TEXT NOT NULL DEFAULT '',
    content_html TEXT NOT NULL DEFAULT '',
    excerpt TEXT NOT NULL DEFAULT '',
    content_hash TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_articles_url_norm ON articles(url_norm);
CREATE INDEX IF NOT EXISTS idx_articles_source ON articles(source_id);
CREATE INDEX IF NOT EXISTS idx_articles_published ON articles(published_at);
CREATE TABLE IF NOT EXISTS article_indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    article_id INTEGER NOT NULL,
    type TEXT NOT NULL DEFAULT '',
    value TEXT NOT NULL DEFAULT '',
    observed_value TEXT NOT NULL DEFAULT '',
    UNIQUE(article_id, type, value)
);
CREATE INDEX IF NOT EXISTS idx_indicators_value ON article_indicators(type, value);
CREATE INDEX IF NOT EXISTS idx_indicators_article ON article_indicators(article_id);
CREATE VIRTUAL TABLE IF NOT EXISTS articles_fts USING fts5(
    article_id UNINDEXED, title, content_text, author, source_name,
    tokenize='porter unicode61 remove_diacritics 2');
CREATE TABLE IF NOT EXISTS malpedia_families (
    uuid TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    common_name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    alt_names TEXT NOT NULL DEFAULT '',
    attribution TEXT NOT NULL DEFAULT '',
    urls TEXT NOT NULL DEFAULT '',
    updated TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS malpedia_actors (
    uuid TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    country TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    refs TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS cti_categories (
    name TEXT PRIMARY KEY
);
"""


def connect(path: str = "") -> sqlite3.Connection:
    db_path = path or cfg.CTI_DB_PATH
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=120000")
    except sqlite3.Error:
        pass
    return conn


def is_corruption_error(exc: Exception) -> bool:
    """True for SQLite errors that mean the local CTI cache must be rebuilt."""
    text = str(exc).lower()
    return isinstance(exc, sqlite3.DatabaseError) and any(m in text for m in _CORRUPT_DB_MARKERS)


def _sidecar_paths(db_path: str) -> list[str]:
    return [db_path + suffix for suffix in ("-wal", "-shm", "-journal")]


def _archive_path(path: str, timestamp: str) -> str:
    directory = os.path.dirname(os.path.abspath(path))
    base = os.path.basename(path)
    return os.path.join(directory, f"{base}.malformed-{timestamp}.bak")


def _quarantine_file(path: str, timestamp: str) -> str:
    """Move a malformed SQLite file aside, keeping a copy if move is blocked."""
    if not os.path.exists(path):
        return ""
    archive = _archive_path(path, timestamp)
    try:
        os.replace(path, archive)
        return archive
    except OSError:
        shutil.copy2(path, archive)
        return archive


def rebuild_database(path: str = "", reason: str = "") -> dict:
    """Quarantine the malformed CTI cache and recreate an empty healthy DB."""
    db_path = os.path.abspath(path or cfg.CTI_DB_PATH)
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    timestamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    archived = []

    with _INIT_DB_LOCK:
        _INITIALIZED_DB_PATHS.discard(db_path)
        for candidate in [db_path] + _sidecar_paths(db_path):
            archived_path = _quarantine_file(candidate, timestamp)
            if archived_path:
                archived.append(archived_path)

        if os.path.exists(db_path):
            raise sqlite3.DatabaseError(
                f"CTI database is still locked after backup; archived copy at {archived[0] if archived else 'n/a'}"
            )

        conn = connect(db_path)
        try:
            conn.executescript(SCHEMA)
            conn.commit()
            _INITIALIZED_DB_PATHS.add(db_path)
        finally:
            conn.close()

    logger.warning("Rebuilt CTI article database after corruption (%s). Backups: %s",
                   reason or "unknown reason", ", ".join(archived) or "none")
    return {"rebuilt": True, "path": db_path, "backups": archived, "reason": reason}


def ensure_healthy(path: str = "", repair: bool = False) -> dict:
    """Run a quick SQLite integrity check, optionally rebuilding on failure."""
    db_path = os.path.abspath(path or cfg.CTI_DB_PATH)
    if not os.path.exists(db_path):
        init_db(db_path)
        return {"ok": True, "path": db_path, "created": True}
    try:
        conn = sqlite3.connect(db_path, timeout=30)
        try:
            row = conn.execute("PRAGMA quick_check").fetchone()
            result = row[0] if row else ""
        finally:
            conn.close()
    except sqlite3.DatabaseError as e:
        if repair and is_corruption_error(e):
            return rebuild_database(db_path, reason=str(e))
        raise
    if result == "ok":
        return {"ok": True, "path": db_path}
    if repair:
        return rebuild_database(db_path, reason=f"quick_check: {result}")
    raise sqlite3.DatabaseError(f"CTI database quick_check failed: {result}")


_BUSY_RETRIES = 5


def _is_busy_error(e: Exception) -> bool:
    return isinstance(e, sqlite3.OperationalError) and "locked" in str(e).lower()


def with_busy_retry(fn, *args, **kwargs):
    """Retry idempotent writes when another process holds the DB briefly."""
    delay = 0.5
    for attempt in range(_BUSY_RETRIES):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            if not _is_busy_error(e) or attempt == _BUSY_RETRIES - 1:
                raise
            logger.info("CTI database busy, retrying (%d/%d)", attempt + 1, _BUSY_RETRIES)
            time.sleep(delay)
            delay *= 2


def init_db(path: str = "") -> str:
    db_path = os.path.abspath(path or cfg.CTI_DB_PATH)
    if db_path in _INITIALIZED_DB_PATHS and os.path.exists(db_path):
        return db_path

    with _INIT_DB_LOCK:
        if db_path in _INITIALIZED_DB_PATHS and os.path.exists(db_path):
            return db_path

        if os.path.exists(db_path):
            try:
                conn = sqlite3.connect(db_path, timeout=30)
                try:
                    row = conn.execute("PRAGMA quick_check").fetchone()
                    result = row[0] if row else ""
                finally:
                    conn.close()
                if result != "ok":
                    raise sqlite3.DatabaseError(f"CTI database quick_check failed: {result}")
            except sqlite3.DatabaseError as e:
                if is_corruption_error(e) or "quick_check failed" in str(e):
                    return rebuild_database(db_path, reason=str(e))["path"]
                raise

        conn = connect(db_path)
        try:
            conn.executescript(SCHEMA)
            conn.commit()
            _INITIALIZED_DB_PATHS.add(db_path)
        finally:
            conn.close()
    return db_path


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())


def normalize_url(url: str) -> str:
    """Canonical URL for dedup: lower scheme/host, drop tracking params + fragment."""
    url = (url or "").strip()
    if not url:
        return ""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return url.lower()
    if parts.scheme not in ("http", "https"):
        return url.lower()
    host = (parts.hostname or "").lower()
    if not host:
        return url.lower()
    netloc = host
    if parts.port and parts.port not in (80, 443):
        netloc = f"{host}:{parts.port}"
    try:
        pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    except ValueError:
        pairs = []
    kept = [(k, v) for k, v in pairs if k.lower() not in TRACKING_PARAMS]
    query = urllib.parse.urlencode(kept)
    path = parts.path or "/"
    return urllib.parse.urlunsplit((parts.scheme.lower(), netloc, path, query, ""))


def content_hash(text: str) -> str:
    norm = " ".join((text or "").split())
    return hashlib.sha256(norm.encode("utf-8", errors="ignore")).hexdigest()


def source_id_for(feed_url: str, domain: str) -> str:
    base = (feed_url or "").strip() or (domain or "").strip().lower()
    return hashlib.sha1(base.encode("utf-8", errors="ignore")).hexdigest()[:16]


def is_media_feed(source: dict) -> bool:
    """Podcast/video feeds never yield articles: skip before any fetching.

    The upstream category travels in the registry `upstream` column
    ("Category | description ...").
    """
    if not isinstance(source, dict):
        return False
    url = (source.get("feed_url") or "").lower()
    if "youtube.com" in url or "youtu.be" in url or url.endswith((".mp3", ".mp4", ".m4a")):
        return True
    cat = ((source.get("upstream") or "").split("|")[0] or "").strip().lower()
    return ("podcast" in cat) or ("youtube" in cat) or (cat == "video")


# --------------------------------------------------------------------------
# Sources (feed registry)
# --------------------------------------------------------------------------
def upsert_source(feed: dict, conn: sqlite3.Connection = None,
                  keep_name: bool = False) -> str:
    return with_busy_retry(_upsert_source, feed, conn, keep_name)


def _upsert_source(feed: dict, conn: sqlite3.Connection = None,
                   keep_name: bool = False) -> str:
    feed_url = (feed.get("feed_url") or "").strip()
    domain = (feed.get("domain") or "").strip().lower()
    sid = source_id_for(feed_url, domain)
    name = (feed.get("title") or "").strip() or domain or feed_url
    upstream = (feed.get("category") or "").strip()
    if feed.get("description"):
        upstream = (upstream + " | " + feed["description"].strip())[:500] if upstream else feed["description"].strip()[:500]
    own = conn is None
    if own:
        conn = connect()
    try:
        row = conn.execute("SELECT id, enabled FROM sources WHERE id = ?", (sid,)).fetchone()
        if row is None:
            enabled = 0 if feed.get("discovery") == "not-found" else 1
            reason = ""
            if feed.get("discovery") == "not-found":
                reason = "No catalog match and no discoverable feed"
            conn.execute(
                "INSERT INTO sources (id, name, domain, feed_url, feed_type, enabled,"
                " discovery, upstream, last_error) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (sid, name, domain, feed_url, (feed.get("feed_type") or "").strip(),
                 enabled, (feed.get("discovery") or "").strip(), upstream, reason))
        else:
            # Refresh metadata, never clobber operator enabled/disabled state.
            # keep_name skips the title so poll-set real feed titles survive
            # registry rebuilds that only carry placeholder names.
            if keep_name:
                conn.execute(
                    "UPDATE sources SET domain = ?, feed_type = ?,"
                    " discovery = ?, upstream = ? WHERE id = ?",
                    (domain, (feed.get("feed_type") or "").strip(),
                     (feed.get("discovery") or "").strip(), upstream, sid))
            else:
                conn.execute(
                    "UPDATE sources SET name = ?, domain = ?, feed_type = ?,"
                    " discovery = ?, upstream = ? WHERE id = ?",
                    (name, domain, (feed.get("feed_type") or "").strip(),
                     (feed.get("discovery") or "").strip(), upstream, sid))
            if feed_url:
                conn.execute("UPDATE sources SET feed_url = ? WHERE id = ?", (feed_url, sid))
        if own:
            conn.commit()
        return sid
    finally:
        if own:
            conn.close()


def get_sources(enabled_only: bool = False, conn: sqlite3.Connection = None):
    own = conn is None
    if own:
        conn = connect()
    try:
        q = "SELECT * FROM sources"
        if enabled_only:
            q += " WHERE enabled = 1"
        q += " ORDER BY name"
        return [dict(r) for r in conn.execute(q).fetchall()]
    finally:
        if own:
            conn.close()


def dedupe_empty_sources() -> int:
    """Delete 0-article enabled sources whose feed URL duplicates another of
    the same domain modulo case/trailing slash (e.g. /feed vs /feed/).

    Only rows with no articles are ever removed; disabled and not-found rows
    are left alone. Returns the deleted count.
    """
    conn = connect()
    try:
        rows = [dict(r) for r in conn.execute("SELECT * FROM sources").fetchall()]
        groups: dict = {}
        for r in rows:
            url = (r.get("feed_url") or "").strip().lower().rstrip("/")
            if not url or not r.get("enabled"):
                continue
            groups.setdefault((r.get("domain", ""), url), []).append(r)
        deleted = 0
        for _key, group in groups.items():
            if len(group) < 2:
                continue
            empty = []
            for r in group:
                n = conn.execute("SELECT COUNT(*) FROM articles WHERE source_id = ?",
                                 (r["id"],)).fetchone()[0]
                if n == 0:
                    empty.append(r)
            if len(empty) < 2:
                continue
            # Keep the row that already synced, else the first; delete rest.
            empty.sort(key=lambda r: (not r.get("last_success"), r.get("name", "")))
            for r in empty[1:]:
                conn.execute("DELETE FROM sources WHERE id = ?", (r["id"],))
                deleted += 1
        conn.commit()
        return deleted
    finally:
        conn.close()


def set_source_enabled(source_id: str, enabled: bool) -> bool:
    return with_busy_retry(_set_source_enabled, source_id, enabled)


def _set_source_enabled(source_id: str, enabled: bool) -> bool:
    conn = connect()
    try:
        cur = conn.execute("UPDATE sources SET enabled = ? WHERE id = ?",
                           (1 if enabled else 0, source_id))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def _validate_feed_url(url: str) -> str:
    """Normalized http(s) feed URL or '' when unusable."""
    url = (url or "").strip()
    if len(url) > 500:
        return ""
    if not url.lower().startswith(("http://", "https://")):
        return ""
    try:
        host = urllib.parse.urlsplit(url).hostname or ""
    except ValueError:
        return ""
    return url if host else ""


def set_source_feed(source_id: str, feed_url: str) -> bool:
    """Replace a source's feed URL in place (articles stay linked).

    Clears the previous error so the new URL is retried on next sync.
    Returns False for unknown ids or unusable URLs.
    """
    feed_url = _validate_feed_url(feed_url)
    if not feed_url or not (source_id or "").strip():
        return False
    return with_busy_retry(_set_source_feed, source_id.strip(), feed_url)


def _set_source_feed(source_id: str, feed_url: str) -> bool:
    conn = connect()
    try:
        cur = conn.execute(
            "UPDATE sources SET feed_url = ?, feed_type = '', last_error = ''"
            " WHERE id = ?", (feed_url, source_id))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def update_source_name(source_id: str, name: str, conn: sqlite3.Connection = None) -> bool:
    """Replace an auto-derived source name with the real feed title."""
    name = (name or "").strip()[:200]
    if not name or not source_id:
        return False
    own = conn is None
    if own:
        conn = connect()
    try:
        cur = conn.execute("UPDATE sources SET name = ? WHERE id = ? AND name != ?",
                           (name, source_id, name))
        if own:
            conn.commit()
        return cur.rowcount > 0
    finally:
        if own:
            conn.close()


def touch_source(source_id: str, success: bool, error: str = "",
                 new_article: bool = False, conn: sqlite3.Connection = None):
    own = conn is None
    if own:
        conn = connect()
    try:
        ts = now_iso()
        if success:
            conn.execute(
                "UPDATE sources SET last_attempt = ?, last_success = ?, last_error = ?"
                + (", last_new_article = ?" if new_article else "") + " WHERE id = ?",
                ((ts, ts, "") + ((ts,) if new_article else ()) + (source_id,)))
        else:
            conn.execute("UPDATE sources SET last_attempt = ?, last_error = ? WHERE id = ?",
                         (ts, (error or "")[:500], source_id))
        count = conn.execute("SELECT COUNT(*) FROM articles WHERE source_id = ?",
                             (source_id,)).fetchone()[0]
        conn.execute("UPDATE sources SET article_count = ? WHERE id = ?", (count, source_id))
        if own:
            conn.commit()
    finally:
        if own:
            conn.close()


# --------------------------------------------------------------------------
# Category & Source Management
# --------------------------------------------------------------------------
def get_categories(conn: sqlite3.Connection = None) -> list[str]:
    """Retrieve all unique category names across sources and custom categories."""
    own = conn is None
    if own:
        conn = connect()
    try:
        cats = set()
        rows = conn.execute("SELECT name FROM cti_categories").fetchall()
        for r in rows:
            if r["name"].strip():
                cats.add(r["name"].strip())
        rows = conn.execute("SELECT upstream FROM sources WHERE upstream != ''").fetchall()
        for r in rows:
            u = r["upstream"].strip()
            if u:
                c = u.split("|", 1)[0].strip()
                if c:
                    cats.add(c)
        return sorted(list(cats), key=lambda x: x.lower())
    finally:
        if own:
            conn.close()


def add_category(name: str) -> bool:
    name = (name or "").strip()
    if not name:
        return False
    return with_busy_retry(_add_category, name)


def _add_category(name: str) -> bool:
    conn = connect()
    try:
        conn.execute("INSERT OR IGNORE INTO cti_categories (name) VALUES (?)", (name,))
        conn.commit()
        return True
    finally:
        conn.close()


def rename_category(old_name: str, new_name: str) -> int:
    old_name = (old_name or "").strip()
    new_name = (new_name or "").strip()
    if not old_name or not new_name or old_name.lower() == new_name.lower():
        return 0
    return with_busy_retry(_rename_category, old_name, new_name)


def _rename_category(old_name: str, new_name: str) -> int:
    conn = connect()
    try:
        conn.execute("UPDATE cti_categories SET name = ? WHERE LOWER(name) = LOWER(?)", (new_name, old_name))
        rows = conn.execute("SELECT id, upstream FROM sources").fetchall()
        updated_count = 0
        for r in rows:
            sid = r["id"]
            upstream = r["upstream"] or ""
            parts = upstream.split("|", 1)
            cat = parts[0].strip()
            if cat.lower() == old_name.lower():
                desc = parts[1].strip() if len(parts) > 1 else ""
                new_upstream = f"{new_name} | {desc}" if desc else new_name
                conn.execute("UPDATE sources SET upstream = ? WHERE id = ?", (new_upstream, sid))
                updated_count += 1
        conn.commit()
        return updated_count
    finally:
        conn.close()


def delete_category(name: str) -> int:
    name = (name or "").strip()
    if not name:
        return 0
    return with_busy_retry(_delete_category, name)


def _delete_category(name: str) -> int:
    conn = connect()
    try:
        conn.execute("DELETE FROM cti_categories WHERE LOWER(name) = LOWER(?)", (name,))
        rows = conn.execute("SELECT id, upstream FROM sources").fetchall()
        updated_count = 0
        for r in rows:
            sid = r["id"]
            upstream = r["upstream"] or ""
            parts = upstream.split("|", 1)
            cat = parts[0].strip()
            if cat.lower() == name.lower():
                desc = parts[1].strip() if len(parts) > 1 else ""
                new_upstream = f"Other | {desc}" if desc else "Other"
                conn.execute("UPDATE sources SET upstream = ? WHERE id = ?", (new_upstream, sid))
                updated_count += 1
        conn.commit()
        return updated_count
    finally:
        conn.close()


def delete_source(source_id: str) -> bool:
    source_id = (source_id or "").strip()
    if not source_id:
        return False
    return with_busy_retry(_delete_source, source_id)


def _delete_source(source_id: str) -> bool:
    conn = connect()
    try:
        articles = conn.execute("SELECT id FROM articles WHERE source_id = ?", (source_id,)).fetchall()
        for a in articles:
            aid = a["id"]
            conn.execute("DELETE FROM article_indicators WHERE article_id = ?", (aid,))
            conn.execute("DELETE FROM articles_fts WHERE article_id = ?", (aid,))
        conn.execute("DELETE FROM articles WHERE source_id = ?", (source_id,))
        cur = conn.execute("DELETE FROM sources WHERE id = ?", (source_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def edit_source_details(source_id: str, name: str = None, category: str = None, feed_url: str = None) -> bool:
    source_id = (source_id or "").strip()
    if not source_id:
        return False
    return with_busy_retry(_edit_source_details, source_id, name, category, feed_url)


def _edit_source_details(source_id: str, name: str = None, category: str = None, feed_url: str = None) -> bool:
    conn = connect()
    try:
        row = conn.execute("SELECT * FROM sources WHERE id = ?", (source_id,)).fetchone()
        if not row:
            return False

        updates = []
        params = []

        if name is not None and name.strip():
            updates.append("name = ?")
            params.append(name.strip()[:200])

        if feed_url is not None and feed_url.strip():
            valid_url = _validate_feed_url(feed_url)
            if valid_url:
                updates.append("feed_url = ?")
                params.append(valid_url)
                updates.append("last_error = ''")

        if category is not None:
            cat_clean = category.strip()
            upstream = row["upstream"] or ""
            parts = upstream.split("|", 1)
            desc = parts[1].strip() if len(parts) > 1 else ""
            new_upstream = f"{cat_clean} | {desc}" if desc else cat_clean
            updates.append("upstream = ?")
            params.append(new_upstream)
            if cat_clean:
                conn.execute("INSERT OR IGNORE INTO cti_categories (name) VALUES (?)", (cat_clean,))

        if not updates:
            return True

        sql = f"UPDATE sources SET {', '.join(updates)} WHERE id = ?"
        params.append(source_id)
        conn.execute(sql, params)
        conn.commit()
        return True
    finally:
        conn.close()


# --------------------------------------------------------------------------
# Articles
# --------------------------------------------------------------------------
def find_article_by_url_norm(url_norm: str, conn: sqlite3.Connection = None):
    if not url_norm:
        return None
    own = conn is None
    if own:
        conn = connect()
    try:
        row = conn.execute("SELECT * FROM articles WHERE url_norm = ?",
                           (url_norm,)).fetchone()
        return dict(row) if row else None
    finally:
        if own:
            conn.close()


def find_articles_by_hash(content_hash: str, conn: sqlite3.Connection = None):
    """All article ids with identical normalized content (cross-URL dupes)."""
    if not content_hash:
        return []
    own = conn is None
    if own:
        conn = connect()
    try:
        return [r[0] for r in conn.execute(
            "SELECT id FROM articles WHERE content_hash = ? ORDER BY id",
            (content_hash,)).fetchall()]
    finally:
        if own:
            conn.close()


def delete_article(article_id: int, conn: sqlite3.Connection = None) -> bool:
    """Remove an article and its indicators + FTS rows."""
    own = conn is None
    if own:
        conn = connect()
    try:
        conn.execute("DELETE FROM article_indicators WHERE article_id = ?",
                     (article_id,))
        conn.execute("DELETE FROM articles_fts WHERE article_id = ?",
                     (article_id,))
        cur = conn.execute("DELETE FROM articles WHERE id = ?", (article_id,))
        if own:
            conn.commit()
        return cur.rowcount > 0
    finally:
        if own:
            conn.close()


def prune_old_articles(days: int = 90, conn: sqlite3.Connection = None) -> int:
    """Hard-delete articles (and indicators) older than N days."""
    own = conn is None
    if own:
        conn = connect()
    try:
        cutoff_time = time.time() - (days * 86400)
        cutoff_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(cutoff_time))
        rows = conn.execute("SELECT id FROM articles WHERE COALESCE(NULLIF(published_at, ''), fetched_at) < ?", (cutoff_iso,)).fetchall()
        deleted = 0
        for r in rows:
            aid = r[0]
            conn.execute("DELETE FROM article_indicators WHERE article_id = ?", (aid,))
            conn.execute("DELETE FROM articles_fts WHERE article_id = ?", (aid,))
            conn.execute("DELETE FROM articles WHERE id = ?", (aid,))
            deleted += 1
        if own:
            conn.commit()
        return deleted
    finally:
        if own:
            conn.close()


def dedupe_articles() -> dict:
    """Delete newer copies of byte-identical articles (same content hash,
    different URLs — e.g. feed aliases or cross-posts). Keeps the earliest
    record in each group. Returns {groups, deleted}."""
    conn = connect()
    stats = {"groups": 0, "deleted": 0}
    try:
        dupes = conn.execute(
            "SELECT content_hash FROM articles WHERE content_hash != ''"
            " GROUP BY content_hash HAVING COUNT(*) > 1").fetchall()
        for (h,) in dupes:
            ids = [r[0] for r in conn.execute(
                "SELECT id FROM articles WHERE content_hash = ? ORDER BY id",
                (h,)).fetchall()]
            if len(ids) < 2:
                continue
            stats["groups"] += 1
            for aid in ids[1:]:
                conn.execute("DELETE FROM article_indicators WHERE article_id = ?",
                             (aid,))
                conn.execute("DELETE FROM articles_fts WHERE article_id = ?",
                             (aid,))
                conn.execute("DELETE FROM articles WHERE id = ?", (aid,))
                stats["deleted"] += 1
        conn.commit()
        return stats
    finally:
        conn.close()


def get_article(article_id: int, conn: sqlite3.Connection = None):
    own = conn is None
    if own:
        conn = connect()
    try:
        row = conn.execute("SELECT * FROM articles WHERE id = ?", (article_id,)).fetchone()
        return dict(row) if row else None
    finally:
        if own:
            conn.close()


def _fts_sync(conn: sqlite3.Connection, article_id: int, title: str,
              content_text: str, author: str, source_name: str):
    conn.execute("DELETE FROM articles_fts WHERE article_id = ?", (article_id,))
    conn.execute(
        "INSERT INTO articles_fts (article_id, title, content_text, author, source_name)"
        " VALUES (?, ?, ?, ?, ?)",
        (article_id, title or "", content_text or "", author or "", source_name or ""))


def source_name(conn: sqlite3.Connection, source_id: str) -> str:
    row = conn.execute("SELECT name FROM sources WHERE id = ?", (source_id,)).fetchone()
    return row["name"] if row else ""


def insert_article(article: dict, conn: sqlite3.Connection = None) -> int:
    own = conn is None
    if own:
        conn = connect()
    try:
        cur = conn.execute(
            "INSERT INTO articles (source_id, title, url, canonical_url, url_norm,"
            " author, published_at, modified_at, fetched_at, content_text,"
            " content_html, excerpt, content_hash)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (article.get("source_id", ""), article.get("title", ""),
             article.get("url", ""), article.get("canonical_url", ""),
             article.get("url_norm", ""), article.get("author", ""),
             article.get("published_at", ""), article.get("modified_at", ""),
             article.get("fetched_at", "") or now_iso(),
             article.get("content_text", ""), article.get("content_html", ""),
             article.get("excerpt", ""), article.get("content_hash", "")))
        aid = cur.lastrowid
        _fts_sync(conn, aid, article.get("title", ""), article.get("content_text", ""),
                  article.get("author", ""), source_name(conn, article.get("source_id", "")))
        if own:
            conn.commit()
        return aid
    finally:
        if own:
            conn.close()


def update_article_content(article_id: int, article: dict,
                           conn: sqlite3.Connection = None) -> bool:
    """Refresh stored content (changed hash): no new record is created."""
    own = conn is None
    if own:
        conn = connect()
    try:
        cur = conn.execute(
            "UPDATE articles SET title = ?, author = ?, published_at = ?,"
            " modified_at = ?, fetched_at = ?, content_text = ?, content_html = ?,"
            " excerpt = ?, content_hash = ? WHERE id = ?",
            (article.get("title", ""), article.get("author", ""),
             article.get("published_at", ""), article.get("modified_at", ""),
             article.get("fetched_at", "") or now_iso(),
             article.get("content_text", ""), article.get("content_html", ""),
             article.get("excerpt", ""), article.get("content_hash", ""),
             article_id))
        if cur.rowcount:
            row = conn.execute("SELECT source_id FROM articles WHERE id = ?",
                               (article_id,)).fetchone()
            _fts_sync(conn, article_id, article.get("title", ""),
                      article.get("content_text", ""), article.get("author", ""),
                      source_name(conn, row["source_id"] if row else ""))
        if own:
            conn.commit()
        return bool(cur.rowcount)
    finally:
        if own:
            conn.close()


def replace_indicators(article_id: int, indicators, conn: sqlite3.Connection = None):
    """indicators: [(type, value, observed)]. Canonical (type, value) dedupes."""
    own = conn is None
    if own:
        conn = connect()
    try:
        conn.execute("DELETE FROM article_indicators WHERE article_id = ?", (article_id,))
        for itype, value, observed in indicators or []:
            if not itype or not value:
                continue
            conn.execute(
                "INSERT OR IGNORE INTO article_indicators"
                " (article_id, type, value, observed_value) VALUES (?, ?, ?, ?)",
                (article_id, itype, value, observed or value))
        if own:
            conn.commit()
    finally:
        if own:
            conn.close()


def article_indicators(article_id: int, conn: sqlite3.Connection = None):
    own = conn is None
    if own:
        conn = connect()
    try:
        return [dict(r) for r in conn.execute(
            "SELECT type, value, observed_value FROM article_indicators"
            " WHERE article_id = ? ORDER BY type, value", (article_id,)).fetchall()]
    finally:
        if own:
            conn.close()


def recent_articles(source_id: str = "", since_iso: str = "", limit: int = 50,
                    offset: int = 0, conn: sqlite3.Connection = None,
                    source_categories: list[str] = None):
    own = conn is None
    if own:
        conn = connect()
    try:
        clauses = ["LOWER(a.title) NOT LIKE '%[virtual event]%'", "LOWER(a.excerpt) NOT LIKE '%[virtual event]%'"]
        params: list = []
        if source_id:
            if "." in source_id and not any(c in source_id for c in " \t/"):
                clauses.append("(a.source_id = ? OR LOWER(s.domain) = ?)")
                params.extend([source_id, source_id.lower()])
            else:
                clauses.append("a.source_id = ?")
                params.append(source_id)
        if since_iso:
            clauses.append("COALESCE(NULLIF(a.published_at, ''), a.fetched_at) >= ?")
            params.append(since_iso)
        if source_categories:
            placeholders = ", ".join("?" for _ in source_categories)
            clauses.append(
                "TRIM(CASE WHEN instr(s.upstream, '|') > 0"
                " THEN substr(s.upstream, 1, instr(s.upstream, '|') - 1)"
                " ELSE s.upstream END) IN (" + placeholders + ")"
            )
            params.extend(source_categories)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = conn.execute(
            f"SELECT a.*, s.name AS source_name,"
            " TRIM(CASE WHEN instr(s.upstream, '|') > 0"
            " THEN substr(s.upstream, 1, instr(s.upstream, '|') - 1)"
            " ELSE s.upstream END) AS source_category,"
            " (SELECT COUNT(*) FROM article_indicators i WHERE i.article_id = a.id)"
            " AS indicator_count FROM articles a"
            " LEFT JOIN sources s ON s.id = a.source_id"
            f" {where} ORDER BY COALESCE(NULLIF(a.published_at, ''), a.fetched_at) DESC"
            " LIMIT ? OFFSET ?", (*params, max(1, limit), max(0, offset))).fetchall()
        total = conn.execute(
            "SELECT COUNT(*) FROM articles a"
            " LEFT JOIN sources s ON s.id = a.source_id"
            f" {where}", params).fetchone()[0]
        return [dict(r) for r in rows], total
    finally:
        if own:
            conn.close()


def fts_search(text: str, limit: int = 50):
    """FTS5 match over title/content/author/source; returns [(id, bm25)]."""
    text = (text or "").strip()
    if not text:
        return []
    conn = connect()
    try:
        # Quote as phrase for multi-word input; fall back to tokens on error.
        query = f'"{text}"' if " " in text else text
        try:
            rows = conn.execute(
                "SELECT article_id, bm25(articles_fts) AS r FROM articles_fts"
                " WHERE articles_fts MATCH ? ORDER BY r LIMIT ?",
                (query, max(1, limit))).fetchall()
        except sqlite3.Error:
            toks = " OR ".join(f'"{t}"' for t in text.split()[:8])
            rows = conn.execute(
                "SELECT article_id, bm25(articles_fts) AS r FROM articles_fts"
                " WHERE articles_fts MATCH ? ORDER BY r LIMIT ?",
                (toks, max(1, limit))).fetchall()
        return [(r["article_id"], r["r"]) for r in rows]
    finally:
        conn.close()


def indicator_articles(ind_type: str, value: str, limit: int = 50):
    """Newest articles mentioning an exact canonical indicator value."""
    value = (value or "").strip().lower()
    if not value or not ind_type:
        return [], 0
    conn = connect()
    try:
        rows = conn.execute(
            "SELECT a.*, s.name AS source_name FROM article_indicators i"
            " JOIN articles a ON a.id = i.article_id"
            " LEFT JOIN sources s ON s.id = a.source_id"
            " WHERE i.type = ? AND i.value = ? AND LOWER(a.title) NOT LIKE '%[virtual event]%'"
            " ORDER BY COALESCE(NULLIF(a.published_at, ''), a.fetched_at) DESC"
            " LIMIT ?", (ind_type, value, max(1, limit))).fetchall()
        total = conn.execute(
            "SELECT COUNT(DISTINCT i.article_id) FROM article_indicators i"
            " JOIN articles a ON a.id = i.article_id"
            " WHERE i.type = ? AND i.value = ? AND LOWER(a.title) NOT LIKE '%[virtual event]%'", (ind_type, value)).fetchone()[0]
        return [dict(r) for r in rows], total
    finally:
        conn.close()

# --------------------------------------------------------------------------
# Malpedia Taxonomy
# --------------------------------------------------------------------------
def upsert_malpedia_family(family: dict, conn: sqlite3.Connection = None):
    own = conn is None
    if own:
        conn = connect()
    try:
        conn.execute(
            "INSERT INTO malpedia_families (uuid, name, common_name, description, alt_names, attribution, urls, updated)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(uuid) DO UPDATE SET "
            "name=excluded.name, common_name=excluded.common_name, description=excluded.description, "
            "alt_names=excluded.alt_names, attribution=excluded.attribution, urls=excluded.urls, updated=excluded.updated",
            (family.get("uuid"), family.get("name", ""), family.get("common_name", ""),
             family.get("description", ""), ",".join(family.get("alt_names", [])),
             ",".join(family.get("attribution", [])), ",".join(family.get("urls", [])),
             family.get("updated", ""))
        )
        if own:
            conn.commit()
    finally:
        if own:
            conn.close()

def upsert_malpedia_actor(actor: dict, conn: sqlite3.Connection = None):
    own = conn is None
    if own:
        conn = connect()
    try:
        conn.execute(
            "INSERT INTO malpedia_actors (uuid, name, country, description, refs)"
            " VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(uuid) DO UPDATE SET "
            "name=excluded.name, country=excluded.country, description=excluded.description, refs=excluded.refs",
            (actor.get("uuid"), actor.get("value", ""), actor.get("meta", {}).get("country", ""),
             actor.get("description", ""), ",".join(actor.get("meta", {}).get("refs", [])))
        )
        if own:
            conn.commit()
    finally:
        if own:
            conn.close()

def find_malpedia_family(name_or_alias: str, conn: sqlite3.Connection = None):
    if not name_or_alias:
        return None
    own = conn is None
    if own:
        conn = connect()
    try:
        # Check exact name or common name
        row = conn.execute(
            "SELECT * FROM malpedia_families WHERE name = ? COLLATE NOCASE OR common_name = ? COLLATE NOCASE",
            (name_or_alias, name_or_alias)
        ).fetchone()
        if row:
            return dict(row)
        # Check alt_names
        rows = conn.execute("SELECT * FROM malpedia_families").fetchall()
        for r in rows:
            alt_names = [a.strip().lower() for a in r["alt_names"].split(",") if a.strip()]
            if name_or_alias.lower() in alt_names:
                return dict(r)
        return None
    finally:
        if own:
            conn.close()

def find_malpedia_actor(name: str, conn: sqlite3.Connection = None):
    if not name:
        return None
    own = conn is None
    if own:
        conn = connect()
    try:
        row = conn.execute(
            "SELECT * FROM malpedia_actors WHERE name = ? COLLATE NOCASE",
            (name,)
        ).fetchone()
        if row:
            return dict(row)
        return None
    finally:
        if own:
            conn.close()


_MALPEDIA_CACHE = None

def _load_malpedia_cache(conn: sqlite3.Connection):
    global _MALPEDIA_CACHE
    if _MALPEDIA_CACHE is not None:
        return _MALPEDIA_CACHE
    cache = {"actors": [], "families": []}
    
    # Load families
    for row in conn.execute("SELECT uuid, name, common_name, alt_names, description FROM malpedia_families").fetchall():
        r = dict(row)
        aliases = [r["name"], r["common_name"]] + [a.strip() for a in r["alt_names"].split(",") if a.strip()]
        # filter out short/common aliases to avoid FPs
        aliases = list(set([a for a in aliases if len(a) > 3]))
        cache["families"].append({
            "uuid": r["uuid"],
            "name": r["name"],
            "common_name": r["common_name"],
            "description": r["description"],
            "aliases": aliases
        })
        
    # Load actors
    for row in conn.execute("SELECT uuid, name, description FROM malpedia_actors").fetchall():
        r = dict(row)
        # malpedia_actors doesn't have an explicit aliases array in our DB, but we can use name
        aliases = [r["name"]]
        aliases = list(set([a for a in aliases if len(a) > 2]))
        cache["actors"].append({
            "uuid": r["uuid"],
            "name": r["name"],
            "description": r["description"],
            "aliases": aliases
        })
        
    _MALPEDIA_CACHE = cache
    return cache

def scan_malpedia_entities(text: str, conn: sqlite3.Connection = None):
    own = conn is None
    if own:
        conn = connect()
    try:
        cache = _load_malpedia_cache(conn)
        found_actors = []
        found_families = []
        text_lower = " " + text.lower() + " "
        
        for fam in cache["families"]:
            for alias in fam["aliases"]:
                if f" {alias.lower()} " in text_lower:
                    found_families.append(fam)
                    break # just need to match once
                    
        for actor in cache["actors"]:
            for alias in actor["aliases"]:
                if f" {alias.lower()} " in text_lower:
                    found_actors.append(actor)
                    break
                    
        return found_actors, found_families
    finally:
        if own:
            conn.close()

